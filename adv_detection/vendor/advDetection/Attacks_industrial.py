#!/usr/bin/env python
# coding: utf-8

# In[56]:


import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import torchattacks
from torchattacks import FGSM, PGD, MIFGSM 
import pandas as pd
from functions import encode_variable
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, recall_score
import torch.nn.functional as F
from pathlib import Path


# In[57]:


import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import torchattacks
from torchattacks import FGSM, PGD, MIFGSM 
import pandas as pd
from functions import encode_variable
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, recall_score
import torch.nn.functional as F
from pathlib import Path


# In[58]:


class RealTabularMIFGSM(torchattacks.MIFGSM):
    def __init__(self, model, eps=0.03, alpha=0.007, steps=10, decay=1.0, mask=None, feature_min = None, feature_max = None):
        super().__init__(model, eps, alpha, steps, decay)
        self.loss = nn.CrossEntropyLoss()  
        self.mask = mask 
        self.feature_min = feature_min
        self.feature_max = feature_max

    def forward(self, images, labels):
        """Overrides MIFGSM for tabular data."""

        adv_images = images.clone().detach()
        adv_images.requires_grad = True 

        momentum = 0
        for _ in range(self.steps):
            outputs = self.model(adv_images)
            loss = self.loss(outputs, labels)

            grad = torch.autograd.grad(loss, adv_images, retain_graph=True, create_graph=True, allow_unused=True)[0]

            if grad is None:
                print("ERROR: Gradient is None! adv_images is not in the graph!")
                break  

            grad = grad / torch.mean(torch.abs(grad), dim=(1,), keepdim=True)
            grad = grad + momentum * self.decay
            momentum = grad

            perturbation = self.alpha * grad.sign()
            if self.mask is not None:
                perturbation = perturbation * self.mask  # Zero out protected features

            adv_images = adv_images + perturbation
            adv_images = torch.clamp(adv_images, min=self.feature_min, max=self.feature_max) 

        return adv_images


# In[59]:


# Generating, training and testing surrogate model
class SurrogateModel(nn.Module):
    def __init__(self, input_dim):
        super(SurrogateModel, self).__init__()
        self.fc1 = nn.Linear(input_dim, 128) 
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 2)  # Binary classification (Normal vs. Anomalous)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        return self.fc3(x)

def test_surrogate(model_surrogate, X_test, y_test, device):
    model_surrogate.eval()
    X_test, y_test = X_test.to(device), y_test.to(device)

    with torch.no_grad():
        y_pred = model_surrogate(X_test).argmax(axis=1).cpu().numpy()

    accuracy = accuracy_score(y_test.cpu().numpy(), y_pred)
    recall = recall_score(y_test.cpu().numpy(), y_pred)
    f1 = f1_score(y_test.cpu().numpy(), y_pred, average='weighted')

    results = {
        "Accuracy": accuracy,
        "Recall": recall,
        "F1 Score": f1
    }
    print(f"Surrogate Model Results: {results}")
    return results

def train_surrogate(X_train, y_train, device):
    input_dim = X_train.shape[1]
    model_surrogate = SurrogateModel(input_dim).to(device)
    optimizer = optim.Adam(model_surrogate.parameters(), lr=0.001)
    criterion = nn.CrossEntropyLoss()

    train_loader = DataLoader(TensorDataset(X_train, y_train), batch_size=32, shuffle=True)

    for epoch in range(8):  # epochs
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            outputs = model_surrogate(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch+1}, Loss: {loss.item():.4f}")

    print("Surrogate model training complete.")
    return model_surrogate


# In[81]:


from sklearn.preprocessing import StandardScaler
def process_data(input_data, device):
    data = input_data.dropna(axis=0)
    print(data)
    #print(data.nunique() > 1)
    #data = data.loc[:, data.nunique() > 1]
    data.columns = [col.strip().lower() for col in data.columns]
    new_cols = ['timestamp' if 'starttimestamp' in col else col for col in data.columns]
    data.columns = new_cols
    try:
        data['timestamp'] = pd.to_datetime(data['timestamp'], errors='coerce')
        data = data.sort_values(by='timestamp', ascending=True)
    except:
        print("timestamp fallido")
    features = [col for col in data.columns if col not in ['city', 'timestamp', 'anomaly', 'normal/attack',  'startdate', 'weekdaystart', 'yearstart', 'hourstart', 'minutestart', 'enddate', 'endtimestamp', 'weekdayend', 'yearend', 'hourend', 'minuteend', 'class']]
    if "connectortype" in [col for col in data.columns]:
        features = ['connectortype', 'durationcharge' , 'durationsession' , 'energy' , 'tariff' ,
                'cost' , 'meanpower', 'maxpower']
        data = encode_variable(data, data.columns.get_loc("connectortype"))

    for feature in features:
        data[feature] = pd.to_numeric(data[feature], errors='coerce')

    data.dropna()
    #data = data.sample(frac=1).reset_index(drop=True)
    x_data = data.loc[:, features].select_dtypes(include=[np.number])
    y_data = data.loc[:, ['anomaly']].values.ravel()
    print(y_data)
    # Now scale
    scaler = StandardScaler()
    x_data = scaler.fit_transform(x_data)

    size = len(x_data)
    size_init = int(size * 0.8)
    x_train = x_data[:size_init]
    y_train = y_data[:size_init]
    x_test = x_data[size_init:]
    y_test = y_data[size_init:]

    #x_train, x_test, y_train, y_test = train_test_split(x_data, y_data, test_size=0.3, random_state=42, stratify=y_data)

    df = pd.DataFrame(x_test, columns=features)
    df["anomaly"] = y_test
    df = df.sample(frac=1).reset_index(drop=True)
    x_test = df.loc[:, features].values
    y_test = df.loc[:, ['anomaly']].values.ravel()
    x_train = np.array(x_train, dtype=np.float32) 
    x_test = np.array(x_test, dtype=np.float32)
    x_train = torch.tensor(x_train, dtype=torch.float32).to(device)
    y_train = torch.tensor(y_train, dtype=torch.long).to(device)
    x_test = torch.tensor(x_test, dtype=torch.float32).to(device)
    y_test = torch.tensor(y_test, dtype=torch.long).to(device)

    return data, x_train, x_test, y_train, y_test, features

def load_anomalous_test_samples(x_test, y_test):
    anomalous_indices = np.where(y_test == 1)[0] 
    X_anomalous = x_test[anomalous_indices]
    y_anomalous = y_test[anomalous_indices]
    return X_anomalous, y_anomalous, anomalous_indices

def process_anomalous_samples(x_train, y_train, x_test, y_test, device):
    # Prepare anomalous x y for perturbation
    X_anomalous_test, y_anomalous_test, anomalous_indices_test = load_anomalous_test_samples(x_test, y_test)
    X_anomalous_train, y_anomalous_train, anomalous_indices_train = load_anomalous_test_samples(x_train, y_train)
    x_anom_train = torch.tensor(X_anomalous_train, dtype=torch.float32).clone().detach().requires_grad_(True).to(device)
    x_anom_train = torch.tensor(X_anomalous_train, dtype=torch.float32).to(device)
    x_anom_train.requires_grad = True
    y_anom_train = torch.tensor(y_anomalous_train, dtype=torch.long).to(device)
    y_anom_train = y_anom_train.view(-1).to(device)

    x_anom_test = torch.tensor(X_anomalous_test, dtype=torch.float32).clone().detach().requires_grad_(True).to(device)
    x_anom_test = torch.tensor(X_anomalous_test, dtype=torch.float32).to(device)
    x_anom_test.requires_grad = True
    y_anom_test = torch.tensor(y_anomalous_test, dtype=torch.long).to(device)
    y_anom_test = y_anom_test.view(-1).to(device)

    return x_anom_train, y_anom_train, x_anom_test, y_anom_test, anomalous_indices_test, anomalous_indices_train

def extract_column_stats(df):
    stats = {}
    feature_min = []
    feature_max = []
    for column in df.columns:
        stats[column] = {
            'max': df[column].max(),
            'min': df[column].min(),
            'mean': df[column].mean()
        }
        feature_min.append(df[column].min())
        feature_max.append(df[column].max())
    print(stats)
    print(feature_min)
    print(feature_max)
    return stats, feature_min, feature_max

def generateMask(x): 
    mask = []
    for i in range(x.cpu().numpy().shape[1]):  
        col = x.cpu().numpy()[:, i] 
        unique_values = np.unique(col)  
        if len(unique_values) < 5 or np.issubdtype(col.dtype, np.integer):
            mask.append(0) 
        else:
            mask.append(1)
    print(mask)
    return mask

def save_samples_csv(adversarial_samples, adv_dir, data, features, y):
    adversarial_dataset = pd.DataFrame(adversarial_samples.detach().cpu().numpy(), columns=data.loc[:, features].columns)
    adversarial_dataset['anomaly'] = y.detach().cpu().numpy()
    adversarial_dataset.to_csv(adv_dir, index=False)
    #print(f"{adv_dir} converted to CSV")

def performAttacks(steps, x, y, mask, feature_min, feature_max, model_surrogate, file, stage, data, features, eps, alpha):
    mifgsm = RealTabularMIFGSM(model_surrogate, eps=eps, alpha=alpha, steps=steps, decay=0.8, mask=mask, feature_min=feature_min,
                                    feature_max=feature_max)
    mifgsm_samples = mifgsm(x, y)
    adv_dir = f'./data/aexamples/{file}/mifgsm/{stage}/adversarialexamples_eps{str(eps)}.csv'
    Path(adv_dir).parent.mkdir(parents=True, exist_ok=True)
    save_samples_csv(mifgsm_samples, adv_dir, data, features, y)

def attack(x, y, mask, feature_min, feature_max, model_surrogate, file, stage, data, features):
    steps = 20
    epsilons = [0.0]

    for value in np.arange(0.003, 0.031, 0.006):
        eps = round(value, 3)
        alpha = round(eps/steps, 4)
        performAttacks(steps, x, y, mask, feature_min, feature_max, model_surrogate, file, stage, data, features, eps, alpha)
        epsilons.append(eps)
    for value in np.arange(0.03, 0.3, 0.06):
        eps = round(value, 3)
        alpha = round(eps/steps, 4)
        performAttacks(steps, x, y, mask, feature_min, feature_max, model_surrogate, file, stage, data, features, eps, alpha)
        epsilons.append(eps)
    if "train" in stage:
        for value in np.arange(0.003, 0.3, 0.05):
            eps = round(value, 3)
            alpha = round(eps/steps, 4)
            performAttacks(steps, x, y, mask, feature_min, feature_max, model_surrogate, file, stage, data, features, eps, alpha)

    return epsilons


# In[85]:


def generate_ae_examples():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f'Device: {device}')
    data_path = Path('./data')
    original_results = {}
    files = [f for f in data_path.iterdir() if f.is_file()]
    for file in files:
        file_name = file.with_suffix('').as_posix().split('/')[1]
        original_results[file_name] = {}
        print(f"Processing file {file_name}")
        if 'xlsx' in file.name:
            data = pd.read_excel(file)
        else:
            data = pd.read_csv(file)
        data, x_train, x_test, y_train, y_test, features = process_data(data, device)
        print(np.unique(y_train.cpu().numpy(), return_counts=True))
        print(np.unique(y_test.cpu().numpy(), return_counts=True))
        # Train and test surrogate model
        model_surrogate = train_surrogate(x_train, y_train, device)
        original_results[file_name]['results'] = test_surrogate(model_surrogate, x_test, y_test, device)
        original_results[file_name]['x_test'] = x_test
        original_results[file_name]['y_test'] = y_test
        original_results[file_name]['x_train'] = x_train
        original_results[file_name]['y_train'] = y_train
        original_results[file_name]['features'] = features
        original_results[file_name]['model_surrogate'] = model_surrogate 
        # Generate data constraints
        stats, feature_min, feature_max = extract_column_stats(data.loc[:, features])
        mask = generateMask(x_train)
        feature_min = torch.tensor(np.array(feature_min), dtype=torch.float32).to(device)
        feature_max = torch.tensor(np.array(feature_max), dtype=torch.float32).to(device)  
        mask = torch.tensor(np.array(mask), dtype=torch.float32).to(device) 

        x_anom_train, y_anom_train, x_anom_test, y_anom_test, anomalous_indices_test, anomalous_indices_train = process_anomalous_samples(x_train.cpu(), y_train.cpu(), x_test.cpu(), y_test.cpu(), device)
        original_results[file_name]['anomalous_indices_test'] = anomalous_indices_test
        original_results[file_name]['anomalous_indices_train'] = anomalous_indices_train
        epsilons = attack(x_anom_train, y_anom_train, mask, feature_min, feature_max, model_surrogate, file_name, 'train', data, features)
        epsilons = attack(x_anom_test, y_anom_test, mask, feature_min, feature_max, model_surrogate, file_name, 'test', data, features)

    return original_results, epsilons, device

original_results, epsilons, device = generate_ae_examples()


# In[86]:


# Test examples
def read_adv_data(advPath):
    adversarial_data = pd.read_csv(advPath)
    features = [col for col in adversarial_data.columns if col not in ['timestamp', 'anomaly', 'normal/attack',  'startdate', 'weekdaystart', 'yearstart', 'hourstart', 'minutestart', 'enddate', 'endtimestamp', 'weekdayend', 'yearend', 'hourend', 'minuteend', 'class']]
    adversarial_x_data = adversarial_data.loc[:, features].values
    adversarial_y_data = adversarial_data.loc[:, ['anomaly']].values.ravel()
    return adversarial_x_data, adversarial_y_data, features

def test_adversarial_samples(advPath, x_test, y_test, model_surrogate, anomalous_indices, device):
    adversarial_x_data, adversarial_y_data, _ = read_adv_data(advPath)
    X_modified, Y_modified  = x_test.clone().cpu().numpy(), y_test.clone().cpu().numpy()
    X_modified[anomalous_indices] = adversarial_x_data
    Y_modified[anomalous_indices] = adversarial_y_data

    try:
        y_pred = model_surrogate.predict(X_modified)
    except: 
        model_surrogate.eval()
        tensor_X_modified = torch.tensor(np.array(X_modified, dtype=np.float32), dtype=torch.float32).to(device)
        with torch.no_grad():
            y_pred = model_surrogate(tensor_X_modified).argmax(axis=1).cpu().numpy()

    accuracy = accuracy_score(Y_modified, y_pred)
    recall = recall_score(Y_modified, y_pred)
    f1 = f1_score(Y_modified, y_pred)
    return  accuracy, f1, recall

def initializeResults(original_results, file_name, epsilons):
    metrics = ["Accuracy", "F1 Score", "Recall", "EIR"]
    attacks = ["MIFGSM"]
    multi_index = pd.MultiIndex.from_product([attacks, metrics], names=["Attack", "Metric"])
    df_results = pd.DataFrame(index=multi_index, columns=epsilons)
    df_results.loc[("MIFGSM", "Accuracy"), 0.0] = original_results[file_name]['results']["Accuracy"]
    df_results.loc[("MIFGSM", "F1 Score"), 0.0] = original_results[file_name]['results']["F1 Score"]
    df_results.loc[("MIFGSM", "Recall"), 0.0] = original_results[file_name]['results']["Recall"]
    df_results.loc[("MIFGSM", "EIR"), 0.0] = "-"
    return df_results

def obtain_adv_results(df_results, original_results, file, stage,  x_test, y_test, anomalous_indices, eps, model_surrogate, device):
    # MIFGSM
    adv_dir = f'./data/aexamples/{file}/mifgsm/{stage}/adversarialexamples_eps{str(eps)}.csv'
    accuracy, f1, recall = test_adversarial_samples(adv_dir, x_test, y_test, model_surrogate, anomalous_indices, device)
    df_results[file].loc[("MIFGSM", "Accuracy"), eps] = accuracy
    df_results[file].loc[("MIFGSM", "F1 Score"), eps] = f1
    df_results[file].loc[("MIFGSM", "Recall"), eps] = recall
    eir = 1 - (df_results[file].loc[("MIFGSM", "Recall"), eps] / max(original_results[file]['results']["Recall"], 1e-8))
    df_results[file].loc[("MIFGSM", "EIR"), eps] = eir * 100

    return df_results

def completeTest(original_results, epsilons, device):
    df_results = {}
    stage = 'test'

    for file in original_results:
        df_results[file] = initializeResults(original_results, file, epsilons)
        x_test, y_test = original_results[file]['x_test'], original_results[file]['y_test']
        anomalous_indices = original_results[file]['anomalous_indices_test']
        model_surrogate = original_results[file]['model_surrogate']
        #for value in np.arange(0.003, 0.031, 0.006): 
        #    eps = round(value, 3)
        #    df_results = obtain_adv_results(df_results, file, stage,  x_test, y_test, anomalous_indices, eps, model_surrogate, device)

        #for value in np.arange(0.03, 0.3, 0.06):
        for value in np.arange(0.003, 0.031, 0.006): 
            eps = round(value, 3)
            df_results = obtain_adv_results(df_results, original_results, file, stage,  x_test, y_test, anomalous_indices, eps, model_surrogate, device)

        for value in np.arange(0.03, 0.3, 0.06):
            eps = round(value, 3)
            df_results = obtain_adv_results(df_results, original_results, file, stage,  x_test, y_test, anomalous_indices, eps, model_surrogate, device)

    return df_results
df_results = completeTest(original_results, epsilons, device)


# In[84]:


import pickle
with open("df_results.pkl", "wb") as f:
    pickle.dump(df_results, f)
with open("original_results.pkl", "wb") as f:
    pickle.dump(original_results, f)


# In[12]:


import pickle
with open("df_results.pkl", "rb") as f:
    df_results = pickle.load(f)
with open("original_results.pkl", "rb") as f:
    original_results = pickle.load(f)


# In[87]:


df_results['Dundee_Clean_With_Anomalies_All']


# In[88]:


df_results['Dundee_Clean_With_Anomalies']


# In[89]:


df_results['Boulder_Clean_With_Anomalies']


# In[90]:


df_results['PaloAlto_2018_2022_Clean_With_Anomalies']


# In[91]:


df_results['Perth_Clean_With_Anomalies']


# In[92]:


df_results['Netherlands_Clean_With_Anomalies']


# In[61]:


df_results['Canada1_clean_WithAnomalies']


# In[62]:


df_results['Germany_clean_WithAnomalies']


# In[63]:


df_results['Portugal_clean_WithAnomalies']


# In[8]:


df_results['US_Alabama_clean_WithAnomalies']


# In[65]:


df_results['vancover_clean_WithAnomalies']


# In[93]:


from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

def trainModelsTransfer(x_train, y_train):
    mask = ~torch.isnan(x_train).any(dim=1)
    x_train = x_train[mask]
    y_train = y_train[mask]
    models = []
    # 1. - Train Catboost   
    print("[CATBOOST]")     
    catboost_model = CatBoostClassifier()
    catboost_model.fit(x_train.cpu().numpy(), y_train.cpu().numpy(), verbose=False)
    models.append(catboost_model)
    # 2 . - Train LGBM        
    print("[LGBM]")    
    lgb_model = LGBMClassifier ()
    lgb_model. fit(x_train.cpu().numpy(), y_train.cpu().numpy())
    models.append(lgb_model)
    # 3. - Train MLP
    print("[MLP]")         
    mlp_model = MLPClassifier()
    mlp_model.fit(x_train.cpu().numpy(), y_train.cpu().numpy())
    models.append(mlp_model)
    # 4. - Train RF   
    print("[RF]")      
    rf_model = RandomForestClassifier()
    rf_model.fit(x_train.cpu().numpy(), y_train.cpu().numpy())
    models.append(rf_model)
    # 5. - Train  XGB   
    print("[XGB]")      
    xgb_model = XGBClassifier()
    xgb_model.fit(x_train.cpu().numpy(), y_train.cpu().numpy())
    models.append(xgb_model)
    return models

def initializeResultsTransfer(epsilons, models, x_test, y_test):
    x_test = x_test.cpu().numpy()
    y_test = y_test.cpu().numpy()
    metrics = ["Accuracy", "F1 Score", "Recall", "EIR"]
    attacks = ["MIFGSM"]
    models_names = ["CATBOOST", "LGBM", "MLP", "RF", "XGB"]
    multi_index = pd.MultiIndex.from_product([models_names, attacks, metrics], names=["Models", "Attack", "Metric"])
    df_results = pd.DataFrame(index=multi_index, columns=epsilons)
    for idx, model_name in enumerate(models_names):
        y_pred = models[idx].predict(x_test)
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        for attack in attacks:
            df_results.loc[(model_name, attack, "Accuracy"), 0.0] = accuracy
            df_results.loc[(model_name, attack, "F1 Score"), 0.0] = f1
            df_results.loc[(model_name, attack, "Recall"), 0.0] = recall
            df_results.loc[(model_name, attack, "EIR"), 0.0] = "-"      

        print(recall)

    return df_results

def test_adversarial_samples_transfer(adv_dir, x_test, y_test, ads_model, anomalous_indices, device):
    adversarial_x_data, adversarial_y_data, _ = read_adv_data(adv_dir)
    X_modified, Y_modified  = x_test.clone().cpu().numpy(), y_test.clone().cpu().numpy()
    X_modified[anomalous_indices] = adversarial_x_data
    Y_modified[anomalous_indices] = adversarial_y_data

    y_pred =  ads_model.predict(X_modified)

    accuracy = accuracy_score(Y_modified, y_pred)
    recall = recall_score(Y_modified, y_pred)
    f1 = f1_score(Y_modified, y_pred)
    print(recall)
    return  accuracy, f1, recall

def obtain_adv_results_transfer(df_results, original_results,  file, stage,  x_test, y_test, anomalous_indices, eps, ads_model, model_name, device):
    # MIFGSM
    adv_dir = f'./data/aexamples/{file}/mifgsm/{stage}/adversarialexamples_eps{str(eps)}.csv'
    accuracy, f1, recall = test_adversarial_samples_transfer(adv_dir, x_test, y_test, ads_model, anomalous_indices, device)
    df_results.loc[(model_name, "MIFGSM", "Accuracy"), eps] = accuracy
    df_results.loc[(model_name,"MIFGSM", "F1 Score"), eps] = f1
    df_results.loc[(model_name,"MIFGSM", "Recall"), eps] = recall
    eir = 1 - (df_results.loc[(model_name,"MIFGSM", "Recall"), eps] / df_results.loc[(model_name,"MIFGSM", "Recall"), 0.0])
    df_results.loc[(model_name,"MIFGSM", "EIR"), eps] = eir * 100
    print(f'Recall: {recall}')
    return df_results
def testTransferability(original_results, epsilons):
    transferability_results = {}
    models_names = ["CATBOOST", "LGBM", "MLP", "RF", "XGB"]
    try_epsilon = [0.0, 0.003, 0.021, 0.090, 0.210]
    # Test normal
    index = 0
    for file in original_results:
        try:
            print(f"processing file {file} number {index}")
            transferability_results[file] = {}
            x_train = original_results[file]['x_train']
            y_train = original_results[file]['y_train']
            x_test = original_results[file]['x_test']
            y_test = original_results[file]['y_test']
            models = trainModelsTransfer(x_train, y_train)
            df_results = initializeResultsTransfer(try_epsilon, models, x_test, y_test)
            transferability_results[file]['models'] = models
            transferability_results[file]['transfer_results'] = df_results
            for idx, model_name in enumerate(models_names):
                for eps in try_epsilon[1:]:
                    transferability_results[file]['transfer_results'] = obtain_adv_results_transfer(transferability_results[file]['transfer_results'] , original_results  , file, 'test',  x_test, y_test, original_results[file]['anomalous_indices_test'], eps, models[idx], model_name, device)
        except Exception as e:
            print(f"File {file} failed because {e}")  
        #if index > 3: 
        #    print(f"Finish with idx {index}")
        #    break
        index = index + 1

# df_results = completeTest(original_results, epsilons, device)
    return transferability_results


# In[94]:


transferability_results = testTransferability(original_results, epsilons)


# In[ ]:


import pickle
with open("transferability_results.pkl", "wb") as f:
    pickle.dump(transferability_results, f)


# In[33]:


import pickle
with open("transferability_results.pkl", "rb") as f:
    transferability_results = pickle.load(f)


# In[114]:


transferability_results['Dundee_Clean_With_Anomalies']['transfer_results']


# In[116]:


transferability_results['PaloAlto_2018_2022_Clean_With_Anomalies']['transfer_results']


# In[117]:


transferability_results['Netherlands_Clean_With_Anomalies']['transfer_results']


# In[118]:


transferability_results['Boulder_Clean_With_Anomalies']['transfer_results']


# In[119]:


transferability_results['Perth_Clean_With_Anomalies']['transfer_results']


# In[11]:


transferability_results['US_Alabama_clean_WithAnomalies']['transfer_results']


# In[121]:


transferability_results['Germany_clean_WithAnomalies']['transfer_results']


# In[122]:


transferability_results['Canada1_clean_WithAnomalies']['transfer_results']


# In[ ]:


transferability_results['vancover_clean_WithAnomalies']['transfer_results']


# In[124]:


transferability_results['Portugal_clean_WithAnomalies']['transfer_results']


# In[95]:


def process_data_gb(input_data, device):
    data = input_data.dropna(axis=0)
    data = data.loc[:, data.nunique() > 1]
    data.columns = [col.strip().lower() for col in data.columns]
    new_cols = ['timestamp' if 'starttimestamp' in col else col for col in data.columns]
    data.columns = new_cols
    try:
        data['timestamp'] = pd.to_datetime(data['timestamp'], errors='coerce')
        data = data.sort_values(by='timestamp', ascending=True)
    except:
        print("timestamp fallido")
    features = [col for col in data.columns if col not in ['city', 'timestamp', 'anomaly', 'normal/attack',  'startdate', 'weekdaystart', 'yearstart', 'hourstart', 'minutestart', 'enddate', 'endtimestamp', 'weekdayend', 'yearend', 'hourend', 'minuteend', 'class']]
    #print(data)
    if "connectortype" in features:
        data = encode_variable(data, data.columns.get_loc("connectortype"))
        features = ['connectortype', 'durationcharge' , 'durationsession' , 'energy' , 'tariff' ,
                'cost' , 'meanpower', 'maxpower']
    for feature in features:
        data[feature] = pd.to_numeric(data[feature], errors='coerce')
    print(data)
    data.dropna()
    #data = data.sample(frac=1).reset_index(drop=True)
    x_data = data.loc[:, features].select_dtypes(include=[np.number])
    y_data = data.loc[:, ['anomaly']].values.ravel()
    print(y_data)

    size = len(x_data)
    size_init = int(size * 0.8)
    x_train = x_data[:size_init]
    y_train = y_data[:size_init]
    x_test = x_data[size_init:]
    y_test = y_data[size_init:]

    #x_train, x_test, y_train, y_test = train_test_split(x_data, y_data, test_size=0.3, random_state=42, stratify=y_data)

    df = pd.DataFrame(x_test, columns=features)
    df["anomaly"] = y_test
    df = df.sample(frac=1).reset_index(drop=True)
    x_test = df.loc[:, features].values
    y_test = df.loc[:, ['anomaly']].values.ravel()
    x_train = np.array(x_train, dtype=np.float32) 
    x_test = np.array(x_test, dtype=np.float32)
    x_train = torch.tensor(x_train, dtype=torch.float32).to(device)
    y_train = torch.tensor(y_train, dtype=torch.long).to(device)
    x_test = torch.tensor(x_test, dtype=torch.float32).to(device)
    y_test = torch.tensor(y_test, dtype=torch.long).to(device)

    return data, x_train, x_test, y_train, y_test, features



# In[96]:


def testTransferability_gb():
    transferability_results = {}
    models_names = ["CATBOOST", "LGBM", "MLP", "RF", "XGB"]
    try_epsilon = [0.0, 0.003, 0.021, 0.090, 0.210]
    # Test normal
    data_path = Path('./data')
    files = [f for f in data_path.iterdir() if f.is_file()]
    for file in files:
        file_name = file.with_suffix('').as_posix().split('/')[1]
        print(f"Processing file {file_name}")
        if 'xlsx' in file.name:
            data = pd.read_excel(file)
        else:
            data = pd.read_csv(file)
        data, x_train, x_test, y_train, y_test, features = process_data_gb(data, device)
        try:
            print(f"processing file {file_name}")
            transferability_results[file_name] = {}
            models = trainModelsTransfer(x_train, y_train)
            df_results = initializeResultsTransfer(try_epsilon, models, x_test, y_test)
            transferability_results[file_name]['models'] = models
            transferability_results[file_name]['transfer_results'] = df_results
            for idx, model_name in enumerate(models_names):
                for eps in try_epsilon[1:]:
                    transferability_results[file_name]['transfer_results'] = obtain_adv_results_transfer(transferability_results[file_name]['transfer_results'] , original_results  , file_name, 'test',  x_test, y_test, original_results[file_name]['anomalous_indices_test'], eps, models[idx], model_name, device)
        except Exception as e:
            print(f"File {file} failed because {e}")  

    return transferability_results


# In[97]:


transferability_results_gb = testTransferability_gb()


# In[39]:


import pickle
with open("transferability_results_gb.pkl", "wb") as f:
    pickle.dump(transferability_results_gb, f)


# In[ ]:


import pickle
with open("transferability_results_gb.pkl", "rb") as f:
    transferability_results_gb = pickle.load(f)


# In[41]:


for file in transferability_results_gb:
    print(file)


# In[43]:


transferability_results_gb['Dundee_Clean_With_Anomalies']['transfer_results']


# In[46]:


transferability_results_gb['PaloAlto_2018_2022_Clean_With_Anomalies']['transfer_results']


# In[47]:


transferability_results_gb['Perth_Clean_With_Anomalies']['transfer_results']


# In[48]:


transferability_results_gb['Boulder_Clean_With_Anomalies']['transfer_results']


# In[49]:


transferability_results_gb['Netherlands_Clean_With_Anomalies']['transfer_results']


# In[50]:


transferability_results_gb['vancover_clean_WithAnomalies']['transfer_results']


# In[51]:


transferability_results_gb['US_Alabama_clean_WithAnomalies']['transfer_results']


# In[53]:


transferability_results_gb['Germany_clean_WithAnomalies']['transfer_results']


# In[54]:


transferability_results_gb['Canada1_clean_WithAnomalies']['transfer_results']


# In[55]:


transferability_results_gb['Portugal_clean_WithAnomalies']['transfer_results']


# In[ ]:





# In[ ]:




