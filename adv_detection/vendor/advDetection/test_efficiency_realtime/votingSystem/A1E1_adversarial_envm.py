# Detection envm DT
import random
import statistics 
import pandas as pd
import numpy as np
import seaborn as sns
import os, sys, inspect
from joblib import load
from itertools import product
import matplotlib.pyplot as plt
import psutil
import time
sys.stdout.reconfigure(line_buffering=True)
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)
from codecarbon import EmissionsTracker
from sklearn.metrics import recall_score, f1_score, accuracy_score
from votingSystem.ADSystems.CatboostADS import CatboostADS
from utilities.functions import encode_variable
from votingSystem.ADSystems.LGBMachineADS import LGBMachineADS
from votingSystem.ADSystems.MultiLayerPerceptronADS import MultiLayerPerceptronADS
from votingSystem.ADSystems.RandomForestADS import RandomForestADS
from votingSystem.ADSystems.XGBoostADS import XGBoostADS
from votingSystem.ADSystems.DeepANN_ADS import DeepANN_ADS
import tensorflow as tf
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
_ = tf.constant(0.0)
tf.config.list_physical_devices()
import threading
from model_utils import build_model
# Para guardar valores de CPU en tiempo real
cpu_usage_samples = []
stop_cpu_monitor = False

# Función que mide CPU cada segundo
def monitor_cpu(cpu_usage_samples, stop_flag):
    """Monitorea el uso de CPU cada segundo hasta que stop_flag esté activado."""
    while not stop_flag["stop"]:
        cpu = psutil.cpu_percent(interval=1)
        cpu_usage_samples.append(cpu)

data = pd.read_csv("../../data/envm.csv")
data = data.sort_values(by='timestamp', ascending=True)

features = ['ldr1', 'led2', 'led3', 'temperature1', 'potentiometer2', 'gas1', 'led1', 'air_quality1', 'temperature2', 'potentiometer1', 'humidity1']
x_envm = data.loc[:, features].values
y_envm = data.loc[:, ['anomaly']].values.ravel()
size = len(x_envm)
size_init = int(size * 0.8)
x_init = x_envm[:size_init]
y_init = y_envm[:size_init]
x_inc = x_envm[size_init:]
y_inc = y_envm[size_init:]

window_size = 1000
envmADS_catboost = CatboostADS(window_size, x_init, y_init, "envmADS_catboost")
envmADS_lgbm = LGBMachineADS(window_size, x_init, y_init, "envmADS_lgbm")
envmADS_MLP = MultiLayerPerceptronADS(window_size, x_init, y_init, "envmADS_MLP")
envmADS_RF = RandomForestADS(window_size, x_init, y_init, "envmADS_RF")
envmADS_xgb = XGBoostADS(window_size, x_init, y_init, "envmADS_xgb")
envmADS_dnn = DeepANN_ADS(window_size, x_init, y_init, f"envmADS_dnn", 11)
adsModels = [envmADS_lgbm, envmADS_MLP, envmADS_MLP, envmADS_RF, envmADS_xgb, envmADS_dnn]


df = pd.DataFrame(x_inc, columns=features)
df["anomaly"] = y_inc
df = df.sample(frac=1).reset_index(drop=True)
x_inc = df.loc[:, features].values
y_inc = df.loc[:, ['anomaly']].values.ravel()

def trim_array_to_equal_parts(arr, num_parts):
    total_elements = len(arr)
    divisible_length = total_elements - (total_elements % num_parts)
    return arr[:divisible_length]

num_splits = 50
x_splits_noatt = np.split(trim_array_to_equal_parts(x_inc, num_splits), num_splits) 
y_splits_noatt = np.split(trim_array_to_equal_parts(y_inc, num_splits), num_splits)
print("Shape of no attack data splits.")
print(x_splits_noatt[num_splits - 1].shape)
print(y_splits_noatt[num_splits - 1].shape)

def generate_equal_splits(x_inc, y_inc, x_adv, y_adv, num_splits):  
    adv_x_splits = np.split(trim_array_to_equal_parts(x_adv, num_splits), num_splits) 
    adv_y_splits = np.split(trim_array_to_equal_parts(y_adv, num_splits), num_splits)

    y_inc = np.array(y_inc)
    x_inc = np.array(x_inc) 
    x_splits = np.split(trim_array_to_equal_parts(x_inc, num_splits), num_splits)
    y_splits = np.split(trim_array_to_equal_parts(y_inc, num_splits), num_splits) 

    normal_indices = np.where(y_inc == 0)[0] 
    x_inc_normal = x_inc[normal_indices]
    y_inc_normal = y_inc[normal_indices]
    x_normal_splits = np.split(trim_array_to_equal_parts(x_inc_normal, num_splits), num_splits)
    y_normal_splits = np.split(trim_array_to_equal_parts(y_inc_normal, num_splits), num_splits) 

    if x_normal_splits[num_splits - 1].shape[0] >= adv_x_splits[num_splits - 1].shape[0]:
        indices = np.random.choice(x_normal_splits[num_splits - 1].shape[0], adv_x_splits[num_splits - 1].shape[0], replace=False)
        for i in range(num_splits):
            x_normal_splits[i] = x_normal_splits[i][indices]
            y_normal_splits[i] = y_normal_splits[i][indices]
    else:
        indices = np.random.choice(adv_x_splits[num_splits - 1].shape[0], x_normal_splits[num_splits - 1].shape[0], replace=False)
        for i in range(num_splits):
            adv_x_splits[i] = adv_x_splits[i][indices]
            adv_y_splits[i] = adv_y_splits[i][indices]
    for i in range(num_splits):
        adv_x_splits[i] = np.concatenate((x_normal_splits[i], adv_x_splits[i]), axis=0)
        adv_y_splits[i] = np.concatenate((y_normal_splits[i], adv_y_splits[i]), axis=0)

    if x_splits[num_splits - 1].shape[0] >= adv_x_splits[num_splits - 1].shape[0]:
        indices = np.random.choice(x_splits[num_splits - 1].shape[0], adv_x_splits[num_splits - 1].shape[0], replace=False)
        for i in range(num_splits):
            x_splits[i] = x_splits[i][indices]
            y_splits[i] = y_splits[i][indices]
    else:

        indices = np.random.choice(adv_x_splits[num_splits - 1].shape[0], x_splits[num_splits - 1].shape[0], replace=False)
        for i in range(num_splits):
            adv_x_splits[i] = adv_x_splits[i][indices]
            adv_y_splits[i] = adv_y_splits[i][indices]

    print(f"Final shape no attack: x_splits {x_splits[0].shape} y_splits {y_splits[0].shape}.")
    print(f"Final shape adversarial adv_x_splits{adv_x_splits[0].shape} adv_ysplits {adv_y_splits[0].shape}.")
    return x_splits, y_splits, adv_x_splits, adv_y_splits

def read_adv_data(advPath):
    adversarial_data = pd.read_csv(advPath)
    ftrs = [item.lower() for item in features]
    adversarial_x_data = adversarial_data.loc[:, ftrs].values
    adversarial_y_data = adversarial_data.loc[:, ['anomaly']].values.ravel()

    return adversarial_x_data, adversarial_y_data 

def generate_random_attack_models(attack: str, eps):
    if attack == "random":
        which_models = [[random.randint(0, 4)] for _ in range(50)]
    elif attack == "all":
        which_models = [[0, 1, 2, 3, 4] for _ in range(50)]
    elif attack == "No attack":
        which_models = [[]]
    else:
        raise Exception("Error, no attack defined.")
    return which_models

def cargar_muestras_adversarias(eps, x_inc, y_inc, num_splits, adv_attack):
    adv_path = f'../../data/aexamples/envm_test/{adv_attack}/test/adversarialexamples_eps{str(eps)}.csv'
    adversarial_x_data, adversarial_y_data = read_adv_data(adv_path)
    #x_test_adversarial = np.array(adversarial_x_data, dtype=np.float32) # Datos anomalos adversarios
    #y_test_adversarial = np.array(adversarial_y_data, dtype=np.float32) # hay que mezclar con datos normales

    anomalous_indices = np.where(y_inc == 1)[0]
    X_modified, Y_modified  = x_inc.copy(), y_inc.copy()
    X_modified[anomalous_indices] = adversarial_x_data
    Y_modified[anomalous_indices] = adversarial_y_data
    y_det = np.zeros(y_inc.shape[0])
    y_det[anomalous_indices] = np.ones(len(anomalous_indices))

    x_splits_adv = np.split(trim_array_to_equal_parts(X_modified, num_splits), num_splits) 
    y_splits_adv = np.split(trim_array_to_equal_parts(Y_modified, num_splits), num_splits)
    y_splits_det = np.split(trim_array_to_equal_parts(y_det, num_splits), num_splits)
    print("Shape of adv data splits.")
    print(x_splits_adv[num_splits - 1].shape)
    print(y_splits_adv[num_splits - 1].shape)
    print(y_splits_det[num_splits - 1].shape)
    return x_splits_adv, y_splits_adv, y_splits_det

def set_y_limits(metric):
    if metric == "Accuracy" or metric == "Recall" or metric == "F1 Score":
            y_min = 0.0# Store min values for each metric
            y_max = 1.05  # Store max values for each metric
    elif metric == "Seconds":
        y_min, y_max = 0, 0.005 
    elif metric == "%":
        y_min, y_max = 0, 10
    elif metric == "KWh":
         y_min, y_max = 0.0, 0.001
    else:
        y_min = -0.2
        y_max = 1.0
    return y_min, y_max
def plot(title, data_models, plot_file_name, metric):
    sns.set_context("notebook", font_scale=1.3)
    #plt.figure(figsize=(10, 4))  
    plt.figure(figsize=(7, 3))  # Create a new figure for each coordinator
    
    # Convert model data to a DataFrame and Melt df_models to long format for Seaborn plotting
    df_models = pd.DataFrame(data_models, columns=["CB", "LGBM", "MLP", "RF", "XGB", "DNN"])
    df_models["Step"] = df_models.index  # Add a time step index
    df_models_long = df_models.melt(id_vars=["Step"], var_name="Model", value_name=metric)
    
    y_min, y_max = set_y_limits(metric)
    sns.lineplot(data=df_models_long, x="Step", y=metric, hue="Model", palette="rocket", linestyle="dashed", rasterized=True)
    plt.ylim(y_min, y_max)

    # Add labels and title
    plt.xlabel("Split")
    plt.ylabel(metric)
    plt.title(f"{title}")
    plt.legend(title="Legend", ncol=2, loc='upper right', bbox_to_anchor=(0.1, 0), fontsize=10,  title_fontsize=12)
    plt.xticks(np.arange(0, 51, 3))
    #plt.savefig(plot_file_name, dpi=300, bbox_inches='tight')  # Save as a high-quality PNG
    plt.savefig(plot_file_name, format="pdf", dpi=200, bbox_inches='tight')
    plt.clf()

def plot_detection(title, data_detection, plot_file_name):
    sns.set_context("notebook", font_scale=1.3)
    plt.figure(figsize=(7, 3))  

    # Convert model data to a DataFrame and Melt df_models to long format for Seaborn plotting
    df_models = pd.DataFrame(data_detection, columns=["f1-score", "recall", "accuracy" ])
    df_models["Step"] = df_models.index  # Add a time step index
    df_models_long = df_models.melt(id_vars=["Step"], var_name="Metric", value_name="Performance")
    
    y_min, y_max = 0.0, 1.05
    sns.lineplot(data=df_models_long, x="Step", y="Performance", hue="Metric", palette="rocket", linestyle="dashed", rasterized=True)
    plt.ylim(y_min, y_max)

    # Add labels and title
    plt.xlabel("Split")
    plt.ylabel("Performance")
    plt.title(f"{title}")
    plt.legend(title="Legend", ncol=2, loc='upper right', fontsize=10,  title_fontsize=12)
    plt.xticks(np.arange(0, 51, 5))
    #plt.savefig(plot_file_name, dpi=300, bbox_inches='tight')  # Save as a high-quality PNG
    plt.savefig(plot_file_name, format="pdf", dpi=200, bbox_inches='tight')
    plt.clf()

def plot_measurement(title, measurements, plot_file_name, metric,epsilons):
    sns.set_context("notebook", font_scale=1.3)
    plt.figure(figsize=(7, 3))  
    # Convert model data to a DataFrame and Melt df_models to long format for Seaborn plotting
    df_models = pd.DataFrame(list(zip(*measurements)), columns=epsilons)
    df_models["Step"] = df_models.index  # Add a time step index
    df_models_long = df_models.melt(id_vars=["Step"], var_name="Epsilon", value_name=metric)
    
    y_min, y_max = set_y_limits(metric)
    sns.lineplot(data=df_models_long, x="Step", y=metric, hue="Epsilon", palette="rocket", rasterized=True)
    plt.ylim(y_min, y_max)

    # Add labels and title
    plt.xlabel("Split")
    plt.ylabel(metric)
    plt.title(f"{title}")
    plt.legend(title="Legend", ncol=2, loc='upper right', fontsize=10,  title_fontsize=12)
    plt.xticks(np.arange(0, 51, 5))
    #plt.savefig(plot_file_name, dpi=300, bbox_inches='tight')  # Save as a high-quality PNG
    plt.savefig(plot_file_name, format="pdf", dpi=200, bbox_inches='tight')
    plt.clf()

def get_metrics(y_labels, y_preds):
    try:
        recall = recall_score(y_labels, y_preds)
        f1 = f1_score(y_labels, y_preds)
        accuracy = accuracy_score(y_labels, y_preds)
    except:
        y_preds = (y_preds > 0.5).astype("int32")
        recall = recall_score(y_labels, y_preds)
        f1 = f1_score(y_labels, y_preds)
        accuracy = accuracy_score(y_labels, y_preds)
    return recall, f1, accuracy

def models_predict(x_sample, y_labels, y_det, det_model, models, threshold, adv_x_sample = None, which_model: list = None):
    models_recall, models_f1, models_accuracy = [], [], []
    models_det_performance = []
    models_emmisions, models_cpu, models_time = [], [], []
    
    for idx, model in enumerate(models):
        adv_obj = False
        stop_flag = {"stop": False}
        if adv_x_sample is not None:
            if idx in which_model:
                adv_obj = True
                y_pred = model.predict_proba_votes(adv_x_sample.astype(np.float32), y_labels, threshold)    
                start_time = time.time()
                tracker = EmissionsTracker(log_level="error")
                tracker.start()
                cpu_thread = threading.Thread(target=monitor_cpu, args=(cpu_usage_samples, stop_flag))
                cpu_thread.start()
                y_pred_det = det_model.predict(adv_x_sample.astype(np.float32))      
                print(f"Adversarial attack performed in model {idx} from models {which_model}."+
                        f"Model name: {str(model).replace('votingSystem.ADSystems.', '').split('.')[0]}")    
                
                stop_flag["stop"] = True
                cpu_thread.join()
                emissions = tracker.stop()
                try:
                    emmisions_kwh = tracker.final_emissions_data.energy_consumed
                except:
                    df = pd.read_csv("emissions_envm.csv")
                    last = df.iloc[-1]
                    emmisions_kwh = last['energy_consumed']
                elapsed_time = time.time() - start_time
                avg_cpu = sum(cpu_usage_samples) / len(cpu_usage_samples) if cpu_usage_samples else 0

        if not adv_obj:
            y_pred = model.predict_proba_votes(x_sample.astype(np.float32), y_labels, threshold)         
            start_time = time.time()
            tracker = EmissionsTracker(output_file="emissions_envm.csv",log_level="error")
            tracker.start()
            cpu_thread = threading.Thread(target=monitor_cpu, args=(cpu_usage_samples, stop_flag))
            cpu_thread.start()
            y_pred_det = det_model.predict(x_sample.astype(np.float32))   
            emissions = tracker.stop()
            stop_flag["stop"] = True
            cpu_thread.join()      
            try:
                emmisions_kwh = tracker.final_emissions_data.energy_consumed
            except:
                df = pd.read_csv("emissions_envm.csv")
                last = df.iloc[-1]
                emmisions_kwh = last['energy_consumed']
            elapsed_time = time.time() - start_time
            avg_cpu = sum(cpu_usage_samples) / len(cpu_usage_samples) if cpu_usage_samples else 0
        models_emmisions.append(emmisions_kwh)
        models_cpu.append(avg_cpu)
        models_time.append(elapsed_time)
        
        if -1 in np.unique(y_pred_det):
            y_pred_det = np.where(y_pred_det == -1, 1, np.where(y_pred_det == 1, 0, y_pred_det))
        models_recall.append(model.get_recall_votes())
        models_f1.append(model.get_f1_score_votes())
        models_accuracy.append(model.get_acc_votes())
        recall_det, f1_det, accuracy_det = get_metrics(y_det, y_pred_det)
        if idx == 0:
            models_det_performance=[f1_det, recall_det, accuracy_det]
    models_emmisions = statistics.mean(models_emmisions)
    models_cpu = statistics.mean(models_cpu)
    models_time = statistics.mean(models_time)
    return models_recall, models_f1, models_accuracy, models_det_performance, models_emmisions, models_cpu, models_time

adversarial_attacks = ['tim']#['mifgsm', 'pgd', 'tim', 'dim']
detection_methods = ['keras_pgdtim'] #['catboost_mifgsm', 'keras_pgdtim']
epsilon = [0]
for value in np.arange(0.01, 1.0, 0.1):
    eps = round(value, 3)
    epsilon.append(eps)
catboost_fgsmdim_model = load('../../data/models/catboost_mifgsm_envm_test.joblib')
keras_pgdtim_model = tf.keras.models.load_model('../../data/models/keras_pgdtim_envm_test.keras')
detection_models = [catboost_fgsmdim_model, keras_pgdtim_model]

print(f"Starting attacks")
for adv_attack in adversarial_attacks:
    print(f"--->{adv_attack}")
    for idx, detection_method in enumerate(detection_methods):
        detection_model = detection_models[idx]
        print(f"------>{detection_method} with {detection_model}")   
        models_emmisions, models_cpu, models_time = [], [], []   
        for idx_eps, eps in enumerate(epsilon):
            models_emmisions_eps, models_cpu_eps, models_time_eps = [], [], []  
            print(f"** Epsilon value: {eps} **")
            if eps == 0:
                attacks = ["No attack"]
                models_f1, models_recall, models_accuracy, models_eir = [], [], [], []
                models_det_f1, models_det_recall, models_det_accuracy = [], [], []
                models_recall_noattack = []
            else:
                attacks = ["all"]
            for att_idx, attack in enumerate(attacks):
                print(f"----- Current attack: {attack} **")
                
                if eps > 0 : #Attack
                    which_models = generate_random_attack_models(attack, eps)
                    x_splits_adv, y_splits_adv, y_splits_det_adv = cargar_muestras_adversarias(eps, x_inc, y_inc, num_splits, adv_attack)

                models_f1, models_recall, models_accuracy, models_eir = [], [], [], []
                models_det_performance = []
                print(f"Staring 50 splits of attack {attack}")
                for i in range(0, num_splits):
                    if eps == 0: # No attack
                        x_samples = x_splits_noatt[i] # Datos normales y anómalos
                        y_samples = y_splits_noatt[i]
                        y_splits_det = np.zeros(len(y_splits_noatt[i]))
                        models_recall_split, models_f1_split, models_accuracy_split, models_performance_split, models_emmisions_split, models_cpu_split, models_time_split = models_predict(x_samples, y_samples, y_splits_det, detection_model, adsModels, threshold=0.45)
                        models_eir.append([0, 0, 0, 0, 0, 0])
                        models_recall_noattack.append(models_recall_split)
                    else: # Attack
                        x_samples = x_splits_noatt[i] # Datos normales y anómalos
                        y_samples = y_splits_noatt[i]
                        adv_x_samples = x_splits_adv[i] # Datos normales y adversarios
                        adv_y_samples = y_splits_adv[i]
                        y_splits_det = y_splits_det_adv[i]
                        which_model = which_models[i]
                        print(f"Target models: {which_model}")
                        models_recall_split, models_f1_split, models_accuracy_split, models_performance_split, models_emmisions_split, models_cpu_split, models_time_split  = models_predict(x_samples, y_samples, y_splits_det, detection_model, adsModels, 0.45, adv_x_samples, which_model)
                        eir = [round(1 - (float(split) / models_recall_noattack[i][j]), 2) for j, split in enumerate(models_recall_split)]
                        models_eir.append(eir)

                    models_recall.append(models_recall_split)
                    models_f1.append(models_f1_split)
                    models_accuracy.append(models_accuracy_split)           
                    models_det_performance.append(models_performance_split)
                    models_emmisions_eps.append(models_emmisions_split)
                    models_cpu_eps.append(models_cpu_split)
                    models_time_eps.append(models_time_split)
                    print(f"----> Split {str(i)} done")
                # Plot and save
                ##### Attack
                #if idx == 0:
                #    print("Plot Attacks")
                #    plot(f"F1-score {attack} eps: {eps}", models_f1, f"./Experiments_results/envm_dt/attack/{adv_attack}/Attack[{att_idx}]_{attack}_eps_0.{str(eps)}_f1.pdf", "F1 Score")
                #    plot(f"Recall {attack} eps: {eps}", models_recall, f"./Experiments_results/envm_dt/attack/{adv_attack}/Attack[{att_idx}]_{attack}_eps_0.{str(eps)}_recall.pdf", "Recall")
                #    plot(f"Accuracy {attack} eps: {eps}", models_accuracy, f"./Experiments_results/envm_dt/attack/{adv_attack}/Attack[{att_idx}]_{attack}_eps_0.{str(eps)}_acc.pdf", "Accuracy")
                #    plot(f"EIR {attack} eps: {eps}", models_eir, f"./Experiments_results/envm_dt/attack/{adv_attack}/Attack[{att_idx}]_{attack}_eps_0.{str(eps)}_eir.pdf", "EIR")
#
                #print("Plot Detection")
                #plot_detection(f"Performance {attack} detection eps: {eps}", models_det_performance, f"./Experiments_results/envm_dt/detection/{detection_method}/{adv_attack}/Detection_[{att_idx}]_{attack}_eps_0.{str(eps)}_perf.pdf")
        
            models_emmisions.append(models_emmisions_eps)
            models_cpu.append(models_cpu_eps)
            models_time.append(models_time_eps)
        print("Plot Measurements")
        plot_measurement(f"CPU %  usage for AE detection", models_cpu, f"./Experiments_results/envm_dt/detection/{detection_method}/{adv_attack}/CPU_Detection_[{att_idx}]_{attack}_eps_0.{str(eps)}_CPU.pdf", "%", epsilon)
        plot_measurement(f"Electrical consumption for AE detection", models_emmisions, f"./Experiments_results/envm_dt/detection/{detection_method}/{adv_attack}/KWH_Detection_[{att_idx}]_{attack}_eps_0.{str(eps)}_KWh.pdf", "KWh", epsilon)
        plot_measurement(f"Elapsed time for AE detection", models_emmisions, f"./Experiments_results/envm_dt/detection/{detection_method}/{adv_attack}/Time_Detection_[{att_idx}]_{attack}_eps_0.{str(eps)}_seconds.pdf", "Seconds", epsilon)  

print("envm TEST finished successfully!!")