# ANALYSIS 1: EXPERIMENTO 2 - ATAQUE A IDS MÁS VULNERABLE: RF
import os, sys, inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from votingSystem.ADSystems.CatboostADS import CatboostADS
import pandas as pd
from utilities.functions import encode_variable
from votingSystem.ADSystems.DecisionTreeADS import DecisionTreeADS
from votingSystem.ADSystems.LGBMachineADS import LGBMachineADS
from votingSystem.ADSystems.MultiLayerPerceptronADS import MultiLayerPerceptronADS
from votingSystem.ADSystems.RandomForestADS import RandomForestADS
from votingSystem.ADSystems.XGBoostADS import XGBoostADS
from votingSystem.CoordinatorMax import CoordinatorMax
from votingSystem.CoordinatorProb import CoordinatorProb
from votingSystem.CoordinatorWeightedProb import CoordinatorWeightedProb

# Solamente 1 dataset
data = pd.read_excel("../datasets/final/Dundee_Clean_With_Anomalies_All.xlsx")
data = data.sort_values(by='startTimestamp', ascending=True)
encode_variable(data, data.columns.get_loc("connectorType"))

features = ["connectorType", "durationSession", "durationCharge", "energy", 'cost', 'tariff', "meanPower", 'maxPower']

x_boulder = data.loc[:, features].values
y_boulder = data.loc[:, ['anomaly']].values.ravel()
size = len(x_boulder)
size_init = int(size * 0.8)
x_boulder_init = x_boulder[:size_init]
y_boulder_init = y_boulder[:size_init]
x_boulder_inc = x_boulder[size_init:]
y_boulder_inc = y_boulder[size_init:]
window_boulder_size = 1000
boulderADS = CatboostADS(window_boulder_size, x_boulder_init, y_boulder_init, "BoulderADS")

x_dundee = data.loc[:, features].values
y_dundee = data.loc[:, ['anomaly']].values.ravel()
size = len(x_dundee)
size_init = int(size * 0.8)
x_dundee_init = x_dundee[:size_init]
y_dundee_init = y_dundee[:size_init]
x_dundee_inc = x_dundee[size_init:]
y_dundee_inc = y_dundee[size_init:]
window_dundee_size = 1000
dundeeADS = LGBMachineADS(window_dundee_size, x_dundee_init, y_dundee_init, "DundeeADS")

x_netherlands = data.loc[:, features].values
y_netherlands = data.loc[:, ['anomaly']].values.ravel()
size = len(x_netherlands)
size_init = int(size * 0.8)
x_netherlands_init = x_netherlands[:size_init]
y_netherlands_init = y_netherlands[:size_init]
x_netherlands_inc = x_netherlands[size_init:]
y_netherlands_inc = y_netherlands[size_init:]
window_netherlands_size = 1000
netherlandsADS = MultiLayerPerceptronADS(window_netherlands_size, x_netherlands_init, y_netherlands_init,
                                         "NetherlandsADS")

x_paloalto = data.loc[:, features].values
y_paloalto = data.loc[:, ['anomaly']].values.ravel()
size = len(x_paloalto)
size_init = int(size * 0.8)
x_paloalto_init = x_paloalto[:size_init]
y_paloalto_init = y_paloalto[:size_init]
x_paloalto_inc = x_paloalto[size_init:]
y_paloalto_inc = y_paloalto[size_init:]
window_paloalto_size = 1000
paloaltoADS = RandomForestADS(window_paloalto_size, x_paloalto_init, y_paloalto_init, "PaloAltoADS")

# x_paloalto2 = paloalto2Data.loc[:, features].values
# y_paloalto2 = paloalto2Data.loc[:, ['anomaly']].values.ravel()
# size = len(x_paloalto2)
# size_init = int(size * 0.8)
# x_paloalto2_init = x_paloalto2[:size_init]
# y_paloalto2_init = y_paloalto2[:size_init]
# x_paloalto2_inc = x_paloalto2[size_init:]
# y_paloalto2_inc = y_paloalto2[size_init:]
# window_paloalto2_size = 2000
# paloalto2ADS = DecisionTreeADS(window_paloalto2_size, x_paloalto2_init, y_paloalto2_init, "PaloAlto2ADS")


x_perth = data.loc[:, features].values
y_perth = data.loc[:, ['anomaly']].values.ravel()
size = len(x_perth)
size_init = int(size * 0.8)
x_perth_init = x_perth[:size_init]
y_perth_init = y_perth[:size_init]
x_perth_inc = x_perth[size_init:]
y_perth_inc = y_perth[size_init:]
window_perth_size = 1000
perthADS = XGBoostADS(window_perth_size, x_perth_init, y_perth_init, "PerthADS")

# x_paris = parisData.loc[:, features].values
# y_paris = parisData.loc[:, ['anomaly']].values.ravel()
# size = len(x_paris)
# size_init = int(size * 0.8)
# x_paris_init = x_paris[:size_init]
# y_paris_init = y_paris[:size_init]
# x_paris_inc = x_paris[size_init:]
# y_paris_inc = y_paris[size_init:]
# window_paris_size = 2000
# parisADS = LGBMachineADS(window_paris_size, x_paris_init, y_paris_init, "ParisADS")


adsModels = [boulderADS, dundeeADS, netherlandsADS, paloaltoADS, perthADS]
# equivalencias: 1: Catboost, 2: LGB, 3: MLP, 4: RF, 5: XGBoost
window_size1 = 1000

coordinator1 = CoordinatorProb(adsModels, window_size1, 0.45)
coordinator2 = CoordinatorProb(adsModels, window_size1, 0.50)
coordinator3 = CoordinatorWeightedProb(adsModels, window_size1, 0.45)
coordinator4 = CoordinatorWeightedProb(adsModels, window_size1, 0.50)
coordinator5 = CoordinatorMax(adsModels, window_size1)

import numpy as np

x_inc = x_boulder_inc
y_inc = y_boulder_inc

df = pd.DataFrame(x_inc, columns=features)
df["anomaly"] = y_inc
df = df.sample(frac=1).reset_index(drop=True)

x_inc = df.loc[:, features].values
y_inc = df.loc[:, ['anomaly']].values.ravel()

num_splits = 150
x_splits = np.array_split(x_inc, num_splits)
y_splits = np.array_split(y_inc, num_splits)
print("Shape of normal data splits.")
print(x_splits[num_splits - 1].shape)
print(y_splits[num_splits - 1].shape)

# Read adversarial samples
#advPath_MIFGSM = './real_adversarialexamplesMIFGSM.csv'
advPath_MIFGSM = './real_adversarialexamplesMIFGSM_train.csv'
adversarial_data = pd.read_csv(advPath_MIFGSM)
adversarial_x_data = adversarial_data.loc[:, features].values
adversarial_y_data = adversarial_data.loc[:, ['anomaly']].values.ravel()
adv_x_splits = np.array_split(adversarial_x_data, 50) # Only 50 splits for the first phase
adv_y_splits = np.array_split(adversarial_y_data, 50)
print("Shape of adversarial data splits.")
print(adv_x_splits[50 - 1].shape)
print(adv_y_splits[50 - 1].shape)

if x_splits[num_splits - 1].shape[0] >= adv_x_splits[50 - 1].shape[0]:
    # Reshape the normal data splits
    indices = np.random.choice(x_splits[num_splits - 1].shape[0], adv_x_splits[50 - 1].shape[0], replace=False)
    for i in range(num_splits):
        x_splits[i] = x_splits[i][indices]
        y_splits[i] = y_splits[i][indices]
    print("Shape of normal data splits reshaped.")
    print(x_splits[num_splits - 1].shape)
    print(y_splits[num_splits - 1].shape)
else:
    # Reshape the adversarial data splits
    indices = np.random.choice(adv_x_splits[50 - 1].shape[0], x_splits[num_splits - 1].shape[0], replace=False)
    for i in range(1, 50):
        adv_x_splits[i] = adv_x_splits[i][indices]
        adv_y_splits[i] = adv_y_splits[i][indices]
    print("Shape of adv data splits reshaped.")
    print(adv_x_splits[50 - 1].shape)
    print(adv_y_splits[50 - 1].shape)



coordinator1_f1_votes = []
models_coord1_f1_votes = []
coordinator1_ac_votes = []
models_coord1_ac_votes = []

coordinator2_f1_votes = []
models_coord2_f1_votes = []
coordinator2_ac_votes = []
models_coord2_ac_votes = []

coordinator3_f1_votes = []
models_coord3_f1_votes = []
coordinator3_ac_votes = []
models_coord3_ac_votes = []

coordinator4_f1_votes = []
models_coord4_f1_votes = []
coordinator4_ac_votes = []
models_coord4_ac_votes = []

coordinator5_f1_votes = []
models_coord5_f1_votes = []
coordinator5_ac_votes = []
models_coord5_ac_votes = []

import random
# Voting phase
for i in range(0, 50):
    # En cada iteración se ataca a un ADS aleatorio
    x_samples = x_splits[i]
    y_samples = y_splits[i]

    adv_x_samples = adv_x_splits[i]
    adv_y_samples = adv_y_splits[i]

    # Add adversarial perturbations to random models in each iteration
    which_model = 4 # RF
    print(f"Adversarial attack to model {which_model}")
    coordinator1.model_predict_some_votes(x_samples, y_samples, adv_x_samples, adv_y_samples, which_model)
    coordinator2.model_predict_some_votes(x_samples, y_samples, adv_x_samples, adv_y_samples, which_model)
    coordinator3.model_predict_some_votes(x_samples, y_samples, adv_x_samples, adv_y_samples, which_model)
    coordinator4.model_predict_some_votes(x_samples, y_samples, adv_x_samples, adv_y_samples, which_model)
    coordinator5.model_predict_some_votes(x_samples, y_samples, adv_x_samples, adv_y_samples, which_model)

    models_coord1_f1_votes.append(coordinator1.get_f1_votes_models())
    models_coord2_f1_votes.append(coordinator2.get_f1_votes_models())
    models_coord3_f1_votes.append(coordinator3.get_f1_votes_models())
    models_coord4_f1_votes.append(coordinator4.get_f1_votes_models())
    models_coord5_f1_votes.append(coordinator5.get_f1_votes_models())

    coordinator1_f1_votes.append(coordinator1.F1_votes)
    coordinator2_f1_votes.append(coordinator2.F1_votes)
    coordinator3_f1_votes.append(coordinator3.F1_votes)
    coordinator4_f1_votes.append(coordinator4.F1_votes)
    coordinator5_f1_votes.append(coordinator5.F1_votes)

    models_coord1_ac_votes.append(coordinator1.get_accuracy_votes_models())
    models_coord2_ac_votes.append(coordinator2.get_accuracy_votes_models())
    models_coord3_ac_votes.append(coordinator3.get_accuracy_votes_models())
    models_coord4_ac_votes.append(coordinator4.get_accuracy_votes_models())
    models_coord5_ac_votes.append(coordinator5.get_accuracy_votes_models())

    coordinator1_ac_votes.append(coordinator1.accuracy_votes)
    coordinator2_ac_votes.append(coordinator2.accuracy_votes)
    coordinator3_ac_votes.append(coordinator3.accuracy_votes)
    coordinator4_ac_votes.append(coordinator4.accuracy_votes)
    coordinator5_ac_votes.append(coordinator5.accuracy_votes)

    # Print F1 coordinators
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 1 => " + str(coordinator1.F1_votes))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 2 => " + str(coordinator2.F1_votes))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 3 => " + str(coordinator3.F1_votes))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 4 => " + str(coordinator4.F1_votes))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 5 => " + str(coordinator5.F1_votes))

    # Print F1 of models
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 1 => " + str(coordinator1.get_f1_votes_models()))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 2 => " + str(coordinator2.get_f1_votes_models()))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 3 => " + str(coordinator3.get_f1_votes_models()))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 4 => " + str(coordinator4.get_f1_votes_models()))
    print("PRE ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 5 => " + str(coordinator5.get_f1_votes_models()))


coordinator1_f1 = []
models_coord1_f1 = []
coordinator1_ac = []
models_coord1_ac = []

coordinator2_f1 = []
models_coord2_f1 = []
coordinator2_ac = []
models_coord2_ac = []

coordinator3_f1 = []
models_coord3_f1 = []
coordinator3_ac = []
models_coord3_ac = []

coordinator4_f1 = []
models_coord4_f1 = []
coordinator4_ac = []
models_coord4_ac = []

coordinator5_f1 = []
models_coord5_f1 = []
coordinator5_ac = []
models_coord5_ac = []

#  Testing phase
for i in range(50, 100):
    x_samples = x_splits[i]
    y_samples = y_splits[i]
    if i % 2 == 0: # No sé por qué intercala
        coordinator1.model_predict_some(x_samples, y_samples, False)
        coordinator2.model_predict_some(x_samples, y_samples, False)
        coordinator3.model_predict_some(x_samples, y_samples, False)
        coordinator4.model_predict_some(x_samples, y_samples, False)
        coordinator5.model_predict_some(x_samples, y_samples, False)
    else:
        coordinator1.model_predict_some(x_samples, y_samples, True)
        coordinator2.model_predict_some(x_samples, y_samples, True)
        coordinator3.model_predict_some(x_samples, y_samples, True)
        coordinator4.model_predict_some(x_samples, y_samples, True)
        coordinator5.model_predict_some(x_samples, y_samples, True)

    models_coord1_f1.append(coordinator1.get_f1_models())
    models_coord2_f1.append(coordinator2.get_f1_models())
    models_coord3_f1.append(coordinator3.get_f1_models())
    models_coord4_f1.append(coordinator4.get_f1_models())
    models_coord5_f1.append(coordinator5.get_f1_models())

    coordinator1_f1.append(coordinator1.F1)
    coordinator2_f1.append(coordinator2.F1)
    coordinator3_f1.append(coordinator3.F1)
    coordinator4_f1.append(coordinator4.F1)
    coordinator5_f1.append(coordinator5.F1)

    models_coord1_ac.append(coordinator1.get_accuracy_models())
    models_coord2_ac.append(coordinator2.get_accuracy_models())
    models_coord3_ac.append(coordinator3.get_accuracy_models())
    models_coord4_ac.append(coordinator4.get_accuracy_models())
    models_coord5_ac.append(coordinator5.get_accuracy_models())

    coordinator1_ac.append(coordinator1.accuracy)
    coordinator2_ac.append(coordinator2.accuracy)
    coordinator3_ac.append(coordinator3.accuracy)
    coordinator4_ac.append(coordinator4.accuracy)
    coordinator5_ac.append(coordinator5.accuracy)

    coordinator1.retrain_models()
    coordinator2.retrain_models()
    coordinator3.retrain_models()
    coordinator4.retrain_models()
    coordinator5.retrain_models()

    # Print F1 coordinators
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 1 => " + str(coordinator1.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 2 => " + str(coordinator2.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 3 => " + str(coordinator3.F1))   
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 4 => " + str(coordinator4.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Coordinator 5 => " + str(coordinator5.F1))

    # Print F1 of models
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Models Coordinator 1 => " + str(coordinator1.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Models Coordinator 2 => " + str(coordinator2.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Models Coordinator 3 => " + str(coordinator3.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Models Coordinator 4 => " + str(coordinator4.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": Recall Models Coordinator 5 => " + str(coordinator5.get_f1_models()))

coordinator1_f1_votes_2 = []
models_coord1_f1_votes_2 = []
coordinator1_ac_votes_2 = []
models_coord1_ac_votes_2 = []

coordinator2_f1_votes_2 = []
models_coord2_f1_votes_2 = []
coordinator2_ac_votes_2 = []
models_coord2_ac_votes_2 = []

coordinator3_f1_votes_2 = []
models_coord3_f1_votes_2 = []
coordinator3_ac_votes_2 = []
models_coord3_ac_votes_2 = []

coordinator4_f1_votes_2 = []
models_coord4_f1_votes_2 = []
coordinator4_ac_votes_2 = []
models_coord4_ac_votes_2 = []

coordinator5_f1_votes_2 = []
models_coord5_f1_votes_2 = []
coordinator5_ac_votes_2 = []
models_coord5_ac_votes_2 = []

# Voting again
for i in range(100, 150):
    x_samples = x_splits[i]
    y_samples = y_splits[i]

    coordinator1.model_predict_some_votes(x_samples, y_samples)
    coordinator2.model_predict_some_votes(x_samples, y_samples)
    coordinator3.model_predict_some_votes(x_samples, y_samples)
    coordinator4.model_predict_some_votes(x_samples, y_samples)
    coordinator5.model_predict_some_votes(x_samples, y_samples)

    models_coord1_f1_votes_2.append(coordinator1.get_f1_votes_models())
    models_coord2_f1_votes_2.append(coordinator2.get_f1_votes_models())
    models_coord3_f1_votes_2.append(coordinator3.get_f1_votes_models())
    models_coord4_f1_votes_2.append(coordinator4.get_f1_votes_models())
    models_coord5_f1_votes_2.append(coordinator5.get_f1_votes_models())

    coordinator1_f1_votes_2.append(coordinator1.F1_votes)
    coordinator2_f1_votes_2.append(coordinator2.F1_votes)
    coordinator3_f1_votes_2.append(coordinator3.F1_votes)
    coordinator4_f1_votes_2.append(coordinator4.F1_votes)
    coordinator5_f1_votes_2.append(coordinator5.F1_votes)

    models_coord1_ac_votes_2.append(coordinator1.get_accuracy_votes_models())
    models_coord2_ac_votes_2.append(coordinator2.get_accuracy_votes_models())
    models_coord3_ac_votes_2.append(coordinator3.get_accuracy_votes_models())
    models_coord4_ac_votes_2.append(coordinator4.get_accuracy_votes_models())
    models_coord5_ac_votes_2.append(coordinator5.get_accuracy_votes_models())

    coordinator1_ac_votes_2.append(coordinator1.accuracy_votes)
    coordinator2_ac_votes_2.append(coordinator2.accuracy_votes)
    coordinator3_ac_votes_2.append(coordinator3.accuracy_votes)
    coordinator4_ac_votes_2.append(coordinator4.accuracy_votes)
    coordinator5_ac_votes_2.append(coordinator5.accuracy_votes)

    # Print F1 coordinators
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 1 => " + str(coordinator1.F1_votes))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 2 => " + str(coordinator2.F1_votes))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 3 => " + str(coordinator3.F1_votes))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 4 => " + str(coordinator4.F1_votes))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Coordinator 5 => " + str(coordinator5.F1_votes))
    # Print F1 of models
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 1 => " + str(coordinator1.get_f1_votes_models()))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 2 => " + str(coordinator2.get_f1_votes_models()))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 3 => " + str(coordinator3.get_f1_votes_models()))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 4 => " + str(coordinator4.get_f1_votes_models()))
    print("POST ENTRENAMIENTO: Split " + str(i) + ": Recall  Models Coordinator 5 => " + str(coordinator5.get_f1_votes_models()))

try:
    os.mkdir('images_sameDataset/')
except:
    print("Directory images_sameDataset already exists")

try:
    os.mkdir('images_sameDataset/votes/')
except:
    print("Directory images_sameDataset/votes already exists")

np.savetxt('images_sameDataset/votes/coordinator1_prob_f1.out', coordinator1_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord1_prob_f1.out', models_coord1_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator1_prob_ac.out', coordinator1_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord1_prob_ac.out', models_coord1_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator2_prob_f1.out', coordinator2_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord2_prob_f1.out', models_coord2_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator2_prob_ac.out', coordinator2_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord2_prob_ac.out', models_coord2_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator3_prob_f1.out', coordinator3_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord3_prob_f1.out', models_coord3_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator3_prob_ac.out', coordinator3_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord3_prob_ac.out', models_coord3_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator4_prob_f1.out', coordinator4_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord4_prob_f1.out', models_coord4_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator4_prob_ac.out', coordinator4_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord4_prob_ac.out', models_coord4_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator5_prob_f1.out', coordinator5_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord5_prob_f1.out', models_coord5_f1_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/coordinator5_prob_ac.out', coordinator5_ac_votes, delimiter=',')
np.savetxt('images_sameDataset/votes/models_coord5_prob_ac.out', models_coord5_ac_votes, delimiter=',')

try:
    os.mkdir('images_sameDataset/both/')
except:
    print("Directory images_sameDataset/both already exists")

np.savetxt('images_sameDataset/both/coordinator1_prob_f1.out', coordinator1_f1, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord1_prob_f1.out', models_coord1_f1, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator1_prob_ac.out', coordinator1_ac, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord1_prob_ac.out', models_coord1_ac, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator2_prob_f1.out', coordinator2_f1, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord2_prob_f1.out', models_coord2_f1, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator2_prob_ac.out', coordinator2_ac, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord2_prob_ac.out', models_coord2_ac, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator3_prob_f1.out', coordinator3_f1, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord3_prob_f1.out', models_coord3_f1, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator3_prob_ac.out', coordinator3_ac, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord3_prob_ac.out', models_coord3_ac, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator4_prob_f1.out', coordinator4_f1, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord4_prob_f1.out', models_coord4_f1, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator4_prob_ac.out', coordinator4_ac, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord4_prob_ac.out', models_coord4_ac, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator5_prob_f1.out', coordinator5_f1, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord5_prob_f1.out', models_coord5_f1, delimiter=',')
np.savetxt('images_sameDataset/both/coordinator5_prob_ac.out', coordinator5_ac, delimiter=',')
np.savetxt('images_sameDataset/both/models_coord5_prob_ac.out', models_coord5_ac, delimiter=',')

try:
    os.mkdir('images_sameDataset/votes_2/')
except:
    print("Directory images_sameDataset/votes_2 already exists")
    
np.savetxt('images_sameDataset/votes_2/coordinator1_prob_f1.out', coordinator1_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord1_prob_f1.out', models_coord1_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator1_prob_ac.out', coordinator1_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord1_prob_ac.out', models_coord1_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator2_prob_f1.out', coordinator2_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord2_prob_f1.out', models_coord2_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator2_prob_ac.out', coordinator2_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord2_prob_ac.out', models_coord2_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator3_prob_f1.out', coordinator3_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord3_prob_f1.out', models_coord3_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator3_prob_ac.out', coordinator3_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord3_prob_ac.out', models_coord3_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator4_prob_f1.out', coordinator4_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord4_prob_f1.out', models_coord4_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator4_prob_ac.out', coordinator4_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord4_prob_ac.out', models_coord4_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator5_prob_f1.out', coordinator5_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord5_prob_f1.out', models_coord5_f1_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/coordinator5_prob_ac.out', coordinator5_ac_votes_2, delimiter=',')
np.savetxt('images_sameDataset/votes_2/models_coord5_prob_ac.out', models_coord5_ac_votes_2, delimiter=',')