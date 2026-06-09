# ANALYSIS 1: EXPERIMENTO 2
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
print(x_splits[num_splits - 1].shape)
print(y_splits[num_splits - 1].shape)

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

for i in range(num_splits):
    x_samples = x_splits[i]
    y_samples = y_splits[i]
    if i % 2 == 0:
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
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Coordinator 1 => " + str(coordinator1.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Coordinator 2 => " + str(coordinator2.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Coordinator 3 => " + str(coordinator3.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Coordinator 4 => " + str(coordinator4.F1))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Coordinator 5 => " + str(coordinator5.F1))

    # Print F1 of models
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Models Coordinator 1 => " + str(coordinator1.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Models Coordinator 2 => " + str(coordinator2.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Models Coordinator 3 => " + str(coordinator3.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Models Coordinator 4 => " + str(coordinator4.get_f1_models()))
    print("ENTRENAMIENTO: Split " + str(i) + ": F1 Models Coordinator 5 => " + str(coordinator5.get_f1_models()))


try:
    os.mkdir('images_sameDataset_v2/')
except:
    print("Directory images_sameDataset_v2/ already exists")

try:
    os.mkdir('images_sameDataset_v2/both/')
except:
    print("Directory images_sameDataset_v2/both/ already exists")
    
np.savetxt('images_sameDataset_v2/both/coordinator1_prob_f1.out', coordinator1_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord1_prob_f1.out', models_coord1_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator1_prob_ac.out', coordinator1_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord1_prob_ac.out', models_coord1_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator2_prob_f1.out', coordinator2_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord2_prob_f1.out', models_coord2_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator2_prob_ac.out', coordinator2_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord2_prob_ac.out', models_coord2_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator3_prob_f1.out', coordinator3_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord3_prob_f1.out', models_coord3_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator3_prob_ac.out', coordinator3_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord3_prob_ac.out', models_coord3_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator4_prob_f1.out', coordinator4_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord4_prob_f1.out', models_coord4_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator4_prob_ac.out', coordinator4_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord4_prob_ac.out', models_coord4_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator5_prob_f1.out', coordinator5_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord5_prob_f1.out', models_coord5_f1, delimiter=',')
np.savetxt('images_sameDataset_v2/both/coordinator5_prob_ac.out', coordinator5_ac, delimiter=',')
np.savetxt('images_sameDataset_v2/both/models_coord5_prob_ac.out', models_coord5_ac, delimiter=',')