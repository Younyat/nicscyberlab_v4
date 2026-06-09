import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import warnings
warnings.filterwarnings("ignore")
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import confusion_matrix
import os
np.random.seed(123)

def get_corr(data):
    return data.corr()

def visualize_correlation(data, name):
    # find the correlation betweeen the variables
    corr = data.corr()
    plt.figure(figsize=(10, 10))
    sns.heatmap(corr, vmax=0.8, square=True, annot=True)
    if not os.path.exists('correlation/'):
        os.makedirs('correlation/')
    path_save = 'correlation/' + name
    plt.savefig(path_save)

def encode_variable(data, idx):
    label_encoder = LabelEncoder()
    data.iloc[:, idx] = label_encoder.fit_transform(data.iloc[:, idx]).astype('float64')
    return data

def remove_columns_higher_correlation(data, threshold):
    corr = data.corr()
    columns = np.full((corr.shape[0],), True, dtype=bool)
    for i in range(corr.shape[0]):
        for j in range(i+1, corr.shape[0]):
            if corr.iloc[i,j] >= threshold:
                columns[j] = False

    selected_columns = data.columns[columns]
    return data[selected_columns]



