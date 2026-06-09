from abc import ABC, abstractmethod
from sklearn.base import clone
import numpy as np
from sklearn.metrics import roc_auc_score
from joblib import dump, load
#import cudf
from sklearn.metrics import recall_score, f1_score, accuracy_score
from sklearn.metrics import precision_score

class ADSModel(ABC):

    def __init__(self, window_size, x, y, name, nfeatures = 0):
        super().__init__()
        self.name = name
        self.filename_model = "ADSystems/" + self.name + ".joblib"
        self.filename_modelInit = "ADSystems/" + self.name + "Init.joblib"
        self.window_size = window_size
        self.model = None
        self.nfeatures = nfeatures
        self.logits = 0.0
        self.entropy_scores = 0.0
        self.recall_votes = 0.0
        self.f1_score_votes = 0.0
        self.acc_votes = 0.0
        self.precision_votes = 0.0
        self.x = x
        self.xInit = np.copy(x)
        self.y = y
        self.yInit = np.copy(y)
        self.numRetrains = 0
        self.__init_train__()

    def save_modelInit(self):
        dump(self.model, self.filename_modelInit)

    def load_modelInit(self):
        self.model = load(self.filename_modelInit)

    def save_model(self):
        dump(self.model, self.filename_model)

    def load_model(self):
        self.model = load(self.filename_model)

    def reset_model(self):
        self.x = np.copy(self.xInit)
        self.y = np.copy(self.yInit)
        self.logits = 0.0
        self.entropy_scores = 0.0
        self.recall_votes = 0.0
        self.f1_score_votes = 0.0
        self.acc_votes = 0.0
        self.precision_votes = 0.0
        self.maxSize = 50000
        self.numRetrains = 0
        self.load_modelInit()

    def __init_train__(self):
        pass

    def retrain_model(self):
        pass
    

    def calculate_recall_votes(self, true_labels, predictions):
        self.recall_votes = recall_score(true_labels, predictions)
    
    def calculate_f1_score_votes(self, true_labels, predictions):
        self.f1_score_votes = f1_score(true_labels, predictions)

    def calculate_acc_votes(self, true_labels, predictions):
        self.acc_votes = accuracy_score(true_labels, predictions)

    def calculate_precision_votes(self, true_labels, predictions):
        self.precision_votes = precision_score(true_labels, predictions)

    def get_logit_votes(self):
        return self.logits
    
    def get_entropy_votes(self):
        return self.entropy_scores
    
    def get_recall_votes(self):
        return self.recall_votes
    
    def get_f1_score_votes(self):
        return self.f1_score_votes

    def get_acc_votes(self):
        return self.acc_votes

    def get_precision_votes(self):
        return self.precision_votes
    
    def predict_proba_one(self, x_samples):
        y_pred_proba = self.model.predict_proba(x_samples)[0]
        return y_pred_proba

    def predict_one(self, x_sample):
        y_pred = self.model.predict([x_sample])[0]
        return y_pred

    def predict_votes(self, x_samples, y_labels):
        y_pred = self.model.predict(x_samples)
        self.calculate_f1_score_votes(y_labels, y_pred)
        self.calculate_recall_votes(y_labels, y_pred)
        self.calculate_acc_votes(y_labels, y_pred)        
        self.calculate_precision_votes(y_labels, y_pred)  
        return y_pred
    
    def predict_proba_votes(self, x_samples, y_labels, threshold):
        y_pred = self.model.predict_proba(x_samples.astype(np.float32))
        #y_pred_one = []
        preds = [pred[1] for pred in y_pred]
        y_pred = [1 if y_prob >= threshold else 0 for y_prob in preds]
        self.calculate_f1_score_votes(y_labels, y_pred)
        self.calculate_recall_votes(y_labels, y_pred)
        self.calculate_acc_votes(y_labels, y_pred)  
        self.calculate_precision_votes(y_labels, y_pred)      
        return preds
    
    def evaluate_one_votes(self, x_sample, y_sample):
        y_pred = self.predict_votes(x_sample, y_sample)
        return y_pred


    def evaluate_one_proba_votes(self, x_sample, y_sample, threshold):
        preds_proba = self.predict_proba_votes(x_sample, y_sample, threshold) # devuelve una lista de probabilidades
        preds_proba = preds_proba.tolist() if isinstance(preds_proba, np.ndarray) else preds_proba
        #if "Boost" in str(self.model):
        #    print(self.model)
        #    logits_pred = self.model.predict_proba(x_sample.astype(np.float32))
        #    self.logits = np.mean(logits_pred)
        #    self.entropy_scores = logits_pred
        #else:
        #    self.logits = np.mean(preds_proba)
        #    self.entropy_scores = preds_proba
        return preds_proba
