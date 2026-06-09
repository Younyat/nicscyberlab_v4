from sklearn.model_selection import train_test_split
from catboost import CatBoostClassifier
from sklearn.base import clone
from votingSystem.ADSModel import ADSModel
import os
import numpy as np
class CatboostADS(ADSModel):
    def __init__(self, window_size, x, y, name):
        ADSModel.__init__(self, window_size, x, y, name)

    def __init_train__(self):
        x_samples = self.x[-self.window_size:]
        y_samples = self.y[-self.window_size:]

        x_train = self.x[:-self.window_size]
        y_train = self.y[:-self.window_size]

        if os.path.exists(self.filename_modelInit):
            print(f"[CATBOOST] Loading the model from the joblib file {self.filename_modelInit}.")
            self.load_modelInit()
        else:
            print("[CATBOOST] Model not found. Training the model.")
            self.model =  CatBoostClassifier()
            self.model.fit(x_train, y_train, verbose=False)

            self.save_modelInit()

        #y_preds = self.model.predict(x_samples)
    

    def retrain_model(self):
        x, y = self.get_balanced_training_data()
        x_train, x_test, y_train, y_test = train_test_split(x, y, shuffle=True)
        print(f"[CATBOOST] Retraining the model with {len(x_train)} x samples and {len(y_train)}.")
        # Copiamos modelo, pasamos a CPU y reentrenamos sustituyendo el model anterior
        params = self.model.get_params()
        params["task_type"] = "CPU"  # Change to CPU
        new_model = CatBoostClassifier(**params)
        print(f"unique classes {np.unique(y_train)}")
        new_model.fit(x_train, y_train, init_model=self.model, verbose=False)
        self.model = new_model
        
        self.numRetrains += 1
 