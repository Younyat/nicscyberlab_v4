from sklearn.model_selection import train_test_split
from lightgbm import LGBMClassifier
from sklearn.base import clone
from votingSystem.ADSModel import ADSModel
import os
import numpy as np
class LGBMachineADS(ADSModel):
    def __init__(self, window_size, x, y, name):
        ADSModel.__init__(self, window_size, x, y, name)

    def __init_train__(self):
        x_samples = self.x[-self.window_size:]
        y_samples = self.y[-self.window_size:]

        x_train = self.x[:-self.window_size]
        y_train = self.y[:-self.window_size]

        if os.path.exists(self.filename_modelInit):
            print(f"[LGB] Loading the model from the joblib file {self.filename_modelInit}.")
            self.load_modelInit()
        else:
            print("[LBG] Model not found. Training the model.")
            self.model = LGBMClassifier()
            #self.model = LGBMClassifier(device='gpu', gpu_platform_id=0, gpu_device_id=0)
            self.model.fit(x_train, y_train)

            self.save_modelInit()

        #y_preds = self.model.predict(x_samples)

    def retrain_model(self):
        x, y = self.get_balanced_training_data()
        x_train, x_test, y_train, y_test = train_test_split(x, y, shuffle=True)
        print(f"[LGB] Retraining the model with {len(x_train)} samples.")
        self.model.fit(x_train, y_train)
        self.numRetrains += 1
