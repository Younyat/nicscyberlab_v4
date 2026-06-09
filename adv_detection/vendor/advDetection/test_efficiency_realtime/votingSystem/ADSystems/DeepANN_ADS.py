
from sklearn.model_selection import train_test_split
from votingSystem.ADSModel import ADSModel
from votingSystem.ADSystems.DeepANN import DeepANN
import os 
import torch
import numpy as np

class DeepANN_ADS(ADSModel):
    def __init__(self, window_size, x, y, name, nfeatures):
        ADSModel.__init__(self, window_size, x, y, name, nfeatures)

    def __init_train__(self):
        x_samples = self.x[-self.window_size:]
        y_samples = self.y[-self.window_size:]

        x_train = self.x[:-self.window_size]
        y_train = self.y[:-self.window_size]
        x_train = torch.tensor(np.array(x_train, dtype=float), dtype=torch.float32)
        y_train = torch.tensor(y_train, dtype=torch.long)

        if os.path.exists(self.filename_modelInit):
            print(f"[DeepANN] Loading the model from the joblib file {self.filename_modelInit}.")
            self.load_modelInit()
        else:
            print("[DeepANN] Model not found. Training the model.")
            input_size = self.nfeatures
            output_size = 2  # Binary classification (0 or 1)
            self.model = DeepANN(input_size, output_size)
            self.model.fit(x_train, y_train, epochs=35)
            self.save_modelInit()

        #y_preds = self.model.predict(x_samples)

    def retrain_model(self):
        x_train, x_test, y_train, y_test = train_test_split(self.x, self.y, shuffle=True)
        self.model.fit(x_train, y_train)
        self.numRetrains += 1
