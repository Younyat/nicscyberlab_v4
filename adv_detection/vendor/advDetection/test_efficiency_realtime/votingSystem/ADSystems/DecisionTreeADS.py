
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.base import clone
from votingSystem.ADSModel import ADSModel
import os

class DecisionTreeADS(ADSModel):
    def __init__(self, window_size, x, y, name):
        ADSModel.__init__(self, window_size, x, y, name)

    def __init_train__(self):
        x_samples = self.x[-self.window_size:]
        y_samples = self.y[-self.window_size:]

        x_train = self.x[:-self.window_size]
        y_train = self.y[:-self.window_size]
        if os.path.exists(self.filename_modelInit):
            print(f"[DT] Loading the model from the joblib file {self.filename_modelInit}.")
            self.load_modelInit()
        else:
            self.model = DecisionTreeClassifier()
            self.model.fit(x_train, y_train)
            self.save_modelInit()

        #y_preds = self.model.predict(x_samples)

    def retrain_model(self):
        x_train, x_test, y_train, y_test = train_test_split(self.x, self.y, shuffle=True)
        self.model.fit(x_train, y_train)
        self.numRetrains += 1
