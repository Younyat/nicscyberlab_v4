from xgboost import XGBClassifier

from utilities.fitAndSaveAlgorithm import fitAndSaveAlgorithmSupervised


def xgboost(dir_path, x_train, y_train, x_test, y_test, clf_name='XGBoost'):
    detectorName = "eXtreme Gradient Boosting"
    path = dir_path + "/xgboost/"
    clf = XGBClassifier()
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)