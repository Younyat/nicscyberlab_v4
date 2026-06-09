from catboost import CatBoostClassifier

from utilities.fitAndSaveAlgorithm import fitAndSaveAlgorithmSupervised


def catboost(dir_path, x_train, y_train, x_test, y_test, clf_name='CatBoost'):
    detectorName = "CatBoost"
    path = dir_path + "/catboost/"
    clf = CatBoostClassifier()
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)