from __future__ import division
from __future__ import print_function
import os, sys, inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
parentdir = os.path.dirname(parentdir)
sys.path.insert(0, parentdir)

from utilities.fitAndSaveAlgorithm import *
from sklearn.metrics import accuracy_score
from autosklearn.classification import AutoSklearnClassifier
from autosklearn.experimental.askl2 import AutoSklearn2Classifier

import matplotlib.pyplot as plt
import scikitplot as skplt
import os
from joblib import dump
import time

def autoML(dir_path, x_train, y_train, x_test, y_test, clf_name='AutoML', timeout=3600, metric=None, scoring=None):
    detectorName = "Auto ML"
    path = dir_path + "/autoML/"
    clf = AutoSklearnClassifier(time_left_for_this_task=timeout, metric=metric, scoring_functions=scoring)

    start = time.time()
    if not os.path.exists(path):
        os.makedirs(path)

    clf.fit(x_train, y_train)

    print(clf.sprint_statistics())
    y_test_pred = clf.predict(x_test)
    acc = accuracy_score(y_test, y_test_pred)
    print("Accuracy: %.3f" % acc)

    skplt.metrics.plot_confusion_matrix(
        y_test, y_test_pred, normalize=False, title="Confusion Matrix on Test Set with " + detectorName)
    plt.savefig('{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path))
    plt.show()

    # save the model
    try:
        dump(clf, path + clf_name + '.joblib')
    except Exception as e:
        print("No se ha podido guardar " + clf_name)

    end = time.time()
    duration = end - start
    print("duration: " + str(duration))

    fileDuration = open(path + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()

def autoML2(dir_path, x_train, y_train, x_test, y_test, clf_name='AutoML', timeout=3600, metric=None, scoring=None):
    detectorName = "Auto ML"
    path = dir_path + "/autoML2/"
    clf = AutoSklearn2Classifier(time_left_for_this_task=timeout, metric=metric, scoring_functions=scoring)

    start = time.time()
    if not os.path.exists(path):
        os.makedirs(path)

    clf.fit(x_train, y_train)

    print(clf.sprint_statistics())
    y_test_pred = clf.predict(x_test)
    acc = accuracy_score(y_test, y_test_pred)
    print("Accuracy: %.3f" % acc)

    skplt.metrics.plot_confusion_matrix(
        y_test, y_test_pred, normalize=False, title="Confusion Matrix on Test Set with " + detectorName)
    plt.savefig('{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path))
    plt.show()

    # save the model
    try:
        dump(clf, path + clf_name + '.joblib')
    except Exception as e:
        print("No se ha podido guardar " + clf_name)

    end = time.time()
    duration = end - start
    print("duration: " + str(duration))

    fileDuration = open(path + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()
