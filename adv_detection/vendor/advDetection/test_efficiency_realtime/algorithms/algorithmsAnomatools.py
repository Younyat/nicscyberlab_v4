from __future__ import division
from __future__ import print_function

from anomatools.models import kNNO, SSDO, SSkNNO
from anomatools.models.inne import iNNE
from utilities.fitAndSaveAlgorithm import *

# Isolation Nearest Neighbor Ensembles
def inne(dir_path, x_train, y_train, x_test, y_test, clf_name='INNE', contamination=0.1):
    detectorName = "INNE"
    path = dir_path+"/inne/"
    clf = iNNE(contamination=contamination, sample_size=20, n_members=150, verbose=True)
    fitAndSaveAlgorithmUnsupervised(detectorName, path, clf, x_train, x_test, y_test, clf_name)

# K-nearest neighbor anomaly detection
def knno(dir_path, x_train, y_train, x_test, y_test, clf_name='KNNO', contamination=0.1):
    detectorName = "KNNO"
    path = dir_path+"/knno/"
    clf = kNNO(contamination=contamination)
    fitAndSaveAlgorithmUnsupervised(detectorName, path, clf, x_train, x_test, y_test, clf_name)

# Semi-Supervised Detection of Outliers
def ssdo(dir_path, x_train, y_train, x_test, y_test, clf_name='SSDO', contamination=0.1):
    detectorName = "SSDO"
    path = dir_path+"/ssdo/"
    clf = SSDO(contamination=contamination)
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Semi-Supervised K-nearest neighbor anomaly detection
def ssknno(dir_path, x_train, y_train, x_test, y_test, clf_name='SSKNNO', contamination=0.1):
    detectorName = "SSKNNO"
    path = dir_path+"/ssknno/"
    clf = SSkNNO(contamination=contamination, k=20, weighted=True)
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)
