from __future__ import division
from __future__ import print_function

from anomatools.models import iNNE
from pyod.models.abod import ABOD
from pyod.models.auto_encoder import AutoEncoder
from pyod.models.cblof import CBLOF
from pyod.models.cof import COF
from pyod.models.feature_bagging import FeatureBagging
from pyod.models.hbos import HBOS
from pyod.models.knn import KNN
from pyod.models.lmdd import LMDD
from pyod.models.loci import LOCI
from pyod.models.loda import LODA
from pyod.models.lof import LOF
from pyod.models.mad import MAD
from pyod.models.mcd import MCD
from pyod.models.mo_gaal import MO_GAAL
from pyod.models.ocsvm import OCSVM
from pyod.models.rod import ROD
from pyod.models.so_gaal import SO_GAAL
from pyod.models.sod import SOD
from pyod.models.sos import SOS
from pyod.models.vae import VAE
from pyod.models.xgbod import XGBOD
from pyod.models.pca import PCA
from pyod.models.lscp import LSCP

from utilities.fitAndSaveAlgorithm import fitAndSaveAlgorithmPyod, fitAndSaveAlgorithmUnsupervised, \
    fitAndSaveAlgorithmSupervised


def abod(dir_path, x_train, y_train, x_test, y_test, clf_name='ABOD', contamination=0.1):
    detectorName = "ABOD"
    path = dir_path+"/abod/"
    clf = ABOD(contamination=contamination, method='default')
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def fast_abod(dir_path, x_train, y_train, x_test, y_test, clf_name='Fast ABOD', contamination=0.1, n_neighbors=5):
    detectorName = "Fast ABOD"
    path = dir_path+"/fast_abod/"
    clf = ABOD(contamination=contamination, method='fast', n_neighbors=n_neighbors)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def auto_encoder(dir_path, x_train, y_train, x_test, y_test, clf_name='AE', contamination=0.1, hidden_neurons=[2]):
    detectorName = "Auto Encoder"
    path = dir_path+"/auto_encoder/"
    clf = AutoEncoder(contamination=contamination, hidden_neurons=hidden_neurons)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def cblof(dir_path, x_train, y_train, x_test, y_test, clf_name='CBLOF', contamination=0.1, n_clusters=8):
    detectorName = "CBLOF"
    path = dir_path + "/cblof/"
    clf = CBLOF(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def cof(dir_path, x_train, y_train, x_test, y_test, clf_name='COF', contamination=0.1):
    detectorName = "COF"
    path = dir_path + "/cof/"
    clf = COF(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def copod(dir_path, x_train, y_train, x_test, y_test, clf_name='COPOD', contamination=0.1):
    detectorName = "COPOD"
    path = dir_path + "/copod/"
    clf = COF(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def feature_bagging(dir_path, x_train, y_train, x_test, y_test, clf_name='Feature Bagging', contamination=0.1):
    detectorName = "Feature Bagging"
    path = dir_path + "/feature_bagging/"
    clf = FeatureBagging(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def hbos(dir_path, x_train, y_train, x_test, y_test, clf_name='HBOS', contamination=0.1, n_bins=10, alpha=0.1, tol=0.5):
    detectorName = "HBOS"
    path = dir_path + "/hbos/"
    clf = HBOS(contamination=contamination, n_bins=n_bins, alpha=alpha, tol=tol)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def inne(dir_path, x_train, y_train, x_test, y_test, clf_name='INNE', contamination=0.1):
    detectorName = "INNE"
    path = dir_path+"/inne/"
    clf = iNNE(contamination=contamination, sample_size=20, n_members=150, verbose=True)
    fitAndSaveAlgorithmUnsupervised(detectorName, path, clf, x_train, x_test, y_test, clf_name)

def knn(dir_path, x_train, y_train, x_test, y_test, clf_name='KNN', contamination=0.1, n_neighbors=5, method='largest',
        radius=1.0, algorithm='auto', leaf_size=30):
    detectorName = "KNN"
    path = dir_path + "/knn/"
    clf = KNN(contamination=contamination, n_neighbors=n_neighbors, method=method, radius=radius, algorithm=algorithm,
              leaf_size=leaf_size)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def lmdd(dir_path, x_train, y_train, x_test, y_test, clf_name='LMDD', contamination=0.1, dis_measure='aad'):
    detectorName = "LMDD"
    path = dir_path + "/lmdd/"
    clf = LMDD(contamination=contamination, dis_measure=dis_measure)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def loci(dir_path, x_train, y_train, x_test, y_test, clf_name='LOCI', contamination=0.1, alpha=0.5, k=3):
    detectorName = "LOCI"
    path = dir_path + "/loci/"
    clf = LOCI(contamination=contamination, alpha=alpha, k=k)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def loda(dir_path, x_train, y_train, x_test, y_test, clf_name='LODA', contamination=0.1, n_bins=10, n_random_cuts=100):
    detectorName = "LODA"
    path = dir_path + "/loda/"
    clf = LODA(contamination=contamination, n_bins=n_bins, n_random_cuts=n_random_cuts)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def lof(dir_path, x_train, y_train, x_test, y_test, clf_name='LOF', contamination=0.1, algorithm="auto", n_neighbors=20, leaf_size=30, p=2):
    detectorName = "LOF"
    path = dir_path + "/lof/"
    clf = LOF(contamination=contamination, algorithm=algorithm, n_neighbors=n_neighbors, p=p, leaf_size=leaf_size)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def lscp(dir_path, x_train, y_train, x_test, y_test, detector_list, clf_name='LSCP', contamination=0.1):
    detectorName = "LSCP"
    path = dir_path + "/lscp/"
    clf = LSCP(contamination=contamination, detector_list=detector_list)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Median Absolute Deviation
def mad(dir_path, x_train, y_train, x_test, y_test, clf_name='MAD', threshold=3.5):
    detectorName = "MAD"
    path = dir_path + "/mad/"
    clf = MAD(threshold=threshold)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Outlier Detection with Minimum Covariance Determinant
def mcd(dir_path, x_train, y_train, x_test, y_test, clf_name='MCD', contamination=0.1):
    detectorName = "MCD"
    path = dir_path + "/mcd/"
    clf = MCD(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Multiple-Objective Generative Adversarial Active Learning
def mo_gaal(dir_path, x_train, y_train, x_test, y_test, clf_name='MO_GAAL', contamination=0.1):
    detectorName = "MO GAAL"
    path = dir_path + "/mo_gaal/"
    clf = MO_GAAL(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def ocsvm(dir_path, x_train, y_train, x_test, y_test, clf_name='OCSVM', contamination=0.1):
    detectorName = "One-class SVM"
    path = dir_path + "/ocsvm/"
    clf = OCSVM(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Principal Component Analysis
def pca_pyod(dir_path, x_train, y_train, x_test, y_test, clf_name='PCA', contamination=0.1):
    detectorName = "PCA"
    path = dir_path + "/pca/"
    clf = PCA(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName,path, clf, x_train, y_train, x_test, y_test, clf_name)

# Rotation based Outlier Detector
def rod(dir_path, x_train, y_train, x_test, y_test, clf_name='ROD', contamination=0.1):
    detectorName = "ROD"
    path = dir_path + "/rod/"
    clf = ROD(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Single-Objective Generative Adversarial Active Learning
def so_gaal(dir_path, x_train, y_train, x_test, y_test, clf_name='SO_GAAL', contamination=0.1):
    detectorName = "SO_GAAL"
    path = dir_path + "/so_gaal/"
    clf = SO_GAAL(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Subspace Outlier Detection
def sod(dir_path, x_train, y_train, x_test, y_test, clf_name='SOD', contamination=0.1):
    detectorName = "SOD"
    path = dir_path + "/sod/"
    clf = SOD(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Stochastic Outlier Selection
def sos(dir_path, x_train, y_train, x_test, y_test, clf_name='SOS', contamination=0.1):
    detectorName = "SOS"
    path = dir_path + "/sos/"
    clf = SOS(contamination=contamination)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Variational Auto Encoder
def vae(dir_path, x_train, y_train, x_test, y_test, clf_name='VAE', contamination=0.1, encoder_neurons=[2]):
    detectorName = "VAE"
    path = dir_path + "/vae/"
    clf = VAE(contamination=contamination, encoder_neurons=encoder_neurons)
    fitAndSaveAlgorithmPyod(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

# Improving Supervised Outlier Detection with Unsupervised Representation Learning
def xgbod(dir_path, x_train, y_train, x_test, y_test, clf_name='XGBOD', contamination=0.1):
    detectorName = "XGBOD"
    path = dir_path + "/xgbod/"
    clf = XGBOD(contamination=contamination)
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def run_pyod_algorithms(dir_path, x_train, y_train, x_test, y_test, clf_name):
    #abod(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #fast_abod(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #auto_encoder(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #cblof(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #lof(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #copod(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #ocsvm(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #vae(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #feature_bagging(dir_path, x_train, y_train, x_test, y_test, clf_name)
    #loda(dir_path, x_train, y_train, x_test, y_test, clf_name)
    sod(dir_path, x_train, y_train, x_test, y_test, clf_name)
    pca_pyod(dir_path, x_train, y_train, x_test, y_test, clf_name)
    xgbod(dir_path, x_train, y_train, x_test, y_test, clf_name)