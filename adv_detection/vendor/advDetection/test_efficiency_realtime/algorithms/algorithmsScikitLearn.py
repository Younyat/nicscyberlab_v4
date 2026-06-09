from __future__ import division
from __future__ import print_function

from sklearn import svm
from sklearn.ensemble import *
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.metrics import confusion_matrix
from sklearn.tree import *
from sklearn.svm import *
from sklearn.semi_supervised import *
from sklearn.cluster import *
from sklearn.neural_network import *
from utilities.fitAndSaveAlgorithm import *
from sklearn.model_selection import cross_val_score

def gaussianProcessClassifier(dir_path, x_train, y_train, x_test, y_test, clf_name='GaussianProcessClassifier', contamination=0.1):
    detectorName = "GaussinaProcessClassifier"
    path = dir_path + "/gaussianProcessClassifier/"
    clf = GaussianProcessClassifier()
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def selfTraining(dir_path, x_train, y_train, x_test, y_test, clf_name='SelfTrainingClassifier', contamination=0.1):
    detectorName = "SelfTrainingClassifier"
    path = dir_path + "/selftrainingClassifier/"
    base_estimator = DecisionTreeClassifier(criterion='entropy', min_samples_leaf=50, min_samples_split=20)
    clf = SelfTrainingClassifier(base_estimator=base_estimator, criterion='k_best')
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def randomForestClassifierCV(x, y):
    detectorName = "Random Forest Classifier"
    clf = RandomForestClassifier(criterion='entropy', min_samples_leaf=50, min_samples_split=20)
    cv = cross_val_score(clf, x, y)
    print(detectorName + " : " +str(cv.mean()))

def randomForestClassifier(dir_path, x_train, y_train, x_test, y_test, clf_name='RandomForestClassifier'):
    detectorName = "Random Forest Classifier"
    path = dir_path + "/randomforestclassifier/"
    clf = RandomForestClassifier()
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def mlp(dir_path, x_train, y_train, x_test, y_test, clf_name='MLP_Classifier'):
    detectorName = "MLP Classifier"
    path = dir_path + "/mlp/"
    clf = MLPClassifier()
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def mlpCV(x, y):
    detectorName = "MLP Classifier"
    clf = MLPClassifier()
    cv = cross_val_score(clf, x, y)
    print(detectorName + " : " +str(cv.mean()))


def bernouilliRBM(dir_path, x_train, y_train, x_test, y_test, clf_name='BernouilliRBM', contamination=0.1):
    detectorName = "BernouilliRBM"
    path = dir_path + "/bernouilliRBM/"
    clf = BernoulliRBM()
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def dtc(dir_path, x_train, y_train, x_test, y_test, clf_name='DecisionTreeClassifier', criterion='gini', min_samples_leaf=1, min_samples_split=2, max_features=None, ccp_alpha=0.0):
    detectorName = "Decision Tree Classifier"
    path = dir_path + "/dtc/"
    clf = DecisionTreeClassifier(criterion=criterion, min_samples_leaf=min_samples_leaf, min_samples_split=min_samples_split, max_features=max_features, ccp_alpha=ccp_alpha)
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def dtcCV(x, y, criterion='gini', min_samples_leaf=1, min_samples_split=2, max_features=None, ccp_alpha=0.0):
    detectorName = "DT Classifier"
    clf = DecisionTreeClassifier(criterion=criterion, min_samples_leaf=min_samples_leaf, min_samples_split=min_samples_split, max_features=max_features, ccp_alpha=ccp_alpha)
    cv = cross_val_score(clf, x, y)
    print(detectorName + " : " +str(cv.mean()))

def gradientBoostingClassifier(dir_path, x_train, y_train, x_test, y_test, clf_name='GradientBoostingClassifier'):
    detectorName = "Gradient Boosting Classifier"
    path = dir_path + "/gradientboostingclassifier/"
    clf = GradientBoostingClassifier(min_samples_leaf=20, max_leaf_nodes=50)
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def gradientBoostingClassifierCV(x, y):
    detectorName = "DT Classifier"
    clf = GradientBoostingClassifier(min_samples_leaf=20, max_leaf_nodes=50)
    cv = cross_val_score(clf, x, y)
    print(detectorName + " : " +str(cv.mean()))

def iforest(dir_path, x_train, y_train, x_test, y_test, clf_name='IForest'):
    detectorName = "Isolation Forest"
    path = dir_path + "/iforest/"
    clf = IsolationForest(contamination=0.01)
    fitAndSaveAlgorithmSupervised(detectorName, path, clf, x_train, y_train, x_test, y_test, clf_name)

def kmeans(dir_path, x_train, y_train, x_test, y_test,  clf_name = 'K-Means',  n_clusters=2):
    detectorName = "K-Means"
    start = time.time()
    path_kmeans = dir_path + "/kmeans/"
    if not os.path.exists(path_kmeans):
        os.makedirs(path_kmeans)

    # train OCSVM detector
    clf = KMeans(n_clusters=n_clusters, max_iter=1000)
    clf.fit(x_train)

    # get the prediction labels and outlier scores of the training data
    y_train_pred = clf.labels_  # binary labels (0: inliers, 1: outliers)

    # get the prediction on the test data
    y_test_pred = clf.predict(x_test)  # outlier labels (0 or 1)

    skplt.metrics.plot_confusion_matrix(
    y_train, y_train_pred, normalize=False, title="Confusion Matrix on Train Set with " + detectorName)
    plt.savefig('{path_images}confusionMatrixTrain_{clf_name}.png'.format(clf_name=clf_name, path_images=path_kmeans))
    plt.show()

    skplt.metrics.plot_confusion_matrix(
    y_test, y_test_pred, normalize=False, title="Confusion Matrix on Test Set with " + detectorName)
    plt.savefig('{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path_kmeans))
    plt.show()

    if x_train.shape[1] == 2: # visualize the results
        visualize(clf_name, x_train, y_train, x_test, y_test, y_train_pred,
                  y_test_pred, show_figure=True, save_figure=True, path_save_figure=path_kmeans)

    # save the model
    dump(clf, path_kmeans + clf_name + '.joblib')

    end = time.time()
    duration = end-start
    print("duration: " + str(duration))

    fileDuration = open(path_kmeans + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()

def svm_svc(dir_path, x_train, y_train, x_test, y_test, clf_name='SVC', contamination=0.1):
    detectorName = "SVC"
    start = time.time()
    path_svm_svc = dir_path + "/svm_svc/"

    if not os.path.exists(path_svm_svc):
        os.makedirs(path_svm_svc)

    clf = SVC(kernel='rbf', C=0.5)
    clf.fit(x_train, y_train)

    # get the prediction on the test data
    y_test_pred = clf.predict(x_test)

    skplt.metrics.plot_confusion_matrix(
        y_test, y_test_pred, normalize=False, title=clf_name + "\nConfusion Matrix on Test Set with " + detectorName)

    plt.savefig('{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path_svm_svc))
    plt.show()

    visualizer = confusion_matrix(clf, x_train, y_train, x_test, y_test, is_fitted=True)
    visualizer.show(path_svm_svc + "/confusionMatrix_" + clf_name + ".png")

    # save the model
    dump(clf, path_svm_svc + clf_name + '.joblib')

    end = time.time()
    duration = end - start
    print("duration: " + str(duration))

    fileDuration = open(path_svm_svc + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()


def svm_linearsvc(x_train, y_train, x_test, y_test, clf_name='linearSVC', contamination=0.1):
    detectorName = "linearSVC"
    start = time.time()
    path_svm_linearsvc = "svm_linearsvc/"

    if not os.path.exists(path_svm_linearsvc):
        os.makedirs(path_svm_linearsvc)

    clf = LinearSVC()
    clf.fit(x_train, y_train)

    # get the prediction on the test data
    y_test_pred = clf.predict(x_test)

    skplt.metrics.plot_confusion_matrix(
        y_test, y_test_pred, normalize=False, title=clf_name + "\nConfusion Matrix on Test Set with " + detectorName)
    plt.savefig(
        '{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path_svm_linearsvc))
    plt.show()

    # save the model
    dump(clf, path_svm_linearsvc + clf_name + '.joblib')

    end = time.time()
    duration = end - start
    print("duration: " + str(duration))

    fileDuration = open(path_svm_linearsvc + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()

def svm_linearsvr(x_train, y_train, x_test, y_test, clf_name='SVR', contamination=0.1):
    detectorName = "linear SVR"
    start = time.time()
    path_svm = "svm_linearsvr/"

    if not os.path.exists(path_svm):
        os.makedirs(path_svm)

    clf = svm.LinearSVC()
    clf.fit(x_train, y_train)

    # get the prediction on the test data
    y_test_pred = clf.predict(x_test)

    skplt.metrics.plot_confusion_matrix(
        y_test, y_test_pred, normalize=False, title=clf_name + "\nConfusion Matrix on Test Set with " + detectorName)
    plt.savefig('{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path_svm))
    plt.show()

    # save the model
    dump(clf, path_svm + clf_name + '.joblib')

    end = time.time()
    duration = end - start
    print("duration: " + str(duration))

    fileDuration = open(path_svm + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()