
import matplotlib.pyplot as plt
import scikitplot as skplt
import os
from joblib import dump
import time

from tpot import TPOTClassifier


def tpot(dir_path, x_train, y_train, x_test, y_test, clf_name='TPOT', verbosity=0, timeout=60,
         early_stop=None, scoring="accuracy", config_dict=None):
    detectorName = "TPOT"
    path = dir_path + "/tpot/"
    clf = TPOTClassifier(verbosity=verbosity, max_time_mins=timeout, early_stop=early_stop, scoring=scoring, config_dict=config_dict)

    start = time.time()
    if not os.path.exists(path):
        os.makedirs(path)

    clf.fit(x_train, y_train)

    y_test_pred = clf.predict(x_test)

    skplt.metrics.plot_confusion_matrix(
        y_test, y_test_pred, normalize=False, title="Confusion Matrix on Test Set with " + detectorName)
    plt.savefig('{path_images}confusionMatrixTest_{clf_name}.png'.format(clf_name=clf_name, path_images=path))
    plt.show()

    # save the model
    try:
        clf.export(path+clf_name + ".py")
    except Exception as e:
        print("No se ha podido guardar " + clf_name)

    end = time.time()
    duration = end - start
    print("duration: " + str(duration))

    fileDuration = open(path + "duration_" + clf_name + ".txt", "w")
    fileDuration.write(str(duration))
    fileDuration.close()