from __future__ import annotations

import pickle
from datetime import datetime

import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

from .config import DATA_SPLIT_FILES, MODELS_DIR
from .model_service import activate_model


def load_split(dataset: str):
    dataset = dataset.lower()
    if dataset not in DATA_SPLIT_FILES:
        raise ValueError(f"Unsupported dataset: {dataset}. Valid values: {list(DATA_SPLIT_FILES.keys())}")

    split_path = DATA_SPLIT_FILES[dataset]
    if not split_path.exists():
        raise FileNotFoundError(f"Split file not found: {split_path}")

    with open(split_path, "rb") as f:
        return pickle.load(f)


def build_default_stacking_model():
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        random_state=0,
        n_jobs=-1,
    )

    lgbm = LGBMClassifier(
        learning_rate=0.05,
        max_depth=15,
        num_leaves=40,
        feature_fraction=0.8,
        bagging_fraction=0.8,
        bagging_freq=5,
        min_data_in_leaf=30,
        min_gain_to_split=0.1,
        random_state=0,
        verbose=-1,
    )

    final_estimator = LogisticRegression(
        max_iter=20000,
        n_jobs=-1,
    )

    model = StackingClassifier(
        estimators=[
            ("rf", rf),
            ("lgbm", lgbm),
        ],
        final_estimator=final_estimator,
        stack_method="predict_proba",
        cv=5,
        n_jobs=-1,
    )

    return model


def _evaluate(model, X_test, y_test) -> dict:
    pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, pred)
    macro_f1 = f1_score(y_test, pred, average="macro")

    report = classification_report(y_test, pred, output_dict=True, zero_division=0)

    labels = sorted(np.unique(np.concatenate([np.array(y_test), np.array(pred)])))
    cm = confusion_matrix(y_test, pred, labels=labels)

    return {
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }


def train_default_model(dataset: str = "2017", set_active: bool = True) -> dict:
    data = load_split(dataset)

    X_train = data["X_train"]
    X_test = data["X_test"]
    y_train = data["y_train"]
    y_test = data["y_test"]

    model = build_default_stacking_model()
    model.fit(X_train, y_train)

    metrics = _evaluate(model, X_test, y_test)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    model_path = MODELS_DIR / f"trained_{dataset}_{ts}.pkl"
    joblib.dump(model, model_path)

    active_model_path = None
    if set_active:
        active_model_path = activate_model(model_path)

    return {
        "ok": True,
        "dataset": dataset,
        "model_path": str(model_path),
        "active_model_path": active_model_path,
        **metrics,
    }


def evaluate_active_model(model, dataset: str = "2017") -> dict:
    data = load_split(dataset)

    X_test = data["X_test"]
    y_test = data["y_test"]

    metrics = _evaluate(model, X_test, y_test)

    return {
        "ok": True,
        "dataset": dataset,
        "rows": int(len(X_test)),
        **metrics,
    }