from __future__ import annotations

from typing import Any

import pandas as pd

from .model_service import get_model
from .schema import COLUMN_ALIASES, FEATURE_COLUMNS


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    return df.rename(columns=COLUMN_ALIASES).copy()


def _get_required_features_from_model(model) -> list[str]:
    if hasattr(model, "feature_names_in_"):
        return [str(x) for x in model.feature_names_in_.tolist()]
    return FEATURE_COLUMNS


def validate_and_prepare_dataframe(df: pd.DataFrame, required_features: list[str]) -> pd.DataFrame:
    normalized = normalize_columns(df)

    missing = [col for col in required_features if col not in normalized.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    prepared = normalized[required_features].copy()

    for col in required_features:
        prepared[col] = pd.to_numeric(prepared[col], errors="coerce")

    bad_cols = [col for col in required_features if prepared[col].isna().any()]
    if bad_cols:
        raise ValueError(f"Invalid or non-numeric values found in columns: {bad_cols}")

    return prepared


def predict_from_dataframe(df: pd.DataFrame) -> dict[str, Any]:
    model = get_model()
    required_features = _get_required_features_from_model(model)
    X = validate_and_prepare_dataframe(df, required_features)

    predictions = model.predict(X).tolist()

    probabilities = None
    classes = None
    max_confidence = None

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        probabilities = proba.tolist()
        max_confidence = proba.max(axis=1).tolist()
        if hasattr(model, "classes_"):
            classes = model.classes_.tolist()

    results = []
    for i, pred in enumerate(predictions):
        item = {
            "row_index": int(i),
            "prediction": str(pred),
        }
        if max_confidence is not None:
            item["confidence"] = float(max_confidence[i])
        if probabilities is not None and classes is not None:
            item["probabilities"] = {
                str(cls): float(probabilities[i][j]) for j, cls in enumerate(classes)
            }
        results.append(item)

    summary: dict[str, int] = {}
    for pred in predictions:
        pred = str(pred)
        summary[pred] = summary.get(pred, 0) + 1

    return {
        "ok": True,
        "input_rows": int(len(X)),
        "required_features": required_features,
        "summary": summary,
        "results": results,
    }


def predict_from_csv_file(file_storage) -> dict[str, Any]:
    df = pd.read_csv(file_storage)
    return predict_from_dataframe(df)