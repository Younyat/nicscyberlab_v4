from __future__ import annotations

import json
import pickle
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from flask import current_app
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from ciberia_lab.services.pcap_features import pcap_to_dataframe


MODULE_ROOT = Path(__file__).resolve().parent.parent
DATASETS_ROOT = MODULE_ROOT / "datasets"
CAPTURES_ROOT = DATASETS_ROOT / "captures"
CUSTOM_DATASETS_ROOT = DATASETS_ROOT / "custom"
SPLITS_ROOT = DATASETS_ROOT / "splits"
MODELS_ROOT = MODULE_ROOT / "models"

for directory in [CAPTURES_ROOT, CUSTOM_DATASETS_ROOT, SPLITS_ROOT, MODELS_ROOT]:
    directory.mkdir(parents=True, exist_ok=True)


NON_FEATURE_COLUMNS = {
    "Attack Type",
    "capture_id",
    "label",
    "scenario_name",
    "attack_type",
    "source_host",
    "target_host",
    "notes",
    "vm_id",
    "vm_name",
    "run_id",
    "pcap_rel",
    "meta_rel",
    "industrial_export_rel",
    "pcap_abs",
    "started_at_utc",
    "stopped_at_utc",
    "legacy_capture",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value.strip())
    return cleaned or "unnamed"


def _capture_id() -> str:
    return f"cap_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"


def _capture_dir(capture_id: str) -> Path:
    return CAPTURES_ROOT / capture_id


def _metadata_path(capture_id: str) -> Path:
    return _capture_dir(capture_id) / "metadata.json"


def _read_json(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _read_metadata(capture_id: str) -> dict[str, Any]:
    path = _metadata_path(capture_id)
    if not path.exists():
        raise FileNotFoundError(f"Capture metadata not found for capture_id={capture_id}")
    return _read_json(path)


def _write_metadata(capture_id: str, data: dict[str, Any]) -> None:
    _write_json(_metadata_path(capture_id), data)


def list_captures() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    if not CAPTURES_ROOT.exists():
        return items

    for directory in CAPTURES_ROOT.iterdir():
        if not directory.is_dir():
            continue

        metadata_file = directory / "metadata.json"
        if not metadata_file.exists():
            continue

        try:
            metadata = _read_json(metadata_file)
            items.append(metadata)
        except Exception:
            continue

    items.sort(key=lambda x: x.get("started_at_utc", ""), reverse=True)
    return items


def start_labeled_capture_via_platform(
    *,
    label: str,
    scenario_name: str,
    attack_type: str,
    source_host: str,
    target_host: str,
    notes: str,
    vm_id: str,
    vm_name: str,
    run_id: str,
    seconds: int,
    protos: list[str],
) -> dict[str, Any]:
    label = label.strip()
    scenario_name = scenario_name.strip()
    attack_type = attack_type.strip()
    source_host = source_host.strip()
    target_host = target_host.strip()
    notes = notes.strip()
    vm_id = vm_id.strip()
    vm_name = vm_name.strip()
    run_id = run_id.strip() or "R1"

    if not label:
        raise ValueError("label is required")
    if not vm_id:
        raise ValueError("vm_id is required")

    capture_id = _capture_id()
    capture_dir = _capture_dir(capture_id)
    capture_dir.mkdir(parents=True, exist_ok=True)

    request_payload = {
        "vm_id": vm_id,
        "run_id": run_id,
        "seconds": int(seconds or 20),
        "protos": protos or ["modbus", "tcp", "udp"],
    }

    with current_app.test_client() as client:
        response = client.post(
            "/api/forensics/traffic/capture",
            json=request_payload,
        )

    try:
        response_data = response.get_json(silent=True) or {}
    except Exception:
        response_data = {}

    if response.status_code != 200 or response_data.get("result") != "ok":
        raise RuntimeError(
            response_data.get("error")
            or response_data.get("message")
            or f"Traffic capture failed with status {response.status_code}"
        )

    pcap_rel = response_data.get("pcap_rel")
    meta_rel = response_data.get("meta_rel")
    industrial_export_rel = response_data.get("industrial_export_rel")

    metadata = {
        "capture_id": capture_id,
        "label": label,
        "scenario_name": scenario_name,
        "attack_type": attack_type,
        "source_host": source_host,
        "target_host": target_host,
        "notes": notes,
        "vm_id": vm_id,
        "vm_name": vm_name,
        "run_id": run_id,
        "seconds": int(seconds or 20),
        "protos": protos or ["modbus", "tcp", "udp"],
        "status": "captured",
        "started_at_utc": _utc_now(),
        "stopped_at_utc": _utc_now(),
        "pcap_rel": pcap_rel,
        "meta_rel": meta_rel,
        "industrial_export_rel": industrial_export_rel,
        "pcap_abs": None,
        "legacy_capture": True,
        "features_csv": None,
        "dataset_appended": False,
        "dataset_name": None,
        "raw_capture_response": response_data,
    }
    _write_metadata(capture_id, metadata)

    return {
        "ok": True,
        "capture_id": capture_id,
        "message": "Labeled legacy capture completed successfully.",
        "metadata": metadata,
    }


def register_existing_legacy_capture(
    *,
    label: str,
    scenario_name: str,
    attack_type: str,
    source_host: str,
    target_host: str,
    notes: str,
    vm_id: str,
    vm_name: str,
    run_id: str,
    pcap_abs: str,
) -> dict[str, Any]:
    label = label.strip()
    vm_id = vm_id.strip()
    pcap_abs = pcap_abs.strip()
    run_id = run_id.strip() or "R1"

    if not label:
        raise ValueError("label is required")
    if not vm_id:
        raise ValueError("vm_id is required")
    if not pcap_abs:
        raise ValueError("pcap_abs is required")

    pcap_path = Path(pcap_abs)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_abs}")

    capture_id = _capture_id()
    capture_dir = _capture_dir(capture_id)
    capture_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "capture_id": capture_id,
        "label": label,
        "scenario_name": scenario_name.strip(),
        "attack_type": attack_type.strip(),
        "source_host": source_host.strip(),
        "target_host": target_host.strip(),
        "notes": notes.strip(),
        "vm_id": vm_id,
        "vm_name": vm_name.strip(),
        "run_id": run_id,
        "seconds": None,
        "protos": [],
        "status": "registered",
        "started_at_utc": _utc_now(),
        "stopped_at_utc": _utc_now(),
        "pcap_rel": None,
        "meta_rel": None,
        "industrial_export_rel": None,
        "pcap_abs": str(pcap_path),
        "legacy_capture": True,
        "features_csv": None,
        "dataset_appended": False,
        "dataset_name": None,
        "raw_capture_response": {},
    }
    _write_metadata(capture_id, metadata)

    return {
        "ok": True,
        "capture_id": capture_id,
        "message": "Existing legacy PCAP registered successfully.",
        "metadata": metadata,
    }


def extract_capture_to_labeled_csv(capture_id: str) -> dict[str, Any]:
    metadata = _read_metadata(capture_id)

    pcap_abs = metadata.get("pcap_abs")
    if not pcap_abs:
        raise ValueError("Capture metadata does not contain pcap_abs. Provide a PCAP path or register the capture first.")

    pcap_file = Path(pcap_abs)
    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    df = pcap_to_dataframe(pcap_file)
    if df.empty:
        raise ValueError("No flow rows were extracted from the capture.")

    df["Attack Type"] = metadata["label"]
    df["capture_id"] = capture_id
    df["label"] = metadata.get("label", "")
    df["scenario_name"] = metadata.get("scenario_name", "")
    df["attack_type"] = metadata.get("attack_type", "")
    df["source_host"] = metadata.get("source_host", "")
    df["target_host"] = metadata.get("target_host", "")
    df["notes"] = metadata.get("notes", "")
    df["vm_id"] = metadata.get("vm_id", "")
    df["vm_name"] = metadata.get("vm_name", "")
    df["run_id"] = metadata.get("run_id", "")
    df["pcap_rel"] = metadata.get("pcap_rel", "")
    df["meta_rel"] = metadata.get("meta_rel", "")
    df["industrial_export_rel"] = metadata.get("industrial_export_rel", "")
    df["pcap_abs"] = metadata.get("pcap_abs", "")
    df["started_at_utc"] = metadata.get("started_at_utc", "")
    df["stopped_at_utc"] = metadata.get("stopped_at_utc", "")
    df["legacy_capture"] = metadata.get("legacy_capture", True)

    out_csv = _capture_dir(capture_id) / "features_labeled.csv"
    df.to_csv(out_csv, index=False)

    metadata["features_csv"] = str(out_csv)
    _write_metadata(capture_id, metadata)

    return {
        "ok": True,
        "capture_id": capture_id,
        "rows": int(len(df)),
        "features_csv": str(out_csv),
        "preview": df.head(20).to_dict(orient="records"),
        "message": "Feature extraction and labeling completed successfully.",
    }


def append_capture_to_dataset(capture_id: str, dataset_name: str) -> dict[str, Any]:
    dataset_name = _safe_name(dataset_name)
    metadata = _read_metadata(capture_id)

    features_csv = metadata.get("features_csv")
    if not features_csv:
        raise ValueError("Capture has no extracted labeled CSV yet.")

    features_csv_path = Path(features_csv)
    if not features_csv_path.exists():
        raise FileNotFoundError(f"Missing labeled CSV: {features_csv_path}")

    src_df = pd.read_csv(features_csv_path)
    dataset_path = CUSTOM_DATASETS_ROOT / f"{dataset_name}.csv"

    if dataset_path.exists():
        dst_df = pd.read_csv(dataset_path)

        if "capture_id" in dst_df.columns and capture_id in set(dst_df["capture_id"].astype(str)):
            return {
                "ok": True,
                "capture_id": capture_id,
                "dataset_name": dataset_name,
                "dataset_csv": str(dataset_path),
                "rows_added": 0,
                "total_rows": int(len(dst_df)),
                "message": "Capture was already appended to this dataset.",
            }

        merged = pd.concat([dst_df, src_df], ignore_index=True)
    else:
        merged = src_df.copy()

    merged.to_csv(dataset_path, index=False)

    metadata["dataset_appended"] = True
    metadata["dataset_name"] = dataset_name
    _write_metadata(capture_id, metadata)

    return {
        "ok": True,
        "capture_id": capture_id,
        "dataset_name": dataset_name,
        "dataset_csv": str(dataset_path),
        "rows_added": int(len(src_df)),
        "total_rows": int(len(merged)),
        "message": "Capture appended to dataset successfully.",
    }


def get_dataset_status(dataset_name: str) -> dict[str, Any]:
    dataset_name = _safe_name(dataset_name)
    dataset_path = CUSTOM_DATASETS_ROOT / f"{dataset_name}.csv"

    if not dataset_path.exists():
        return {
            "ok": True,
            "dataset_name": dataset_name,
            "exists": False,
            "message": "Dataset does not exist yet.",
        }

    df = pd.read_csv(dataset_path)
    class_distribution = {}
    if "Attack Type" in df.columns:
        class_distribution = df["Attack Type"].value_counts().to_dict()

    captures_included = []
    if "capture_id" in df.columns:
        captures_included = sorted(df["capture_id"].astype(str).dropna().unique().tolist())

    return {
        "ok": True,
        "dataset_name": dataset_name,
        "exists": True,
        "dataset_csv": str(dataset_path),
        "rows": int(len(df)),
        "columns": df.columns.tolist(),
        "class_distribution": class_distribution,
        "captures_included": captures_included,
        "message": "Custom dataset status loaded successfully.",
    }


def build_custom_split(dataset_name: str, test_size: float = 0.3, random_state: int = 42) -> dict[str, Any]:
    dataset_name = _safe_name(dataset_name)
    dataset_path = CUSTOM_DATASETS_ROOT / f"{dataset_name}.csv"

    if not dataset_path.exists():
        raise FileNotFoundError(f"Custom dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if "Attack Type" not in df.columns:
        raise ValueError("Dataset must contain an 'Attack Type' column.")

    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]
    if not feature_cols:
        raise ValueError("No feature columns available for split generation.")

    X = df[feature_cols].copy()
    y = df["Attack Type"].copy()

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X = X.fillna(0)

    stratify = None
    class_counts = y.value_counts()
    if len(class_counts) > 1 and int(class_counts.min()) >= 2:
        stratify = y

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    split_path = SPLITS_ROOT / f"{dataset_name}.pkl"
    with open(split_path, "wb") as f:
        pickle.dump(
            {
                "X_train": X_train,
                "X_test": X_test,
                "y_train": y_train,
                "y_test": y_test,
            },
            f,
        )

    return {
        "ok": True,
        "dataset_name": dataset_name,
        "split_file": str(split_path),
        "rows_total": int(len(df)),
        "rows_train": int(len(X_train)),
        "rows_test": int(len(X_test)),
        "feature_count": int(len(feature_cols)),
        "class_distribution": y.value_counts().to_dict(),
        "message": "Custom train/test split built successfully.",
    }


def train_custom_model(dataset_name: str, set_active: bool = True) -> dict[str, Any]:
    dataset_name = _safe_name(dataset_name)
    split_path = SPLITS_ROOT / f"{dataset_name}.pkl"

    if not split_path.exists():
        raise FileNotFoundError(f"Custom split not found: {split_path}")

    with open(split_path, "rb") as f:
        data = pickle.load(f)

    X_train = data["X_train"]
    X_test = data["X_test"]
    y_train = data["y_train"]
    y_test = data["y_test"]

    model = StackingClassifier(
        estimators=[
            ("rf", RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)),
            ("et", ExtraTreesClassifier(n_estimators=200, random_state=42, n_jobs=-1)),
        ],
        final_estimator=LogisticRegression(max_iter=5000),
        passthrough=False,
        cv=5,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    accuracy = float(accuracy_score(y_test, pred))
    report = classification_report(y_test, pred, output_dict=True, zero_division=0)
    labels = sorted(y_test.astype(str).unique().tolist())
    cm = confusion_matrix(y_test, pred, labels=labels).tolist()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    model_path = MODELS_ROOT / f"trained_custom_{dataset_name}_{ts}.pkl"
    joblib.dump(model, model_path)

    active_model_path = MODELS_ROOT / "active_model.pkl"
    if set_active:
        shutil.copy2(model_path, active_model_path)

    return {
        "ok": True,
        "dataset_name": dataset_name,
        "accuracy": accuracy,
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "classification_report": report,
        "confusion_matrix": cm,
        "labels": labels,
        "model_path": str(model_path),
        "active_model_path": str(active_model_path if set_active else model_path),
        "rows_test": int(len(X_test)),
        "message": "Custom model training completed successfully.",
    }