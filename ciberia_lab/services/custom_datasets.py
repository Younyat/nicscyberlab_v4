from __future__ import annotations

import json
import pickle
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from werkzeug.utils import secure_filename

from .config import BASE_PROFILE_INFO, DATASETS_CUSTOM_DIR, DATA_SPLIT_FILES


def _slugify(value: str) -> str:
    value = secure_filename(value).lower().strip()
    value = re.sub(r"[^a-z0-9_\-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or f"custom_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"


def _dataset_dir(dataset_id: str) -> Path:
    return DATASETS_CUSTOM_DIR / dataset_id


def _metadata_path(dataset_id: str) -> Path:
    return _dataset_dir(dataset_id) / "metadata.json"


def _split_path(dataset_id: str) -> Path:
    return _dataset_dir(dataset_id) / "data_split.pkl"


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _validate_split_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("The uploaded split file must contain a dictionary")

    required = ["X_train", "X_test", "y_train", "y_test"]
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValueError(f"Missing required keys in split payload: {missing}")

    return payload


def _candidate_custom_dirs() -> list[Path]:
    candidates = [DATASETS_CUSTOM_DIR, DATASETS_CUSTOM_DIR / "custom"]
    valid = []

    for path in candidates:
        if path.exists() and path.is_dir():
            valid.append(path)

    return valid


def list_custom_profiles() -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    visited_dirs: set[str] = set()

    for base_dir in _candidate_custom_dirs():
        for item in sorted(base_dir.iterdir(), key=lambda p: p.name.lower()):
            if not item.is_dir():
                continue

            item_key = str(item.resolve())
            if item_key in visited_dirs:
                continue
            visited_dirs.add(item_key)

            split_file = item / "data_split.pkl"
            metadata_file = item / "metadata.json"

            if not split_file.exists():
                continue

            metadata = _read_json(metadata_file, {})

            dataset_id = str(metadata.get("profile") or item.name).strip()
            if not dataset_id:
                dataset_id = item.name

            profiles[dataset_id] = {
                "profile": dataset_id,
                "title": metadata.get("title", dataset_id),
                "notebook": metadata.get("notebook", "custom_dataset"),
                "goal": metadata.get("goal", "Custom dataset imported into CiberIA Lab"),
                "split_file": str(split_file),
                "base_model_file": metadata.get("base_model_file", ""),
                "mode": "custom_dataset",
                "source": "custom",
                "label_column": metadata.get("label_column", "Attack Type"),
                "imported_at_utc": metadata.get("imported_at_utc", ""),
                "rows_train": metadata.get("rows_train"),
                "rows_test": metadata.get("rows_test"),
                "features": metadata.get("features"),
                "directory_name": item.name,
                "has_metadata": metadata_file.exists(),
            }

    return profiles


def get_all_profiles() -> dict[str, dict[str, Any]]:
    merged = dict(BASE_PROFILE_INFO)
    merged.update(list_custom_profiles())
    return merged


def get_all_split_files() -> dict[str, Path]:
    merged = dict(DATA_SPLIT_FILES)
    for dataset_id, info in list_custom_profiles().items():
        merged[dataset_id] = Path(info["split_file"])
    return merged


def import_custom_split_dataset(
    file_storage,
    dataset_name: str,
    dataset_id: str | None = None,
    label_column: str = "Attack Type",
) -> dict[str, Any]:
    title = (dataset_name or "").strip()
    if not title:
        raise ValueError("dataset_name is required")

    final_dataset_id = _slugify(dataset_id or title)
    target_dir = _dataset_dir(final_dataset_id)
    target_dir.mkdir(parents=True, exist_ok=True)

    uploaded_tmp = target_dir / f"_upload_{secure_filename(file_storage.filename or 'data_split.pkl')}"
    file_storage.save(uploaded_tmp)

    try:
        with uploaded_tmp.open("rb") as f:
            payload = pickle.load(f)

        payload = _validate_split_payload(payload)

        split_path = _split_path(final_dataset_id)
        with split_path.open("wb") as f:
            pickle.dump(payload, f)

        x_train = payload["X_train"]
        x_test = payload["X_test"]

        rows_train = int(len(x_train))
        rows_test = int(len(x_test))
        features = list(x_train.columns) if hasattr(x_train, "columns") else None

        metadata = {
            "profile": final_dataset_id,
            "title": title,
            "goal": "Custom dataset imported into CiberIA Lab",
            "label_column": label_column,
            "imported_at_utc": datetime.now(timezone.utc).isoformat(),
            "rows_train": rows_train,
            "rows_test": rows_test,
            "features": features,
            "original_filename": file_storage.filename or "",
        }

        _write_json(_metadata_path(final_dataset_id), metadata)

        return {
            "ok": True,
            "dataset": metadata,
            "split_file": str(split_path),
            "profiles": list(get_all_profiles().values()),
            "message": "Custom dataset imported successfully.",
        }
    finally:
        if uploaded_tmp.exists():
            uploaded_tmp.unlink(missing_ok=True)


def delete_custom_dataset(dataset_id: str) -> dict[str, Any]:
    dataset_id = (dataset_id or "").strip().lower()
    if not dataset_id:
        raise ValueError("dataset is required")

    if dataset_id in BASE_PROFILE_INFO:
        raise ValueError("Built-in datasets cannot be deleted")

    target_dir = _dataset_dir(dataset_id)
    if not target_dir.exists():
        raise FileNotFoundError(f"Custom dataset not found: {dataset_id}")

    shutil.rmtree(target_dir)
    return {
        "ok": True,
        "dataset": dataset_id,
        "message": "Custom dataset deleted successfully.",
    }