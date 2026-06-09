from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import joblib

from .config import ACTIVE_MODEL_PATH, DEFAULT_MODEL_PATH


_MODEL: Any | None = None
_MODEL_PATH_LOADED: Path | None = None
_MODEL_MTIME_LOADED: float | None = None


def ensure_active_model() -> Path:
    if not ACTIVE_MODEL_PATH.exists():
        if not DEFAULT_MODEL_PATH.exists():
            raise FileNotFoundError(f"Default model not found: {DEFAULT_MODEL_PATH}")
        ACTIVE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(DEFAULT_MODEL_PATH, ACTIVE_MODEL_PATH)
    return ACTIVE_MODEL_PATH


def clear_model_cache() -> None:
    global _MODEL, _MODEL_PATH_LOADED, _MODEL_MTIME_LOADED
    _MODEL = None
    _MODEL_PATH_LOADED = None
    _MODEL_MTIME_LOADED = None


def get_model(force_reload: bool = False):
    global _MODEL, _MODEL_PATH_LOADED, _MODEL_MTIME_LOADED

    model_path = ensure_active_model()
    current_mtime = model_path.stat().st_mtime

    should_reload = force_reload
    should_reload = should_reload or _MODEL is None
    should_reload = should_reload or _MODEL_PATH_LOADED != model_path
    should_reload = should_reload or _MODEL_MTIME_LOADED != current_mtime

    if should_reload:
      _MODEL = joblib.load(model_path)
      _MODEL_PATH_LOADED = model_path
      _MODEL_MTIME_LOADED = current_mtime

    return _MODEL


def get_active_model_path() -> str:
    return str(ensure_active_model())


def activate_model(model_path: str | Path) -> str:
    src = Path(model_path)
    if not src.exists():
        raise FileNotFoundError(f"Model file not found: {src}")

    ACTIVE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, ACTIVE_MODEL_PATH)

    clear_model_cache()
    get_model(force_reload=True)

    return str(ACTIVE_MODEL_PATH)