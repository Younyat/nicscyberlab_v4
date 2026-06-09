from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def get_module_root() -> Path:
    return Path(__file__).resolve().parents[1]


def get_config_path() -> Path:
    return get_module_root() / "config" / "module_config.json"


def get_module_runtime_config() -> dict[str, Any]:
    module_root = get_module_root()
    config_path = get_config_path()

    raw = {}
    if config_path.exists():
        raw = json.loads(config_path.read_text(encoding="utf-8"))

    vendor_repo_dir = raw.get("vendor_repo_dir", "adv_detection/vendor/advDetection")
    runs_dir = raw.get("runs_dir", "adv_detection/runs")

    resolved_vendor_repo = (module_root.parents[0] / vendor_repo_dir).resolve()
    resolved_runs_dir = (module_root.parents[0] / runs_dir).resolve()

    data = {
        "enabled": bool(raw.get("enabled", True)),
        "module_name": str(raw.get("module_name", "adv_detection")),
        "vendor_repo_dir": vendor_repo_dir,
        "vendor_repo_dir_resolved": str(resolved_vendor_repo),
        "runs_dir": runs_dir,
        "runs_dir_resolved": str(resolved_runs_dir),
        "default_entrypoint": str(raw.get("default_entrypoint", "")),
        "default_dataset": str(raw.get("default_dataset", "")),
        "python_bin": str(raw.get("python_bin", "python3")),
        "venv_activate": str(raw.get("venv_activate", "")),
        "notes": str(raw.get("notes", "")),
    }

    return data