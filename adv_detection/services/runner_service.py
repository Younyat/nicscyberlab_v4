from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config_service import get_module_runtime_config


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _module_paths() -> dict[str, Path]:
    cfg = get_module_runtime_config()
    project_root = Path(__file__).resolve().parents[2]
    module_root = Path(__file__).resolve().parents[1]
    vendor_root = Path(cfg["vendor_repo_dir_resolved"])
    runs_root = Path(cfg["runs_dir_resolved"])

    runs_root.mkdir(parents=True, exist_ok=True)

    return {
        "project_root": project_root,
        "module_root": module_root,
        "vendor_root": vendor_root,
        "runs_root": runs_root,
    }


def build_status_payload() -> dict[str, Any]:
    cfg = get_module_runtime_config()
    paths = _module_paths()
    vendor_root = paths["vendor_root"]

    return {
        "enabled": cfg["enabled"],
        "module_name": cfg["module_name"],
        "vendor_repo_exists": vendor_root.exists(),
        "vendor_repo_dir": str(vendor_root),
        "runs_dir": str(paths["runs_root"]),
        "python_bin": cfg["python_bin"],
        "venv_activate": cfg["venv_activate"],
        "vendor_summary": _scan_vendor_repo(vendor_root),
    }


def list_vendor_assets() -> dict[str, Any]:
    paths = _module_paths()
    vendor_root = paths["vendor_root"]

    if not vendor_root.exists():
        raise FileNotFoundError(f"Vendor repository not found: {vendor_root}")

    notebooks = sorted(str(p.relative_to(vendor_root)) for p in vendor_root.rglob("*.ipynb"))
    python_files = sorted(str(p.relative_to(vendor_root)) for p in vendor_root.rglob("*.py"))

    known_data_dirs = []
    for rel in ["data", "detection", "results", "test_efficiency_realtime", "catboost_info"]:
        full = vendor_root / rel
        if full.exists():
            known_data_dirs.append(rel)

    return {
        "vendor_repo_dir": str(vendor_root),
        "notebooks": notebooks,
        "python_files": python_files,
        "known_dirs": known_data_dirs,
    }


def run_vendor_entrypoint(payload: dict[str, Any]) -> dict[str, Any]:
    paths = _module_paths()
    cfg = get_module_runtime_config()
    vendor_root = paths["vendor_root"]

    if not vendor_root.exists():
        raise FileNotFoundError(f"Vendor repository not found: {vendor_root}")

    mode = str(payload.get("mode", "notebook")).strip().lower()
    entrypoint = str(payload.get("entrypoint", "")).strip()
    arguments = str(payload.get("arguments", "")).strip()
    timeout = int(payload.get("timeout", 3600))
    custom_command = str(payload.get("custom_command", "")).strip()

    if mode not in {"notebook", "python_file", "custom_command"}:
        raise ValueError("mode must be notebook, python_file or custom_command")

    if mode != "custom_command" and not entrypoint:
        raise ValueError("entrypoint is required")

    if mode == "custom_command" and not custom_command:
        raise ValueError("custom_command is required")

    run_id = f"run_{_utc_compact()}_{uuid.uuid4().hex[:8]}"
    run_dir = paths["runs_root"] / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "run_id": run_id,
        "started_at_utc": _utc_now_iso(),
        "mode": mode,
        "entrypoint": entrypoint,
        "arguments": arguments,
        "timeout": timeout,
        "custom_command": custom_command,
        "vendor_repo_dir": str(vendor_root),
    }
    (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    cmd = _build_command(
        mode=mode,
        entrypoint=entrypoint,
        arguments=arguments,
        custom_command=custom_command,
        vendor_root=vendor_root,
        run_dir=run_dir,
        python_bin=str(cfg["python_bin"]),
    )

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["ADV_DETECTION_RUN_ID"] = run_id
    env["ADV_DETECTION_RUN_DIR"] = str(run_dir)
    env["ADV_DETECTION_VENDOR_DIR"] = str(vendor_root)

    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"

    started = datetime.now(timezone.utc)
    with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
        process = subprocess.run(
            cmd,
            cwd=str(vendor_root),
            env=env,
            stdout=stdout_file,
            stderr=stderr_file,
            timeout=timeout,
            shell=False,
            check=False,
        )

    finished = datetime.now(timezone.utc)

    copied_results = _collect_vendor_outputs(vendor_root=vendor_root, run_dir=run_dir)

    result = {
        "run_id": run_id,
        "started_at_utc": started.isoformat(),
        "finished_at_utc": finished.isoformat(),
        "duration_seconds": round((finished - started).total_seconds(), 3),
        "success": process.returncode == 0,
        "return_code": process.returncode,
        "command": cmd,
        "copied_outputs": copied_results,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "run_dir": str(run_dir),
    }
    (run_dir / "run_result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    return result


def _scan_vendor_repo(vendor_root: Path) -> dict[str, Any]:
    if not vendor_root.exists():
        return {
            "notebooks": 0,
            "python_files": 0,
            "top_level_dirs": [],
            "top_level_files": [],
        }

    notebooks = list(vendor_root.rglob("*.ipynb"))
    python_files = list(vendor_root.rglob("*.py"))

    top_level_dirs = sorted([p.name for p in vendor_root.iterdir() if p.is_dir()])
    top_level_files = sorted([p.name for p in vendor_root.iterdir() if p.is_file()])

    return {
        "notebooks": len(notebooks),
        "python_files": len(python_files),
        "top_level_dirs": top_level_dirs,
        "top_level_files": top_level_files,
    }


def _build_command(
    mode: str,
    entrypoint: str,
    arguments: str,
    custom_command: str,
    vendor_root: Path,
    run_dir: Path,
    python_bin: str,
) -> list[str]:
    if mode == "custom_command":
        return shlex.split(custom_command)

    entrypoint_path = (vendor_root / entrypoint).resolve()
    if not entrypoint_path.exists():
        raise FileNotFoundError(f"Entrypoint not found: {entrypoint_path}")

    extra_args = shlex.split(arguments) if arguments else []

    if mode == "python_file":
        return [python_bin, str(entrypoint_path), *extra_args]

    executed_notebook_path = run_dir / entrypoint_path.name

    return [
        "jupyter",
        "nbconvert",
        "--to",
        "notebook",
        "--execute",
        str(entrypoint_path),
        "--output",
        str(executed_notebook_path),
        "--ExecutePreprocessor.timeout=-1",
        *extra_args,
    ]


def _collect_vendor_outputs(vendor_root: Path, run_dir: Path) -> list[dict[str, Any]]:
    copied = []
    targets = ["results", "detection", "test_efficiency_realtime"]

    exports_dir = run_dir / "vendor_outputs"
    exports_dir.mkdir(parents=True, exist_ok=True)

    for target in targets:
        src = vendor_root / target
        if not src.exists():
            continue

        dst = exports_dir / target
        if src.is_dir():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            copied.append(
                {
                    "type": "directory",
                    "name": target,
                    "source": str(src),
                    "destination": str(dst),
                }
            )

    root_level_patterns = ["*.pkl", "*.csv", "*.json", "*.txt"]
    for pattern in root_level_patterns:
        for item in vendor_root.glob(pattern):
            if not item.is_file():
                continuea
            dst = exports_dir / item.name
            shutil.copy2(item, dst)
            copied.append(
                {
                    "type": "file",
                    "name": item.name,
                    "source": str(item),
                    "destination": str(dst),
                }
            )

    return copied