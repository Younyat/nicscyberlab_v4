from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config_service import get_module_runtime_config


def _runs_root() -> Path:
    cfg = get_module_runtime_config()
    path = Path(cfg["runs_dir_resolved"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def list_recent_runs(limit: int = 20) -> dict[str, Any]:
    runs_root = _runs_root()
    limit = max(1, min(limit, 200))

    runs = []
    for item in sorted(runs_root.iterdir(), key=lambda p: p.name, reverse=True):
        if not item.is_dir():
            continue

        meta_path = item / "run_meta.json"
        result_path = item / "run_result.json"

        meta = {}
        result = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                meta = {}

        if result_path.exists():
            try:
                result = json.loads(result_path.read_text(encoding="utf-8"))
            except Exception:
                result = {}

        runs.append(
            {
                "run_id": item.name,
                "path": str(item),
                "started_at_utc": meta.get("started_at_utc", ""),
                "finished_at_utc": result.get("finished_at_utc", ""),
                "mode": meta.get("mode", ""),
                "entrypoint": meta.get("entrypoint", ""),
                "return_code": result.get("return_code"),
                "success": result.get("success"),
            }
        )

        if len(runs) >= limit:
            break

    return {
        "runs": runs,
        "count": len(runs),
    }


def get_run_detail(run_id: str) -> dict[str, Any]:
    if not run_id.strip():
        raise ValueError("run_id is required")

    run_dir = _runs_root() / run_id
    if not run_dir.exists() or not run_dir.is_dir():
        raise FileNotFoundError(f"Run not found: {run_id}")

    files = []
    for item in sorted(run_dir.rglob("*")):
        if item.is_file():
            files.append(
                {
                    "name": item.name,
                    "relative_path": str(item.relative_to(run_dir)),
                    "size": item.stat().st_size,
                }
            )

    def read_json_if_exists(filename: str) -> dict[str, Any]:
        path = run_dir / filename
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def read_text_if_exists(filename: str, limit: int = 200_000) -> str:
        path = run_dir / filename
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")[:limit]
        except Exception:
            return ""

    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "meta": read_json_if_exists("run_meta.json"),
        "result": read_json_if_exists("run_result.json"),
        "stdout": read_text_if_exists("stdout.txt"),
        "stderr": read_text_if_exists("stderr.txt"),
        "files": files,
    }