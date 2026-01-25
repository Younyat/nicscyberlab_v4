# -*- coding: utf-8 -*-

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_modbus_file(file_path: Path) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    analysis = {
        "file": file_path.name,
        "analysis_utc": utc_now_iso(),
        "lines": len(lines),
        "timeout_detected": any("timed out" in l.lower() for l in lines),
        "exception_detected": any("exception" in l.lower() for l in lines),
    }

    return analysis


def analyze_modbus_snapshot(industrial_dir: Path, metadata_dir: Path) -> Dict[str, Any]:
    modbus_files = sorted(industrial_dir.glob("modbus_*.txt"))

    results = {
        "modbus_snapshots": len(modbus_files),
        "files": [],
        "analysis_utc": utc_now_iso()
    }

    for f in modbus_files:
        results["files"].append(parse_modbus_file(f))

    out_file = metadata_dir / "industrial_analysis.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return {
        "status": "completed",
        "output": str(out_file),
        "modbus_files_analyzed": len(modbus_files)
    }
