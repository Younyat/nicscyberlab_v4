# -*- coding: utf-8 -*-

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def analyze_snapshot(snapshot_file: Path) -> Dict[str, Any]:
    with open(snapshot_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    commands = data.get("commands", {})

    analysis = {
        "snapshot_file": snapshot_file.name,
        "analysis_utc": utc_now_iso(),
        "process_count": len(commands.get("ps", {}).get("stdout", "").splitlines()),
        "open_ports_detected": "ESTAB" in commands.get("ss", {}).get("stdout", ""),
        "iptables_access": commands.get("iptables", {}).get("rc", -1) == 0,
    }

    return analysis


def analyze_system_snapshot(system_dir: Path, metadata_dir: Path) -> Dict[str, Any]:
    snapshots = sorted(system_dir.glob("snapshot_*.json"))

    results = {
        "snapshot_count": len(snapshots),
        "snapshots": [],
        "analysis_utc": utc_now_iso()
    }

    for snap in snapshots:
        results["snapshots"].append(analyze_snapshot(snap))

    out_file = metadata_dir / "system_analysis.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return {
        "status": "completed",
        "output": str(out_file),
        "snapshots_analyzed": len(snapshots)
    }
