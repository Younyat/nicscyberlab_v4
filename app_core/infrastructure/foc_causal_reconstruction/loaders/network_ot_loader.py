from __future__ import annotations

import json
from pathlib import Path


def _load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_network_ot_context(case_path: Path) -> dict:
    network = _load_json(case_path / "analysis" / "03_network" / "network_findings.json") or {}
    ot = _load_json(case_path / "analysis" / "06_ot" / "ot_findings.json") or {}
    network_files = (network.get("findings") or {}).get("files") or []
    ot_file_entries = (ot.get("findings") or {}).get("files") or []
    total_modbus_frames = sum(int(item.get("modbus_frames") or 0) for item in network_files if isinstance(item, dict))
    total_ot_records = sum(int(item.get("records") or 0) for item in ot_file_entries if isinstance(item, dict))
    return {
        "network_findings_path": case_path / "analysis" / "03_network" / "network_findings.json",
        "network_findings_present": bool(network),
        "total_modbus_frames": total_modbus_frames,
        "ot_findings_path": case_path / "analysis" / "06_ot" / "ot_findings.json",
        "ot_findings_present": bool(ot),
        "total_ot_records": total_ot_records,
    }
