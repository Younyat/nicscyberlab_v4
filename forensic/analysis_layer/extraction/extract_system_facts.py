#!/usr/bin/env python3
import json
import pathlib

def extract_system_facts(case_path: pathlib.Path) -> dict:
    """
    Extracts objective system-level facts from system snapshots.
    """
    system_dir = case_path / "system"
    facts = {
        "process_count": 0,
        "open_ports": False,
        "iptables_accessible": False
    }

    if not system_dir.exists():
        return facts

    for snapshot in system_dir.glob("*.json"):
        with open(snapshot, "r") as f:
            data = json.load(f)

        facts["process_count"] += len(data.get("commands", {}).get("ps", {}).get("stdout", "").splitlines())
        facts["open_ports"] = "ESTAB" in data.get("commands", {}).get("ss", {}).get("stdout", "")
        facts["iptables_accessible"] = data.get("commands", {}).get("iptables", {}).get("rc", 1) == 0

    return facts
