#!/usr/bin/env python3
import pathlib

def extract_industrial_state(case_path: pathlib.Path) -> dict:
    """
    Extracts raw industrial snapshots (Modbus register dumps).
    """
    industrial_dir = case_path / "industrial"
    state = {
        "snapshots": [],
        "timeouts": False
    }

    if not industrial_dir.exists():
        return state

    for f in industrial_dir.glob("*.txt"):
        with open(f, "r") as fd:
            content = fd.read()

        state["snapshots"].append({
            "file": f.name,
            "lines": content.splitlines()
        })

        if "timeout" in content.lower() or "exception" in content.lower():
            state["timeouts"] = True

    return state
