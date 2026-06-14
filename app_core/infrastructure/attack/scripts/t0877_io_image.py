#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from pathlib import Path

from app_core.infrastructure.attack.industrial_ops import (
    artifact_ref,
    attacker_context_from_argv,
    build_causal_edges,
    build_uncertainty_report,
    clone_runtime_artifacts,
    collect_state,
    emit_json_banner,
    ensure_validated_context,
    output_dir_from_argv,
    utc_now,
    write_json,
)
from app_core.infrastructure.attack.industrial_resolver import derive_scenario_id


ATTACK_ID = "T0877_IO_IMAGE"
MITRE_ID = "T0877"
VARIABLES = [
    "level",
    "level_max",
    "openOutletValve",
    "outletValveOpenStatus",
    "openInletValve",
    "inletValveOpenStatus",
    "airValveOpenStatus",
]


def main(argv: list[str]) -> int:
    target_ip = argv[1] if len(argv) > 1 else ""
    output_dir = output_dir_from_argv(argv)
    attacker = attacker_context_from_argv(argv)
    context = ensure_validated_context(output_dir, require_validation=False)
    clone_runtime_artifacts(output_dir)
    scenario_id = derive_scenario_id()
    target_ip = target_ip or context["register_map"]["plc"].get("ip") or "unknown"

    print("===========================================")
    print("ATT&CK PROFILE: T0877 - I/O Image")
    print(f"TARGET: {target_ip}")
    print("MODE: READ-ONLY PLC STATE SNAPSHOT")
    print("===========================================")

    before = collect_state(context, VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    time.sleep(1)
    after = collect_state(context, VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    snapshot = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "target_ip": target_ip,
        "target_role": "industrial_plc",
        "source_ip": attacker["source_ip"],
        "generated_at_utc": utc_now(),
        "variables": {
            name: {
                "before": before["variables"].get(name, {}),
                "after": after["variables"].get(name, {}),
            }
            for name in VARIABLES
        },
    }
    uncertainty = build_uncertainty_report(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        notes=[
            {
                "canonical_name": name,
                "status": "confirmed" if before["variables"].get(name, {}).get("status") == "ok" else "unresolved",
                "reason": before["variables"].get(name, {}).get("reason", "mapping_or_read"),
            }
            for name in VARIABLES
        ],
    )
    causal = build_causal_edges(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        source_ip=attacker["source_ip"],
        target_ip=target_ip,
        target_role="industrial_plc",
    )

    files = {
        "io_image_before.json": before,
        "io_image_after.json": after,
        "process_state_snapshot.json": snapshot,
        "causal_edges.json": causal,
        "uncertainty_report.json": uncertainty,
    }
    for name, payload in files.items():
        write_json(output_dir / name, payload)

    summary = {
        "attack_id": ATTACK_ID,
        "target_ip": target_ip,
        "available_variables": sum(1 for item in before["variables"].values() if item.get("status") == "ok"),
        "artifacts": [artifact_ref(output_dir / name, output_dir) for name in files],
    }
    emit_json_banner(summary)
    return 0 if summary["available_variables"] > 0 else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
