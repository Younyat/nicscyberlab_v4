#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from app_core.infrastructure.attack.industrial_ops import (
    artifact_ref,
    attacker_context_from_argv,
    build_uncertainty_report,
    clone_runtime_artifacts,
    collect_state,
    emit_json_banner,
    ensure_validated_context,
    load_params,
    output_dir_from_argv,
    utc_now,
    write_json,
)
from app_core.infrastructure.attack.industrial_resolver import derive_scenario_id


ATTACK_ID = "T0802_AUTOMATED_COLLECTION"
MITRE_ID = "T0802"
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
    params = load_params(argv)
    output_dir = output_dir_from_argv(argv)
    attacker = attacker_context_from_argv(argv)
    context = ensure_validated_context(output_dir, require_validation=False)
    clone_runtime_artifacts(output_dir)
    scenario_id = derive_scenario_id()
    duration_seconds = int(params.get("duration_seconds", 10))
    sampling_interval = int(params.get("sampling_interval_seconds", 1))
    target_ip = context["register_map"]["plc"].get("ip") or argv[1] or "unknown"

    print("===========================================")
    print("ATT&CK PROFILE: T0802 - Automated Collection")
    print(f"TARGET: {target_ip}")
    print(f"WINDOW: {duration_seconds}s every {sampling_interval}s")
    print("MODE: READ-ONLY STATE COLLECTION")
    print("===========================================")

    session_path = output_dir / "collection_session.jsonl"
    samples = []
    started = time.time()
    while time.time() - started < max(duration_seconds, 1):
        state = collect_state(context, VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
        state["attack_id"] = ATTACK_ID
        state["mitre_id"] = MITRE_ID
        state["scenario_id"] = scenario_id
        samples.append(state)
        with session_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(state, sort_keys=True) + "\n")
        time.sleep(max(sampling_interval, 1))

    summary = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "target_ip": target_ip,
        "target_role": "industrial_plc",
        "source_ip": attacker["source_ip"],
        "generated_at_utc": utc_now(),
        "duration_seconds": duration_seconds,
        "sampling_interval_seconds": sampling_interval,
        "samples": len(samples),
        "available_reads": sum(
            1 for sample in samples for item in sample.get("variables", {}).values() if item.get("status") == "ok"
        ),
    }
    uncertainty = build_uncertainty_report(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        notes=[
            {
                "canonical_name": name,
                "status": "confirmed" if any(sample.get("variables", {}).get(name, {}).get("status") == "ok" for sample in samples) else "unresolved",
                "reason": "collection_window_observation",
            }
            for name in VARIABLES
        ],
    )
    write_json(output_dir / "collection_summary.json", summary)
    write_json(output_dir / "uncertainty_report.json", uncertainty)

    emit_json_banner(
        {
            "attack_id": ATTACK_ID,
            "samples": len(samples),
            "artifacts": [
                artifact_ref(session_path, output_dir),
                artifact_ref(output_dir / "collection_summary.json", output_dir),
                artifact_ref(output_dir / "uncertainty_report.json", output_dir),
            ],
        }
    )
    return 0 if samples else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
