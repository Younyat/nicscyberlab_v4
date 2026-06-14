#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from app_core.infrastructure.attack.industrial_ops import (
    attacker_context_from_argv,
    clone_runtime_artifacts,
    emit_json_banner,
    mbpoll_read,
    output_dir_from_argv,
    utc_now,
    write_json,
)
from app_core.infrastructure.attack.industrial_resolver import (
    ASSET_REGISTER_MAP_PATH,
    MODBUS_VALIDATION_PATH,
    generate_ics_attack_policy,
    resolve_industrial_context,
)


def main(argv: list[str]) -> int:
    output_dir = output_dir_from_argv(argv)
    attacker = attacker_context_from_argv(argv)
    context = resolve_industrial_context()
    clone_runtime_artifacts(output_dir)
    register_map = context["register_map"]
    plc = register_map.get("plc", {})
    scada_map = context.get("scada_map", {})
    devices = scada_map.get("modbus_devices", []) or []
    slave_id = int(devices[0].get("slaveid") or 1) if devices else 1

    print("===========================================")
    print("VALIDATION PROFILE: Tank Modbus Map")
    print(f"TARGET: {plc.get('ip') or 'unknown'}:{plc.get('port') or 502}")
    print("MODE: LIVE MODBUS READ VALIDATION")
    print("===========================================")

    validated_registers = []
    conflicts = []
    notes = []

    configured_endpoint = register_map.get("validation", {}).get("configured_endpoint")
    for visual_ep in register_map.get("validation", {}).get("visual_endpoints", []) or []:
        if configured_endpoint and visual_ep != configured_endpoint:
            conflicts.append(
                {
                    "type": "fuxa_svg_endpoint_conflict",
                    "configured_endpoint": configured_endpoint,
                    "svg_text_endpoint": visual_ep,
                    "decision": "ignore_svg_text",
                }
            )

    interesting = {"level", "level_max", "airValveOpenStatus", "openOutletValve", "outletValveOpenStatus", "openInletValve", "inletValveOpenStatus"}
    for register in register_map.get("registers", []):
        canonical_name = register.get("canonical_name")
        if canonical_name not in interesting:
            continue
        candidates = []
        for key in ("fuxa_address_candidate", "modbus_address_candidate"):
            candidate = register.get(key)
            if candidate is None:
                continue
            try:
                candidates.append(int(candidate))
            except Exception:
                continue
        seen = set()
        read_result = None
        winning_address = None
        for address in candidates:
            if address in seen:
                continue
            seen.add(address)
            read_result = mbpoll_read(
                plc.get("ip") or "",
                slave_id,
                register.get("modbus_table", "holding_register"),
                address,
                source_ip=attacker["source_ip"],
                source_user=attacker["source_user"],
            )
            if read_result.get("ok"):
                winning_address = address
                break

        status = "ok" if winning_address is not None else "failed"
        if status != "ok":
            notes.append(
                {
                    "canonical_name": canonical_name,
                    "status": "unresolved",
                    "reason": "live_validation_failed",
                    "candidates": candidates,
                }
            )
        validated_registers.append(
            {
                "canonical_name": canonical_name,
                "plc_iec_address": register.get("plc_iec_address"),
                "fuxa_address": register.get("fuxa_address"),
                "validated_modbus_address": winning_address,
                "read_status": status,
                "value": read_result.get("value") if read_result else None,
                "confidence": "observed" if status == "ok" else "low",
                "modbus_table": register.get("modbus_table"),
                "stdout": (read_result or {}).get("stdout"),
                "stderr": (read_result or {}).get("stderr"),
            }
        )

    validation_status = "validated" if any(item.get("canonical_name") == "level_max" and item.get("read_status") == "ok" for item in validated_registers) else "degraded"
    payload = {
        "target_ip": plc.get("ip"),
        "target_port": plc.get("port", 502),
        "validated_at_utc": utc_now(),
        "status": validation_status,
        "validated_registers": validated_registers,
        "conflicts": conflicts,
        "notes": notes,
    }
    write_json(MODBUS_VALIDATION_PATH, payload)
    write_json(output_dir / "industrial_modbus_validation.json", payload)
    policy = generate_ics_attack_policy(validation=payload, register_map=register_map)
    write_json(output_dir / "ics_attack_policy.json", policy)
    emit_json_banner(payload)
    return 0 if validation_status == "validated" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
