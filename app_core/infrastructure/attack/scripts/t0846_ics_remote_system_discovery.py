#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from app_core.infrastructure.attack.industrial_ops import (
    artifact_ref,
    attacker_context_from_argv,
    build_causal_edges,
    build_uncertainty_report,
    clone_runtime_artifacts,
    emit_json_banner,
    output_dir_from_argv,
    tcp_probe,
    utc_now,
    write_json,
)
from app_core.infrastructure.attack.industrial_resolver import derive_scenario_id, resolve_industrial_context


ATTACK_ID = "T0846_ICS_REMOTE_SYSTEM_DISCOVERY"
MITRE_ID = "T0846.001"


def main(argv: list[str]) -> int:
    output_dir = output_dir_from_argv(argv)
    attacker = attacker_context_from_argv(argv)
    context = resolve_industrial_context()
    clone_runtime_artifacts(output_dir)
    scenario_id = derive_scenario_id()
    plc = context["runtime_assets"]["plc"]
    scada = context["runtime_assets"]["scada"]

    print("===========================================")
    print("ATT&CK PROFILE: T0846.001 - Remote System Discovery")
    print(f"PLC TARGET: {plc.get('ip') or 'unknown'}")
    print("MODE: BOUNDED ICS SERVICE VALIDATION")
    print("===========================================")

    services = []
    for label, ip, ports in (
        ("plc", plc.get("ip"), [502]),
        ("scada", scada.get("ip"), [1881, 1880, 80, 443]),
    ):
        if not ip:
            continue
        for port in ports:
            reachable = tcp_probe(ip, port, source_ip=attacker["source_ip"], source_user=attacker["source_user"])
            services.append(
                {
                    "asset": label,
                    "ip": ip,
                    "port": port,
                    "reachable": reachable,
                }
            )

    discovery = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "run_id": Path(output_dir).name,
        "generated_at_utc": utc_now(),
        "source_ip": attacker["source_ip"],
        "target_role": "industrial_plc",
        "plc_ip": plc.get("ip"),
        "scada_ip": scada.get("ip"),
        "services": services,
    }
    observed = {
        "attack_id": ATTACK_ID,
        "mitre_id": MITRE_ID,
        "scenario_id": scenario_id,
        "generated_at_utc": utc_now(),
        "observed_services": services,
    }
    causal = build_causal_edges(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        source_ip=attacker["source_ip"],
        target_ip=plc.get("ip") or "unknown",
        target_role="industrial_plc",
    )
    uncertainty = build_uncertainty_report(
        attack_id=ATTACK_ID,
        mitre_id=MITRE_ID,
        scenario_id=scenario_id,
        notes=[
            {
                "canonical_name": "plc_ip_resolution",
                "status": "confirmed" if plc.get("ip") else "unresolved",
                "reason": "runtime_inventory",
            },
            {
                "canonical_name": "modbus_service_check",
                "status": "confirmed" if any(item["asset"] == "plc" and item["port"] == 502 and item["reachable"] for item in services) else "unresolved",
                "reason": "bounded_tcp_probe",
            },
        ],
    )

    files = {
        "discovery_scan.json": discovery,
        "observed_services.json": observed,
        "causal_edges.json": causal,
        "uncertainty_report.json": uncertainty,
    }
    for name, payload in files.items():
        write_json(output_dir / name, payload)

    summary = {
        "attack_id": ATTACK_ID,
        "plc_ip_resolved": bool(plc.get("ip")),
        "modbus_service_observed": any(item["asset"] == "plc" and item["port"] == 502 and item["reachable"] for item in services),
        "artifacts": [artifact_ref(output_dir / name, output_dir) for name in files],
    }
    emit_json_banner(summary)
    return 0 if summary["plc_ip_resolved"] and summary["modbus_service_observed"] else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
