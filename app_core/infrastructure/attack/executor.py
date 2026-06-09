from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from app_core.infrastructure.attack.catalog import find_attack_by_id


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def slugify_attack_id(attack_id: str) -> str:
    return (
        str(attack_id or "attack")
        .replace(".", "_")
        .replace("/", "_")
        .replace(" ", "_")
    )


def get_output_dir(attack_id: str, case_dir: str = "") -> str:
    root = case_dir or OUTPUTS_DIR
    ensure_dir(root)
    return ensure_dir(os.path.join(root, f"{utc_timestamp()}_{slugify_attack_id(attack_id)}"))


def severity_requires_dfir(severity: str) -> bool:
    return str(severity or "").upper() in {"HIGH", "CRITICAL"}


def build_execution_result(
    attack: Dict[str, Any],
    payload: Dict[str, Any],
    attacker_ip: str,
    target_user: str,
    target_image: str,
    output_dir: str,
) -> Dict[str, Any]:
    return {
        "attack_id": attack["attack_id"],
        "display_name": attack["display_name"],
        "mitre_id": attack["mitre_id"],
        "mitre_technique": attack["mitre_technique"],
        "mitre_domain": attack["mitre_domain"],
        "tactic": attack["tactic"],
        "detection_engine": attack["detection_engine"],
        "severity": attack["severity"],
        "execution_mode": attack["execution_mode"],
        "target_ip": payload.get("target_ip") or payload.get("target"),
        "target_role": payload.get("target_role", ""),
        "target_user": target_user,
        "target_image": target_image,
        "attacker_ip": attacker_ip,
        "case_dir": payload.get("case_dir", ""),
        "parameters": payload.get("parameters", {}) or {},
        "expected_alerts": attack.get("expected_alerts", []),
        "expected_artifacts": attack.get("expected_artifacts", []),
        "rollback_required": bool(attack.get("rollback_required")),
        "dfir_escalation": bool(attack.get("dfir_escalation") or severity_requires_dfir(attack.get("severity"))),
        "safety_policy": attack.get("safety_policy", ""),
        "output_dir": output_dir,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "stdout": [],
        "stderr": [],
        "timeline_event": {
            "event_type": "attack_execution",
            "severity": attack.get("severity", "LOW"),
            "dfir_relevant": bool(attack.get("dfir_escalation") or severity_requires_dfir(attack.get("severity"))),
        },
        "chain_of_custody": [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "attack_execution_started",
                "operator": "dashboard_tactical_hud",
                "artifact": "result.json",
            }
        ],
    }


def persist_execution_result(output_dir: str, result: Dict[str, Any]) -> None:
    ensure_dir(output_dir)
    with open(os.path.join(output_dir, "result.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)


def stream_attack_execution(
    manager: Any,
    attack: Dict[str, Any],
    local_script: str,
    attacker_ip: str,
    attacker_user: str,
    target_user: str,
    target_image: str,
    payload: Dict[str, Any],
) -> Iterable[str]:
    output_dir = get_output_dir(attack["attack_id"], payload.get("case_dir", ""))
    result = build_execution_result(
        attack=attack,
        payload=payload,
        attacker_ip=attacker_ip,
        target_user=target_user,
        target_image=target_image,
        output_dir=output_dir,
    )
    persist_execution_result(output_dir, result)

    args: List[str] = [
        payload.get("target_ip") or payload.get("target") or "",
        target_user,
        json.dumps(payload.get("parameters", {}) or {}, separators=(",", ":")),
        output_dir,
    ]

    exit_code: Optional[int] = None
    raw_lines: List[str] = []

    yield f"data: [ATTACK PROFILE] {attack['attack_id']} | {attack['mitre_id']} | {attack['mitre_technique']}\n\n"
    yield f"data: [DETECTION ENGINE] {attack['detection_engine']}\n\n"
    yield f"data: [EXECUTION MODE] {attack['execution_mode']}\n\n"
    yield f"data: [OUTPUT DIR] {output_dir}\n\n"

    for event in manager.execute_remote_stream(attacker_ip, attacker_user, local_script, args):
        if event.startswith("data:"):
            clean = event.replace("data:", "", 1).strip()
            raw_lines.append(clean)
            if clean.startswith("[EXIT CODE]"):
                try:
                    exit_code = int(clean.replace("[EXIT CODE]", "", 1).strip())
                except ValueError:
                    exit_code = 1
            elif clean.startswith("[SSH ERROR]") or clean.startswith("[FAIL]"):
                result["stderr"].append(clean)
            elif clean:
                result["stdout"].append(clean)
        yield event

    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    result["exit_code"] = exit_code if exit_code is not None else 1
    result["success"] = result["exit_code"] == 0 and not result["stderr"]
    result["raw_event_stream"] = raw_lines
    result["forensic_case_event"] = result["dfir_escalation"]
    result["chain_of_custody"].append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "attack_execution_completed",
            "operator": "dashboard_tactical_hud",
            "artifact": "result.json",
        }
    )
    persist_execution_result(output_dir, result)


def resolve_requested_attack(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    attack_id = payload.get("attack_id", "")
    return find_attack_by_id(attack_id)
