from __future__ import annotations

from typing import Any, Dict, List, Optional


ATTACK_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "recon_icmp",
        "display_name": "ICMP Reconnaissance",
        "category": "Reconnaissance",
        "attack_stage": "Discovery",
        "mitre_attack": ["T1046"],
        "mitre_ics": [],
        "script_name": "ping_target.sh",
        "expected_alerts": ["IDS/SURICATA"],
        "expected_artifacts": ["icmp telemetry", "suricata alert", "wazuh event"],
        "risk_level": "low",
        "is_realistic": True,
        "is_simulated_event": False,
    },
    {
        "id": "recon_portscan",
        "display_name": "Port Scan Reconnaissance",
        "category": "Reconnaissance",
        "attack_stage": "Discovery",
        "mitre_attack": ["T1046"],
        "mitre_ics": [],
        "script_name": "port_scan_recon.sh",
        "expected_alerts": ["IDS/SURICATA"],
        "expected_artifacts": ["nmap output", "network telemetry", "suricata alert"],
        "risk_level": "medium",
        "is_realistic": True,
        "is_simulated_event": False,
    },
    {
        "id": "credential_unauthorized_ssh",
        "display_name": "Unauthorized SSH Attempt",
        "category": "Credential Access",
        "attack_stage": "Initial Access",
        "mitre_attack": ["T1110", "T1078"],
        "mitre_ics": [],
        "script_name": "unauthorized_ssh_attempt.sh",
        "expected_alerts": ["AUTH/ATAQUE"],
        "expected_artifacts": ["failed ssh auth logs", "wazuh auth alerts"],
        "risk_level": "medium",
        "is_realistic": True,
        "is_simulated_event": False,
    },
    {
        "id": "collection_data_exfiltration",
        "display_name": "Data Exfiltration over SCP",
        "category": "Collection/Exfiltration",
        "attack_stage": "Actions on Objectives",
        "mitre_attack": ["T1005", "T1048"],
        "mitre_ics": [],
        "script_name": "data_exfiltration.sh",
        "expected_alerts": ["AUTH/ATAQUE", "IDS/SURICATA"],
        "expected_artifacts": ["scp transfer logs", "copied passwd file", "network traces"],
        "risk_level": "high",
        "is_realistic": True,
        "is_simulated_event": False,
    },
    {
        "id": "impact_file_tamper",
        "display_name": "Controlled File Tamper",
        "category": "Impact",
        "attack_stage": "Impact",
        "mitre_attack": ["T1565.001"],
        "mitre_ics": [],
        "script_name": "file_tamper_sim.sh",
        "expected_alerts": ["FIM/INTEGRIDAD"],
        "expected_artifacts": ["file hashes", "modified lab files", "fim alerts"],
        "risk_level": "medium",
        "is_realistic": True,
        "is_simulated_event": False,
    },
    {
        "id": "ics_modbus_register_write",
        "display_name": "Modbus Register Manipulation",
        "category": "ICS Manipulation",
        "attack_stage": "Impact",
        "mitre_attack": [],
        "mitre_ics": ["T0831"],
        "script_name": "modbus_register_attack.sh",
        "expected_alerts": ["IDS/SURICATA"],
        "expected_artifacts": ["modbus write telemetry", "pcap", "ot alert"],
        "risk_level": "high",
        "is_realistic": True,
        "is_simulated_event": False,
    },
    {
        "id": "validation_multi_vector",
        "display_name": "Multi-Vector Detection Validation",
        "category": "Detection Validation",
        "attack_stage": "Exercise",
        "mitre_attack": ["T1110", "T1565.001", "T1046"],
        "mitre_ics": [],
        "script_name": "multi_Attack_sim.sh",
        "expected_alerts": ["FIM/INTEGRIDAD", "AUTH/ATAQUE", "IDS/SURICATA"],
        "expected_artifacts": ["fim events", "auth failures", "network alerts"],
        "risk_level": "medium",
        "is_realistic": False,
        "is_simulated_event": True,
    },
]


def get_attack_catalog() -> List[Dict[str, Any]]:
    return [dict(item) for item in ATTACK_CATALOG]


def find_attack_by_id(attack_id: str) -> Optional[Dict[str, Any]]:
    attack_id = (attack_id or "").strip()
    if not attack_id:
        return None
    for item in ATTACK_CATALOG:
        if item["id"] == attack_id:
            return dict(item)
    return None


def resolve_script_name(script_name: str = "", attack_id: str = "") -> Optional[str]:
    if script_name:
        return script_name
    attack = find_attack_by_id(attack_id)
    if attack:
        return attack["script_name"]
    return None
