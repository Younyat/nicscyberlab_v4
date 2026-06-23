from __future__ import annotations

# Shared, generic helpers reused by the evidence_support package. The
# original lightweight extract/orchestration logic that used to live in this
# module has been superseded by app_core/infrastructure/foc_reconstruction/
# evidence_support/ (atom-level triage, cross-layer correlation, hypothesis
# support / storyline / claimability / counter-evidence reports).

_LAYER_LABELS = {
    "attack": "Controlled attack execution",
    "network": "Network and PCAP evidence",
    "memory": "Memory evidence",
    "disk": "Disk evidence",
    "ot": "OT export evidence",
    "alerts": "Alerts and detection evidence",
    "timeline": "Timeline evidence",
    "custody": "Integrity and custody evidence",
    "analysis": "Multilayer analysis support",
    "causal_graph": "Causal graph",
    "cross_layer": "Cross-layer findings",
}


def _build_hypotheses(ground_truth: dict, attack: dict) -> list[dict]:
    expected = (ground_truth or {}).get("attack_expected") or {}
    protocol = str(expected.get("protocol") or "").lower()
    if protocol.startswith("modbus"):
        text = (
            "A controlled unauthorized Modbus manipulation was executed against the PLC and produced "
            "observable effects across network, OT, detection, acquisition, preservation, and forensic analysis layers."
        )
        attack_family = "ics_manipulation_of_control"
        target_asset = expected.get("target") or "not_available"
    else:
        text = (
            "A real attack execution occurred in the controlled scenario and produced observable forensic "
            "effects in the preserved evidence lifecycle."
        )
        attack_family = "generic_controlled_attack"
        target_asset = expected.get("target") or ((attack.get("target") or {}).get("instance_name")) or "not_available"
    return [
        {
            "hypothesis_id": "H1",
            "hypothesis_text": text,
            "attack_family": attack_family,
            "mitre_technique": expected.get("technique_id") or "not_available",
            "target_asset": target_asset,
            "expected_layers": list((ground_truth or {}).get("expected_analysis_layers") or []) or list(_LAYER_LABELS.keys()),
            "global_support_level": None,
            "main_supporting_evidence": [],
            "main_limitations": [],
        }
    ]
