from __future__ import annotations

from pathlib import Path

from .evidence_lifecycle_dashboard import (
    _json_load,
    _write_json,
    _mtime,
    _executive_dir,
    _source_bundle,
    _pick_attack,
    _resolve_real_ground_truth,
)
from .foc_case_analysis import _case_dir_from_entry, get_case_entry
from .foc_paths import relative_path
from .foc_sources import utc_now
from ..foc_causal_reconstruction.service import causal_graph_payload, causal_status_payload

# Lightweight, derived, read-only layer. It does not reanalyze PCAPs, memory
# dumps, disk images, or OT exports - it only normalizes what the causal
# reconstruction graph and the existing multilayer findings already computed,
# so it adds zero new heavy parsing and can never drift from the causal graph
# it is built from.

_SUPPORT_LEVELS = ["contradicted", "not_evaluable", "no_support", "weak_support", "moderate_support", "strong_support"]

# Maps a causal edge's required_evidence type to the Evidence Support Extract
# layer it belongs to. An edge can require more than one type; the first
# match wins.
_LAYER_BY_REQ_TYPE = {
    "attack_attestation": "attack",
    "network_modbus_observation": "network",
    "plc_state_observation": "ot",
    "detection_attestation": "alerts",
    "alert_correlation": "alerts",
    "memory_analysis_useful": "memory",
    "forensic_intervention": "custody",
    "case_manifest_link": "custody",
    "manifest": "custody",
    "chain_of_custody": "custody",
    "forensic_analysis_report": "analysis",
    "analysis_visual_summary": "analysis",
}

_SUPPORT_BY_EDGE_STATUS = {
    "recovered": "moderate_support",
    "degraded": "weak_support",
    "ambiguous": "weak_support",
    "missing": "no_support",
}

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
    "cross_layer": "Cross-layer findings",
}


def _extract_path(case_dir: Path) -> Path:
    return _executive_dir(case_dir) / "evidence_support_extract.json"


def _support_index(level: str) -> int:
    try:
        return _SUPPORT_LEVELS.index(level)
    except ValueError:
        return _SUPPORT_LEVELS.index("not_evaluable")


def _finding_layers(required_evidence: list[str]) -> list[str]:
    # An edge can require several evidence types spanning multiple layers
    # (e.g. a multilayer-analysis edge requiring both memory and custody
    # evidence) - keep every distinct mapped layer so none of them silently
    # drop out of layer_support, instead of only the first match.
    layers: list[str] = []
    for req in required_evidence or []:
        layer = _LAYER_BY_REQ_TYPE.get(req)
        if layer and layer not in layers:
            layers.append(layer)
    return layers or ["cross_layer"]


def _finding_from_edge(edge: dict) -> dict:
    support_status = str(edge.get("support_status") or "missing")
    layers = _finding_layers(edge.get("required_evidence") or [])
    return {
        "finding_id": edge.get("edge_id") or "unknown_edge",
        "layer": layers[0],
        "layers": layers,
        "finding_type": edge.get("relation_type") or "derived_relation",
        "summary": edge.get("meaning") or edge.get("status_reason") or "not_available",
        "supports_hypothesis": _SUPPORT_BY_EDGE_STATUS.get(support_status, "not_evaluable"),
        "related_hypothesis": "H1",
        "related_causal_edges": [edge.get("edge_id")] if edge.get("edge_id") else [],
        "evidence_refs": edge.get("evidence_refs") or [],
        "timestamp": "not_available",
        "source_node": edge.get("source") or "not_available",
        "target_node": edge.get("target") or "not_available",
        "confidence": edge.get("confidence") or "unknown",
        "limitations": edge.get("limitations") or [],
    }


def _findings_from_cross_layer(case_dir: Path) -> list[dict]:
    payload = _json_load(case_dir / "analysis" / "10_findings" / "cross_layer_findings.json") or {}
    items = payload.get("findings") or []
    findings = []
    for index, item in enumerate(items if isinstance(items, list) else []):
        confidence = str(item.get("confidence") or "unknown").lower()
        support = "moderate_support" if confidence == "high" else "weak_support" if confidence in {"medium", "low"} else "not_evaluable"
        findings.append(
            {
                "finding_id": f"cross_layer_{index}",
                "layer": "cross_layer",
                "layers": ["cross_layer"],
                "finding_type": "cross_layer_correlation",
                "summary": item.get("finding") or "not_available",
                "supports_hypothesis": support,
                "related_hypothesis": "H1",
                "related_causal_edges": [],
                "evidence_refs": item.get("evidence_refs") or [],
                "timestamp": "not_available",
                "source_node": "not_available",
                "target_node": "not_available",
                "confidence": confidence,
                "limitations": list(payload.get("limitations") or []),
            }
        )
    return findings


def _layer_support_from_findings(findings: list[dict]) -> dict:
    by_layer: dict[str, list[dict]] = {}
    for finding in findings:
        for layer in finding.get("layers") or [finding["layer"]]:
            by_layer.setdefault(layer, []).append(finding)
    layer_support: dict[str, dict] = {}
    for layer, items in by_layer.items():
        best = max(items, key=lambda item: _support_index(item["supports_hypothesis"]))
        limitations: list[str] = []
        for item in items:
            for limitation in item.get("limitations") or []:
                if limitation not in limitations:
                    limitations.append(limitation)
        layer_support[layer] = {
            "support_level": best["supports_hypothesis"],
            "summary": best["summary"],
            "finding_count": len(items),
            "limitations": limitations,
        }
    return layer_support


def _fallback_layer_support(count: int, label: str) -> dict:
    if not count:
        return {
            "support_level": "not_evaluable",
            "summary": f"No {label} were analyzed for this case.",
            "finding_count": 0,
            "limitations": [f"{label.capitalize()} were not analyzed for this case."],
        }
    return {
        "support_level": "weak_support",
        "summary": f"{count} {label} were analyzed and provide generic context.",
        "finding_count": 1,
        "limitations": [f"{label.capitalize()} evidence is generic context and does not by itself confirm the hypothesis."],
    }


def _timeline_layer_support(causal_status: dict) -> dict:
    temporal_state = str((causal_status.get("metrics_preview") or {}).get("temporal_confidence_state") or "unknown")
    mapping = {"strong": "moderate_support", "limited": "weak_support", "ambiguous": "weak_support", "unknown": "not_evaluable"}
    support_level = mapping.get(temporal_state, "not_evaluable")
    limitations = []
    warnings = causal_status.get("warnings") or []
    if warnings:
        limitations.extend(warnings)
    return {
        "support_level": support_level,
        "summary": f"Temporal confidence is {temporal_state} based on the preserved clock-offset evidence.",
        "finding_count": 1,
        "limitations": limitations or ["No additional temporal limitation recorded."],
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


def _aggregate_global_support(layer_support: dict) -> str:
    levels = [item.get("support_level") for item in layer_support.values() if item.get("support_level") not in (None, "not_evaluable")]
    if not levels:
        return "not_evaluable"
    if "contradicted" in levels:
        return "contradicted"
    strong_or_moderate = sum(1 for level in levels if level in {"moderate_support", "strong_support"})
    if strong_or_moderate >= 2 and all(level == "strong_support" for level in levels if level in {"moderate_support", "strong_support"}):
        return "strong_support"
    if strong_or_moderate >= 2:
        return "moderate_support"
    if any(level == "weak_support" for level in levels):
        return "weak_support"
    return "no_support"


def build_evidence_support_extract(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        raise FileNotFoundError(f"Case {case_id} was not found.")
    case_dir = _case_dir_from_entry(entry)
    bundle = _source_bundle()
    causal_status = causal_status_payload(case_id, case_dir)
    graph_payload = causal_graph_payload(case_id, case_dir) or {}
    ground_truth = _resolve_real_ground_truth(causal_status, bundle.get("scenario_ground_truth") or {})
    attack = _pick_attack(bundle, ground_truth)

    edges = graph_payload.get("edges") or []
    findings = [_finding_from_edge(edge) for edge in edges]
    findings.extend(_findings_from_cross_layer(case_dir))

    layer_support = _layer_support_from_findings(findings)

    disk_findings = _json_load(case_dir / "analysis" / "05_disk" / "disk_findings.json") or {}
    disk_images_analyzed = int((disk_findings.get("findings") or {}).get("disk_images_analyzed") or 0)
    layer_support.setdefault("disk", _fallback_layer_support(disk_images_analyzed, "disk images"))
    layer_support.setdefault("timeline", _timeline_layer_support(causal_status))
    for layer_key in _LAYER_LABELS:
        layer_support.setdefault(layer_key, {"support_level": "not_evaluable", "summary": "No relevant evidence was evaluated for this layer.", "finding_count": 0, "limitations": []})

    global_support_level = _aggregate_global_support(layer_support)
    hypotheses = _build_hypotheses(ground_truth, attack)
    main_supporting = [f"{_LAYER_LABELS.get(layer, layer)}: {item['summary']}" for layer, item in layer_support.items() if item.get("support_level") in {"moderate_support", "strong_support"}]
    main_limitations = sorted({limitation for item in layer_support.values() for limitation in (item.get("limitations") or [])})
    hypotheses[0]["global_support_level"] = global_support_level
    hypotheses[0]["main_supporting_evidence"] = main_supporting
    hypotheses[0]["main_limitations"] = main_limitations

    supporting = [f for f in findings if f["supports_hypothesis"] in {"moderate_support", "strong_support"}]
    degraded_or_ambiguous = [f for f in findings if f["supports_hypothesis"] == "weak_support"]
    missing_or_not_evaluable = [f for f in findings if f["supports_hypothesis"] in {"no_support", "not_evaluable"}]
    contradictions = [f for f in findings if f["supports_hypothesis"] == "contradicted"]

    summary_text = (
        f"The preserved evidence provides {global_support_level.replace('_', ' ')} for hypothesis H1 "
        f"({hypotheses[0]['attack_family']}, technique {hypotheses[0]['mitre_technique']}, target "
        f"{hypotheses[0]['target_asset']}). {len(supporting)} findings provide direct or corroborating support, "
        f"{len(degraded_or_ambiguous)} remain weak or indirect, and {len(missing_or_not_evaluable)} are missing or "
        "not evaluable. This assessment is derived entirely from already-generated multilayer analysis and causal "
        "reconstruction outputs; it does not reanalyze primary evidence."
    )

    return {
        "case_id": case_id,
        "scenario_id": causal_status.get("scenario_id") or graph_payload.get("scenario_id") or "unknown",
        "generated_at": utc_now(),
        "is_stale": False,
        "hypotheses": hypotheses,
        "layer_support": layer_support,
        "findings": findings,
        "supporting_evidence": supporting,
        "degraded_or_ambiguous_evidence": degraded_or_ambiguous,
        "missing_or_not_evaluable_evidence": missing_or_not_evaluable,
        "contradictions": contradictions,
        "final_support_assessment": {
            "global_support_level": global_support_level,
            "summary_text": summary_text,
        },
    }


def generate_evidence_support_extract(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    payload = build_evidence_support_extract(case_id)
    _write_json(_extract_path(case_dir), payload)
    payload["extract_path"] = relative_path(_extract_path(case_dir))
    return payload


def load_evidence_support_extract(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    path = _extract_path(case_dir)
    payload = _json_load(path)
    if not isinstance(payload, dict):
        return {"case_id": case_id, "available": False, "extract_path": relative_path(path), "extract": None}
    causal_status = causal_status_payload(case_id, case_dir)
    extract_mtime = _mtime(path)
    causal_mtime = _mtime(case_dir / "derived" / "reconstruction" / "causal_graph.json")
    payload["is_stale"] = bool(extract_mtime and causal_mtime and causal_mtime > extract_mtime)
    return {"case_id": case_id, "available": True, "extract_path": relative_path(path), "extract": payload}


def evidence_support_extract_stub(case_id: str, case_dir: Path) -> dict:
    """Cheap, summary-only view for the executive payload - no findings detail."""
    path = _extract_path(case_dir)
    payload = _json_load(path)
    if not isinstance(payload, dict):
        return {"status": "not_available", "path": relative_path(path)}
    extract_mtime = _mtime(path)
    causal_mtime = _mtime(case_dir / "derived" / "reconstruction" / "causal_graph.json")
    is_stale = bool(extract_mtime and causal_mtime and causal_mtime > extract_mtime)
    assessment = payload.get("final_support_assessment") or {}
    return {
        "status": "stale" if is_stale else "available",
        "is_stale": is_stale,
        "path": relative_path(path),
        "global_support_level": assessment.get("global_support_level"),
        "hypothesis_count": len(payload.get("hypotheses") or []),
        "supporting_findings": len(payload.get("supporting_evidence") or []),
        "degraded_or_ambiguous_findings": len(payload.get("degraded_or_ambiguous_evidence") or []),
        "missing_or_not_evaluable_findings": len(payload.get("missing_or_not_evaluable_evidence") or []),
        "contradictions": len(payload.get("contradictions") or []),
        "main_limitation": (payload.get("hypotheses") or [{}])[0].get("main_limitations", ["not_available"])[0] if payload.get("hypotheses") else "not_available",
        "stale_reason": "This support extract is stale. The displayed support metrics may not reflect the latest causal reconstruction artifacts." if is_stale else None,
        "required_action": "regenerate evidence support extract" if is_stale else None,
    }
