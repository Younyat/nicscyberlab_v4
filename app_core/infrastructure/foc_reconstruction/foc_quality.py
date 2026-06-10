from pathlib import Path

from .foc_config import GENERATED_FILES
from .foc_manifest_manager import read_generated_json
from .foc_sources import utc_now


def _exists(key: str) -> bool:
    return GENERATED_FILES[key].is_file()


def _count_hashes() -> int:
    payload = read_generated_json(GENERATED_FILES["hashes_index"]) or {}
    hashes = payload.get("hashes", {}) if isinstance(payload, dict) else {}
    return len([v for v in hashes.values() if v])


def _bindings_complete(scenario_bom: dict) -> bool:
    bindings = scenario_bom.get("node_instance_bindings", []) if isinstance(scenario_bom, dict) else []
    if not bindings:
        return False
    return all(
        b.get("status") == "bound" and b.get("instance_id") not in {"unresolved", "unknown"}
        for b in bindings
    )


def _timeline_detection_summary(timeline: dict) -> dict:
    events = timeline.get("events", []) if isinstance(timeline, dict) else []
    alerts = [event for event in events if event.get("event_type") == "detection_alert"]
    triage = [event for event in events if event.get("event_type") == "triage_result"]
    attacks = [event for event in events if event.get("event_type") == "attack_execution"]
    resolved = 0
    correlation_counts = {
        "confirmed": 0,
        "inferred_high": 0,
        "inferred_medium": 0,
        "inferred_low": 0,
        "unresolved": 0,
    }
    for event in alerts:
        node_ok = event.get("related_node_id") not in {"", "unresolved", "unknown", None}
        if node_ok:
            resolved += 1
        details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
        corr = details.get("correlation_status", "unresolved")
        if corr not in correlation_counts:
            corr = "unresolved"
        correlation_counts[corr] += 1
    total = len(alerts)
    ratio = (resolved / total) if total else 0.0
    confirmed = correlation_counts["confirmed"]
    if total == 0:
        relationship_quality = "not_generated_yet"
    elif confirmed == total and ratio >= 0.9:
        relationship_quality = "available"
    else:
        relationship_quality = "partial"
    return {
        "attack_events": len(attacks),
        "alerts_total": total,
        "triage_total": len(triage),
        "resolved_alerts": resolved,
        "resolved_ratio": ratio,
        "resolved_ratio_text": f"{resolved}/{total}" if total else "0/0",
        "data_availability": "available" if total else "not_generated_yet",
        "relationship_quality": relationship_quality,
        "confirmed_ratio_text": f"{confirmed}/{total}" if total else "0/0",
        "correlation_counts": correlation_counts,
    }


def _artifact_summary(artifacts: dict) -> dict:
    items = artifacts.get("artifacts", []) if isinstance(artifacts, dict) else []
    summary = {
        "total": len(items),
        "acquisition_metadata": 0,
        "preserved_evidence": 0,
        "forensic_inputs": 0,
        "analysis_outputs": 0,
        "primary_evidence": 0,
        "custody_logs": 0,
    }
    for item in items:
        art_class = item.get("artifact_class", "auxiliary")
        if art_class in summary:
            summary[art_class] += 1
        if item.get("is_primary_evidence"):
            summary["primary_evidence"] += 1
        if item.get("artifact_type") == "custody_log":
            summary["custody_logs"] += 1
    return summary


def _relationships_summary(relationships: dict) -> dict:
    edges = relationships.get("edges", []) if isinstance(relationships, dict) else []
    summary = {
        "attack_alert_links": 0,
        "attack_alert_candidate_links": 0,
        "attack_alert_confirmed_links": 0,
        "attack_alert_inferred_links": 0,
        "attack_alert_unresolved_links": 0,
        "alert_evidence_links": 0,
        "alert_case_links": 0,
        "case_artifact_links": 0,
        "evidence_custody_links": 0,
        "evidence_analysis_links": 0,
    }
    for edge in edges:
        relation = edge.get("relation")
        from_type = edge.get("from_type")
        to_type = edge.get("to_type")
        correlation_status = edge.get("correlation_status") or edge.get("relationship_status") or "unresolved"
        if relation == "produced_alert":
            summary["attack_alert_candidate_links"] += 1
            if edge.get("to_id") not in {"", "unresolved", "unknown", None}:
                summary["attack_alert_links"] += 1
            if correlation_status == "confirmed":
                summary["attack_alert_confirmed_links"] += 1
            elif correlation_status in {"inferred_high", "inferred_medium", "inferred_low", "inferred"}:
                summary["attack_alert_inferred_links"] += 1
            else:
                summary["attack_alert_unresolved_links"] += 1
        elif from_type == "alert" and relation in {"linked_evidence", "supports_evidence"}:
            summary["alert_evidence_links"] += 1
        elif from_type == "alert" and to_type == "case":
            summary["alert_case_links"] += 1
        elif relation == "contains_artifact" and from_type == "case":
            summary["case_artifact_links"] += 1
        elif relation == "preserved_in" and from_type == "evidence":
            summary["evidence_custody_links"] += 1
        elif relation == "supports_analysis":
            summary["evidence_analysis_links"] += 1
    return summary


def _maturity_statuses(
    scenario_points: int,
    tools_points: int,
    bindings_points: int,
    timeline_points: int,
    detection_summary: dict,
    rel_summary: dict,
    artifact_summary: dict,
) -> dict:
    structural = "complete" if scenario_points and tools_points and bindings_points else ("partial" if scenario_points or tools_points else "missing")
    if timeline_points and detection_summary["alerts_total"] > 0:
        operational = "mostly_available" if detection_summary["resolved_ratio"] >= 0.5 else "partial"
    elif timeline_points or detection_summary["alerts_total"] > 0:
        operational = "partial"
    else:
        operational = "not_generated_yet"

    if rel_summary["alert_evidence_links"] > 0 and artifact_summary["preserved_evidence"] > 0:
        evidential = "available"
    elif artifact_summary["preserved_evidence"] > 0 or rel_summary["alert_case_links"] > 0:
        evidential = "partial"
    else:
        evidential = "not_generated_yet"

    if artifact_summary["analysis_outputs"] > 0 and rel_summary["evidence_analysis_links"] > 0:
        forensic = "completed"
    else:
        forensic = "not_completed"

    semantic = "available" if forensic == "completed" and False else "not_generated"
    return {
        "structural": structural,
        "operational": operational,
        "evidential": evidential,
        "forensic": forensic,
        "semantic": semantic,
    }


def build_status() -> dict:
    manifest = read_generated_json(GENERATED_FILES["manifest"])
    scenario_bom = read_generated_json(GENERATED_FILES["scenario_bom"]) or {}
    tools_bom = read_generated_json(GENERATED_FILES["tools_bom"]) or {}
    timeline = read_generated_json(GENERATED_FILES["timeline"]) or {}
    sources = read_generated_json(GENERATED_FILES["sources_index"]) or {}
    relationships = read_generated_json(GENERATED_FILES["relationships_index"]) or {}
    artifacts = read_generated_json(GENERATED_FILES["artifacts_index"]) or {}

    if not isinstance(manifest, dict):
        scenario_exists = Path("scenario/scenario_file.json").exists()
        return {
            "initialized": False,
            "mode": "bootstrap" if scenario_exists else "not_available",
            "scenario_id": "unknown",
            "last_update": "not_available",
            "reproducibility_score": 0,
            "completeness": "insufficient",
            "critical_gaps": 1 if scenario_exists else 0,
            "status": "bootstrap_required" if scenario_exists else "not_initialized",
        }

    rel_summary = _relationships_summary(relationships)
    detection_summary = _timeline_detection_summary(timeline)
    artifact_summary = _artifact_summary(artifacts)

    scenario_points = 15 if _exists("scenario_bom") else 0
    tools_points = 15 if _exists("tools_bom") else 0
    timeline_points = 10 if _exists("timeline") else 0
    sources_points = 10 if _exists("sources_index") else 0
    hashes_points = 10 if _count_hashes() > 0 else 0
    bindings_points = 10 if _bindings_complete(scenario_bom) else 0

    confirmed_ratio = 0.0
    if detection_summary["alerts_total"] > 0:
        confirmed_ratio = rel_summary["attack_alert_confirmed_links"] / detection_summary["alerts_total"]
    attack_alert_points = min(10, round(10 * confirmed_ratio, 2))
    alert_evidence_points = 10 if rel_summary["alert_evidence_links"] > 0 else 0
    evidence_custody_points = 0
    if artifact_summary["custody_logs"] > 0:
        evidence_custody_points = 4
    if artifact_summary["custody_logs"] > 0 and rel_summary["alert_evidence_links"] > 0:
        evidence_custody_points = 10
    analysis_points = 10 if artifact_summary["analysis_outputs"] > 0 and rel_summary["evidence_analysis_links"] > 0 else 0

    score = (
        scenario_points
        + tools_points
        + timeline_points
        + sources_points
        + hashes_points
        + bindings_points
        + attack_alert_points
        + alert_evidence_points
        + evidence_custody_points
        + analysis_points
    )

    maturity = _maturity_statuses(
        scenario_points,
        tools_points,
        bindings_points,
        timeline_points,
        detection_summary,
        rel_summary,
        artifact_summary,
    )

    if maturity["forensic"] == "completed" and maturity["evidential"] == "available" and score >= 90:
        completeness = "complete"
        status = "valid"
    elif maturity["structural"] == "complete" and score >= 50:
        completeness = "partial"
        status = "incomplete"
    else:
        completeness = "insufficient"
        status = "insufficient"

    gaps_payload = build_gaps()
    critical_gaps = int(gaps_payload.get("critical_gaps", 0)) if isinstance(gaps_payload, dict) else 0

    return {
        "initialized": True,
        "mode": "bootstrap" if manifest.get("bootstrap_mode") else "native",
        "scenario_id": manifest.get("scenario_id", "unknown"),
        "last_update": manifest.get("updated_at") or "unknown",
        "reproducibility_score": round(score, 2),
        "completeness": completeness,
        "critical_gaps": critical_gaps,
        "status": status,
        "scenario_name": manifest.get("scenario_name", "unknown"),
        "maturity": maturity,
        "components": {
            "scenario_bom": scenario_points,
            "tools_bom": tools_points,
            "timeline": timeline_points,
            "sources_index": sources_points,
            "hashes": hashes_points,
            "node_instance_bindings": bindings_points,
            "attack_alert_links": attack_alert_points,
            "alert_evidence_links": alert_evidence_points,
            "evidence_custody_chain": evidence_custody_points,
            "analysis_outputs": analysis_points,
        },
        "relationship_summary": rel_summary,
        "detection_summary": detection_summary,
        "artifact_summary": artifact_summary,
        "artifact_counts": {
            "timeline_events": len((timeline or {}).get("events", [])),
            "sources": len((sources or {}).get("sources", [])),
            "artifacts": len((artifacts or {}).get("artifacts", [])) if isinstance(artifacts, dict) else 0,
        },
    }


def build_gaps() -> dict:
    scenario_bom = read_generated_json(GENERATED_FILES["scenario_bom"]) or {}
    tools_bom = read_generated_json(GENERATED_FILES["tools_bom"]) or {}
    timeline = read_generated_json(GENERATED_FILES["timeline"]) or {}
    sources = read_generated_json(GENERATED_FILES["sources_index"]) or {}
    relationships = read_generated_json(GENERATED_FILES["relationships_index"]) or {}
    artifacts = read_generated_json(GENERATED_FILES["artifacts_index"]) or {}

    gaps: list[dict] = []

    def add_gap(gap_type: str, severity: str, status: str, description: str, expected: str, action: str):
        gaps.append(
            {
                "gap_id": f"gap-{len(gaps)+1:03d}",
                "type": gap_type,
                "severity": severity,
                "status": status,
                "description": description,
                "source_expected": expected,
                "recommended_action": action,
            }
        )

    if not scenario_bom.get("scenario_id") or scenario_bom.get("scenario_id") == "unknown":
        add_gap("missing_scenario_id", "critical", "missing", "Scenario ID is not available.", "scenario/scenario_file.json", "Regenerate FOC after validating the base scenario file.")

    for binding in scenario_bom.get("node_instance_bindings", []):
        if binding.get("status") != "bound":
            add_gap(
                "missing_node_instance_binding",
                "high",
                "unresolved",
                f"Node {binding.get('node_name', 'unknown')} is not bound to a normalized instance.",
                "tools-installer-tmp/*.json or tools-installer/installed/*.json",
                "Deploy or register node tools to expose an instance binding.",
            )

    for node in tools_bom.get("nodes", []):
        if node.get("pending_tools"):
            add_gap(
                "pending_tool_installation",
                "medium",
                "inferred",
                f"Node {node.get('instance_name', 'unknown')} still has pending tools.",
                "tools-installer/installed/*.json",
                "Complete the tool installation or regenerate after the installer finishes.",
            )
        if node.get("failed_tools"):
            add_gap(
                "failed_tool_installation",
                "medium",
                "confirmed",
                f"Node {node.get('instance_name', 'unknown')} has failed tool installs.",
                "tools-installer/logs/*.log",
                "Review installation logs and retry the failed tools.",
            )

    rel_summary = _relationships_summary(relationships)
    detection_summary = _timeline_detection_summary(timeline)
    artifact_summary = _artifact_summary(artifacts)

    if rel_summary["attack_alert_confirmed_links"] == 0 and detection_summary["alerts_total"] > 0:
        add_gap(
            "missing_confirmed_attack_alert_relation",
            "high",
            "unresolved",
            "Detections exist but no confirmed attack-to-alert links were established.",
            "attack outputs and alerts_store",
            "Correlate attack outputs with alert signatures, node bindings, and time windows.",
        )
    elif detection_summary["alerts_total"] > 0 and detection_summary["resolved_ratio"] < 0.9:
        add_gap(
            "partial_detection_correlation",
            "medium",
            "partial",
            f"Detection data exists, but only {detection_summary['resolved_ratio_text']} alerts were resolved to nodes.",
            "alerts_store and scenario bindings",
            "Improve node or instance correlation for alert records.",
        )

    if rel_summary["alert_evidence_links"] == 0:
        add_gap(
            "missing_alert_to_evidence_link",
            "high",
            "unresolved",
            "Alerts exist but no alert-to-evidence link was confirmed.",
            "alerts_store and evidence_store",
            "Create or link a forensic case for the relevant alerts.",
        )

    if rel_summary["alert_evidence_links"] == 0 and rel_summary["case_artifact_links"] > 0:
        add_gap(
            "case_exists_but_not_linked_to_alerts",
            "high",
            "unresolved",
            "Forensic cases and artifacts exist, but no explicit alert-to-case or alert-to-evidence relation was established.",
            "CASE-* manifests, pipeline events, and alert identifiers",
            "Link the relevant alert identifiers to case creation, acquisition, and preserved evidence.",
        )

    if artifact_summary["preserved_evidence"] == 0 and (artifact_summary["acquisition_metadata"] > 0 or artifact_summary["forensic_inputs"] > 0):
        add_gap(
            "metadata_without_primary_evidence",
            "medium",
            "partial",
            "Acquisition metadata or forensic inputs exist, but no primary preserved evidence was indexed.",
            "CASE-*/network, CASE-*/disk, CASE-*/memory, CASE-*/industrial",
            "Verify that evidence preservation produced primary artifacts such as PCAP, memory, disk, or industrial captures.",
        )

    if isinstance(artifacts, dict):
        artifact_items = artifacts.get("artifacts", [])
        if artifact_items and not any(a.get("sha256") for a in artifact_items):
            add_gap(
                "missing_evidence_hash",
                "high",
                "unresolved",
                "Artifacts were indexed without usable hashes.",
                "foc-reconstruction/hashes and case manifests",
                "Regenerate FOC after confirming hashable source artifacts.",
            )
        if artifact_summary["custody_logs"] == 0:
            add_gap(
                "missing_chain_of_custody",
                "critical",
                "missing",
                "No chain-of-custody artifact was indexed.",
                "CASE-*/chain_of_custody.log",
                "Acquire or preserve a forensic case with custody enabled.",
            )
        if artifact_summary["analysis_outputs"] == 0:
            add_gap(
                "missing_forensic_analysis_result",
                "medium",
                "missing",
                "No forensic analysis output directory was indexed.",
                "CASE-*/analysis/",
                "Run memory or disk analysis and regenerate FOC.",
            )

    if not any(s.get("status") == "present" for s in (sources or {}).get("sources", [])):
        add_gap(
            "missing_sources",
            "critical",
            "missing",
            "No primary sources were indexed.",
            "scenario, tools, attack, alerts, and forensics sources",
            "Verify source paths and rerun bootstrap or regenerate.",
        )

    if not any(event.get("event_type") == "attack_execution" for event in (timeline or {}).get("events", [])):
        add_gap(
            "missing_attack_result",
            "low",
            "missing",
            "No attack executions are present in the timeline.",
            "app_core/infrastructure/attack/outputs/*/result.json",
            "Execute or preserve attack output records before regeneration.",
        )

    critical_count = len([gap for gap in gaps if gap.get("severity") == "critical"])
    return {
        "generated_at": utc_now(),
        "critical_gaps": critical_count,
        "gaps": gaps,
    }
