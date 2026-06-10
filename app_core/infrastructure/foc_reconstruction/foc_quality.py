from pathlib import Path

from .foc_config import GENERATED_FILES
from .foc_manifest_manager import read_generated_json
from .foc_paths import relative_path
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
    return all(b.get("status") == "bound" and b.get("instance_id") not in {"unresolved", "unknown"} for b in bindings)


def _relationships_summary(relationships: dict) -> dict:
    edges = relationships.get("edges", []) if isinstance(relationships, dict) else []
    attack_alert = 0
    alert_evidence = 0
    case_artifact = 0
    evidence_analysis = 0
    for edge in edges:
        relation = edge.get("relation")
        if relation == "produced_alert" and edge.get("to_id") not in {"unresolved", "unknown"}:
            attack_alert += 1
        elif edge.get("from_type") == "alert" and relation in {"linked_evidence", "supports_evidence"}:
            alert_evidence += 1
        elif relation == "contains_artifact" and edge.get("from_type") == "case":
            case_artifact += 1
        elif relation == "supports_analysis":
            evidence_analysis += 1
    return {
        "attack_alert_links": attack_alert,
        "alert_evidence_links": alert_evidence,
        "case_artifact_links": case_artifact,
        "evidence_analysis_links": evidence_analysis,
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
    scenario_points = 15 if _exists("scenario_bom") else 0
    tools_points = 15 if _exists("tools_bom") else 0
    timeline_points = 10 if _exists("timeline") else 0
    sources_points = 10 if _exists("sources_index") else 0
    hashes_points = 10 if _count_hashes() > 0 else 0
    bindings_points = 10 if _bindings_complete(scenario_bom) else 0
    attack_alert_points = 10 if rel_summary["attack_alert_links"] > 0 else 0
    alert_evidence_points = 10 if rel_summary["alert_evidence_links"] > 0 else 0
    case_custody_present = False
    if isinstance(artifacts, dict):
        case_custody_present = any(a.get("artifact_type") == "custody_log" for a in artifacts.get("artifacts", []))
    custody_points = 10 if case_custody_present else 0

    score = (
        scenario_points
        + tools_points
        + timeline_points
        + sources_points
        + hashes_points
        + bindings_points
        + attack_alert_points
        + alert_evidence_points
        + custody_points
    )

    if score >= 90:
        completeness = "complete"
    elif score >= 50:
        completeness = "partial"
    else:
        completeness = "insufficient"

    gaps_payload = build_gaps()
    critical_gaps = int(gaps_payload.get("critical_gaps", 0)) if isinstance(gaps_payload, dict) else 0

    return {
        "initialized": True,
        "mode": "bootstrap" if manifest.get("bootstrap_mode") else "native",
        "scenario_id": manifest.get("scenario_id", "unknown"),
        "last_update": manifest.get("updated_at") or "unknown",
        "reproducibility_score": score,
        "completeness": completeness,
        "critical_gaps": critical_gaps,
        "status": "valid" if score >= 90 else ("incomplete" if score >= 50 else "insufficient"),
        "scenario_name": manifest.get("scenario_name", "unknown"),
        "components": {
            "scenario_bom": scenario_points,
            "tools_bom": tools_points,
            "timeline": timeline_points,
            "sources_index": sources_points,
            "hashes": hashes_points,
            "node_instance_bindings": bindings_points,
            "attack_alert_links": attack_alert_points,
            "alert_evidence_links": alert_evidence_points,
            "case_manifest_and_custody": custody_points,
        },
        "relationship_summary": rel_summary,
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
    if rel_summary["attack_alert_links"] == 0:
        add_gap(
            "missing_attack_alert_relation",
            "high",
            "unresolved",
            "Attack executions exist but no normalized attack-to-alert links were confirmed.",
            "attack outputs and alerts_store",
            "Correlate attack outputs with alert signatures or timestamps.",
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
        if not any(a.get("artifact_type") == "custody_log" for a in artifact_items):
            add_gap(
                "missing_chain_of_custody",
                "critical",
                "missing",
                "No chain-of-custody artifact was indexed.",
                "CASE-*/chain_of_custody.log",
                "Acquire or preserve a forensic case with custody enabled.",
            )
        if not any(a.get("artifact_type") in {"vol3_output_dir", "tsk_output_dir"} for a in artifact_items):
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
