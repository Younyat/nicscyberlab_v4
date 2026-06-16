from copy import deepcopy


def empty_source_reference() -> dict:
    return {
        "source_id": "",
        "source_type": "",
        "path": "",
        "kind": "",
        "status": "unknown",
        "mtime": None,
        "size": None,
        "sha256": None,
        "details": {},
    }


def empty_artifact_reference() -> dict:
    return {
        "artifact_id": "",
        "evidence_id": "not_available",
        "id_origin": "unknown",
        "artifact_type": "",
        "artifact_class": "auxiliary",
        "is_primary_evidence": False,
        "path": "",
        "case_id": "not_available",
        "related_instance_id": "unresolved",
        "related_node_id": "unresolved",
        "sha256": None,
        "size": None,
        "status": "unknown",
        "details": {},
    }


def empty_relationship_edge() -> dict:
    return {
        "edge_id": "",
        "from_type": "",
        "from_id": "",
        "relation": "",
        "to_type": "",
        "to_id": "",
        "status": "ok",
        "relationship_status": "confirmed",
        "correlation_status": "confirmed",
        "correlation_confidence": "high",
        "correlation_reason": "direct_mapping",
        "evidence": [],
        "details": {},
    }


def empty_timeline_event() -> dict:
    return {
        "timeline_event_id": "",
        "id_origin": "unknown",
        "timestamp": "",
        "event_type": "",
        "phase": "unknown",
        "status": "unknown",
        "source_type": "",
        "source_path": "",
        "related_node_id": "unresolved",
        "related_instance_id": "unresolved",
        "related_attack_id": "unresolved",
        "related_alert_id": "unresolved",
        "related_case_id": "unresolved",
        "related_artifact_id": "unresolved",
        "description": "",
        "details": {},
    }


def empty_scenario_bom() -> dict:
    return {
        "scenario_id": "unknown",
        "scenario_name": "unknown",
        "generated_at": "",
        "base_scenario_path": "scenario/scenario_file.json",
        "nodes": [],
        "edges": [],
        "it_nodes": [],
        "ot_nodes": [],
        "node_roles": [],
        "node_types": [],
        "deployment_properties": {},
        "ot_extensions": [],
        "industrial_linkages": [],
        "node_instance_bindings": [],
        "scenario_state": {},
        "source_files": [],
        "warnings": [],
    }


def empty_tools_bom() -> dict:
    return {
        "scenario_id": "unknown",
        "generated_at": "",
        "nodes": [],
        "active_nodes_count": 0,
        "orphan_tool_artifacts": [],
        "historical_tool_artifacts": [],
        "host_tool_artifacts": [],
        "host_tool_inventory": [],
        "source_files": [],
        "warnings": [],
    }


def empty_foc_manifest() -> dict:
    return {
        "foc_id": "",
        "scenario_id": "unknown",
        "scenario_name": "unknown",
        "created_at": "",
        "updated_at": "",
        "reconstructed_at": "",
        "lifecycle_state": "unknown",
        "read_only_reconstruction": True,
        "bootstrap_mode": False,
        "scenario_bom": {"path": "foc-reconstruction/scenario_bom.json", "sha256": ""},
        "tools_bom": {"path": "foc-reconstruction/tools_bom.json", "sha256": ""},
        "timeline": {"path": "foc-reconstruction/timeline.json", "sha256": ""},
        "id_mapping_path": "foc-reconstruction/indexes/id_mapping.json",
        "source_indexes": {
            "sources": "foc-reconstruction/indexes/sources_index.json",
            "artifacts": "foc-reconstruction/indexes/artifacts_index.json",
            "relationships": "foc-reconstruction/indexes/relationships_index.json",
            "cases": "foc-reconstruction/indexes/cases_index.json",
        },
        "derived_context": {
            "attack_attestation": "foc-reconstruction/attestations/attack_attestation.json",
            "detection_attestation": "foc-reconstruction/attestations/detection_attestation.json",
            "alerts_normalized": "foc-reconstruction/attestations/alerts_normalized.json",
            "alert_correlation": "foc-reconstruction/attestations/alert_correlation.json",
            "alert_correlation_summary": "foc-reconstruction/attestations/alert_correlation_summary.json",
            "acquisition_profile": "foc-reconstruction/attestations/acquisition_profile.json",
            "forensic_intervention": "foc-reconstruction/attestations/forensic_intervention.json",
            "forensic_analysis_manifest": "foc-reconstruction/attestations/forensic_analysis_manifest.json",
            "scenario_ground_truth": "foc-reconstruction/attestations/scenario_ground_truth.json",
            "case_manifest_link": "foc-reconstruction/attestations/case_manifest_link.json",
            "foc_context_summary": "foc-reconstruction/attestations/foc_context_summary.json",
            "foc_readiness_report": "foc-reconstruction/validation/foc_readiness_report.json",
        },
        "warnings": [],
        "generation_status": "ok",
    }


def clone(data: dict) -> dict:
    return deepcopy(data)
