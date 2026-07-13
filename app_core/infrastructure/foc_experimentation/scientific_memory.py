from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

from .config import (
    ANALYSIS_REGISTRY_PATH,
    BLUEPRINTS_DIR,
    CASE_REGISTRY_PATH,
    EXECUTION_REGISTRY_PATH,
    LEGACY_COMPARISON_REGISTRY_PATH,
    RESULT_REGISTRY_PATH,
    RETENTION_REGISTRY_PATH,
    SCENARIO_REGISTRY_PATH,
)
from ..foc_reconstruction.foc_paths import relative_path
from ..foc_reconstruction.foc_sources import utc_now


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Use PID-unique tmp name to avoid cross-worker collisions in multi-process servers
    tmp = path.with_name(f"{path.stem}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _hash_payload(*parts) -> str:
    digest = hashlib.sha256()
    normalized = "|".join(json.dumps(part, sort_keys=True, ensure_ascii=False, default=str) for part in parts)
    digest.update(normalized.encode("utf-8"))
    return digest.hexdigest()


def _short_hash(*parts) -> str:
    return _hash_payload(*parts)[:24]


def ensure_scientific_memory_layout() -> None:
    for path in [
        SCENARIO_REGISTRY_PATH.parent,
        CASE_REGISTRY_PATH.parent,
        EXECUTION_REGISTRY_PATH.parent,
        RESULT_REGISTRY_PATH.parent,
        ANALYSIS_REGISTRY_PATH.parent,
        RETENTION_REGISTRY_PATH.parent,
        BLUEPRINTS_DIR,
        LEGACY_COMPARISON_REGISTRY_PATH.parent,
    ]:
        path.mkdir(parents=True, exist_ok=True)


def load_registry(path: Path) -> dict:
    ensure_scientific_memory_layout()
    payload = _json_load(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        return {"generated_at": utc_now(), "entries": []}
    return payload


def upsert_registry_entry(path: Path, key_field: str, payload: dict) -> dict:
    registry = load_registry(path)
    entries = [item for item in registry.get("entries", []) if item.get(key_field) != payload.get(key_field)]
    entries.append(payload)
    registry = {"generated_at": utc_now(), "entries": entries}
    _write_json(path, registry)
    return registry


def append_retention_manifest(manifest: dict) -> dict:
    return upsert_registry_entry(RETENTION_REGISTRY_PATH, "retention_manifest_id", manifest)


def _expected_edge_ids(ground_truth_payload: dict | None) -> list[str]:
    out: list[str] = []
    for item in list((ground_truth_payload or {}).get("expected_edges") or []):
        if isinstance(item, dict):
            out.append(str(item.get("edge_id") or item.get("id") or "unknown_edge"))
        else:
            out.append(str(item))
    return sorted(out)


def _node_roles(case_bundle: dict | None, scenario_profile: dict | None, attack_profile: dict | None) -> list[str]:
    summary = (case_bundle or {}).get("summary") or {}
    execution = summary.get("execution_summary") or {}
    roles = execution.get("node_roles") or execution.get("roles") or []
    if roles:
        return sorted({str(item) for item in roles if item})
    inferred = [
        "monitor" if (summary.get("trigger_summary") or {}).get("trigger_type") else None,
        "plc" if (attack_profile or {}).get("protocol") == "modbus_tcp" else None,
        "target" if (scenario_profile or {}).get("scenario_id") else None,
    ]
    return sorted({item for item in inferred if item})


def compute_topology_fingerprint(case_bundle: dict | None, scenario_profile: dict | None, attack_profile: dict | None) -> str:
    summary = (case_bundle or {}).get("summary") or {}
    trigger = summary.get("trigger_summary") or {}
    evidence = summary.get("evidence_lifecycle") or {}
    roles = _node_roles(case_bundle, scenario_profile, attack_profile)
    signature = {
        "scenario_id": (scenario_profile or {}).get("scenario_id") or "not_available",
        "node_roles": roles,
        "target_nodes": trigger.get("target_nodes") or [],
        "preserved_targets": evidence.get("preserved_targets") or [],
        "topology_signature": (scenario_profile or {}).get("topology_signature") or {},
    }
    return _short_hash(signature)


def compute_scenario_fingerprint(
    scenario_profile: dict | None,
    attack_profile: dict | None,
    case_bundle: dict | None,
    ground_truth_payload: dict | None,
) -> str:
    summary = (case_bundle or {}).get("summary") or {}
    signature = {
        "scenario_id": (scenario_profile or {}).get("scenario_id") or "not_available",
        "scenario_name": (scenario_profile or {}).get("scenario_name") or "not_available",
        "topology_fingerprint": compute_topology_fingerprint(case_bundle, scenario_profile, attack_profile),
        "expected_edge_ids": _expected_edge_ids(ground_truth_payload),
        "trigger_family": ((summary.get("trigger_summary") or {}).get("trigger_type")) or "not_available",
        "scenario_signature": (scenario_profile or {}).get("scenario_signature") or {},
    }
    return _short_hash(signature)


def compute_attack_parameters_hash(attack_profile: dict | None) -> str:
    payload = {
        "protocol": (attack_profile or {}).get("protocol"),
        "ot_function": (attack_profile or {}).get("ot_function"),
        "register": (attack_profile or {}).get("register"),
        "expected_value": (attack_profile or {}).get("expected_value"),
        "tool_used": (attack_profile or {}).get("tool_used"),
        "tool_version": (attack_profile or {}).get("tool_version"),
    }
    return _short_hash(payload)


def compute_comparison_family_id(
    *,
    scenario_fingerprint: str,
    topology_fingerprint: str,
    attack_profile_id: str,
    attack_script_sha256: str,
    attack_parameters_hash: str,
    expected_causal_edges: list[str],
    trigger_policy_id: str,
    acquisition_profile_id: str,
    analysis_profile_id: str,
    foc_profile_id: str,
) -> str:
    digest = _short_hash(
        scenario_fingerprint,
        topology_fingerprint,
        attack_profile_id,
        attack_script_sha256,
        attack_parameters_hash,
        expected_causal_edges,
        trigger_policy_id,
        acquisition_profile_id,
        analysis_profile_id,
        foc_profile_id,
    )
    return f"family-{digest[:16]}"


def build_scenario_reconstruction_blueprint(
    *,
    scenario_profile: dict,
    attack_profile: dict,
    ground_truth_payload: dict,
    case_bundle: dict | None,
    campaign_config: dict | None,
) -> dict:
    summary = (case_bundle or {}).get("summary") or {}
    multilayer = summary.get("multilayer_analysis_summary") or {}
    return {
        "scenario_id": scenario_profile.get("scenario_id") or "not_available",
        "scenario_name": scenario_profile.get("scenario_name") or "not_available",
        "topology_definition": {
            "topology_fingerprint": compute_topology_fingerprint(case_bundle, scenario_profile, attack_profile),
            "node_roles": _node_roles(case_bundle, scenario_profile, attack_profile),
        },
        "it_nodes": [],
        "ot_nodes": [],
        "node_roles": _node_roles(case_bundle, scenario_profile, attack_profile),
        "network_definitions": [],
        "plc_configuration_reference": attack_profile.get("protocol") if attack_profile.get("protocol") != "not_available" else None,
        "scada_hmi_configuration_reference": None,
        "tool_installation_profile": {"analysis_profile_id": (campaign_config or {}).get("analysis_profile_id") or "default_multilayer_analysis_v1"},
        "ids_configuration_profile": {"detection_policy_id": (campaign_config or {}).get("detection_policy_id") or "wazuh_suricata_alert_ingestion_v1"},
        "siem_configuration_profile": {"trigger_policy_id": (campaign_config or {}).get("trigger_policy_id") or "highest_severity_alert_v1"},
        "attack_compatibility_profile": {
            "attack_profile_id": attack_profile.get("attack_id") or "not_available",
            "mitre_technique_id": attack_profile.get("technique_id") or "not_available",
            "attack_script_reference": attack_profile.get("attack_script_reference") or "not_available",
        },
        "acquisition_compatibility_profile": {
            "acquisition_profile_id": (campaign_config or {}).get("acquisition_profile_id") or "default_kolla_lime_tshark_v1",
            "expected_artifacts": ((summary.get("trigger_summary") or {}).get("expected_artifacts")) or [],
        },
        "expected_causal_model": {"expected_edges": _expected_edge_ids(ground_truth_payload)},
        "expected_alerts": ((summary.get("trigger_summary") or {}).get("expected_alerts")) or [],
        "expected_artifacts": multilayer.get("artifacts_indexed") or "not_available",
        "deployment_dependencies": [],
        "validation_checks": [
            "scenario metadata available",
            "expected causal model available",
            "attack profile available",
        ],
        "generated_at": utc_now(),
    }


def build_scenario_result_card(
    *,
    scenario_profile: dict,
    attack_profile: dict,
    ground_truth_payload: dict,
    case_bundle: dict | None,
    campaign_id: str | None,
    execution_id: str | None,
    level: str | None,
    campaign_config: dict | None,
    blueprint_path: Path,
) -> dict:
    summary = (case_bundle or {}).get("summary") or {}
    scenario_fingerprint = compute_scenario_fingerprint(scenario_profile, attack_profile, case_bundle, ground_truth_payload)
    topology_fingerprint = compute_topology_fingerprint(case_bundle, scenario_profile, attack_profile)
    card = {
        "scenario_card_id": f"scn-card-{uuid.uuid4().hex[:10]}",
        "scenario_id": scenario_profile.get("scenario_id") or "not_available",
        "scenario_name": scenario_profile.get("scenario_name") or "not_available",
        "scenario_fingerprint": scenario_fingerprint,
        "created_at": scenario_profile.get("created_at") or utc_now(),
        "topology_fingerprint": topology_fingerprint,
        "node_roles": _node_roles(case_bundle, scenario_profile, attack_profile),
        "node_images": [],
        "node_flavors": [],
        "network_configuration_hash": _short_hash(topology_fingerprint, scenario_profile.get("scenario_id")),
        "security_groups_hash": "not_available",
        "PLC_configuration_hash": _short_hash(attack_profile.get("protocol"), attack_profile.get("register")),
        "SCADA_HMI_configuration_hash": "not_available",
        "installed_tools_summary": {"analysis_profile_id": (campaign_config or {}).get("analysis_profile_id") or "default_multilayer_analysis_v1"},
        "IDS_configuration_hash": _short_hash((campaign_config or {}).get("detection_policy_id") or "wazuh_suricata_alert_ingestion_v1"),
        "SIEM_configuration_hash": _short_hash((campaign_config or {}).get("trigger_policy_id") or "highest_severity_alert_v1"),
        "monitor_configuration_hash": "not_available",
        "supported_attack_profiles": [attack_profile.get("attack_id") or "not_available"],
        "associated_campaigns": [campaign_id] if campaign_id else [],
        "associated_cases": [case_bundle.get("case_id")] if case_bundle else [],
        "associated_result_cards": [],
        "reconstruction_blueprint_path": relative_path(blueprint_path),
        "scenario_retention_policy": "lightweight_blueprint_retained",
        "active_scenario_exists": str(level or "").upper() in {"B", "C"},
        "destroyed_at": None,
        "can_be_redeployed": True,
        "generated_at": utc_now(),
        "summary_source_case_id": case_bundle.get("case_id") if case_bundle else None,
        "expected_alerts": ((summary.get("trigger_summary") or {}).get("expected_alerts")) or [],
        "expected_causal_edges": _expected_edge_ids(ground_truth_payload),
    }
    return card


def build_case_result_card(
    *,
    case_bundle: dict,
    scenario_fingerprint: str,
    execution_id: str,
    campaign_id: str,
    comparison_profile_path: Path,
    result_card_path: Path,
    retention_policy: str,
    heavy_artifacts_retained: bool,
) -> dict:
    summary = case_bundle.get("summary") or {}
    paths = case_bundle.get("paths") or {}
    trigger = summary.get("trigger_summary") or {}
    lifecycle = summary.get("evidence_lifecycle") or {}
    preservation = {
        "manifest_available": bool(paths.get("manifest") and paths["manifest"].exists()),
        "chain_of_custody_available": bool(paths.get("custody") and paths["custody"].exists()),
        "analysis_report_available": bool(paths.get("analysis_report") and paths["analysis_report"].exists()),
    }
    return {
        "case_card_id": f"case-card-{uuid.uuid4().hex[:10]}",
        "case_id": case_bundle.get("case_id"),
        "case_path": case_bundle.get("case_rel_path"),
        "scenario_id": (summary.get("scenario_id") or "not_available"),
        "scenario_fingerprint": scenario_fingerprint,
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "created_at": case_bundle.get("entry", {}).get("created_at") or utc_now(),
        "attack_profile_id": ((case_bundle.get("attack_record") or {}).get("attack_id")) or "not_available",
        "mitre_technique_id": (((case_bundle.get("attack_record") or {}).get("mitre") or {}).get("technique_id")) or "not_available",
        "trigger_policy": trigger.get("trigger_selection_method") or "not_available",
        "acquisition_profile": "default_kolla_lime_tshark_v1",
        "evidence_layers_available": list((summary.get("multilayer_analysis_summary") or {}).keys()),
        "artifact_counts_by_type": (summary.get("integrity_summary") or {}).get("artifact_counts_by_type") or {},
        "preservation_summary": preservation,
        "chain_of_custody_summary": {
            "available": preservation["chain_of_custody_available"],
            "path": relative_path(paths.get("custody")) if paths.get("custody") else None,
        },
        "manifest_hash": (summary.get("integrity_summary") or {}).get("manifest_hash") or "not_available",
        "case_digest_hash": (summary.get("integrity_summary") or {}).get("case_digest_hash") or "not_available",
        "analysis_status": (summary.get("multilayer_analysis_summary") or {}).get("execution_status") or "not_available",
        "FOC_status": (summary.get("causal_summary") or {}).get("status") or "not_available",
        "comparison_profile_path": relative_path(comparison_profile_path),
        "forensic_result_card_path": relative_path(result_card_path),
        "heavy_artifacts_retained": heavy_artifacts_retained,
        "retention_policy": retention_policy,
    }


def build_analysis_result_card(
    *,
    execution_id: str,
    campaign_id: str,
    level: str,
    case_bundle: dict | None,
    comparison_profile: dict,
) -> dict:
    multilayer = comparison_profile.get("multilayer_analysis") or {}
    causal = comparison_profile.get("causal_reconstruction") or {}
    uncertainty = comparison_profile.get("uncertainty") or {}
    return {
        "analysis_card_id": f"analysis-card-{uuid.uuid4().hex[:10]}",
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "evaluation_level": level,
        "case_id": (case_bundle or {}).get("case_id"),
        "generated_at": utc_now(),
        "analysis_profile_id": "default_multilayer_analysis_v1",
        "layers_expected": multilayer.get("layers_expected"),
        "layers_with_useful_output": multilayer.get("layers_with_useful_output"),
        "forensic_reconstruction_status": multilayer.get("forensic_reconstruction_status"),
        "causal_status": causal.get("status"),
        "uncertainty_class": uncertainty.get("temporal_confidence"),
    }


def build_forensic_result_card(
    *,
    execution_id: str,
    campaign_id: str | None,
    level: str | None,
    case_bundle: dict | None,
    scenario_profile: dict,
    attack_profile: dict,
    ground_truth_payload: dict,
    attack_script_sha256: str,
    campaign_config: dict,
    comparison_profile: dict,
    comparison_profile_path: Path,
    result_card_path: Path,
    retention_policy: str = "original_case_retained",
    heavy_artifacts_retained: bool = True,
) -> dict:
    summary = (case_bundle or {}).get("summary") or {}
    causal = comparison_profile.get("causal_reconstruction") or {}
    uncertainty = comparison_profile.get("uncertainty") or {}
    hypothesis = comparison_profile.get("hypothesis_support") or {}
    final_conclusion = comparison_profile.get("final_conclusion") or {}
    trigger = comparison_profile.get("detection_trigger") or {}
    multilayer = comparison_profile.get("multilayer_analysis") or {}

    scenario_fingerprint = compute_scenario_fingerprint(scenario_profile, attack_profile, case_bundle, ground_truth_payload)
    topology_fingerprint = compute_topology_fingerprint(case_bundle, scenario_profile, attack_profile)
    attack_profile_id = str(attack_profile.get("attack_id") or "not_available")
    attack_parameters_hash = compute_attack_parameters_hash(attack_profile)
    expected_causal_edges = _expected_edge_ids(ground_truth_payload)
    trigger_policy_id = str(campaign_config.get("trigger_policy_id") or "highest_severity_alert_v1")
    acquisition_profile_id = str(campaign_config.get("acquisition_profile_id") or "default_kolla_lime_tshark_v1")
    analysis_profile_id = str(campaign_config.get("analysis_profile_id") or "default_multilayer_analysis_v1")
    foc_profile_id = str(campaign_config.get("foc_profile_id") or "default_foc_causal_reconstruction_v1")

    if str(level).upper() == "A":
        base_case_id = (case_bundle or {}).get("case_id") or "not_available"
        comparison_family_id = campaign_config.get("requested_comparison_family_id") or f"family-{_short_hash('level_a_repeatability', base_case_id, scenario_fingerprint, attack_profile_id, acquisition_profile_id, analysis_profile_id, foc_profile_id, expected_causal_edges)[:16]}"
    else:
        comparison_family_id = campaign_config.get("requested_comparison_family_id") or compute_comparison_family_id(
            scenario_fingerprint=scenario_fingerprint,
            topology_fingerprint=topology_fingerprint,
            attack_profile_id=attack_profile_id,
            attack_script_sha256=attack_script_sha256,
            attack_parameters_hash=attack_parameters_hash,
            expected_causal_edges=expected_causal_edges,
            trigger_policy_id=trigger_policy_id,
            acquisition_profile_id=acquisition_profile_id,
            analysis_profile_id=analysis_profile_id,
            foc_profile_id=foc_profile_id,
        )

    original_case_path = (case_bundle or {}).get("case_path")
    original_case_rel = (case_bundle or {}).get("case_rel_path")
    useful_layers = []
    for layer_name in ("network", "memory", "disk", "ot", "alerts", "timeline", "cross_layer"):
        if (multilayer.get(f"{layer_name}_analyzed") or 0) or layer_name in str(multilayer):
            useful_layers.append(layer_name)
    scientific_limitations = list(comparison_profile.get("scientific_limitations") or [])
    final_conclusion_class = (
        final_conclusion.get("conclusion_class")
        or final_conclusion.get("summary_class")
        or hypothesis.get("final_claimability_status")
        or "not_available"
    )

    return {
        "result_card_id": f"RC-{uuid.uuid4().hex[:12].upper()}",
        "case_id": (case_bundle or {}).get("case_id"),
        "original_case_id": (case_bundle or {}).get("case_id"),
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "evaluation_level": level,
        "source_type": "reanalysis_of_existing_case" if str(level).upper() == "A" else ("redeployed_scenario_execution" if str(level).upper() == "C" else "new_incident_execution"),
        "created_at": utc_now(),
        "scenario_id": scenario_profile.get("scenario_id") or "not_available",
        "scenario_fingerprint": scenario_fingerprint,
        "topology_fingerprint": topology_fingerprint,
        "scenario_version": scenario_profile.get("created_at") or "not_available",
        "attack_profile_id": attack_profile_id,
        "attack_name": attack_profile.get("technique_name") or "not_available",
        "mitre_technique_id": attack_profile.get("technique_id") or "not_available",
        "mitre_technique": attack_profile.get("technique_id") or "not_available",
        "attack_script": attack_profile.get("attack_script_reference") or "not_available",
        "attack_script_sha256": attack_script_sha256,
        "attack_parameters_hash": attack_parameters_hash,
        "detection_engine": campaign_config.get("detection_policy_id") or "wazuh_suricata_alert_ingestion_v1",
        "expected_alerts": ((summary.get("trigger_summary") or {}).get("expected_alerts")) or [],
        "expected_artifacts": ((summary.get("trigger_summary") or {}).get("expected_artifacts")) or [],
        "trigger_policy": trigger_policy_id,
        "trigger_policy_id": trigger_policy_id,
        "selected_trigger": trigger.get("selected_trigger") or "not_available",
        "acquisition_profile_id": acquisition_profile_id,
        "acquisition_scope": comparison_profile.get("acquisition") or {},
        "preservation_summary": comparison_profile.get("preservation") or {},
        "evidence_layers_available": list((comparison_profile.get("reports") or {}).keys()),
        "useful_layers": useful_layers,
        "CPR": causal.get("cpr"),
        "Weighted_CPR": causal.get("weighted_cpr"),
        "recovered_edges": causal.get("recovered_edges"),
        "degraded_edges": causal.get("degraded_edges"),
        "missing_edges": causal.get("missing_edges"),
        "uncertainty_class": uncertainty.get("temporal_confidence"),
        "hypothesis_support": hypothesis.get("global_support_level"),
        "final_conclusion_class": final_conclusion_class,
        "scientific_limitations": scientific_limitations,
        "comparison_family_id": comparison_family_id,
        "comparable_with": [],
        "recommended_next_attack_profile": attack_profile_id,
        "original_case_path": original_case_rel or (relative_path(Path(original_case_path)) if original_case_path else None),
        "comparison_profile_path": relative_path(comparison_profile_path),
        "retention_policy": retention_policy,
        "heavy_artifacts_retained": heavy_artifacts_retained,
        "heavy_artifacts_location": original_case_rel or (relative_path(Path(original_case_path)) if original_case_path else None),
        "heavy_artifacts_expiry": None,
        "analysis_profile_id": analysis_profile_id,
        "foc_profile_id": foc_profile_id,
        "expected_causal_edges": expected_causal_edges,
        "ground_truth_seal_valid": ((comparison_profile.get("ground_truth_seal") or {}).get("seal_valid")),
        "trigger_attack_alignment": trigger.get("trigger_attack_alignment"),
    }


def build_analysis_repeatability_profile(
    *,
    base_case_id: str | None,
    base_case_path: str | None,
    execution_id: str,
    campaign_id: str,
    comparison_profile: dict,
    result_card_id: str,
    comparison_profile_path: Path,
    analysis_profile_id: str,
    foc_profile_id: str,
) -> dict:
    causal = comparison_profile.get("causal_reconstruction") or {}
    uncertainty = comparison_profile.get("uncertainty") or {}
    hypothesis = comparison_profile.get("hypothesis_support") or {}
    final_conclusion = comparison_profile.get("final_conclusion") or {}
    return {
        "base_case_id": base_case_id,
        "base_case_path": base_case_path,
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "analysis_profile": analysis_profile_id,
        "FOC_profile": foc_profile_id,
        "CPR": causal.get("cpr"),
        "Weighted_CPR": causal.get("weighted_cpr"),
        "uncertainty_class": uncertainty.get("temporal_confidence"),
        "hypothesis_support": hypothesis.get("global_support_level"),
        "final_conclusion_class": final_conclusion.get("conclusion_class") or hypothesis.get("final_claimability_status"),
        "scientific_limitations": list(comparison_profile.get("scientific_limitations") or []),
        "comparison_profile_path": relative_path(comparison_profile_path),
        "result_card_id": result_card_id,
        "generated_at": utc_now(),
    }


def build_retention_manifest(
    *,
    case_id: str,
    execution_id: str,
    campaign_id: str,
    original_case_path: str | None,
    operator: str,
    reason: str,
    preserved_profiles: list[str],
    preserved_hashes: dict,
    what_was_deleted_or_archived: list[str],
    heavy_artifacts_retained: bool,
    heavy_artifacts_location: str | None,
    comparison_readiness_after_cleanup: str,
) -> dict:
    return {
        "retention_manifest_id": f"ret-{uuid.uuid4().hex[:10]}",
        "case_id": case_id,
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "what_was_retained": preserved_profiles,
        "what_was_deleted_or_archived": what_was_deleted_or_archived,
        "deletion_or_archive_time": utc_now(),
        "operator": operator,
        "reason": reason,
        "preserved_profiles": preserved_profiles,
        "preserved_hashes": preserved_hashes,
        "original_case_path": original_case_path,
        "heavy_artifacts_retained": heavy_artifacts_retained,
        "heavy_artifacts_location": heavy_artifacts_location,
        "comparison_readiness_after_cleanup": comparison_readiness_after_cleanup,
    }


def register_scientific_memory(
    *,
    case_bundle: dict | None,
    execution_id: str,
    campaign_id: str,
    level: str,
    scenario_profile: dict,
    attack_profile: dict,
    ground_truth_payload: dict,
    comparison_profile: dict,
    comparison_profile_path: Path,
    result_card: dict,
    result_card_path: Path,
    campaign_config: dict,
) -> dict:
    ensure_scientific_memory_layout()
    blueprint = build_scenario_reconstruction_blueprint(
        scenario_profile=scenario_profile,
        attack_profile=attack_profile,
        ground_truth_payload=ground_truth_payload,
        case_bundle=case_bundle,
        campaign_config=campaign_config,
    )
    blueprint_path = BLUEPRINTS_DIR / f"{result_card['comparison_family_id']}_scenario_reconstruction_blueprint.json"
    _write_json(blueprint_path, blueprint)

    scenario_card = build_scenario_result_card(
        scenario_profile=scenario_profile,
        attack_profile=attack_profile,
        ground_truth_payload=ground_truth_payload,
        case_bundle=case_bundle,
        campaign_id=campaign_id,
        execution_id=execution_id,
        level=level,
        campaign_config=campaign_config,
        blueprint_path=blueprint_path,
    )
    existing_scenario_registry = load_registry(SCENARIO_REGISTRY_PATH)
    existing_scenario_card = next(
        (item for item in existing_scenario_registry.get("entries", []) if item.get("scenario_fingerprint") == scenario_card["scenario_fingerprint"]),
        None,
    )
    existing_result_cards = list((existing_scenario_card or {}).get("associated_result_cards") or []) if isinstance(existing_scenario_card, dict) else []
    existing_campaigns = list((existing_scenario_card or {}).get("associated_campaigns") or []) if isinstance(existing_scenario_card, dict) else []
    existing_cases = list((existing_scenario_card or {}).get("associated_cases") or []) if isinstance(existing_scenario_card, dict) else []
    scenario_card["associated_result_cards"] = sorted({*existing_result_cards, result_card["result_card_id"]})
    scenario_card["associated_campaigns"] = sorted({*existing_campaigns, campaign_id})
    if case_bundle:
        scenario_card["associated_cases"] = sorted({*existing_cases, case_bundle.get("case_id")})

    case_card = None
    if case_bundle:
        case_card = build_case_result_card(
            case_bundle=case_bundle,
            scenario_fingerprint=result_card["scenario_fingerprint"],
            execution_id=execution_id,
            campaign_id=campaign_id,
            comparison_profile_path=comparison_profile_path,
            result_card_path=result_card_path,
            retention_policy=result_card["retention_policy"],
            heavy_artifacts_retained=bool(result_card["heavy_artifacts_retained"]),
        )

    execution_card = {
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "evaluation_level": level,
        "case_id": (case_bundle or {}).get("case_id"),
        "scenario_id": scenario_profile.get("scenario_id") or "not_available",
        "comparison_family_id": result_card["comparison_family_id"],
        "comparison_profile_path": relative_path(comparison_profile_path),
        "forensic_result_card_path": relative_path(result_card_path),
        "created_at": utc_now(),
    }

    analysis_card = build_analysis_result_card(
        execution_id=execution_id,
        campaign_id=campaign_id,
        level=level,
        case_bundle=case_bundle,
        comparison_profile=comparison_profile,
    )

    upsert_registry_entry(SCENARIO_REGISTRY_PATH, "scenario_fingerprint", scenario_card)
    if case_card:
        upsert_registry_entry(CASE_REGISTRY_PATH, "case_id", case_card)
    upsert_registry_entry(EXECUTION_REGISTRY_PATH, "execution_id", execution_card)
    upsert_registry_entry(RESULT_REGISTRY_PATH, "result_card_id", result_card)
    upsert_registry_entry(LEGACY_COMPARISON_REGISTRY_PATH, "result_card_id", result_card)
    upsert_registry_entry(ANALYSIS_REGISTRY_PATH, "analysis_card_id", analysis_card)

    scenario_card_path = SCENARIO_REGISTRY_PATH.parent / scenario_card["scenario_fingerprint"] / "scenario_result_card.json"
    execution_card_path = EXECUTION_REGISTRY_PATH.parent / execution_id / "execution_result_card.json"
    analysis_card_path = ANALYSIS_REGISTRY_PATH.parent / analysis_card["analysis_card_id"] / "analysis_result_card.json"
    _write_json(scenario_card_path, scenario_card)
    _write_json(execution_card_path, execution_card)
    _write_json(analysis_card_path, analysis_card)
    case_card_path = None
    if case_card:
        case_card_path = CASE_REGISTRY_PATH.parent / str(case_card["case_id"]) / "case_result_card.json"
        _write_json(case_card_path, case_card)

    return {
        "scenario_card": scenario_card,
        "case_card": case_card,
        "execution_card": execution_card,
        "analysis_card": analysis_card,
        "scenario_card_path": relative_path(scenario_card_path),
        "case_card_path": relative_path(case_card_path) if case_card_path else None,
        "execution_card_path": relative_path(execution_card_path),
        "analysis_card_path": relative_path(analysis_card_path),
        "blueprint_path": relative_path(blueprint_path),
    }
