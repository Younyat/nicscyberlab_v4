from __future__ import annotations

import json
from pathlib import Path

from .config import CASE_REGISTRY_PATH, SCENARIO_REGISTRY_PATH
from .profile_builder import load_case_bundle
from .scientific_memory import (
    _short_hash,
    _write_json,
    build_case_result_card,
    build_scenario_reconstruction_blueprint,
    build_scenario_result_card,
    compute_scenario_fingerprint,
    ensure_scientific_memory_layout,
    load_registry,
    upsert_registry_entry,
)
from ..foc_reconstruction.foc_case_analysis import cases_with_analysis_state
from ..foc_reconstruction.foc_paths import project_path, relative_path
from ..foc_reconstruction.foc_sources import utc_now


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _active_scenario_sources() -> dict:
    base_path = project_path("scenario", "scenario_file.json")
    industrial_state_path = project_path("industrial-scenario", "state", "industrial_state.json")
    industrial_dir = project_path("industrial-scenario", "scenarios")
    industrial_candidates = sorted(industrial_dir.glob("industrial_*.json")) if industrial_dir.exists() else []
    industrial_path = industrial_candidates[-1] if industrial_candidates else None
    deployment_path = project_path("scenario", "deployment_status.json")
    return {
        "base_path": base_path,
        "industrial_state_path": industrial_state_path,
        "industrial_path": industrial_path,
        "deployment_path": deployment_path,
        "base": _json_load(base_path) or {},
        "industrial_state": _json_load(industrial_state_path) or {},
        "industrial": _json_load(industrial_path) or {},
        "deployment": _json_load(deployment_path) or {},
    }


def get_active_scenario_memory_hint() -> dict:
    sources = _active_scenario_sources()
    base = sources["base"]
    industrial = sources["industrial"]
    industrial_state = sources["industrial_state"]
    deployment = sources["deployment"]
    scenario_id = (
        industrial_state.get("scenario_id")
        or industrial.get("scenario_id")
        or base.get("scenario_id")
        or industrial.get("scenario_name")
        or base.get("scenario_name")
        or base.get("name")
        or "not_available"
    )
    scenario_name = (
        industrial_state.get("scenario_name")
        or industrial.get("scenario_name")
        or base.get("scenario_name")
        or base.get("name")
        or "not_available"
    )
    return {
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "active_scenario_exists": bool(base or industrial or industrial_state),
        "deployment_status": deployment.get("status") or "not_available",
    }


def sync_active_scenario_memory() -> dict | None:
    ensure_scientific_memory_layout()
    sources = _active_scenario_sources()
    base = sources["base"]
    industrial = sources["industrial"]
    industrial_state = sources["industrial_state"]
    deployment = sources["deployment"]
    if not base and not industrial and not industrial_state:
        return None

    hint = get_active_scenario_memory_hint()
    scenario_id = hint["scenario_id"]
    scenario_name = hint["scenario_name"]
    scenario_profile = {
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "created_at": utc_now(),
        "topology_signature": {
            "base_keys": sorted(base.keys()),
            "industrial_keys": sorted(industrial.keys()),
            "industrial_state_keys": sorted(industrial_state.keys()),
            "base_sha": _short_hash(base),
            "industrial_sha": _short_hash(industrial),
            "industrial_state_sha": _short_hash(industrial_state),
        },
        "scenario_signature": {
            "deployment_status": deployment.get("status") or "not_available",
            "base_sha": _short_hash(base),
            "industrial_sha": _short_hash(industrial),
            "industrial_state_sha": _short_hash(industrial_state),
        },
    }
    attack_profile = {
        "attack_id": "not_available",
        "technique_id": "not_available",
        "technique_name": "not_available",
        "attack_script_reference": "not_available",
        "protocol": industrial_state.get("protocol") or "not_available",
        "register": industrial_state.get("register"),
        "expected_value": industrial_state.get("expected_value"),
    }
    ground_truth_payload = {
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "expected_edges": [],
    }
    scenario_fingerprint = compute_scenario_fingerprint(scenario_profile, attack_profile, None, ground_truth_payload)
    blueprint = build_scenario_reconstruction_blueprint(
        scenario_profile=scenario_profile,
        attack_profile=attack_profile,
        ground_truth_payload=ground_truth_payload,
        case_bundle=None,
        campaign_config={
            "analysis_profile_id": "default_multilayer_analysis_v1",
            "detection_policy_id": "wazuh_suricata_alert_ingestion_v1",
            "trigger_policy_id": "highest_severity_alert_v1",
            "acquisition_profile_id": "default_kolla_lime_tshark_v1",
        },
    )
    blueprint_path = SCENARIO_REGISTRY_PATH.parent.parent / "blueprints" / f"{scenario_fingerprint}_scenario_reconstruction_blueprint.json"
    _write_json(blueprint_path, blueprint)
    existing = next(
        (item for item in load_registry(SCENARIO_REGISTRY_PATH).get("entries", []) if item.get("scenario_fingerprint") == scenario_fingerprint),
        None,
    )
    card = build_scenario_result_card(
        scenario_profile=scenario_profile,
        attack_profile=attack_profile,
        ground_truth_payload=ground_truth_payload,
        case_bundle=None,
        campaign_id=None,
        execution_id=None,
        level="C",
        campaign_config={"analysis_profile_id": "default_multilayer_analysis_v1"},
        blueprint_path=blueprint_path,
    )
    card["scenario_card_id"] = (existing or {}).get("scenario_card_id") or card["scenario_card_id"]
    card["associated_campaigns"] = sorted(set((existing or {}).get("associated_campaigns") or []))
    card["associated_cases"] = sorted(set((existing or {}).get("associated_cases") or []))
    card["associated_result_cards"] = sorted(set((existing or {}).get("associated_result_cards") or []))
    card["active_scenario_exists"] = True
    card["destroyed_at"] = None
    upsert_registry_entry(SCENARIO_REGISTRY_PATH, "scenario_fingerprint", card)
    scenario_card_path = SCENARIO_REGISTRY_PATH.parent / scenario_fingerprint / "scenario_result_card.json"
    _write_json(scenario_card_path, card)
    return {"scenario_card": card, "scenario_card_path": relative_path(scenario_card_path), "blueprint_path": relative_path(blueprint_path)}


def sync_case_registry_from_existing_cases(limit: int | None = None) -> dict:
    ensure_scientific_memory_layout()
    entries = load_registry(CASE_REGISTRY_PATH).get("entries", [])
    existing = {item.get("case_id"): item for item in entries if item.get("case_id")}
    synced = 0
    skipped = 0
    errors: list[dict] = []
    for item in cases_with_analysis_state().get("cases", []):
        case_id = str(item.get("case_id") or "").strip()
        if not case_id:
            continue
        if limit is not None and synced >= limit:
            break
        case_bundle = load_case_bundle(case_id=case_id)
        if not case_bundle:
            skipped += 1
            continue
        summary = case_bundle.get("summary") or {}
        scenario_profile = {
            "scenario_id": summary.get("scenario_id") or "not_available",
            "scenario_name": summary.get("scenario_name") or item.get("source_case_name") or "not_available",
            "created_at": item.get("created_at") or utc_now(),
            "topology_signature": {"case_id": case_id},
            "scenario_signature": {"case_digest_hash": ((summary.get("integrity_summary") or {}).get("case_digest_hash")) or "not_available"},
        }
        attack_record = case_bundle.get("attack_record") or {}
        ground_truth = case_bundle.get("ground_truth") or {}
        attack_profile = {
            "attack_id": attack_record.get("attack_id") or (((ground_truth.get("attack_expected") or {}).get("selector") or {}).get("attack_id")) or "not_available",
            "technique_id": (((ground_truth.get("attack_expected") or {}).get("technique_id")) or ((attack_record.get("mitre") or {}).get("technique_id"))) or "not_available",
            "technique_name": (((ground_truth.get("attack_expected") or {}).get("technique_name")) or ((attack_record.get("mitre") or {}).get("technique_name"))) or "not_available",
            "attack_script_reference": attack_record.get("source_reference") or "not_available",
            "protocol": ((ground_truth.get("attack_expected") or {}).get("protocol")) or "not_available",
            "register": (ground_truth.get("attack_expected") or {}).get("register"),
            "expected_value": (ground_truth.get("attack_expected") or {}).get("expected_value"),
        }
        try:
            scenario_fingerprint = compute_scenario_fingerprint(scenario_profile, attack_profile, case_bundle, ground_truth)
            existing_card = existing.get(case_id)
            comparison_profile_path = Path((existing_card or {}).get("comparison_profile_path")) if (existing_card or {}).get("comparison_profile_path") else Path(case_bundle.get("case_path")) / "derived" / "experimentation" / "forensic_comparison_profile.json"
            result_card_path = Path((existing_card or {}).get("forensic_result_card_path")) if (existing_card or {}).get("forensic_result_card_path") else Path(case_bundle.get("case_path")) / "derived" / "experimentation" / "forensic_result_card.json"
            case_card = build_case_result_card(
                case_bundle=case_bundle,
                scenario_fingerprint=scenario_fingerprint,
                execution_id=(existing_card or {}).get("execution_id") or f"REGISTERED-{case_id}",
                campaign_id=(existing_card or {}).get("campaign_id") or "not_applicable_registered_case",
                comparison_profile_path=comparison_profile_path,
                result_card_path=result_card_path,
                retention_policy=(existing_card or {}).get("retention_policy") or "original_case_retained",
                heavy_artifacts_retained=bool((existing_card or {}).get("heavy_artifacts_retained", True)),
            )
            if existing_card:
                case_card["case_card_id"] = existing_card.get("case_card_id") or case_card["case_card_id"]
            upsert_registry_entry(CASE_REGISTRY_PATH, "case_id", case_card)
            case_card_path = CASE_REGISTRY_PATH.parent / case_id / "case_result_card.json"
            _write_json(case_card_path, case_card)
            synced += 1
        except Exception as exc:
            errors.append({"case_id": case_id, "error": str(exc)})
    return {"synced": synced, "skipped": skipped, "errors": errors}


def sync_scientific_memory() -> dict:
    scenario_sync = sync_active_scenario_memory()
    case_sync = sync_case_registry_from_existing_cases()
    return {
        "scenario_sync": scenario_sync,
        "case_sync": case_sync,
        "generated_at": utc_now(),
    }
