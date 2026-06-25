from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint, jsonify, request

from app_core.infrastructure.foc_experimentation.campaign_service import (
    build_campaign_proposal,
    campaign_preflight,
    create_campaign,
    get_campaign,
    list_campaigns,
    start_campaign,
    start_campaign_job,
    start_comparison_job,
    update_campaign_state,
)
from app_core.infrastructure.foc_experimentation.comparability_service import (
    load_comparison_result,
    load_execution_profile,
)
from app_core.infrastructure.foc_experimentation.comparison_registry import (
    find_comparable_families,
    find_recommended_comparable_result,
    load_registry,
    register_existing_case_as_result_card,
)
from app_core.infrastructure.foc_experimentation.config import (
    CAMPAIGNS_ROOT,
    CASE_REGISTRY_PATH,
    METHODOLOGICAL_BASIS_FILE,
    RESULT_REGISTRY_PATH,
    SCENARIO_REGISTRY_PATH,
)
from app_core.infrastructure.foc_experimentation.execution_service import execution_artifacts, load_execution, regenerate_execution_profile
from app_core.infrastructure.foc_experimentation.job_runner import get_job
from app_core.infrastructure.foc_experimentation.methodological_basis import load_methodological_basis
from app_core.infrastructure.foc_experimentation.scientific_memory import load_registry as load_memory_registry
from app_core.infrastructure.foc_experimentation.scientific_memory_sync import sync_scientific_memory
from app_core.infrastructure.foc_experimentation.retention_service import prepare_retention_cleanup
from app_core.infrastructure.attack.catalog import get_attack_catalog
from app_core.infrastructure.foc_reconstruction.foc_case_analysis import cases_with_analysis_state
from app_core.infrastructure.foc_reconstruction.foc_paths import relative_path

experimentation_bp = Blueprint("foc_experimentation", __name__)


@experimentation_bp.route("/api/foc/experimentation/health", methods=["GET"])
def api_foc_experimentation_health():
    sync_scientific_memory()
    return jsonify(
        {
            "status": "ok",
            "module": "foc_experimentation",
            "campaigns_root": relative_path(CAMPAIGNS_ROOT),
            "campaigns_root_exists": CAMPAIGNS_ROOT.exists(),
            "methodological_basis_file": relative_path(METHODOLOGICAL_BASIS_FILE),
        }
    ), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns", methods=["GET"])
def api_foc_experimentation_campaigns():
    sync_scientific_memory()
    return jsonify(list_campaigns()), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns/proposal", methods=["POST"])
def api_foc_experimentation_campaign_proposal():
    body = request.get_json(silent=True) or {}
    payload = build_campaign_proposal(
        case_id=str(body.get("case_id") or "").strip() or None,
        level=str(body.get("level") or "").strip() or None,
        scenario_id=str(body.get("scenario_id") or "").strip() or None,
    )
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns/preflight", methods=["POST"])
def api_foc_experimentation_campaign_preflight():
    body = request.get_json(silent=True) or {}
    return jsonify(campaign_preflight(body)), 200


@experimentation_bp.route("/api/foc/experimentation/source-cases", methods=["GET"])
def api_foc_experimentation_source_cases():
    sync_scientific_memory()
    return jsonify(cases_with_analysis_state()), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns/create", methods=["POST"])
def api_foc_experimentation_campaigns_create():
    body = request.get_json(silent=True) or {}
    try:
        payload = create_campaign(body)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(payload), 201


@experimentation_bp.route("/api/foc/experimentation/campaigns/<campaign_id>", methods=["GET"])
def api_foc_experimentation_campaign_detail(campaign_id: str):
    payload = get_campaign(campaign_id)
    if not payload:
        return jsonify({"error": "campaign_not_found", "campaign_id": campaign_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns/<campaign_id>/start", methods=["POST"])
def api_foc_experimentation_campaign_start(campaign_id: str):
    body = request.get_json(silent=True) or {}
    try:
        payload = start_campaign(campaign_id, overrides=body)
    except FileNotFoundError:
        return jsonify({"error": "campaign_not_found", "campaign_id": campaign_id}), 404
    return jsonify(payload), 202


@experimentation_bp.route("/api/foc/experimentation/campaigns/<campaign_id>/pause", methods=["POST"])
def api_foc_experimentation_campaign_pause(campaign_id: str):
    try:
        payload = update_campaign_state(campaign_id, "paused")
    except FileNotFoundError:
        return jsonify({"error": "campaign_not_found", "campaign_id": campaign_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns/<campaign_id>/stop", methods=["POST"])
def api_foc_experimentation_campaign_stop(campaign_id: str):
    try:
        payload = update_campaign_state(campaign_id, "stopped")
    except FileNotFoundError:
        return jsonify({"error": "campaign_not_found", "campaign_id": campaign_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/campaigns/<campaign_id>/run-next", methods=["POST"])
def api_foc_experimentation_campaign_run_next(campaign_id: str):
    body = request.get_json(silent=True) or {}
    try:
        job = start_campaign_job(campaign_id, overrides=body)
    except FileNotFoundError:
        return jsonify({"error": "campaign_not_found", "campaign_id": campaign_id}), 404
    return jsonify(job), 202


@experimentation_bp.route("/api/foc/experimentation/executions/<execution_id>", methods=["GET"])
def api_foc_experimentation_execution_detail(execution_id: str):
    payload = load_execution(execution_id)
    if not payload:
        return jsonify({"error": "execution_not_found", "execution_id": execution_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/executions/<execution_id>/status", methods=["GET"])
def api_foc_experimentation_execution_status(execution_id: str):
    payload = load_execution(execution_id)
    if not payload:
        return jsonify({"error": "execution_not_found", "execution_id": execution_id}), 404
    return jsonify({"execution_id": execution_id, "status": payload.get("status"), "stage_statuses": payload.get("stage_statuses")}), 200


@experimentation_bp.route("/api/foc/experimentation/executions/<execution_id>/artifacts", methods=["GET"])
def api_foc_experimentation_execution_artifacts(execution_id: str):
    payload = execution_artifacts(execution_id)
    if payload.get("error") == "execution_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/executions/<execution_id>/regenerate-profile", methods=["POST"])
def api_foc_experimentation_execution_regenerate_profile(execution_id: str):
    payload = regenerate_execution_profile(execution_id)
    if payload.get("error") == "execution_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/comparability/compare", methods=["POST"])
def api_foc_experimentation_comparability_compare():
    body = request.get_json(silent=True) or {}
    execution_ids = list(body.get("execution_ids") or [])
    if len(execution_ids) < 2:
        return jsonify({"error": "at_least_two_execution_ids_required"}), 400
    job = start_comparison_job(
        body.get("campaign_id"),
        execution_ids,
        delta_wcpr_allowed=float(body["delta_wcpr_allowed"]) if body.get("delta_wcpr_allowed") is not None else None,
    )
    return jsonify(job), 202


@experimentation_bp.route("/api/foc/experimentation/comparability/results/<comparison_id>", methods=["GET"])
def api_foc_experimentation_comparability_result(comparison_id: str):
    payload = load_comparison_result(comparison_id)
    if not payload:
        return jsonify({"error": "comparison_not_found", "comparison_id": comparison_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/comparability/profile/<execution_id>", methods=["GET"])
def api_foc_experimentation_comparability_profile(execution_id: str):
    payload = load_execution_profile(execution_id)
    if not payload:
        return jsonify({"error": "comparison_profile_not_found", "execution_id": execution_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/methodological-basis", methods=["GET"])
def api_foc_experimentation_methodological_basis():
    return jsonify(load_methodological_basis()), 200


@experimentation_bp.route("/api/foc/experimentation/ground-truth-seal/<execution_id>", methods=["GET"])
def api_foc_experimentation_ground_truth_seal(execution_id: str):
    profile = load_execution(execution_id)
    if not profile:
        return jsonify({"error": "execution_not_found", "execution_id": execution_id}), 404
    execution_path = profile.get("execution_abs_path")
    if not execution_path:
        return jsonify({"error": "execution_path_not_available", "execution_id": execution_id}), 404
    path = Path(execution_path) / "ground_truth_seal.json"
    if not path.is_file():
        return jsonify({"error": "ground_truth_seal_not_found", "execution_id": execution_id}), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8"))), 200


@experimentation_bp.route("/api/foc/experimentation/jobs/<job_id>", methods=["GET"])
def api_foc_experimentation_job_status(job_id: str):
    payload = get_job(job_id)
    if not payload:
        return jsonify({"error": "job_not_found", "job_id": job_id}), 404
    return jsonify(payload), 200


@experimentation_bp.route("/api/foc/experimentation/comparison-registry", methods=["GET"])
def api_foc_experimentation_comparison_registry():
    registry = load_registry()
    scenario_id = str(request.args.get("scenario_id") or "").strip() or None
    scenario_fingerprint = str(request.args.get("scenario_fingerprint") or "").strip() or None
    entries = registry.get("entries", [])
    if scenario_fingerprint:
        entries = [item for item in entries if item.get("scenario_fingerprint") == scenario_fingerprint]
    elif scenario_id:
        matches = find_comparable_families(scenario_id=scenario_id)
        match_ids = {item.get("result_card_id") for item in matches}
        entries = [item for item in entries if item.get("result_card_id") in match_ids]
    return jsonify({"generated_at": registry.get("generated_at"), "entries": entries}), 200


@experimentation_bp.route("/api/foc/experimentation/comparison-registry/recommend", methods=["GET"])
def api_foc_experimentation_comparison_registry_recommend():
    scenario_id = str(request.args.get("scenario_id") or "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id_required"}), 400
    level = str(request.args.get("level") or "").strip().upper() or None
    attack_profile_id = str(request.args.get("attack_profile_id") or "").strip() or None
    trigger_policy = str(request.args.get("trigger_policy") or "").strip() or None
    acquisition_profile_id = str(request.args.get("acquisition_profile_id") or "").strip() or None
    matches = find_comparable_families(scenario_id=scenario_id)
    if not matches:
        return jsonify({"scenario_id": scenario_id, "level": level, "has_recommendation": False, "matches": []}), 200
    recommended = find_recommended_comparable_result(
        scenario_id=scenario_id,
        attack_profile_id=attack_profile_id,
        trigger_policy=trigger_policy,
        acquisition_profile_id=acquisition_profile_id,
    ) or matches[0]
    return (
        jsonify(
            {
                "scenario_id": scenario_id,
                "level": level,
                "has_recommendation": True,
                "recommended": recommended,
                "matches": matches,
                "message": "The system found previous comparable results. To compare the next execution with those results, use the same attack profile, trigger policy, acquisition profile, and scenario family.",
            }
        ),
        200,
    )


@experimentation_bp.route("/api/foc/experimentation/scientific-memory/scenarios", methods=["GET"])
def api_foc_experimentation_scientific_memory_scenarios():
    sync_scientific_memory()
    return jsonify(load_memory_registry(SCENARIO_REGISTRY_PATH)), 200


@experimentation_bp.route("/api/foc/experimentation/scientific-memory/cases", methods=["GET"])
def api_foc_experimentation_scientific_memory_cases():
    sync_scientific_memory()
    return jsonify(load_memory_registry(CASE_REGISTRY_PATH)), 200


@experimentation_bp.route("/api/foc/experimentation/scientific-memory/results", methods=["GET"])
def api_foc_experimentation_scientific_memory_results():
    sync_scientific_memory()
    return jsonify(load_memory_registry(RESULT_REGISTRY_PATH)), 200


@experimentation_bp.route("/api/foc/experimentation/scientific-memory/sync", methods=["POST"])
def api_foc_experimentation_scientific_memory_sync():
    return jsonify(sync_scientific_memory()), 200


@experimentation_bp.route("/api/foc/experimentation/comparison-registry/register-case", methods=["POST"])
def api_foc_experimentation_comparison_registry_register_case():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "case_id_required"}), 400
    result = register_existing_case_as_result_card(case_id)
    if result.get("error") == "case_not_found":
        return jsonify(result), 404
    if result.get("error"):
        return jsonify(result), 400
    return jsonify(result), 201


@experimentation_bp.route("/api/foc/experimentation/retention/prepare", methods=["POST"])
def api_foc_experimentation_retention_prepare():
    body = request.get_json(silent=True) or {}
    execution_id = str(body.get("execution_id") or "").strip()
    if not execution_id:
        return jsonify({"error": "execution_id_required"}), 400
    payload = prepare_retention_cleanup(
        execution_id,
        campaign_id=str(body.get("campaign_id") or "").strip() or None,
        operator=str(body.get("operator") or "foc_experimentation"),
        reason=str(body.get("reason") or "Preserve lightweight profiles for future comparison without duplicating heavy evidence."),
        action=str(body.get("action") or "archive_metadata_only"),
        apply_changes=bool(body.get("apply_changes")),
        confirm_delete=bool(body.get("confirm_delete")),
    )
    if payload.get("error"):
        return jsonify(payload), 400
    return jsonify(payload), 200


_ATTACK_CATALOG_FIELDS = (
    "attack_id",
    "display_name",
    "category",
    "description",
    "mitre_domain",
    "mitre_id",
    "mitre_technique",
    "tactic",
    "detection_engine",
    "target_roles",
    "severity",
    "script",
    "expected_alerts",
    "expected_artifacts",
    "rollback_required",
    "dfir_escalation",
)


@experimentation_bp.route("/api/foc/experimentation/attack-catalog", methods=["GET"])
def api_foc_experimentation_attack_catalog():
    # Reuses the real MITRE ATT&CK-aligned catalog used by the Tactical Cyber
    # Operations Dashboard (app_core/infrastructure/attack/catalog.py) so the
    # campaign builder shows the operator the actual technique, script, and
    # expected evidence that would be selected -- never a placeholder.
    target_role = str(request.args.get("target_role") or "").strip()
    attacks = get_attack_catalog(target_role=target_role)
    items = [{key: attack.get(key) for key in _ATTACK_CATALOG_FIELDS} for attack in attacks]
    return jsonify({"attacks": items}), 200
