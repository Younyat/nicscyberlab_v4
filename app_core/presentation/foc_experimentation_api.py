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
from app_core.infrastructure.foc_experimentation.config import CAMPAIGNS_ROOT, METHODOLOGICAL_BASIS_FILE
from app_core.infrastructure.foc_experimentation.execution_service import execution_artifacts, load_execution, regenerate_execution_profile
from app_core.infrastructure.foc_experimentation.job_runner import get_job
from app_core.infrastructure.foc_experimentation.methodological_basis import load_methodological_basis
from app_core.infrastructure.foc_reconstruction.foc_case_analysis import cases_with_analysis_state
from app_core.infrastructure.foc_reconstruction.foc_paths import relative_path

experimentation_bp = Blueprint("foc_experimentation", __name__)


@experimentation_bp.route("/api/foc/experimentation/health", methods=["GET"])
def api_foc_experimentation_health():
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
