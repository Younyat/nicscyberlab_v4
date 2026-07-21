"""
Campaign repetitions detail center — Flask blueprint.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from .service import (
    get_level_a_repetition_detail,
    get_level_b_repetition_detail,
    get_level_c_repetition_detail,
    list_recent_repetitions,
)

campaign_repetitions_bp = Blueprint("campaign_repetitions", __name__)


@campaign_repetitions_bp.route("/api/campaign-repetitions/recent", methods=["GET"])
def api_recent():
    level = request.args.get("level")
    limit = request.args.get("limit", default=20, type=int)
    return jsonify({"repetitions": list_recent_repetitions(level=level, limit=limit)}), 200


@campaign_repetitions_bp.route("/api/campaign-repetitions/level-c/<job_id>/<int:rep_num>", methods=["GET"])
def api_level_c_detail(job_id: str, rep_num: int):
    detail = get_level_c_repetition_detail(job_id, rep_num)
    if not detail:
        return jsonify({"error": "not_found"}), 404
    return jsonify(detail), 200


@campaign_repetitions_bp.route("/api/campaign-repetitions/level-b/<job_id>/<int:rep_num>", methods=["GET"])
def api_level_b_detail(job_id: str, rep_num: int):
    detail = get_level_b_repetition_detail(job_id, rep_num)
    if not detail:
        return jsonify({"error": "not_found"}), 404
    return jsonify(detail), 200


@campaign_repetitions_bp.route("/api/campaign-repetitions/level-a/<job_id>", methods=["GET"])
def api_level_a_detail(job_id: str):
    detail = get_level_a_repetition_detail(job_id)
    if not detail:
        return jsonify({"error": "not_found"}), 404
    return jsonify(detail), 200
