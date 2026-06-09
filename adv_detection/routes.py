from __future__ import annotations

from pathlib import Path

from flask import Blueprint, current_app, jsonify, send_file, request

from .services.config_service import get_module_runtime_config
from .services.result_service import (
    get_run_detail,
    list_recent_runs,
)
from .services.runner_service import (
    build_status_payload,
    list_vendor_assets,
    run_vendor_entrypoint,
)

adv_detection_bp = Blueprint(
    "adv_detection",
    __name__,
    url_prefix="/adv-detection",
)


@adv_detection_bp.get("/")
def page():
    html_path = Path(current_app.root_path) / "static" / "adv_detection.html"
    return send_file(html_path)


@adv_detection_bp.get("/api/status")
def api_status():
    try:
        data = build_status_payload()
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@adv_detection_bp.get("/api/config")
def api_config():
    try:
        data = get_module_runtime_config()
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@adv_detection_bp.get("/api/assets")
def api_assets():
    try:
        data = list_vendor_assets()
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@adv_detection_bp.get("/api/runs")
def api_runs():
    try:
        limit = int(request.args.get("limit", 20))
        data = list_recent_runs(limit=limit)
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@adv_detection_bp.get("/api/runs/<run_id>")
def api_run_detail(run_id: str):
    try:
        data = get_run_detail(run_id)
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404


@adv_detection_bp.post("/api/run")
def api_run():
    try:
        payload = request.get_json(force=True) or {}
        data = run_vendor_entrypoint(payload)
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400