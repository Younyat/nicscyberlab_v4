"""
Scenario Snapshot — Flask blueprint.
Read-only endpoints for capture, listing, validation, sealing, export, diff.
"""
from __future__ import annotations

import threading

from flask import Blueprint, Response, jsonify, request

from .service import (
    capture_snapshot,
    delete_snapshot,
    delete_snapshot_force,
    diff_snapshots,
    export_snapshot,
    get_capture_status,
    get_snapshot,
    list_snapshots,
    seal_snapshot,
    verify_nodes_live,
)

scenario_snapshot_bp = Blueprint("scenario_snapshot", __name__)

# Background capture state
_bg_thread: threading.Thread | None = None
_bg_result: dict | None = None
_bg_lock = threading.Lock()


def _run_capture_bg():
    global _bg_result
    try:
        result = capture_snapshot()
        with _bg_lock:
            _bg_result = result
    except Exception as exc:
        with _bg_lock:
            _bg_result = {"status": "FAILED", "error": str(exc)}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@scenario_snapshot_bp.route("/api/scenario-snapshot/capture", methods=["POST"])
def api_capture():
    """Launch a background snapshot capture. Returns immediately."""
    global _bg_thread, _bg_result

    status = get_capture_status()
    if status.get("in_progress"):
        return jsonify({"status": "IN_PROGRESS", "message": "A capture is already running."}), 409

    with _bg_lock:
        _bg_result = None

    t = threading.Thread(target=_run_capture_bg, daemon=True)
    with _bg_lock:
        _bg_thread = t
    t.start()

    return jsonify({"status": "COLLECTING", "message": "Snapshot capture started."}), 202


@scenario_snapshot_bp.route("/api/scenario-snapshot/status", methods=["GET"])
def api_capture_status():
    """Poll the background capture status."""
    in_progress = get_capture_status().get("in_progress", False)
    with _bg_lock:
        result = _bg_result

    if in_progress:
        return jsonify({"status": "COLLECTING", "result": None}), 200

    if result is None:
        # Nothing started yet — return summary + full snapshot so UI can render without a second roundtrip
        snaps = list_snapshots()
        latest_summary = snaps[0] if snaps else None
        latest_full = get_snapshot(snaps[0]["snapshot_id"]) if snaps else None
        return jsonify({
            "status": "IDLE",
            "result": None,
            "latest_snapshot": latest_summary,
            "latest_snapshot_full": latest_full,
        }), 200

    return jsonify({"status": result.get("status", "COMPLETED"), "result": result}), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots", methods=["GET"])
def api_list_snapshots():
    snaps = list_snapshots()
    return jsonify({"snapshots": snaps, "total": len(snaps)}), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/current", methods=["GET"])
def api_current_snapshot():
    """Return the most recent snapshot or a status if none exists."""
    snaps = list_snapshots()
    if not snaps:
        return jsonify({"snapshot": None, "message": "No snapshots captured yet."}), 200
    latest = get_snapshot(snaps[0]["snapshot_id"])
    return jsonify({"snapshot": latest}), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>", methods=["GET"])
def api_get_snapshot(snapshot_id: str):
    snap = get_snapshot(snapshot_id)
    if not snap:
        return jsonify({"error": "not_found"}), 404
    return jsonify(snap), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>/validate", methods=["POST"])
def api_validate_snapshot(snapshot_id: str):
    snap = get_snapshot(snapshot_id)
    if not snap:
        return jsonify({"error": "not_found"}), 404
    validation = snap.get("validation") or {}
    return jsonify({
        "snapshot_id": snapshot_id,
        "validation": validation,
        "overall_reproduction_ready": validation.get("overall_reproduction_ready", False),
    }), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>/seal", methods=["POST"])
def api_seal_snapshot(snapshot_id: str):
    result = seal_snapshot(snapshot_id)
    if result.get("error"):
        return jsonify(result), 409
    return jsonify({
        "status": "SEALED",
        "snapshot_id": snapshot_id,
        "sealed_at_utc": result.get("sealed_at_utc"),
        "snapshot_hash": (result.get("hashes") or {}).get("snapshot_hash"),
    }), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>/export", methods=["GET"])
def api_export_snapshot(snapshot_id: str):
    data = export_snapshot(snapshot_id)
    if data.get("error"):
        return jsonify(data), 404
    import json
    content = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    return Response(
        content,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{snapshot_id}.json"'},
    )


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>/relationships", methods=["GET"])
def api_snapshot_relationships(snapshot_id: str):
    snap = get_snapshot(snapshot_id)
    if not snap:
        return jsonify({"error": "not_found"}), 404
    return jsonify(snap.get("relationships") or {}), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>/diff", methods=["GET"])
def api_snapshot_diff(snapshot_id: str):
    other_id = request.args.get("compare_with", "")
    if not other_id:
        return jsonify({"error": "compare_with parameter required"}), 400
    result = diff_snapshots(snapshot_id, other_id)
    return jsonify(result), 200 if not result.get("error") else 404


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>", methods=["DELETE"])
def api_delete_snapshot(snapshot_id: str):
    force = request.args.get("force", "").lower() in {"1", "true", "yes"}
    if force:
        result = delete_snapshot_force(snapshot_id)
    else:
        result = delete_snapshot(snapshot_id)
    if result.get("error"):
        code = 404 if result["error"] == "snapshot_not_found" else 409
        return jsonify(result), code
    return jsonify(result), 200


@scenario_snapshot_bp.route("/api/scenario-snapshot/snapshots/<snapshot_id>/verify-nodes", methods=["POST"])
def api_verify_nodes(snapshot_id: str):
    """Trigger live SSH node verification and update the snapshot."""
    _bg_thread_local = threading.Thread(
        target=lambda: verify_nodes_live(snapshot_id), daemon=True
    )
    _bg_thread_local.start()
    return jsonify({"status": "VERIFYING", "snapshot_id": snapshot_id,
                    "message": "Live node verification started in background."}), 202
