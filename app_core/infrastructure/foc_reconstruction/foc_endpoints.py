import logging
import json
import time

from flask import Blueprint, Response, jsonify, request

from .foc_config import GENERATED_FILES
from .foc_bootstrap import bootstrap_existing_context, read_id_mapping
from .foc_events import iter_events_since, safe_notify_foc, snapshot_watch_state
from .foc_manifest_manager import read_generated_json, regenerate_foc
from .foc_quality import build_gaps, build_status

logger = logging.getLogger(__name__)

foc_bp = Blueprint("foc_reconstruction", __name__)
FOC_STREAM_POLL_INTERVAL_SECONDS = 5.0
FOC_AUTO_REFRESH_MIN_INTERVAL_SECONDS = 30.0


def _read_or_404(path_key: str):
    payload = read_generated_json(GENERATED_FILES[path_key])
    if payload is None:
        return jsonify(
            {
                "error": "FOC artifact not generated",
                "artifact": path_key,
                "hint": "Call POST /api/foc/regenerate first.",
            }
        ), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/manifest", methods=["GET"])
def api_foc_manifest():
    return _read_or_404("manifest")


@foc_bp.route("/api/foc/scenario-bom", methods=["GET"])
def api_foc_scenario_bom():
    return _read_or_404("scenario_bom")


@foc_bp.route("/api/foc/tools-bom", methods=["GET"])
def api_foc_tools_bom():
    return _read_or_404("tools_bom")


@foc_bp.route("/api/foc/timeline", methods=["GET"])
def api_foc_timeline():
    return _read_or_404("timeline")


@foc_bp.route("/api/foc/sources", methods=["GET"])
def api_foc_sources():
    return _read_or_404("sources_index")


@foc_bp.route("/api/foc/relationships", methods=["GET"])
def api_foc_relationships():
    return _read_or_404("relationships_index")


@foc_bp.route("/api/foc/artifacts", methods=["GET"])
def api_foc_artifacts():
    return _read_or_404("artifacts_index")


@foc_bp.route("/api/foc/cases", methods=["GET"])
def api_foc_cases():
    return _read_or_404("cases_index")


@foc_bp.route("/api/foc/id-mapping", methods=["GET"])
def api_foc_id_mapping():
    return _read_or_404("id_mapping")


@foc_bp.route("/api/foc/status", methods=["GET"])
def api_foc_status():
    return jsonify(build_status()), 200


@foc_bp.route("/api/foc/gaps", methods=["GET"])
def api_foc_gaps():
    return jsonify(build_gaps()), 200


@foc_bp.route("/api/foc/bootstrap", methods=["POST"])
def api_foc_bootstrap():
    force_arg = str(request.args.get("force", "false")).strip().lower()
    force = force_arg in {"1", "true", "yes", "on"}
    try:
        result = bootstrap_existing_context(force=force)
        if result.get("status") == "already_initialized":
            return jsonify(result), 200
        manifest = regenerate_foc(bootstrap_mode=True)
        return jsonify({"result": "ok", "bootstrap": result, "manifest": manifest}), 200
    except Exception as exc:
        logger.warning("FOC bootstrap failed: %s", exc, exc_info=True)
        return jsonify({"result": "error", "warning": str(exc)}), 500


@foc_bp.route("/api/foc/regenerate", methods=["POST"])
def api_foc_regenerate():
    try:
        current_manifest = read_generated_json(GENERATED_FILES["manifest"]) or {}
        manifest = regenerate_foc(bootstrap_mode=bool(current_manifest.get("bootstrap_mode")))
        return jsonify({"result": "ok", "manifest": manifest}), 200
    except Exception as exc:
        logger.warning("FOC regeneration failed: %s", exc, exc_info=True)
        return jsonify({"result": "error", "warning": str(exc)}), 500


@foc_bp.route("/api/foc/events/stream", methods=["GET"])
def api_foc_events_stream():
    def event_stream():
        last_offset = 0
        last_watch = snapshot_watch_state()
        pending_watch = None
        pending_changed: list[str] = []
        last_regen_ts = 0.0
        yield f"event: snapshot\ndata: {json.dumps({'status': build_status(), 'ts_utc': time.time()})}\n\n"
        while True:
            try:
                entries, last_offset_new = iter_events_since(last_offset)
                for entry in entries:
                    yield f"event: foc_event\ndata: {json.dumps(entry)}\n\n"
                last_offset = last_offset_new

                current_watch = snapshot_watch_state()
                if current_watch != last_watch:
                    pending_watch = current_watch
                    pending_changed = [key for key, value in current_watch.items() if last_watch.get(key) != value]

                if pending_watch is not None and (time.time() - last_regen_ts) >= FOC_AUTO_REFRESH_MIN_INTERVAL_SECONDS:
                    try:
                        manifest = regenerate_foc(bootstrap_mode=bool((read_generated_json(GENERATED_FILES['manifest']) or {}).get('bootstrap_mode')))
                        safe_notify_foc("foc_auto_refresh", {"changed_sources": pending_changed, "scenario_id": manifest.get("scenario_id", "unknown")})
                        yield f"event: foc_refresh\ndata: {json.dumps({'changed_sources': pending_changed, 'status': build_status()})}\n\n"
                        last_watch = pending_watch
                        pending_watch = None
                        pending_changed = []
                        last_regen_ts = time.time()
                    except Exception as exc:
                        logger.warning("FOC auto refresh failed: %s", exc, exc_info=True)
                        yield f"event: degraded\ndata: {json.dumps({'warning': str(exc)})}\n\n"

                yield f"event: heartbeat\ndata: {json.dumps({'ts_utc': time.time()})}\n\n"
                time.sleep(FOC_STREAM_POLL_INTERVAL_SECONDS)
            except GeneratorExit:
                break
            except Exception as exc:
                logger.warning("FOC stream failed: %s", exc, exc_info=True)
                yield f"event: degraded\ndata: {json.dumps({'warning': str(exc)})}\n\n"
                time.sleep(3)

    return Response(event_stream(), mimetype="text/event-stream")
