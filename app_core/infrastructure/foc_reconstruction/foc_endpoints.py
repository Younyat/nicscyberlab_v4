import logging
import json
import time
import threading

from flask import Blueprint, Response, jsonify, request

from .foc_case_analysis import (
    analysis_logs,
    analysis_report,
    analysis_visual_summary,
    cases_with_analysis_state,
    load_time_sync_status,
    load_analysis_status,
    run_analysis,
    run_time_sync,
    validate_analysis,
    generate_symbols_for_case,
)
from .foc_case_analysis import _analysis_cancel_path, get_case_entry, _case_dir_from_entry
from .foc_config import GENERATED_FILES
from .foc_bootstrap import bootstrap_existing_context, read_id_mapping
from .foc_events import iter_events_since, safe_notify_foc, snapshot_watch_state
from .foc_manifest_manager import read_generated_json, regenerate_foc
from .foc_quality import build_gaps, build_status, load_quality_context
from .foc_paths import project_path
from .foc_sources import utc_now
from .evidence_lifecycle_dashboard import (
    generate_evidence_lifecycle_summary,
    get_lifecycle_job,
    load_evidence_lifecycle_dashboard,
    report_file_payload,
    report_index_payload,
    start_full_lifecycle_job,
    start_summary_job,
)
from .evidence_support.service import (
    load_claimability_report,
    load_counter_evidence_report,
    load_evidence_atoms,
    load_evidence_support_status,
    load_forensic_storyline,
    load_hypothesis_support_report,
    start_evidence_support_job,
)
from ..foc_causal_reconstruction.service import (
    causal_graph_payload,
    causal_graph_summary_payload,
    causal_metrics_payload,
    causal_report_payload,
    causal_status_payload,
    causal_uncertainty_payload,
    run_causal_reconstruction,
)
from ..forensics.volatility_symbols import (
    get_job as get_vol3_job,
    start_symbol_generation_job,
    symbols_inventory_payload,
)

logger = logging.getLogger(__name__)

foc_bp = Blueprint("foc_reconstruction", __name__)
FOC_STREAM_POLL_INTERVAL_SECONDS = 5.0
FOC_AUTO_REFRESH_MIN_INTERVAL_SECONDS = 30.0
FOC_DASHBOARD_CACHE_TTL_SECONDS = 5.0
_FOC_DASHBOARD_CACHE_LOCK = threading.Lock()
_FOC_DASHBOARD_CACHE = {
    "ts": 0.0,
    "payload": None,
}


def _build_dashboard_payload(force: bool = False) -> dict:
    now = time.time()
    with _FOC_DASHBOARD_CACHE_LOCK:
        cached_payload = _FOC_DASHBOARD_CACHE.get("payload")
        cached_ts = float(_FOC_DASHBOARD_CACHE.get("ts") or 0.0)
        if not force and cached_payload is not None and (now - cached_ts) < FOC_DASHBOARD_CACHE_TTL_SECONDS:
            return cached_payload

    started = time.perf_counter()
    context = load_quality_context()
    payload = {
        "status": build_status(context=context),
        "manifest": context.get("manifest"),
        "scenario": context.get("scenario_bom"),
        "tools": context.get("tools_bom"),
        "timeline": context.get("timeline"),
        "gaps": build_gaps(context=context),
        "sources": context.get("sources"),
        "relationships": context.get("relationships"),
        "artifacts": read_generated_json(GENERATED_FILES["artifacts_index"]),
        "cases": read_generated_json(GENERATED_FILES["cases_index"]),
        "generated_at": time.time(),
        "render_hint": {
            "cache_ttl_seconds": FOC_DASHBOARD_CACHE_TTL_SECONDS,
            "build_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    }

    with _FOC_DASHBOARD_CACHE_LOCK:
        _FOC_DASHBOARD_CACHE["ts"] = now
        _FOC_DASHBOARD_CACHE["payload"] = payload
    return payload


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
    return jsonify(cases_with_analysis_state()), 200


@foc_bp.route("/api/foc/cases/<case_id>/analysis-status", methods=["GET"])
def api_foc_case_analysis_status(case_id: str):
    payload = load_analysis_status(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/cases/<case_id>/analysis/run", methods=["POST"])
def api_foc_case_analysis_run(case_id: str):
    force_arg = str(request.args.get("force", "false")).strip().lower()
    force = force_arg in {"1", "true", "yes", "on"}
    payload = run_analysis(case_id, force=force)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("error") == "analysis_already_running":
        return jsonify(payload), 409
    return jsonify(payload), 202


@foc_bp.route("/api/foc/cases/<case_id>/analysis/logs", methods=["GET"])
def api_foc_case_analysis_logs(case_id: str):
    payload = analysis_logs(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/cases/<case_id>/analysis/report", methods=["GET"])
def api_foc_case_analysis_report(case_id: str):
    payload = analysis_report(case_id)
    if payload is None:
        return jsonify({"error": "analysis_report_not_found", "case_id": case_id}), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/cases/<case_id>/analysis/visual-summary", methods=["GET"])
def api_foc_case_analysis_visual_summary(case_id: str):
    payload = analysis_visual_summary(case_id)
    if payload is None:
        return jsonify({"error": "analysis_visual_summary_not_found", "case_id": case_id}), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/cases/<case_id>/time-sync/status", methods=["GET"])
def api_foc_case_time_sync_status(case_id: str):
    payload = load_time_sync_status(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/cases/<case_id>/time-sync/run", methods=["POST"])
def api_foc_case_time_sync_run(case_id: str):
    body = request.get_json(silent=True) or {}
    payload = run_time_sync(
        case_id,
        fix_time=bool(body.get("fix_time")),
        threshold_ms=int(body["threshold_ms"]) if body.get("threshold_ms") is not None else None,
        maintenance_override=bool(body.get("maintenance_override")),
    )
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("status") == "blocked_policy":
        return jsonify(payload), 409
    return jsonify(payload), 202 if payload.get("status") == "running" else 200


@foc_bp.route("/api/foc/time-sync/measure", methods=["POST"])
def api_foc_time_sync_measure():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = run_time_sync(case_id, fix_time=False, maintenance_override=False)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 202 if payload.get("status") == "running" else 200


@foc_bp.route("/api/foc/time-sync/fix", methods=["POST"])
def api_foc_time_sync_fix():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = run_time_sync(
        case_id,
        fix_time=True,
        threshold_ms=int(body["threshold_ms"]) if body.get("threshold_ms") is not None else None,
        maintenance_override=bool(body.get("maintenance_override")),
    )
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("status") == "blocked_policy":
        return jsonify(payload), 409
    return jsonify(payload), 202 if payload.get("status") == "running" else 200


def _causal_case_entry_or_404(case_id: str):
    entry = get_case_entry(case_id)
    if not entry:
        return None, (jsonify({"error": "case_not_found", "case_id": case_id}), 404)
    try:
        case_dir = _case_dir_from_entry(entry)
    except Exception as exc:
        return None, (jsonify({"error": "case_path_unavailable", "case_id": case_id, "reason": str(exc)}), 500)
    return (entry, case_dir), None


@foc_bp.route("/api/foc/causal/status", methods=["GET"])
def api_foc_causal_status():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    return jsonify(causal_status_payload(case_id, case_dir)), 200


@foc_bp.route("/api/foc/causal/run", methods=["POST"])
def api_foc_causal_run():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    result = run_causal_reconstruction(
        case_id=case_id,
        case_path=case_dir,
        strict=bool(body.get("strict")),
        degraded_ok=bool(body.get("degraded_ok")),
        ground_truth_path=body.get("ground_truth_path"),
        out_dir=body.get("out_dir"),
    )
    http_code = 202 if result.get("status") == "running" else 200
    return jsonify(result), http_code


@foc_bp.route("/api/foc/evidence-lifecycle-dashboard", methods=["GET"])
def api_foc_evidence_lifecycle_dashboard():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = load_evidence_lifecycle_dashboard(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-lifecycle-dashboard/generate", methods=["POST"])
def api_foc_evidence_lifecycle_dashboard_generate():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = start_summary_job(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 202


@foc_bp.route("/api/foc/lifecycle/run-multilayer-analysis", methods=["POST"])
def api_foc_lifecycle_run_multilayer_analysis():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    force = bool(body.get("force"))
    payload = run_analysis(case_id, force=force)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("error") == "analysis_already_running":
        return jsonify(payload), 409
    return jsonify(payload), 202


@foc_bp.route("/api/foc/lifecycle/run-causal", methods=["POST"])
def api_foc_lifecycle_run_causal():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    result = run_causal_reconstruction(
        case_id=case_id,
        case_path=case_dir,
        strict=bool(body.get("strict")),
        degraded_ok=bool(body.get("degraded_ok", True)),
        ground_truth_path=body.get("ground_truth_path"),
        out_dir=body.get("out_dir"),
    )
    http_code = 202 if result.get("status") == "running" else 200
    return jsonify(result), http_code


@foc_bp.route("/api/foc/causal/run-all", methods=["POST"])
def api_foc_causal_run_all():
    import time
    import math
    from .foc_case_analysis import _list_case_entries

    entries = _list_case_entries()
    if not entries:
        return jsonify({"error": "no_cases_indexed"}), 404

    # Trigger reconstruction for every case
    running_pairs = []
    results_map: dict = {}
    for entry in entries:
        cid = str(entry.get("case_id") or "").strip()
        if not cid:
            continue
        try:
            case_dir = _case_dir_from_entry(entry)
        except Exception:
            results_map[cid] = {"case_id": cid, "state": "error", "error": "path_unavailable"}
            continue
        res = run_causal_reconstruction(case_id=cid, case_path=case_dir, degraded_ok=True)
        results_map[cid] = (res, case_dir)
        if (res.get("status") or res.get("state") or "") in ("running", "queued"):
            running_pairs.append((cid, case_dir))

    # Poll running jobs (max 45 s each, check every 300 ms)
    if running_pairs:
        deadline = time.time() + 45
        remaining = list(running_pairs)
        while remaining and time.time() < deadline:
            time.sleep(0.3)
            still = []
            for cid, case_dir in remaining:
                st = causal_status_payload(cid, case_dir)
                state = st.get("state") or st.get("status") or ""
                if state in ("running", "queued", ""):
                    still.append((cid, case_dir))
                else:
                    results_map[cid] = (st, case_dir)
            remaining = still

    # Build per-case summary + aggregate
    per_case = []
    cprs, wcprs = [], []

    # Stable edge display order
    _edge_label_map = {
        "edge_attack_execution_to_ot_write": "e1",
        "edge_ot_write_to_network_modbus_write": "e2",
        "edge_network_modbus_write_to_detection_surface": "e3",
        "edge_ot_write_to_plc_state_observation": "e4",
        "edge_detection_surface_to_alert_observation": "e5",
        "edge_alert_observation_to_forensic_case": "e6",
        "edge_forensic_case_to_preserved_case_evidence": "e7",
        "edge_preserved_case_evidence_to_multilayer_analysis": "e8",
    }

    for entry in entries:
        cid = str(entry.get("case_id") or "").strip()
        val = results_map.get(cid)
        if not val or isinstance(val, dict) and val.get("error"):
            per_case.append({"case_id": cid, "source_case_name": entry.get("source_case_name"), "state": "error"})
            continue

        result, case_dir = val if isinstance(val, tuple) else (val, None)
        mp = result.get("metrics_preview") or {}
        cpr = mp.get("causal_path_recoverability")
        wcpr = mp.get("weighted_cpr")
        if cpr is not None:
            cprs.append(cpr)
        if wcpr is not None:
            wcprs.append(wcpr)

        # Read edge states from causal_graph.json
        edge_states: dict = {}
        if case_dir is not None:
            try:
                import json as _json
                cg_path = case_dir / "derived" / "reconstruction" / "causal_graph.json"
                if cg_path.is_file():
                    cg = _json.loads(cg_path.read_text(encoding="utf-8"))
                    for e in (cg.get("edges") or []):
                        label = _edge_label_map.get(e.get("edge_id") or "")
                        if label:
                            edge_states[label] = e.get("support_status") or "unknown"
            except Exception:
                pass

        per_case.append({
            "case_id": cid,
            "source_case_name": entry.get("source_case_name"),
            "state": result.get("state") or result.get("status"),
            "cpr": cpr,
            "wcpr": wcpr,
            "recovered_edges": mp.get("recovered_edges"),
            "ambiguous_edges": mp.get("ambiguous_edges"),
            "degraded_edges": mp.get("degraded_edges"),
            "missing_edges": mp.get("missing_edges"),
            "expected_edges": mp.get("expected_edges"),
            "edge_states": edge_states,
        })

    n = len(cprs)
    mean_cpr = sum(cprs) / n if n else None
    sigma_cpr = math.sqrt(sum((x - mean_cpr) ** 2 for x in cprs) / n) if n else None
    mean_wcpr = sum(wcprs) / len(wcprs) if wcprs else None

    return jsonify({
        "status": "completed",
        "case_count": len(entries),
        "completed_count": n,
        "mean_cpr": mean_cpr,
        "sigma_cpr": sigma_cpr,
        "mean_wcpr": mean_wcpr,
        "per_case": per_case,
    }), 200


@foc_bp.route("/api/foc/lifecycle/run-full", methods=["POST"])
def api_foc_lifecycle_run_full():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = start_full_lifecycle_job(
        case_id,
        force_analysis=bool(body.get("force_analysis")),
        strict=bool(body.get("strict")),
        degraded_ok=bool(body.get("degraded_ok", True)),
    )
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 202


@foc_bp.route("/api/foc/lifecycle/generate-summary", methods=["POST"])
def api_foc_lifecycle_generate_summary():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = start_summary_job(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 202


@foc_bp.route("/api/foc/lifecycle/job-status", methods=["GET"])
def api_foc_lifecycle_job_status():
    job_id = str(request.args.get("job_id") or "").strip()
    if not job_id:
        return jsonify({"error": "missing_job_id"}), 400
    payload = get_lifecycle_job(job_id)
    if not payload:
        return jsonify({"error": "job_not_found", "job_id": job_id}), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/reports/index", methods=["GET"])
def api_foc_reports_index():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = report_index_payload(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/reports/file", methods=["GET"])
def api_foc_reports_file():
    case_id = str(request.args.get("case_id") or "").strip()
    report_type = str(request.args.get("type") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    if not report_type:
        return jsonify({"error": "missing_report_type"}), 400
    payload = report_file_payload(case_id, report_type)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("error") in {"report_type_not_supported", "report_not_found"}:
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-support/run", methods=["POST"])
def api_foc_evidence_support_run():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = start_evidence_support_job(case_id, force=False)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("error") == "evidence_support_already_running":
        return jsonify(payload), 409
    if payload.get("status") == "already_current":
        return jsonify(payload), 200
    return jsonify(payload), 202


@foc_bp.route("/api/foc/evidence-support/regenerate", methods=["POST"])
def api_foc_evidence_support_regenerate():
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = start_evidence_support_job(case_id, force=True)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    if payload.get("error") == "evidence_support_already_running":
        return jsonify(payload), 409
    return jsonify(payload), 202


@foc_bp.route("/api/foc/evidence-support/status", methods=["GET"])
def api_foc_evidence_support_status():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = load_evidence_support_status(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-support/report", methods=["GET"])
def api_foc_evidence_support_report():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = load_hypothesis_support_report(case_id)
    if payload.get("error") in {"case_not_found", "not_generated"}:
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-support/storyline", methods=["GET"])
def api_foc_evidence_support_storyline():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = load_forensic_storyline(case_id)
    if payload.get("error") in {"case_not_found", "not_generated"}:
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-support/claimability", methods=["GET"])
def api_foc_evidence_support_claimability():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = load_claimability_report(case_id)
    if payload.get("error") in {"case_not_found", "not_generated"}:
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-support/counter-evidence", methods=["GET"])
def api_foc_evidence_support_counter_evidence():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload = load_counter_evidence_report(case_id)
    if payload.get("error") in {"case_not_found", "not_generated"}:
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/evidence-support/atoms", methods=["GET"])
def api_foc_evidence_support_atoms():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    limit_raw = request.args.get("limit")
    limit = int(limit_raw) if limit_raw and limit_raw.isdigit() else 200
    payload = load_evidence_atoms(case_id, limit=limit)
    if payload.get("error") in {"case_not_found", "not_generated"}:
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/causal/report", methods=["GET"])
def api_foc_causal_report():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    report = causal_report_payload(case_id, case_dir)
    if report is None:
        return jsonify({"error": "causal_report_not_found", "case_id": case_id}), 404
    return jsonify(report), 200


@foc_bp.route("/api/foc/causal/metrics", methods=["GET"])
def api_foc_causal_metrics():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    report = causal_metrics_payload(case_id, case_dir)
    if report is None:
        return jsonify({"error": "causal_metrics_not_found", "case_id": case_id}), 404
    return jsonify(report), 200


@foc_bp.route("/api/foc/causal/graph", methods=["GET"])
def api_foc_causal_graph():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    report = causal_graph_payload(case_id, case_dir)
    if report is None:
        return jsonify({"error": "causal_graph_not_found", "case_id": case_id}), 404
    return jsonify(report), 200


@foc_bp.route("/api/foc/causal/uncertainty", methods=["GET"])
def api_foc_causal_uncertainty():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    report = causal_uncertainty_payload(case_id, case_dir)
    if report is None:
        return jsonify({"error": "causal_uncertainty_not_found", "case_id": case_id}), 404
    return jsonify(report), 200


@foc_bp.route("/api/foc/causal/graph-summary", methods=["GET"])
def api_foc_causal_graph_summary():
    case_id = str(request.args.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"error": "missing_case_id"}), 400
    payload, error = _causal_case_entry_or_404(case_id)
    if error:
        return error
    _, case_dir = payload
    report = causal_graph_summary_payload(case_id, case_dir)
    if report is None:
        return jsonify({"error": "causal_graph_summary_not_found", "case_id": case_id}), 404
    return jsonify(report), 200


@foc_bp.route("/api/foc/cases/<case_id>/analysis/validate", methods=["POST"])
def api_foc_case_analysis_validate(case_id: str):
    payload = validate_analysis(case_id)
    if payload.get("error") == "case_not_found":
        return jsonify(payload), 404
    return jsonify(payload), 200


@foc_bp.route("/api/foc/cases/<case_id>/analysis/cancel", methods=["POST"])
def api_foc_case_analysis_cancel(case_id: str):
    # create a cancellation request file that the running analysis will observe
    entry = get_case_entry(case_id)
    if not entry:
        return jsonify({"error": "case_not_found", "case_id": case_id}), 404
    try:
        case_dir = _case_dir_from_entry(entry)
    except Exception:
        case_dir = None
    if not case_dir:
        return jsonify({"error": "case_path_unavailable", "case_id": case_id}), 500
    cancel_path = _analysis_cancel_path(case_dir)
    try:
        cancel_path.parent.mkdir(parents=True, exist_ok=True)
        cancel_path.write_text(utc_now(), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to request analysis cancel: %s", exc, exc_info=True)
        return jsonify({"error": "cancel_request_failed", "reason": str(exc)}), 500
    return jsonify({"result": "cancellation_requested", "case_id": case_id, "cancel_path": str(cancel_path)}), 200


@foc_bp.route("/api/foc/cases/<case_id>/symbols/generate", methods=["POST"])
def api_foc_generate_symbols(case_id: str):
    body = request.get_json(silent=True) or {}
    memory_artifact_id = body.get("memory_artifact_id") or body.get("dump_id")
    overwrite = bool(body.get("overwrite"))
    mode = (body.get("mode") or "manual").strip() or "manual"
    try:
        job = start_symbol_generation_job(
            case_id=case_id,
            memory_artifact_id=memory_artifact_id,
            overwrite=overwrite,
            mode=mode,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc), "case_id": case_id}), 404
    except Exception as exc:
        logger.warning("Failed to start FOC symbol generation: %s", exc, exc_info=True)
        return jsonify({"error": str(exc), "case_id": case_id}), 500
    return jsonify(job), 202


@foc_bp.route("/api/foc/cases/<case_id>/symbols/status", methods=["GET"])
def api_foc_symbols_status(case_id: str):
    return jsonify(symbols_inventory_payload(case_id=case_id)), 200


@foc_bp.route("/api/foc/cases/<case_id>/symbols/jobs/<job_id>", methods=["GET"])
def api_foc_symbols_job(case_id: str, job_id: str):
    job = get_vol3_job(job_id)
    if not job:
        return jsonify({"error": "job_not_found", "job_id": job_id, "case_id": case_id}), 404
    return jsonify(job), 200


@foc_bp.route("/api/foc/id-mapping", methods=["GET"])
def api_foc_id_mapping():
    return _read_or_404("id_mapping")


@foc_bp.route("/api/foc/attack-attestation", methods=["GET"])
def api_foc_attack_attestation():
    return _read_or_404("attack_attestation")


@foc_bp.route("/api/foc/detection-attestation", methods=["GET"])
def api_foc_detection_attestation():
    return _read_or_404("detection_attestation")


@foc_bp.route("/api/foc/alerts-normalized", methods=["GET"])
def api_foc_alerts_normalized():
    return _read_or_404("alerts_normalized")


@foc_bp.route("/api/foc/alert-correlation", methods=["GET"])
def api_foc_alert_correlation():
    full_arg = str(request.args.get("full", "false")).strip().lower()
    path_key = "alert_correlation" if full_arg in {"1", "true", "yes", "on"} else "alert_correlation_summary"
    return _read_or_404(path_key)


@foc_bp.route("/api/foc/alert-correlation-summary", methods=["GET"])
def api_foc_alert_correlation_summary():
    return _read_or_404("alert_correlation_summary")


@foc_bp.route("/api/foc/acquisition-profile", methods=["GET"])
def api_foc_acquisition_profile():
    return _read_or_404("acquisition_profile")


@foc_bp.route("/api/foc/forensic-intervention", methods=["GET"])
def api_foc_forensic_intervention():
    return _read_or_404("forensic_intervention")


@foc_bp.route("/api/foc/forensic-analysis-manifest", methods=["GET"])
def api_foc_forensic_analysis_manifest():
    return _read_or_404("forensic_analysis_manifest")


@foc_bp.route("/api/foc/scenario-ground-truth", methods=["GET"])
def api_foc_scenario_ground_truth():
    return _read_or_404("scenario_ground_truth")


@foc_bp.route("/api/foc/case-manifest-link", methods=["GET"])
def api_foc_case_manifest_link():
    return _read_or_404("case_manifest_link")


@foc_bp.route("/api/foc/context-summary", methods=["GET"])
def api_foc_context_summary():
    return _read_or_404("foc_context_summary")


@foc_bp.route("/api/foc/readiness-report", methods=["GET"])
def api_foc_readiness_report():
    return _read_or_404("foc_readiness_report")


@foc_bp.route("/api/foc/status", methods=["GET"])
def api_foc_status():
    return jsonify(_build_dashboard_payload().get("status") or {}), 200


@foc_bp.route("/api/foc/gaps", methods=["GET"])
def api_foc_gaps():
    return jsonify(_build_dashboard_payload().get("gaps") or {}), 200


@foc_bp.route("/api/foc/dashboard", methods=["GET"])
def api_foc_dashboard():
    force_arg = str(request.args.get("force", "false")).strip().lower()
    force = force_arg in {"1", "true", "yes", "on"}
    return jsonify(_build_dashboard_payload(force=force)), 200


@foc_bp.route("/api/foc/bootstrap", methods=["POST"])
def api_foc_bootstrap():
    force_arg = str(request.args.get("force", "false")).strip().lower()
    force = force_arg in {"1", "true", "yes", "on"}
    try:
        result = bootstrap_existing_context(force=force)
        if result.get("status") == "already_initialized":
            return jsonify(result), 200
        # force=True: a real bootstrap just happened -- this must reflect
        # it, never silently skip via regenerate_foc()'s new short-TTL guard
        # (see that function's docstring).
        manifest = regenerate_foc(bootstrap_mode=True, force=True)
        with _FOC_DASHBOARD_CACHE_LOCK:
            _FOC_DASHBOARD_CACHE["ts"] = 0.0
            _FOC_DASHBOARD_CACHE["payload"] = None
        return jsonify({"result": "ok", "bootstrap": result, "manifest": manifest}), 200
    except Exception as exc:
        logger.warning("FOC bootstrap failed: %s", exc, exc_info=True)
        return jsonify({"result": "error", "warning": str(exc)}), 500


@foc_bp.route("/api/foc/regenerate", methods=["POST"])
def api_foc_regenerate():
    try:
        current_manifest = read_generated_json(GENERATED_FILES["manifest"]) or {}
        # force=True: this IS the user-facing "Regenerate" button -- it must
        # always do real, fresh work, never the short-TTL skip meant only
        # for the back-to-back pipeline calls (see regenerate_foc()'s docstring).
        manifest = regenerate_foc(bootstrap_mode=bool(current_manifest.get("bootstrap_mode")), force=True)
        with _FOC_DASHBOARD_CACHE_LOCK:
            _FOC_DASHBOARD_CACHE["ts"] = 0.0
            _FOC_DASHBOARD_CACHE["payload"] = None
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
                        # force=True: this path only runs when snapshot_watch_state()
                        # detected a REAL change (plus its own
                        # FOC_AUTO_REFRESH_MIN_INTERVAL_SECONDS rate limit) --
                        # it must reflect that change, not skip it.
                        manifest = regenerate_foc(bootstrap_mode=bool((read_generated_json(GENERATED_FILES['manifest']) or {}).get('bootstrap_mode')), force=True)
                        with _FOC_DASHBOARD_CACHE_LOCK:
                            _FOC_DASHBOARD_CACHE["ts"] = 0.0
                            _FOC_DASHBOARD_CACHE["payload"] = None
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
