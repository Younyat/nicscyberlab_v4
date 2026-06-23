from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

from .foc_case_analysis import (
    _case_dir_from_entry,
    analysis_visual_summary,
    get_case_entry,
    load_analysis_status,
    load_time_sync_status,
    run_analysis,
    run_time_sync,
)
from .foc_config import GENERATED_FILES
from .foc_manifest_manager import read_generated_json
from .foc_paths import relative_path
from .foc_sources import utc_now
from ..foc_causal_reconstruction.service import (
    causal_metrics_payload,
    causal_status_payload,
    causal_uncertainty_payload,
    run_causal_reconstruction,
    summarize_case_causal_state,
)

logger = logging.getLogger(__name__)

_EXEC_MAX_PREVIEW_BYTES = 1024 * 1024
_POLL_SECONDS = 2.5
_JOB_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}
_RUNNING_JOB_THREADS: dict[str, threading.Thread] = {}


def _json_load(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)
    tmp.replace(path)


def _read_text(path: Path, limit_bytes: int | None = None) -> tuple[str, bool]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            if limit_bytes is None:
                return fh.read(), False
            content = fh.read(limit_bytes + 1)
            if len(content) > limit_bytes:
                return content[:limit_bytes], True
            return content, False
    except Exception:
        return "", False


def _executive_dir(case_dir: Path) -> Path:
    return case_dir / "derived" / "executive"


def _summary_path(case_dir: Path) -> Path:
    return _executive_dir(case_dir) / "evidence_lifecycle_summary.json"


def _jobs_dir(case_dir: Path) -> Path:
    return _executive_dir(case_dir) / "jobs"


def _job_path(case_dir: Path, job_id: str) -> Path:
    return _jobs_dir(case_dir) / f"{job_id}.json"


def _mtime(path: Path) -> float:
    try:
        return float(path.stat().st_mtime)
    except Exception:
        return 0.0


def _mtime_iso(path: Path) -> str | None:
    ts = _mtime(path)
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _parse_ts(value) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    if normalized.endswith("+0000") or normalized.endswith("-0000"):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        from datetime import datetime

        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _duration_seconds(started_at, finished_at) -> float | None:
    start = _parse_ts(started_at)
    end = _parse_ts(finished_at)
    if start is None or end is None or end < start:
        return None
    return round(end - start, 3)


def _artifact_paths(case_dir: Path) -> dict[str, Path]:
    return {
        "executive_summary": _summary_path(case_dir),
        "forensic_analysis_report": case_dir / "analysis" / "forensic_analysis_report.json",
        "analysis_visual_summary": case_dir / "analysis" / "visual" / "analysis_visual_summary.json",
        "evidence_inventory": case_dir / "analysis" / "00_inventory" / "evidence_inventory.json",
        "integrity_custody_report": case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json",
        "clock_offset_report": case_dir / "analysis" / "02_time_validation" / "clock_offset_report.json",
        "network_findings": case_dir / "analysis" / "03_network" / "network_findings.json",
        "memory_findings": case_dir / "analysis" / "04_memory" / "memory_findings.json",
        "disk_findings": case_dir / "analysis" / "05_disk" / "disk_findings.json",
        "ot_findings": case_dir / "analysis" / "06_ot" / "ot_findings.json",
        "alert_findings": case_dir / "analysis" / "07_alerts" / "alert_findings.json",
        "pipeline_findings": case_dir / "analysis" / "08_pipeline_custody" / "pipeline_findings.json",
        "unified_forensic_timeline": case_dir / "analysis" / "09_timeline" / "unified_forensic_timeline.json",
        "cross_layer_findings": case_dir / "analysis" / "10_findings" / "cross_layer_findings.json",
        "causal_status": case_dir / "derived" / "reconstruction" / "causal_status.json",
        "causal_graph": case_dir / "derived" / "reconstruction" / "causal_graph.json",
        "reconstruction_metrics": case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json",
        "uncertainty_report": case_dir / "derived" / "reconstruction" / "uncertainty_report.json",
        "causal_edges_csv": case_dir / "derived" / "reconstruction" / "causal_edges.csv",
        "causal_reconstruction_report": case_dir / "derived" / "reconstruction" / "causal_reconstruction_report.md",
        "manifest": case_dir / "manifest.json",
        "chain_of_custody": case_dir / "chain_of_custody.log",
        "time_sync": case_dir / "metadata" / "time_sync.json",
        "time_sync_before": case_dir / "metadata" / "time_sync_before.json",
        "time_sync_after": case_dir / "metadata" / "time_sync_after.json",
    }


def _source_bundle() -> dict:
    return {
        "attack_attestation": read_generated_json(GENERATED_FILES["attack_attestation"]) or {},
        "detection_attestation": read_generated_json(GENERATED_FILES["detection_attestation"]) or {},
        "alert_correlation_summary": read_generated_json(GENERATED_FILES["alert_correlation_summary"]) or {},
        "forensic_intervention": read_generated_json(GENERATED_FILES["forensic_intervention"]) or {},
        "foc_context_summary": read_generated_json(GENERATED_FILES["foc_context_summary"]) or {},
        "foc_readiness_report": read_generated_json(GENERATED_FILES["foc_readiness_report"]) or {},
        "scenario_ground_truth": read_generated_json(GENERATED_FILES["scenario_ground_truth"]) or {},
        "case_manifest_link": read_generated_json(GENERATED_FILES["case_manifest_link"]) or {},
    }


def _pick_intervention(case_id: str, bundle: dict) -> dict:
    interventions = (bundle.get("forensic_intervention") or {}).get("interventions") or []
    for item in interventions:
        if str(item.get("case_id")) == str(case_id):
            return item
    return interventions[0] if interventions else {}


def _pick_attack(bundle: dict, ground_truth: dict) -> dict:
    attacks = (bundle.get("attack_attestation") or {}).get("attacks") or []
    expected = (ground_truth or {}).get("attack_expected") or {}
    selector = expected.get("selector") or {}
    attack_id = selector.get("attack_id")
    if attack_id:
        for attack in attacks:
            if str(attack.get("attack_id")) == str(attack_id):
                return attack
    technique_id = selector.get("mitre.technique_id") or expected.get("technique_id")
    protocol = selector.get("operation.protocol") or expected.get("protocol")
    for attack in attacks:
        attack_technique = str(((attack.get("mitre") or {}).get("technique_id")) or "")
        if technique_id and attack_technique != str(technique_id):
            continue
        attack_protocol = (((attack.get("operation") or {}).get("protocol")) or "")
        if protocol and str(attack_protocol) != str(protocol):
            continue
        return attack
    return attacks[0] if attacks else {}


def _timeline_mode_summary(case_dir: Path) -> dict:
    timeline = _json_load(case_dir / "analysis" / "09_timeline" / "unified_forensic_timeline.json") or {}
    entries = None
    if isinstance(timeline, dict):
        entries = timeline.get("entries")
        if not isinstance(entries, list):
            entries = timeline.get("findings")
    if not isinstance(entries, list):
        return {"available": False, "entries": 0}
    return {"available": True, "entries": len(entries)}


def _count_custody_events(case_dir: Path) -> int:
    try:
        if not (case_dir / "chain_of_custody.log").is_file():
            return 0
        return len([line for line in (case_dir / "chain_of_custody.log").read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()])
    except Exception:
        return 0


def _build_multilayer_summary(case_dir: Path, analysis_status: dict, visual_summary: dict, summary_path: Path) -> dict:
    phases = analysis_status.get("phases") or {}
    visual_layers = visual_summary.get("layer_statuses") or {}
    layers: list[dict] = []
    counter = Counter()
    useful_counter = Counter()

    for phase_key, phase_payload in phases.items():
        phase_payload = phase_payload or {}
        visual = visual_layers.get(phase_key) or {}
        status = str(phase_payload.get("status") or "not_started")
        effective = str(visual.get("effective_status") or ("failed" if status.startswith("failed") else "not_available"))
        usefulness = "not_available"
        if effective.startswith("completed_with_useful_output"):
            usefulness = "completed_with_useful_output"
        elif effective.startswith("completed_without_useful_output") or effective.startswith("completed_no_effective"):
            usefulness = "completed_without_useful_output"
        elif effective.startswith("partial"):
            usefulness = "partial_useful_output"
        elif status.startswith("failed"):
            usefulness = "failed"
        artifact_path = visual.get("artifact_path") or phase_payload.get("output_path")
        stdout_log = visual.get("stdout_log_path") or phase_payload.get("stdout_path")
        stderr_log = visual.get("stderr_log_path") or phase_payload.get("stderr_path")
        started_at = phase_payload.get("started_at")
        finished_at = phase_payload.get("finished_at")
        duration = _duration_seconds(started_at, finished_at)
        layer = {
            "layer_name": phase_payload.get("label") or visual.get("label") or phase_key,
            "phase": phase_key,
            "status": status,
            "usefulness_status": usefulness,
            "artifact_path": artifact_path,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration,
            "summary": visual.get("summary") or phase_payload.get("summary") or status.replace("_", " "),
            "stdout_log": stdout_log,
            "stderr_log": stderr_log,
            "error_message": phase_payload.get("error_message") or visual.get("warning"),
            "limitations": [item for item in [visual.get("short_limitation"), phase_payload.get("limitation")] if item],
        }
        layers.append(layer)
        counter[status] += 1
        useful_counter[usefulness] += 1

    summary_status = str(visual_summary.get("execution_status") or analysis_status.get("status") or "not_started")
    evidence_status = str(visual_summary.get("evidence_analysis_status") or "not_available")
    forensic_status = str(visual_summary.get("forensic_reconstruction_status") or "not_available")
    synthetic_status = "completed" if summary_path.exists() else "not_started"
    synthetic_usefulness = "completed_with_useful_output" if summary_path.exists() else "not_available"
    layers.append(
        {
            "layer_name": "Executive summary update",
            "phase": "executive_summary_update",
            "status": synthetic_status,
            "usefulness_status": synthetic_usefulness,
            "artifact_path": relative_path(summary_path) if summary_path.exists() else None,
            "started_at": None,
            "finished_at": utc_now() if summary_path.exists() else None,
            "duration_seconds": None,
            "summary": "Executive lifecycle summary generated." if summary_path.exists() else "Executive lifecycle summary not generated yet.",
            "stdout_log": None,
            "stderr_log": None,
            "error_message": None,
            "limitations": [] if summary_path.exists() else ["Generate the executive summary to expose the scientific decision surface."],
        }
    )

    counter[synthetic_status] += 1
    useful_counter[synthetic_usefulness] += 1
    report_payload = _json_load(case_dir / "analysis" / "forensic_analysis_report.json") or {}
    memory_findings = _json_load(case_dir / "analysis" / "04_memory" / "memory_findings.json") or {}
    disk_findings = _json_load(case_dir / "analysis" / "05_disk" / "disk_findings.json") or {}
    network_findings = _json_load(case_dir / "analysis" / "03_network" / "network_findings.json") or {}
    ot_findings = _json_load(case_dir / "analysis" / "06_ot" / "ot_findings.json") or {}
    alert_findings = _json_load(case_dir / "analysis" / "07_alerts" / "alert_findings.json") or {}
    cross_findings = _json_load(case_dir / "analysis" / "10_findings" / "cross_layer_findings.json") or {}
    timeline_info = _timeline_mode_summary(case_dir)
    memory_findings_block = (memory_findings.get("findings") or {}) if isinstance(memory_findings, dict) else {}
    return {
        "execution_status": summary_status,
        "evidence_analysis_status": evidence_status,
        "forensic_reconstruction_status": forensic_status,
        "analysis_confidence": visual_summary.get("confidence_state") or "unknown",
        "is_stale": False,
        "layers_expected": len(layers),
        "layers_completed": counter.get("completed", 0),
        "layers_with_useful_output": useful_counter.get("completed_with_useful_output", 0),
        "layers_partial": counter.get("partial", 0),
        "layers_failed": counter.get("failed", 0),
        "layers_skipped": counter.get("skipped", 0),
        "artifacts_indexed": ((report_payload.get("evidence_inventory") or {}).get("artifacts_indexed")) or ((visual_layers.get("evidence_inventory") or {}).get("summary") or "").replace("Artifacts indexed: ", "") or None,
        "pcaps_analyzed": ((network_findings.get("findings") or {}).get("pcaps_analyzed")) or 0,
        "memory_dumps_analyzed": (
            memory_findings_block.get("dumps_analyzed")
            or memory_findings.get("dumps_analysed")
            or (memory_findings.get("partial_findings") or {}).get("dumps_analysed")
            or 0
        ),
        "disk_images_analyzed": ((disk_findings.get("findings") or {}).get("disk_images_analyzed")) or 0,
        "ot_files_analyzed": len(((ot_findings.get("findings") or {}).get("files") or [])),
        "alerts_summarized": ((alert_findings.get("findings") or {}).get("alerts_total")) or 0,
        "timeline_entries": timeline_info.get("entries") or 0,
        "cross_layer_findings": len((cross_findings.get("findings") or [])) if isinstance(cross_findings.get("findings"), list) else ((cross_findings.get("summary") or {}).get("count") or 0),
        "report_path": analysis_status.get("forensic_analysis_report_path"),
        "main_limitation": visual_summary.get("main_limitation") or "No multilayer limitations reported.",
        "layers": layers,
    }


def _build_integrity_summary(case_dir: Path) -> dict:
    integrity = _json_load(case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json") or {}
    manifest_present = (case_dir / "manifest.json").is_file()
    custody_present = (case_dir / "chain_of_custody.log").is_file()
    artifact_count = len(((_json_load(case_dir / "manifest.json") or {}).get("artifacts")) or [])
    verification = integrity.get("verification") or {}
    return {
        "manifest_present": manifest_present,
        "chain_of_custody_present": custody_present,
        "custody_events": _count_custody_events(case_dir),
        "artifacts_declared": artifact_count,
        "overall_status": integrity.get("status") or ("completed" if manifest_present and custody_present else "partial"),
        "verified_artifacts": verification.get("verified_artifacts") or integrity.get("verified_artifacts"),
        "failed_artifacts": verification.get("failed_artifacts") or integrity.get("failed_artifacts"),
        "main_limitation": (integrity.get("limitations") or [None])[0],
        "artifact_path": relative_path(case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json") if (case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json").exists() else None,
    }


def _derive_temporal_sync_status(time_sync_payload: dict) -> str:
    raw = str(
        time_sync_payload.get("temporal_sync_status")
        or time_sync_payload.get("sync_status")
        or ((time_sync_payload.get("summary") or {}).get("temporal_sync_status"))
        or ((time_sync_payload.get("summary") or {}).get("sync_status"))
        or ""
    ).strip()
    if raw:
        return raw
    if time_sync_payload.get("error"):
        return "unknown"
    max_ms = (
        time_sync_payload.get("max_clock_offset_ms")
        or ((time_sync_payload.get("summary") or {}).get("max_clock_offset_ms"))
        or 0
    )
    try:
        max_ms = float(max_ms)
    except Exception:
        max_ms = 0.0
    if max_ms <= 1000:
        return "synchronized"
    if max_ms <= 5000:
        return "degraded"
    if max_ms > 0:
        return "not_synchronized"
    return "unknown"


def _build_uncertainty_summary(case_dir: Path, time_sync_status: dict, causal_uncertainty: dict) -> dict:
    temporal = (causal_uncertainty or {}).get("temporal") or {}
    summary = time_sync_status.get("summary") or {}
    max_offset_seconds = temporal.get("max_clock_offset_seconds")
    if max_offset_seconds is None:
        raw_ms = summary.get("max_clock_offset_ms") or time_sync_status.get("max_clock_offset_ms")
        try:
            max_offset_seconds = round(float(raw_ms) / 1000.0, 6)
        except Exception:
            max_offset_seconds = None
    source = temporal.get("time_sync_source") or ("preserved_case_metadata" if (case_dir / "metadata" / "time_sync.json").exists() else "current_measurement_unavailable")
    return {
        "temporal_confidence": temporal.get("temporal_confidence_state") or temporal.get("temporal_status") or "unknown",
        "max_clock_offset_seconds": max_offset_seconds,
        "uncertainty_window_seconds": temporal.get("uncertainty_window_seconds"),
        "synchronized_status": _derive_temporal_sync_status(time_sync_status),
        "correction_applied": bool(summary.get("correction_applied") or time_sync_status.get("fix_time_requested")),
        "nodes_measured": summary.get("nodes_ok") if summary.get("nodes_ok") is not None else time_sync_status.get("nodes_ok"),
        "nodes_failed": summary.get("nodes_failed") if summary.get("nodes_failed") is not None else time_sync_status.get("nodes_failed"),
        "worst_node": summary.get("worst_node") or time_sync_status.get("worst_node"),
        "time_sync_source": source,
        "current_measurement_status": time_sync_status.get("status") or "not_executed",
        "before_path": relative_path(case_dir / "metadata" / "time_sync_before.json") if (case_dir / "metadata" / "time_sync_before.json").exists() else None,
        "after_path": relative_path(case_dir / "metadata" / "time_sync_after.json") if (case_dir / "metadata" / "time_sync_after.json").exists() else None,
        "latest_path": relative_path(case_dir / "metadata" / "time_sync.json") if (case_dir / "metadata" / "time_sync.json").exists() else None,
        "main_limitation": temporal.get("temporal_warning") or temporal.get("temporal_caution"),
        "completeness": (causal_uncertainty or {}).get("completeness") or {},
        "integrity": (causal_uncertainty or {}).get("integrity") or {},
        "acquisition": (causal_uncertainty or {}).get("acquisition") or {},
    }


def _build_modbus_specificity(ground_truth: dict, attack: dict, network_findings: dict, ot_findings: dict, alert_findings: dict) -> dict:
    expected = (ground_truth or {}).get("attack_expected") or {}
    top_signatures = ((alert_findings.get("findings") or {}).get("top_signatures")) or {}
    signatures_joined = " ".join(str(key) for key in top_signatures.keys())
    modbus_seen = int((network_findings.get("findings") or {}).get("pcaps_analyzed") or 0) > 0 and any(
        int(item.get("modbus_frames") or 0) > 0 for item in ((network_findings.get("findings") or {}).get("files") or [])
    )
    function_codes = (((ot_findings.get("findings") or {}).get("function_codes")) or {})
    expected_fn = str(expected.get("modbus_function") or expected.get("ot_function") or "")
    protocol_state = "confirmed" if modbus_seen else "not_available"
    function_state = "partial"
    if expected_fn and expected_fn in function_codes:
        function_state = "confirmed"
    elif "write multiple registers" in signatures_joined.lower():
        function_state = "partial"
    elif modbus_seen:
        function_state = "not_available"
    register_state = "partial" if expected.get("register") not in {None, "not_available"} and modbus_seen else "not_available"
    value_state = "partial" if expected.get("expected_value") not in {None, "not_available"} and modbus_seen else "not_available"
    plc_state = "partial" if any(int(item.get("records") or 0) > 0 for item in (((ot_findings.get("findings") or {}).get("files")) or [])) else "not_available"
    return {
        "protocol": {"status": protocol_state, "value": expected.get("protocol") or ((attack.get("operation") or {}).get("protocol")) or "not_available"},
        "function_code": {"status": function_state, "value": expected.get("modbus_function") or expected.get("ot_function") or "not_available"},
        "register": {"status": register_state, "value": expected.get("register", "not_available")},
        "value": {"status": value_state, "value": expected.get("expected_value", "not_available")},
        "target_plc": {"status": "confirmed" if expected.get("target") else "not_available", "value": expected.get("target") or ((attack.get("target") or {}).get("instance_name")) or "not_available"},
        "plc_or_scada_state": {"status": plc_state, "value": "OT exports parsed" if plc_state != "not_available" else "not_available"},
        "message": "Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing." if modbus_seen and (register_state != "confirmed" or value_state != "confirmed") else None,
    }


def _resolve_real_ground_truth(causal_status: dict, fallback: dict) -> dict:
    # `bundle["scenario_ground_truth"]` is the preserved attestation snapshot,
    # which uses a different (scenario-graph-derived) schema with no
    # top-level `attack_expected` key. The causal reconstruction module
    # already resolved the real, attack_expected-bearing ground truth file
    # for this case; read that same file instead of guessing from the
    # wrong-schema snapshot, so attack selection and Modbus/target fields
    # are computed from the same source of truth the causal graph used.
    gt_path = (causal_status.get("ground_truth_summary") or {}).get("ground_truth_path")
    if gt_path:
        payload = _json_load(Path(gt_path))
        if isinstance(payload, dict) and payload.get("attack_expected"):
            return payload
    return fallback


def _build_causal_summary(case_dir: Path, bundle: dict, causal_status: dict, metrics: dict, uncertainty: dict, trigger_summary: dict) -> dict:
    ground_truth = _resolve_real_ground_truth(causal_status, bundle.get("scenario_ground_truth") or {})
    attack = _pick_attack(bundle, ground_truth)
    network_findings = _json_load(case_dir / "analysis" / "03_network" / "network_findings.json") or {}
    ot_findings = _json_load(case_dir / "analysis" / "06_ot" / "ot_findings.json") or {}
    alert_findings = _json_load(case_dir / "analysis" / "07_alerts" / "alert_findings.json") or {}
    attack_expected = ground_truth.get("attack_expected") or {}
    trigger_label = str(trigger_summary.get("trigger") or "")
    causal_technique = attack_expected.get("technique_id")
    causal_protocol = str(attack_expected.get("protocol") or "")
    causal_target = attack_expected.get("target")
    causal_attack_path_resolved = bool(causal_technique and causal_protocol and causal_target)
    same_event_family = None
    mismatch = None
    if not causal_attack_path_resolved:
        # Do not claim alignment - or misalignment - when the causal attack
        # path itself could not be resolved; that is a distinct, weaker claim.
        mismatch = "Trigger and causal attack path alignment cannot be confirmed from the current summary."
    elif trigger_label and "/" in trigger_label and causal_protocol.lower().startswith("modbus"):
        same_event_family = False
        mismatch = (
            "The acquisition trigger is host/FIM-oriented, while the causal reconstruction evaluates an OT "
            "Modbus path. These paths must be interpreted separately unless an explicit cross-layer link is available."
        )
    else:
        same_event_family = True
    return {
        "status": causal_status.get("status") or "not_available",
        "ground_truth_status": ((causal_status.get("ground_truth_summary") or {}).get("ground_truth_validation_status")) or ((causal_status.get("ground_truth_summary") or {}).get("ground_truth_status")) or "not_available",
        "expected_edges": metrics.get("expected_edges"),
        "recovered_edges": metrics.get("recovered_edges"),
        "degraded_edges": metrics.get("degraded_edges"),
        "ambiguous_edges": metrics.get("ambiguous_edges"),
        "missing_edges": metrics.get("missing_edges"),
        "cpr": metrics.get("causal_path_recoverability"),
        "weighted_cpr": metrics.get("weighted_cpr"),
        "reconstruction_confidence": metrics.get("reconstruction_confidence"),
        "reconstruction_state": causal_status.get("reconstruction_state") or causal_status.get("status") or "not_available",
        "causal_interpretation_confidence": causal_status.get("scientific_confidence") or "unknown",
        "main_limitation": metrics.get("main_limitation") or causal_status.get("reason"),
        "is_stale": bool(causal_status.get("is_stale")),
        "ground_truth_path": ((causal_status.get("ground_truth_summary") or {}).get("ground_truth_path")),
        "attack_expected": attack_expected,
        "selected_attack": {
            "attack_id": attack.get("attack_id"),
            "attack_name": attack.get("attack_name"),
            "technique_id": ((attack.get("mitre") or {}).get("technique_id")),
            "protocol": ((attack.get("operation") or {}).get("protocol")),
            "tool_used": ((attack.get("operation") or {}).get("tool_used")),
            "target": ((attack.get("target") or {}).get("instance_name")) or ((attack.get("target") or {}).get("node_name")),
            "execution_status": attack.get("execution_status") or "not_available",
        },
        "uncertainty_dependency": {
            "temporal_confidence": ((uncertainty.get("temporal") or {}).get("temporal_confidence_state")) or "unknown",
            "max_clock_offset_seconds": ((uncertainty.get("temporal") or {}).get("max_clock_offset_seconds")),
        },
        "trigger_vs_causal_path": {
            "trigger_path": trigger_label or "not_available",
            "trigger_rule_id": trigger_summary.get("triggering_alert_rule_id") or "not_available",
            "causal_attack_path": f"{attack_expected.get('technique_id', 'not_available')} {attack_expected.get('protocol', 'not_available')} -> {attack_expected.get('target', 'not_available')}",
            "same_event_family": same_event_family,
            "message": mismatch,
        },
        "modbus_specificity": _build_modbus_specificity(ground_truth, attack, network_findings, ot_findings, alert_findings),
    }


def _phase_status_from_bool(flag: bool, partial: bool = False, blocked: bool = False, stale: bool = False) -> str:
    if stale:
        return "stale"
    if blocked:
        return "blocked"
    if partial:
        return "completed_with_degradation"
    return "completed" if flag else "not_generated"


def _build_reports_index(case_dir: Path) -> list[dict]:
    entries = []
    for report_type, path in _artifact_paths(case_dir).items():
        exists = path.exists()
        size_bytes = None
        if exists:
            try:
                size_bytes = path.stat().st_size
            except OSError:
                exists = False
        entries.append(
            {
                "type": report_type,
                "path": relative_path(path),
                "exists": exists and size_bytes is not None,
                "size_bytes": size_bytes,
                "mtime": _mtime_iso(path) if exists else None,
            }
        )
    return entries


def _build_limitations_and_actions(summary: dict) -> tuple[list[str], list[str]]:
    limitations: list[str] = []
    actions: list[str] = []
    uncertainty = summary.get("uncertainty_summary") or {}
    multilayer = summary.get("multilayer_analysis_summary") or {}
    causal = summary.get("causal_summary") or {}
    integrity = summary.get("integrity_summary") or {}
    trigger_vs_causal = (causal.get("trigger_vs_causal_path") or {}).get("message")
    modbus = (causal.get("modbus_specificity") or {}).get("message")

    if multilayer.get("main_limitation"):
        limitations.append(str(multilayer.get("main_limitation")))
    if causal.get("main_limitation"):
        limitations.append(str(causal.get("main_limitation")))
    if uncertainty.get("main_limitation"):
        limitations.append(str(uncertainty.get("main_limitation")))
    if trigger_vs_causal:
        limitations.append(trigger_vs_causal)
    if modbus:
        limitations.append(modbus)
    if integrity.get("overall_status") not in {"completed", "verified", "ok"}:
        limitations.append("Case-wide integrity or custody validation remains partial.")

    if multilayer.get("execution_status") in {"not_started", "failed", "partial"}:
        actions.append("Run or regenerate the multilayer forensic analysis before drawing stronger reconstruction claims.")
    if uncertainty.get("synchronized_status") in {"not_synchronized", "degraded", "unknown"}:
        actions.append("Measure clock offset before the next controlled run, and only apply time correction in explicit laboratory maintenance mode.")
    if causal.get("status") in {"not_available", "blocked_missing_analysis", "blocked_missing_ground_truth", "failed"}:
        actions.append("Run or regenerate causal reconstruction after validating the required multilayer and ground-truth inputs.")
    if causal.get("is_stale"):
        actions.append("Regenerate causal reconstruction because one or more analysis inputs changed after the current causal artifacts were generated.")
    if modbus:
        actions.append("Strengthen Modbus packet-level parsing if register and value precision are required for stronger OT-specific causal claims.")
    if trigger_vs_causal:
        actions.append("Generate a dedicated OT-triggered case or explicitly document this case as a multi-vector acquisition-trigger mismatch.")
    if integrity.get("overall_status") not in {"completed", "verified", "ok"}:
        actions.append("Review the integrity and custody validation report and restore missing verifications before escalating confidence claims.")

    extract = summary.get("evidence_support_extract") or {}
    if extract.get("status") == "not_available":
        actions.append("Generate the Evidence Support Extract to obtain a normalized, hypothesis-level forensic support assessment.")
    elif extract.get("status") == "stale":
        actions.append("Regenerate the Evidence Support Extract because causal reconstruction artifacts changed after it was last generated.")
    elif extract.get("main_limitation") and extract.get("main_limitation") != "not_available":
        limitations.append(str(extract.get("main_limitation")))

    return list(dict.fromkeys(limitations)), list(dict.fromkeys(actions))


def _build_final_conclusion(summary: dict) -> dict:
    multilayer = summary.get("multilayer_analysis_summary") or {}
    causal = summary.get("causal_summary") or {}
    uncertainty = summary.get("uncertainty_summary") or {}
    integrity = summary.get("integrity_summary") or {}
    supported: list[str] = []
    degraded: list[str] = []
    unsupported: list[str] = []

    if integrity.get("manifest_present") and integrity.get("chain_of_custody_present"):
        supported.append("Evidence was preserved under a manifest and chain of custody.")
    if multilayer.get("execution_status") == "completed":
        supported.append("Multilayer forensic analysis was executed over the preserved case artifacts.")
    for layer in multilayer.get("layers") or []:
        if layer.get("phase") == "executive_summary_update":
            continue
        if layer.get("usefulness_status") == "completed_with_useful_output":
            supported.append(f"{layer.get('layer_name')} produced useful output.")
    if str(causal.get("status")).startswith("completed"):
        supported.append("A derived causal reconstruction was generated from preserved FOC artifacts and ground truth.")
    if int(causal.get("recovered_edges") or 0) > 0:
        supported.append(f"{causal.get('recovered_edges')} expected causal edges were recovered with sufficient support.")

    offset_seconds = uncertainty.get("max_clock_offset_seconds")
    if uncertainty.get("temporal_confidence") in {"ambiguous", "limited", "unknown"}:
        degraded.append(
            f"Temporal ordering is weak because the preserved clock offset is approximately "
            f"{'unknown' if offset_seconds is None else offset_seconds} seconds."
        )
    if int(causal.get("degraded_edges") or 0) > 0:
        degraded.append(f"{causal.get('degraded_edges')} causal edges remain degraded due to partial support.")
    if int(causal.get("ambiguous_edges") or 0) > 0:
        degraded.append(f"{causal.get('ambiguous_edges')} causal edges remain temporally ambiguous under the current uncertainty window.")
    if (causal.get("trigger_vs_causal_path") or {}).get("message"):
        degraded.append((causal.get("trigger_vs_causal_path") or {}).get("message"))
    if (causal.get("modbus_specificity") or {}).get("message"):
        degraded.append((causal.get("modbus_specificity") or {}).get("message"))
    if integrity.get("overall_status") not in {"completed", "verified", "ok"}:
        degraded.append("Case-wide integrity remains partial.")

    unsupported.extend(
        [
            "Absolute causality.",
            "Court-ready admissibility.",
            "Strong time-order causality under the current clock-offset uncertainty.",
            "Full production OT generalization.",
        ]
    )
    if (causal.get("modbus_specificity") or {}).get("register", {}).get("status") != "confirmed":
        unsupported.append("Complete Modbus register/value causality at packet-level precision.")
    unsupported.append("Full semantic reconstruction if semantic artifacts have not been generated.")

    extract = summary.get("evidence_support_extract") or {}
    global_support_level = extract.get("global_support_level")
    extract_clause = ""
    if extract.get("status") == "available" and global_support_level:
        extract_clause = f" The normalized Evidence Support Extract assesses the controlling hypothesis as {str(global_support_level).replace('_', ' ')}."
        if global_support_level in {"moderate_support", "strong_support"}:
            supported.append(f"The Evidence Support Extract assesses hypothesis H1 as {global_support_level.replace('_', ' ')} across independently-sourced layers.")
        elif global_support_level == "contradicted":
            degraded.append("The Evidence Support Extract found at least one contradiction against the controlling hypothesis.")
        else:
            degraded.append(f"The Evidence Support Extract assesses hypothesis H1 as only {str(global_support_level).replace('_', ' ')}.")

    summary_text = (
        "The preserved evidence supports a partial causal-forensic reconstruction of the controlled incident. "
        f"The multilayer forensic analysis {multilayer.get('execution_status') or 'remains unavailable'} and "
        f"produced {multilayer.get('layers_with_useful_output') or 0} useful layers. "
        f"The causal reconstruction recovered {causal.get('recovered_edges') or 0} of {causal.get('expected_edges') or 0} expected edges. "
        f"However, the interpretation remains limited by temporal confidence={uncertainty.get('temporal_confidence') or 'unknown'}, "
        f"integrity status={integrity.get('overall_status') or 'unknown'}, and the stated Modbus/trigger limitations."
        f"{extract_clause}"
    )
    return {
        "supported": list(dict.fromkeys(supported)),
        "degraded_or_ambiguous": list(dict.fromkeys(degraded)),
        "unsupported_or_not_claimable": list(dict.fromkeys(unsupported)),
        "summary_text": summary_text,
    }


def build_evidence_lifecycle_summary(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        raise FileNotFoundError(f"Case {case_id} was not found.")
    case_dir = _case_dir_from_entry(entry)
    bundle = _source_bundle()
    visual_summary = analysis_visual_summary(case_id) or {}
    analysis_status = load_analysis_status(case_id)
    time_sync_status = load_time_sync_status(case_id)
    causal_status = causal_status_payload(case_id, case_dir)
    causal_metrics = causal_metrics_payload(case_id, case_dir) or {}
    causal_uncertainty = causal_uncertainty_payload(case_id, case_dir) or {}
    intervention = _pick_intervention(case_id, bundle)
    summary_path = _summary_path(case_dir)
    summary_mtime = _mtime(summary_path)
    report_index = _build_reports_index(case_dir)
    multilayer = _build_multilayer_summary(case_dir, analysis_status, visual_summary, summary_path)
    integrity = _build_integrity_summary(case_dir)
    uncertainty = _build_uncertainty_summary(case_dir, time_sync_status, causal_uncertainty)
    causal = _build_causal_summary(case_dir, bundle, causal_status, causal_metrics, causal_uncertainty, intervention)

    evidence_lifecycle = {
        "status": "preserved_and_analyzed" if integrity.get("manifest_present") and multilayer.get("execution_status") == "completed" else "partial",
        "manifest_path": relative_path(case_dir / "manifest.json") if (case_dir / "manifest.json").exists() else None,
        "chain_of_custody_path": relative_path(case_dir / "chain_of_custody.log") if (case_dir / "chain_of_custody.log").exists() else None,
        "evidence_items": integrity.get("artifacts_declared") or 0,
        "custody_events": integrity.get("custody_events") or 0,
        "rail": [
            {"phase": "scenario_deployed", "label": "Scenario deployed", "status": _phase_status_from_bool(bool((bundle.get("foc_context_summary") or {}).get("scenario_id")))},
            {"phase": "attack_executed", "label": "Attack executed", "status": _phase_status_from_bool(bool((bundle.get("attack_attestation") or {}).get("attacks")), partial=bool(causal.get("selected_attack", {}).get("attack_id")) and causal.get("selected_attack", {}).get("execution_status") not in {"completed", "not_available"})},
            {"phase": "detection_observed", "label": "Detection observed", "status": _phase_status_from_bool(bool((bundle.get("detection_attestation") or {}).get("observed_detection_rules")))},
            {"phase": "trigger_selected", "label": "Trigger selected", "status": _phase_status_from_bool(bool(intervention.get("trigger")), partial=bool(causal.get("trigger_vs_causal_path", {}).get("message")))},
            {"phase": "acquisition_executed", "label": "Acquisition executed", "status": _phase_status_from_bool(bool(intervention.get("collected_artifacts")), partial=str(intervention.get("intervention_status")) != "completed")},
            {"phase": "evidence_preserved", "label": "Evidence preserved", "status": _phase_status_from_bool(integrity.get("manifest_present") and integrity.get("chain_of_custody_present"))},
            {"phase": "integrity_custody_checked", "label": "Integrity and custody checked", "status": integrity.get("overall_status") or "partial"},
            {"phase": "time_synchronization_validated", "label": "Time synchronization validated", "status": uncertainty.get("synchronized_status") or "unknown"},
            {"phase": "multilayer_analysis_completed", "label": "Multilayer analysis completed", "status": multilayer.get("execution_status") or "not_generated"},
            {"phase": "timeline_generated", "label": "Timeline generated", "status": _phase_status_from_bool((multilayer.get("timeline_entries") or 0) > 0)},
            {"phase": "cross_layer_findings_generated", "label": "Cross-layer findings generated", "status": _phase_status_from_bool((multilayer.get("cross_layer_findings") or 0) > 0)},
            {"phase": "causal_reconstruction_generated", "label": "Causal reconstruction generated", "status": causal.get("status") or "not_generated", "stale": bool(causal.get("is_stale"))},
            {"phase": "executive_conclusion_produced", "label": "Executive conclusion produced", "status": "completed"},
        ],
    }

    execution_summary = {
        "overall_status": causal.get("status") or multilayer.get("execution_status") or "not_available",
        "evidence_lifecycle_status": evidence_lifecycle.get("status"),
        "multilayer_analysis_status": multilayer.get("execution_status"),
        "causal_reconstruction_status": causal.get("status"),
        "evidence_analysis_confidence": multilayer.get("analysis_confidence") or "unknown",
        "forensic_reconstruction_confidence": visual_summary.get("forensic_reconstruction_status") or "unknown",
        "causal_interpretation_confidence": causal.get("causal_interpretation_confidence") or "unknown",
        "main_limitation": causal.get("main_limitation") or multilayer.get("main_limitation") or uncertainty.get("main_limitation"),
        "generated_report_path": analysis_status.get("forensic_analysis_report_path"),
    }

    trigger_summary = {
        "trigger": intervention.get("trigger") or "not_available",
        "trigger_type": intervention.get("trigger_type") or "not_available",
        "triggering_alert_id": intervention.get("triggering_alert_id") or "not_available",
        "triggering_alert_rule_id": intervention.get("triggering_alert_rule_id") or "not_available",
        "triggering_alert_name": intervention.get("triggering_alert_name") or "not_available",
        "trigger_selection_method": intervention.get("trigger_selection_method") or "not_available",
        "trigger_selection_score": intervention.get("trigger_selection_score"),
        "candidate_triggers_evaluated": intervention.get("candidate_triggers_evaluated"),
        "stronger_trigger_available": intervention.get("stronger_trigger_available"),
        "intervention_status": intervention.get("intervention_status") or "not_available",
        "target_nodes": intervention.get("target_nodes") or [],
    }

    # Local import to avoid a module-level circular import: evidence_support_extract
    # itself imports several helpers from this module.
    from .evidence_support_extract import evidence_support_extract_stub

    summary = {
        "case_id": case_id,
        "source_case_name": entry.get("source_case_name"),
        "scenario_id": (bundle.get("foc_context_summary") or {}).get("scenario_id") or ((bundle.get("scenario_ground_truth") or {}).get("scenario_id")) or "unknown",
        "scenario_name": (bundle.get("foc_context_summary") or {}).get("scenario_name") or ((bundle.get("scenario_ground_truth") or {}).get("scenario_name")) or "unknown",
        "generated_at": utc_now(),
        "is_stale": False,
        "case_path": relative_path(case_dir),
        "execution_summary": execution_summary,
        "trigger_summary": trigger_summary,
        "evidence_lifecycle": evidence_lifecycle,
        "multilayer_analysis_summary": multilayer,
        "causal_summary": causal,
        "uncertainty_summary": uncertainty,
        "integrity_summary": integrity,
        "evidence_support_extract": evidence_support_extract_stub(case_id, case_dir),
        "reports_and_artifacts": report_index,
        "final_forensic_conclusion": {},
        "limitations": [],
        "next_required_actions": [],
    }
    limitations, actions = _build_limitations_and_actions(summary)
    summary["limitations"] = limitations
    summary["next_required_actions"] = actions
    summary["final_forensic_conclusion"] = _build_final_conclusion(summary)

    source_paths = [
        _artifact_paths(case_dir)["forensic_analysis_report"],
        _artifact_paths(case_dir)["analysis_visual_summary"],
        _artifact_paths(case_dir)["reconstruction_metrics"],
        _artifact_paths(case_dir)["uncertainty_report"],
        _artifact_paths(case_dir)["causal_status"],
        _artifact_paths(case_dir)["time_sync"],
        GENERATED_FILES["forensic_intervention"],
        GENERATED_FILES["attack_attestation"],
        GENERATED_FILES["detection_attestation"],
        GENERATED_FILES["foc_context_summary"],
    ]
    latest_source_mtime = max((_mtime(path) for path in source_paths if path.exists()), default=0.0)
    summary["is_stale"] = bool(summary_mtime and latest_source_mtime > summary_mtime)
    summary["stale_reason"] = "Executive summary is stale and should be regenerated." if summary["is_stale"] else None
    return summary


def generate_evidence_lifecycle_summary(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        raise FileNotFoundError(f"Case {case_id} was not found.")
    case_dir = _case_dir_from_entry(entry)
    payload = build_evidence_lifecycle_summary(case_id)
    _write_json(_summary_path(case_dir), payload)
    payload["summary_path"] = relative_path(_summary_path(case_dir))
    return payload


def load_evidence_lifecycle_dashboard(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    summary_path = _summary_path(case_dir)
    summary = _json_load(summary_path)
    analysis_status = load_analysis_status(case_id)
    time_sync_status = load_time_sync_status(case_id)
    causal_state = summarize_case_causal_state(case_id, case_dir, analysis_status=analysis_status)
    return {
        "case_id": case_id,
        "source_case_name": entry.get("source_case_name"),
        "case_path": relative_path(case_dir),
        "summary_available": isinstance(summary, dict),
        "summary_path": relative_path(summary_path),
        "summary": summary if isinstance(summary, dict) else None,
        "live_status": {
            "analysis": analysis_status,
            "time_sync": time_sync_status,
            "causal": causal_state,
        },
        "reports_index": _build_reports_index(case_dir),
    }


def _new_job(case_id: str, case_dir: Path, job_type: str, title: str) -> dict:
    job_id = f"lifecycle-{uuid.uuid4().hex[:12]}"
    payload = {
        "job_id": job_id,
        "case_id": case_id,
        "case_path": relative_path(case_dir),
        "job_type": job_type,
        "title": title,
        "status": "queued",
        "requested_at": utc_now(),
        "started_at": None,
        "finished_at": None,
        "current_phase": "queued",
        "progress_percent": 0,
        "phases": [],
        "warnings": [],
        "errors": [],
        "generated_artifacts": [],
        "job_path": relative_path(_job_path(case_dir, job_id)),
    }
    with _JOB_LOCK:
        _JOBS[job_id] = payload
    _write_json(_job_path(case_dir, job_id), payload)
    return payload


def _set_job(job: dict, case_dir: Path, **updates) -> None:
    job.update(updates)
    job["updated_at"] = utc_now()
    with _JOB_LOCK:
        _JOBS[job["job_id"]] = job
    _write_json(_job_path(case_dir, job["job_id"]), job)


def _update_phase(job: dict, case_dir: Path, phase_name: str, status: str, **extra) -> None:
    phases = job.setdefault("phases", [])
    phase = next((item for item in phases if item.get("name") == phase_name), None)
    if not phase:
        phase = {"name": phase_name}
        phases.append(phase)
    phase.update({"status": status})
    phase.update(extra)
    job["current_phase"] = phase_name
    _set_job(job, case_dir, phases=phases)


def get_lifecycle_job(job_id: str) -> dict | None:
    with _JOB_LOCK:
        payload = _JOBS.get(job_id)
    if payload:
        return payload
    case_root = Path(__file__).resolve().parents[1] / "forensics" / "evidence_store"
    for case_dir in case_root.glob("CASE-*"):
        candidate = _job_path(case_dir, job_id)
        payload = _json_load(candidate)
        if isinstance(payload, dict):
            return payload
    return None


def _wait_for_terminal(case_id: str, getter, running_statuses: set[str], terminal_statuses: set[str], timeout_seconds: int = 7200) -> dict:
    start = time.time()
    last = getter(case_id)
    while (time.time() - start) < timeout_seconds:
        current = getter(case_id)
        last = current
        state = str(current.get("status") or current.get("state") or "").strip()
        if state in terminal_statuses:
            return current
        if state not in running_statuses:
            return current
        time.sleep(_POLL_SECONDS)
    last.setdefault("warnings", []).append("Timeout reached while waiting for background phase completion.")
    return last


def _summary_worker(job: dict, case_dir: Path) -> None:
    try:
        _set_job(job, case_dir, status="running", started_at=utc_now(), current_phase="generating_summary", progress_percent=15)
        _update_phase(job, case_dir, "generate_executive_summary", "running", started_at=utc_now())
        payload = generate_evidence_lifecycle_summary(job["case_id"])
        _update_phase(
            job,
            case_dir,
            "generate_executive_summary",
            "completed",
            finished_at=utc_now(),
            artifact_path=payload.get("summary_path"),
        )
        _set_job(
            job,
            case_dir,
            status="completed",
            finished_at=utc_now(),
            current_phase="completed",
            progress_percent=100,
            generated_artifacts=[payload.get("summary_path")],
        )
    except Exception as exc:
        _update_phase(job, case_dir, "generate_executive_summary", "failed", finished_at=utc_now(), error_message=str(exc))
        _set_job(job, case_dir, status="failed", finished_at=utc_now(), current_phase="failed", progress_percent=100, errors=[str(exc)])
    finally:
        with _JOB_LOCK:
            _RUNNING_JOB_THREADS.pop(job["job_id"], None)


def start_summary_job(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    job = _new_job(case_id, case_dir, "executive_summary_generation", "Generate Executive Summary")
    worker = threading.Thread(target=_summary_worker, args=(job, case_dir), daemon=True, name=f"executive-summary-{case_id}")
    with _JOB_LOCK:
        _RUNNING_JOB_THREADS[job["job_id"]] = worker
    worker.start()
    return job


def _run_full_worker(job: dict, case_dir: Path, force_analysis: bool, strict: bool, degraded_ok: bool) -> None:
    case_id = job["case_id"]
    generated_artifacts: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    try:
        _set_job(job, case_dir, status="running", started_at=utc_now(), current_phase="measure_clock_offset", progress_percent=5)

        _update_phase(job, case_dir, "measure_clock_offset", "running", started_at=utc_now())
        run_time_sync(case_id, fix_time=False, maintenance_override=False)
        time_sync_status = _wait_for_terminal(case_id, load_time_sync_status, {"running"}, {"completed", "failed", "blocked_policy"})
        if str(time_sync_status.get("status")) == "failed":
            warnings.append(str(time_sync_status.get("reason") or "Clock-offset measurement failed."))
            _update_phase(job, case_dir, "measure_clock_offset", "partial", finished_at=utc_now(), summary=time_sync_status.get("reason"))
        else:
            _update_phase(
                job,
                case_dir,
                "measure_clock_offset",
                "completed",
                finished_at=utc_now(),
                artifact_path=((time_sync_status.get("output_paths") or {}).get("json")) or relative_path(case_dir / "metadata" / "time_sync.json"),
            )
            if ((time_sync_status.get("output_paths") or {}).get("json")):
                generated_artifacts.append((time_sync_status.get("output_paths") or {}).get("json"))
        _set_job(job, case_dir, progress_percent=20, current_phase="run_multilayer_analysis", warnings=warnings)

        _update_phase(job, case_dir, "run_multilayer_analysis", "running", started_at=utc_now())
        run_analysis(case_id, force=force_analysis)
        analysis_status = _wait_for_terminal(case_id, load_analysis_status, {"running"}, {"completed", "partial", "failed"})
        if str(analysis_status.get("status")) == "failed":
            reason = "; ".join(str(item) for item in (analysis_status.get("errors") or []) if item) or "Multilayer analysis failed."
            errors.append(reason)
            _update_phase(job, case_dir, "run_multilayer_analysis", "failed", finished_at=utc_now(), error_message=reason, artifact_path=analysis_status.get("forensic_analysis_report_path"))
            _set_job(job, case_dir, status="failed", finished_at=utc_now(), current_phase="failed", progress_percent=100, errors=errors, warnings=warnings)
            return
        if analysis_status.get("forensic_analysis_report_path"):
            generated_artifacts.append(analysis_status.get("forensic_analysis_report_path"))
        _update_phase(job, case_dir, "run_multilayer_analysis", analysis_status.get("status") or "completed", finished_at=utc_now(), artifact_path=analysis_status.get("forensic_analysis_report_path"))
        _set_job(job, case_dir, progress_percent=55, current_phase="run_causal_reconstruction", warnings=warnings)

        _update_phase(job, case_dir, "run_causal_reconstruction", "running", started_at=utc_now())
        run_causal_reconstruction(case_id=case_id, case_path=case_dir, strict=strict, degraded_ok=degraded_ok)
        causal_status = _wait_for_terminal(case_id, lambda cid: summarize_case_causal_state(cid, case_dir, analysis_status=analysis_status), {"running"}, {"completed", "completed_with_degradation", "failed", "blocked_missing_ground_truth", "blocked_missing_analysis", "ready_to_run"})
        causal_state = str(causal_status.get("status") or causal_status.get("state") or "")
        if causal_state in {"failed", "blocked_missing_ground_truth", "blocked_missing_analysis"}:
            errors.append(str(causal_status.get("reason") or "Causal reconstruction failed or was blocked."))
            _update_phase(job, case_dir, "run_causal_reconstruction", "failed", finished_at=utc_now(), error_message=causal_status.get("reason"))
        else:
            if causal_state == "completed_with_degradation":
                warnings.append(str(causal_status.get("reason") or "Causal reconstruction completed with degradation."))
            _update_phase(job, case_dir, "run_causal_reconstruction", causal_state or "completed", finished_at=utc_now(), artifact_path=((causal_status.get("output_paths") or {}).get("causal_graph")))
            for value in (causal_status.get("output_paths") or {}).values():
                if value:
                    generated_artifacts.append(value)

        _set_job(job, case_dir, progress_percent=80, current_phase="generate_executive_summary", warnings=warnings, errors=errors)
        _update_phase(job, case_dir, "generate_executive_summary", "running", started_at=utc_now())
        payload = generate_evidence_lifecycle_summary(case_id)
        generated_artifacts.append(payload.get("summary_path"))
        _update_phase(job, case_dir, "generate_executive_summary", "completed", finished_at=utc_now(), artifact_path=payload.get("summary_path"))

        final_status = "completed_with_degradation" if warnings else "completed"
        if errors:
            final_status = "failed"
        _set_job(
            job,
            case_dir,
            status=final_status,
            finished_at=utc_now(),
            current_phase="completed",
            progress_percent=100,
            warnings=list(dict.fromkeys(warnings)),
            errors=list(dict.fromkeys(errors)),
            generated_artifacts=list(dict.fromkeys([item for item in generated_artifacts if item])),
        )
    except Exception as exc:
        _set_job(job, case_dir, status="failed", finished_at=utc_now(), current_phase="failed", progress_percent=100, errors=[str(exc)])
    finally:
        with _JOB_LOCK:
            _RUNNING_JOB_THREADS.pop(job["job_id"], None)


def start_full_lifecycle_job(case_id: str, force_analysis: bool = False, strict: bool = False, degraded_ok: bool = True) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    job = _new_job(case_id, case_dir, "full_evidence_lifecycle", "Run Full Evidence Lifecycle")
    worker = threading.Thread(
        target=_run_full_worker,
        args=(job, case_dir, bool(force_analysis), bool(strict), bool(degraded_ok)),
        daemon=True,
        name=f"full-evidence-lifecycle-{case_id}",
    )
    with _JOB_LOCK:
        _RUNNING_JOB_THREADS[job["job_id"]] = worker
    worker.start()
    return job


def report_index_payload(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    return {
        "case_id": case_id,
        "case_path": relative_path(case_dir),
        "reports": _build_reports_index(case_dir),
    }


def report_file_payload(case_id: str, report_type: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    path = _artifact_paths(case_dir).get(str(report_type))
    if path is None:
        return {"error": "report_type_not_supported", "case_id": case_id, "report_type": report_type}
    if not path.exists():
        return {"error": "report_not_found", "case_id": case_id, "report_type": report_type, "path": relative_path(path)}
    size = path.stat().st_size
    suffix = path.suffix.lower()
    if suffix == ".json" and size <= _EXEC_MAX_PREVIEW_BYTES:
        payload = _json_load(path)
        return {
            "case_id": case_id,
            "report_type": report_type,
            "path": relative_path(path),
            "size_bytes": size,
            "format": "json",
            "content": payload,
            "truncated": False,
        }
    text, truncated = _read_text(path, limit_bytes=_EXEC_MAX_PREVIEW_BYTES)
    return {
        "case_id": case_id,
        "report_type": report_type,
        "path": relative_path(path),
        "size_bytes": size,
        "format": "text",
        "content": text,
        "truncated": truncated,
    }
