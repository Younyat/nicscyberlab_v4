from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

from .foc_case_analysis import (
    ANALYSIS_PHASES,
    _case_dir_from_entry,
    analysis_visual_summary,
    get_case_entry,
    load_analysis_status,
    load_time_sync_status,
    run_analysis,
    run_time_sync,
)
from .foc_config import GENERATED_FILES
from .foc_manifest_manager import read_generated_json, regenerate_foc
from .foc_paths import relative_path
from .foc_sources import utc_now
from .foc_bootstrap import bootstrap_existing_context
from ..foc_causal_reconstruction.service import (
    causal_graph_payload,
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

_EDGE_REQ_LABELS = {
    "attack_attestation": "attack attestation",
    "network_modbus_observation": "network Modbus observation",
    "plc_state_observation": "OT or PLC state observation",
    "detection_attestation": "detection attestation",
    "alert_correlation": "alert correlation",
    "memory_analysis_useful": "useful memory analysis output",
    "forensic_intervention": "forensic intervention record",
    "case_manifest_link": "case-manifest link",
    "manifest": "manifest",
    "chain_of_custody": "chain of custody",
    "forensic_analysis_report": "forensic analysis report",
    "analysis_visual_summary": "analysis visual summary",
}

_ANALYSIS_TRACE_LAYOUT = {
    "preflight_validation": ("multilayer_forensic_analysis", "multilayer_preflight", "Multilayer analysis preflight", "multilayer"),
    "evidence_inventory": ("verify_preserved_evidence", "verify_evidence_inventory", "Preserved evidence inventory", "verification"),
    "integrity_custody_validation": ("verify_preserved_evidence", "verify_chain_of_custody", "Chain of custody verification", "verification"),
    "temporal_validation": ("run_multilayer_analysis", "time_synchronization_and_timestamp_quality_assessment", "Time synchronization and timestamp quality assessment", "time_sync"),
    "network_analysis": ("run_multilayer_analysis", "network_analysis", "Network analysis", "network"),
    "memory_analysis": ("run_multilayer_analysis", "memory_analysis", "Memory analysis", "memory"),
    "disk_analysis": ("run_multilayer_analysis", "disk_analysis", "Disk analysis", "disk"),
    "ot_export_analysis": ("run_multilayer_analysis", "ot_and_industrial_artifacts_analysis", "OT and industrial artifacts analysis", "ot"),
    "alerts_detection_analysis": ("run_multilayer_analysis", "alerts_analysis", "Alerts analysis", "alerts"),
    "pipeline_custody_analysis": ("run_multilayer_analysis", "pipeline_and_custody_analysis", "Pipeline and custody analysis", "pipeline_custody"),
    "unified_forensic_timeline": ("run_multilayer_analysis", "unified_timeline_generation", "Unified timeline generation", "timeline"),
    "cross_layer_findings": ("run_multilayer_analysis", "cross_layer_findings_generation", "Cross-layer findings generation", "cross_layer"),
    "forensic_analysis_report_generation": ("run_multilayer_analysis", "multilayer_analysis_finalization", "Multilayer analysis finalization", "multilayer"),
    "foc_readiness_update": ("regenerate_foc_context", "regenerate_foc_context", "Regenerate FOC context", "foc"),
}


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


def _job_cancel_path(case_dir: Path, job_id: str) -> Path:
    return _jobs_dir(case_dir) / f"{job_id}.cancel"


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


def _duration_ms(started_at, finished_at) -> int | None:
    duration = _duration_seconds(started_at, finished_at)
    if duration is None:
        return None
    return int(round(duration * 1000))


def _listify_artifacts(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, dict):
        return [str(item) for item in value.values() if item]
    if value:
        return [str(value)]
    return []


def _count_items(value) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        total = 0
        saw = False
        for item in value.values():
            nested = _count_items(item)
            if nested is not None:
                total += nested
                saw = True
        return total if saw else len(value)
    return None


def _findings_generated_count(payload: dict | None) -> int | None:
    findings = (payload or {}).get("findings")
    if findings is None:
        return None
    if isinstance(findings, dict):
        for key in ("findings", "results", "files", "entries", "events"):
            if key in findings:
                nested = _count_items(findings.get(key))
                if nested is not None:
                    return nested
        nested = _count_items(findings)
        return nested
    return _count_items(findings)


def _normalize_trace_status(status: str | None) -> str:
    raw = str(status or "unknown").strip().lower()
    if raw in {"completed", "running", "queued"}:
        return raw
    if raw.startswith("partial"):
        return "partial"
    if raw in {"completed_with_degradation", "degraded"}:
        return "degraded"
    if raw.startswith("blocked"):
        return "blocked"
    if raw.startswith("skipped"):
        return "skipped"
    if raw.startswith("failed"):
        return "failed"
    if raw in {"pending", "not_started", "ready_to_run"}:
        return "queued"
    return raw or "unknown"


def _upsert_phase_trace(
    job: dict,
    case_dir: Path,
    *,
    case_id: str,
    phase_id: str,
    parent_phase_id: str | None,
    phase_label: str,
    layer: str,
    status: str,
    started_at=None,
    finished_at=None,
    input_artifacts_used=None,
    output_artifacts_generated=None,
    artifacts_processed_count=None,
    findings_generated_count=None,
    warnings=None,
    blockers=None,
    scientific_limitation_reason=None,
    detail=None,
) -> None:
    trace = list(job.get("phase_trace") or [])
    existing = next((item for item in trace if str(item.get("phase_id")) == str(phase_id)), None)
    if not existing:
        existing = {
            "case_id": case_id,
            "phase_id": phase_id,
            "parent_phase_id": parent_phase_id,
            "phase_label": phase_label,
            "layer": layer,
        }
        trace.append(existing)
    existing.update(
        {
            "case_id": case_id,
            "phase_id": phase_id,
            "parent_phase_id": parent_phase_id,
            "phase_label": phase_label,
            "layer": layer,
            "status": _normalize_trace_status(status),
            "utc_start_time": started_at or existing.get("utc_start_time"),
            "utc_end_time": finished_at,
            "duration_ms": _duration_ms(started_at or existing.get("utc_start_time"), finished_at) if finished_at else existing.get("duration_ms"),
            "input_artifacts_used": list(dict.fromkeys(_listify_artifacts(input_artifacts_used) or existing.get("input_artifacts_used") or [])),
            "output_artifacts_generated": list(dict.fromkeys(_listify_artifacts(output_artifacts_generated) or existing.get("output_artifacts_generated") or [])),
            "number_of_artifacts_processed": artifacts_processed_count if artifacts_processed_count is not None else existing.get("number_of_artifacts_processed"),
            "number_of_findings_generated": findings_generated_count if findings_generated_count is not None else existing.get("number_of_findings_generated"),
            "warnings": list(dict.fromkeys([str(item) for item in (warnings or existing.get("warnings") or []) if item])),
            "blockers": list(dict.fromkeys([str(item) for item in (blockers or existing.get("blockers") or []) if item])),
            "scientific_limitation_reason": scientific_limitation_reason or existing.get("scientific_limitation_reason"),
            "detail": detail or existing.get("detail"),
            "updated_at": utc_now(),
        }
    )
    _set_job(job, case_dir, phase_trace=trace)


def _sync_multilayer_phase_trace(job: dict, case_dir: Path, case_id: str, analysis_status: dict) -> None:
    phases = (analysis_status or {}).get("phases") or {}
    for phase_key, _, _ in ANALYSIS_PHASES:
        if phase_key == "temporal_validation":
            continue
        phase_payload = phases.get(phase_key) or {}
        phase_status = str(phase_payload.get("status") or "").strip()
        if not phase_status:
            continue
        parent_phase_id, phase_id, phase_label, layer = _ANALYSIS_TRACE_LAYOUT.get(
            phase_key,
            ("run_multilayer_analysis", phase_key, phase_key.replace("_", " ").title(), "multilayer"),
        )
        output_path = phase_payload.get("output_path")
        output_payload = _json_load((Path(__file__).resolve().parents[3] / output_path).resolve()) if output_path else None
        warnings = []
        blockers = []
        limitations = list((phase_payload.get("limitations") or []))
        errors = list((phase_payload.get("errors") or []))
        if _normalize_trace_status(phase_status) == "failed":
            blockers.extend(errors or limitations)
        elif _normalize_trace_status(phase_status) in {"blocked", "partial", "degraded"}:
            warnings.extend(limitations or errors)
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id=phase_id,
            parent_phase_id=parent_phase_id,
            phase_label=phase_label,
            layer=layer,
            status=phase_status,
            started_at=phase_payload.get("started_at"),
            finished_at=phase_payload.get("finished_at"),
            input_artifacts_used=(output_payload or {}).get("input_artifacts") or [],
            output_artifacts_generated=[output_path] if output_path else [],
            artifacts_processed_count=_count_items((output_payload or {}).get("input_artifacts")) or _count_items((output_payload or {}).get("related_outputs")),
            findings_generated_count=_findings_generated_count(output_payload),
            warnings=warnings,
            blockers=blockers,
            scientific_limitation_reason=(limitations or [None])[0],
            detail=(output_payload or {}).get("summary") or phase_payload.get("label"),
        )


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


def _build_memory_analysis_detail(case_dir: Path) -> dict:
    memory_findings = _json_load(case_dir / "analysis" / "04_memory" / "memory_findings.json") or {}
    findings = memory_findings.get("findings") or {}
    results = findings.get("results") or []
    standard_plugins = {
        "banners": "Kernel banner extraction",
        "pslist": "Process listing",
        "sockstat": "Socket listing",
        "lsmod": "Loaded modules",
        "check_syscall": "Syscall checks",
        "bash": "Shell history",
    }
    plugin_counts = {key: {"completed": 0, "failed": 0, "partial": 0, "blocked": 0} for key in standard_plugins}
    kernel_symbols_available = 0
    dumps_opened = 0
    useful_memory_atoms = 0
    blocked_plugins: list[str] = []
    partial_plugins: list[str] = []
    dump_details: list[dict] = []

    for result in results:
        status = str(result.get("status") or "unknown")
        if status in {"completed", "partial"}:
            dumps_opened += 1
        execution_report_path = result.get("execution_report_path")
        execution_report = _json_load(Path(execution_report_path)) if execution_report_path else None
        plugin_results = (execution_report or {}).get("plugin_results") or []
        selected_symbol = (execution_report or {}).get("selected_symbol")
        if selected_symbol:
            kernel_symbols_available += 1
        completed_plugins = set(result.get("completed_plugins") or [])
        failed_plugins = set(result.get("failed_plugins") or [])
        dump_plugin_status = {}
        for plugin_key, plugin_label in standard_plugins.items():
            plugin_result = next((item for item in plugin_results if str(item.get("plugin_key")) == plugin_key), None)
            plugin_status = str((plugin_result or {}).get("status") or ("completed" if plugin_key in completed_plugins else "failed" if plugin_key in failed_plugins else "not_evaluable"))
            if plugin_status == "completed":
                plugin_counts[plugin_key]["completed"] += 1
                useful_memory_atoms += 1
            elif plugin_status in {"partial", "partial_missing_symbols", "partial_memory_plugin_coverage"}:
                plugin_counts[plugin_key]["partial"] += 1
                partial_plugins.append(plugin_key)
            elif plugin_status in {"blocked", "skipped", "not_available"}:
                plugin_counts[plugin_key]["blocked"] += 1
                blocked_plugins.append(plugin_key)
            else:
                plugin_counts[plugin_key]["failed"] += 1
                blocked_plugins.append(plugin_key)
            dump_plugin_status[plugin_key] = {
                "label": plugin_label,
                "status": plugin_status,
                "summary": (plugin_result or {}).get("summary") or {},
                "symbol_table_status": (plugin_result or {}).get("symbol_table_status"),
                "missing_requirement": (plugin_result or {}).get("missing_requirement"),
            }
        dump_details.append(
            {
                "dump_id": result.get("dump_id"),
                "status": status,
                "detected_os": result.get("detected_os"),
                "detected_kernel": result.get("detected_kernel"),
                "symbols_available": bool(selected_symbol),
                "selected_symbol": selected_symbol,
                "plugin_statuses": dump_plugin_status,
            }
        )

    dumps_total = len(results)
    kernel_symbols_state = "yes" if dumps_total and kernel_symbols_available == dumps_total else "partial" if kernel_symbols_available else "no"
    overall_status = str(memory_findings.get("status") or "not_available")
    usefulness = "blocked"
    reason = "Memory analysis did not produce effective plugin output."
    if dumps_opened and useful_memory_atoms:
        usefulness = "useful"
        reason = "Memory dumps opened successfully and produced usable plugin output."
    elif dumps_opened:
        usefulness = "partial"
        reason = "Memory dumps opened successfully, but plugin coverage is partial or non-useful for some categories."
    elif dumps_total:
        usefulness = "blocked"
        reason = "Memory dumps were discovered, but no dump produced an effective analysis pass."
    if memory_findings.get("limitations"):
        reason = str((memory_findings.get("limitations") or [reason])[0])
    return {
        "status": overall_status,
        "dumps_total": dumps_total,
        "dumps_analyzed": findings.get("dumps_analyzed") or dumps_opened,
        "memory_dump_opened_successfully": "yes" if dumps_opened else "no",
        "kernel_banner_extracted": "yes" if plugin_counts["banners"]["completed"] else "no",
        "compatible_symbols_available": kernel_symbols_state,
        "memory_layer_usefulness": usefulness,
        "reason": reason,
        "blocked_plugins": sorted(set(blocked_plugins)),
        "partial_plugins": sorted(set(partial_plugins)),
        "useful_memory_atoms_extracted": useful_memory_atoms,
        "plugins": [
            {
                "plugin_key": plugin_key,
                "label": plugin_label,
                "completed_dumps": counts["completed"],
                "partial_dumps": counts["partial"],
                "failed_dumps": counts["failed"],
                "blocked_dumps": counts["blocked"],
                "status": "yes" if counts["completed"] == dumps_total and dumps_total else "partial" if (counts["completed"] or counts["partial"]) else "no",
            }
            for plugin_key, plugin_label in standard_plugins.items()
            for counts in [plugin_counts[plugin_key]]
        ],
        "dumps": dump_details,
    }


def _build_alert_triage_summary(bundle: dict, intervention: dict, alert_findings: dict) -> dict:
    alert_correlation = bundle.get("alert_correlation_summary") or {}
    findings = (alert_findings or {}).get("findings") or {}
    total_alerts = findings.get("alerts_total") or alert_correlation.get("total_alerts") or 0
    correlated = alert_correlation.get("correlated_alerts")
    unresolved = alert_correlation.get("unresolved_alerts")
    relevant = alert_correlation.get("relevant_alerts")
    noise_alerts = alert_correlation.get("noise_alerts")
    inside_window = relevant if relevant is not None else "not_available"
    outside_window = max(int(total_alerts) - int(relevant), 0) if relevant is not None and total_alerts is not None else "not_available"
    correlated_int = int(correlated or 0)
    uncorrelated_int = int(unresolved or 0)
    total_int = int(total_alerts or 0)
    noise_ratio = round((float(noise_alerts or 0) / float(total_int)), 4) if total_int else None
    selected_trigger = intervention.get("trigger") or intervention.get("triggering_alert_name") or "not_available"
    selected_source = intervention.get("triggering_alert_original_sensor") or intervention.get("triggering_alert_collector") or "not_available"
    top_rules = findings.get("top_rules") or {}
    rejected_candidates = []
    for rule_id, count in list(top_rules.items())[:5]:
        if str(rule_id) == str(intervention.get("triggering_alert_rule_id")):
            continue
        rejected_candidates.append(f"rule {rule_id} observed {count} times")
    return {
        "total_alerts_indexed": total_alerts,
        "alerts_inside_selected_case_window": inside_window,
        "alerts_outside_selected_case_window": outside_window,
        "correlated_alerts": correlated_int,
        "uncorrelated_alerts": uncorrelated_int,
        "trigger_candidates_evaluated": intervention.get("candidate_triggers_evaluated") or 0,
        "selected_trigger": selected_trigger,
        "selected_trigger_rule": intervention.get("triggering_alert_rule_id") or "not_available",
        "selected_trigger_source": selected_source,
        "selected_trigger_score": intervention.get("trigger_selection_score"),
        "reason_for_selection": intervention.get("trigger_selection_reason") or intervention.get("trigger_selection_method") or "not_available",
        "stronger_trigger_available": intervention.get("stronger_trigger_available"),
        "rejected_candidates_summary": rejected_candidates,
        "noise_ratio": noise_ratio,
        "source_label": "executive summary snapshot",
    }


def _build_evidence_story(case_dir: Path) -> dict:
    storyline = _json_load(case_dir / "derived" / "evidence_support" / "forensic_storyline.json") or {}
    claimability = _json_load(case_dir / "derived" / "evidence_support" / "claimability_report.json") or {}
    hypothesis = _json_load(case_dir / "derived" / "evidence_support" / "hypothesis_support_report.json") or {}
    steps = list(storyline.get("steps") or [])
    has_modbus = any("modbus" in str(step.get("event_description") or "").lower() for step in steps)
    has_trigger_mismatch = any("trigger" in str(step.get("event_description") or "").lower() for step in steps)
    sentences = [
        "The preserved evidence indicates Modbus/TCP activity targeting the PLC during the evaluated incident window."
        if has_modbus
        else "The preserved evidence indicates OT-network activity during the evaluated incident window.",
        "Network evidence confirms the presence of Modbus/TCP traffic, while OT state evidence provides partial support for a process-level effect.",
        "The forensic acquisition was triggered by a host or FIM-oriented alert, not by a directly confirmed OT alert."
        if has_trigger_mismatch
        else "The preserved case includes a trigger path that can be compared against the reconstructed attack path.",
        "The preserved case evidence was processed through the multilayer forensic pipeline and produced useful outputs across the expected analysis layers.",
        "The resulting reconstruction supports a partial causal explanation, but not full packet-level register and value causality."
        if hypothesis
        else "The resulting reconstruction remains bounded by explicit temporal, integrity, and protocol-specific limitations.",
    ]
    summary_text = " ".join(sentences)
    return {
        "status": "available" if steps else "not_available",
        "source_label": "evidence support extract",
        "summary_text": summary_text,
        "step_count": len(steps),
        "supported_claim_count": len(claimability.get("supported_claims") or []),
        "partially_supported_claim_count": len(claimability.get("partially_supported_claims") or []),
        "unsupported_claim_count": len(claimability.get("unsupported_or_not_claimable_claims") or []),
    }


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
        "source_label": "executive summary snapshot",
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
        "validation_execution_status": integrity.get("status") or ("completed" if manifest_present and custody_present else "partial"),
        "validation_output_status": "useful" if integrity else "not_available",
        "verified_artifacts": verification.get("verified_artifacts") or integrity.get("verified_artifacts"),
        "failed_artifacts": verification.get("failed_artifacts") or integrity.get("failed_artifacts"),
        "main_limitation": (integrity.get("limitations") or [None])[0],
        "artifact_path": relative_path(case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json") if (case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json").exists() else None,
        "source_label": "executive summary snapshot",
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
    node_clock_sync_status = temporal.get("node_clock_synchronization_status") or _derive_temporal_sync_status(time_sync_status)
    causal_temporal_ordering_confidence = temporal.get("causal_temporal_ordering_confidence") or temporal.get("temporal_confidence_state") or "unknown"
    available_timestamp_resolvability = temporal.get("evidence_timestamp_resolvability") or "not_applicable"
    evidence_timestamp_availability = temporal.get("evidence_timestamp_availability") or "not_applicable"
    if evidence_timestamp_availability in {"partial", "unknown", "not_available"} or causal_temporal_ordering_confidence in {"limited", "ambiguous", "unknown"}:
        causal_edge_timestamp_coverage = "partial"
    elif evidence_timestamp_availability in {"full", "confirmed"}:
        causal_edge_timestamp_coverage = "full"
    else:
        causal_edge_timestamp_coverage = evidence_timestamp_availability
    before_after_available = bool(
        temporal.get("before_after_clock_correction_data_available")
        or (case_dir / "metadata" / "time_sync_before.json").exists()
        or (case_dir / "metadata" / "time_sync_after.json").exists()
    )
    return {
        # Kept for backward compatibility: this used to be the single
        # "temporal confidence" number. It is now an alias of
        # causal_temporal_ordering_confidence below - the four separated
        # fields are the ones new UI/reporting code should read.
        "temporal_confidence": causal_temporal_ordering_confidence,
        "source_label": "causal reconstruction artifacts",
        "node_clock_synchronization_status": node_clock_sync_status,
        "evidence_timestamp_availability": evidence_timestamp_availability,
        "evidence_timestamp_resolvability": available_timestamp_resolvability,
        "available_timestamp_resolvability": available_timestamp_resolvability,
        "causal_edge_timestamp_coverage": causal_edge_timestamp_coverage,
        "causal_temporal_ordering_confidence": causal_temporal_ordering_confidence,
        "causal_temporal_ordering_reason": temporal.get("causal_temporal_ordering_reason"),
        "causal_temporal_ordering_limiting_factor": temporal.get("causal_temporal_ordering_limiting_factor"),
        "temporal_model_note": temporal.get("temporal_model_note"),
        "max_clock_offset_seconds": max_offset_seconds,
        "uncertainty_window_seconds": temporal.get("uncertainty_window_seconds"),
        "synchronized_status": node_clock_sync_status,
        "correction_applied": bool(summary.get("correction_applied") or time_sync_status.get("fix_time_requested")),
        "nodes_measured": summary.get("nodes_ok") if summary.get("nodes_ok") is not None else time_sync_status.get("nodes_ok"),
        "nodes_failed": summary.get("nodes_failed") if summary.get("nodes_failed") is not None else time_sync_status.get("nodes_failed"),
        "worst_node": summary.get("worst_node") or time_sync_status.get("worst_node"),
        "time_sync_source": source,
        "current_measurement_status": time_sync_status.get("status") or "not_executed",
        "before_path": relative_path(case_dir / "metadata" / "time_sync_before.json") if (case_dir / "metadata" / "time_sync_before.json").exists() else None,
        "after_path": relative_path(case_dir / "metadata" / "time_sync_after.json") if (case_dir / "metadata" / "time_sync_after.json").exists() else None,
        "before_after_clock_correction_data_available": before_after_available,
        "latest_path": relative_path(case_dir / "metadata" / "time_sync.json") if (case_dir / "metadata" / "time_sync.json").exists() else None,
        "main_limitation": temporal.get("causal_temporal_ordering_reason") or temporal.get("temporal_warning") or temporal.get("temporal_caution"),
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
    interpretation = {
        "confirmed": "Modbus/TCP traffic targeting the PLC was observed." if modbus_seen else "Modbus/TCP activity targeting the PLC was not confirmed.",
        "partially_supported": "function code, register, value, and OT state relation." if modbus_seen else "not_available",
        "not_fully_claimable": "complete packet-level register and value causality." if modbus_seen else "packet-level Modbus specificity.",
        "summary": (
            "The evidence supports the presence of Modbus/TCP activity toward the PLC. However, register-level and value-level causal precision remain partial because packet-level parsing does not fully confirm all Modbus parameters."
            if modbus_seen
            else "The evidence does not currently confirm Modbus/TCP activity toward the PLC."
        ),
    }
    return {
        "protocol": {"status": protocol_state, "value": expected.get("protocol") or ((attack.get("operation") or {}).get("protocol")) or "not_available"},
        "function_code": {"status": function_state, "value": expected.get("modbus_function") or expected.get("ot_function") or "not_available"},
        "register": {"status": register_state, "value": expected.get("register", "not_available")},
        "value": {"status": value_state, "value": expected.get("expected_value", "not_available")},
        "target_plc": {"status": "confirmed" if expected.get("target") else "not_available", "value": expected.get("target") or ((attack.get("target") or {}).get("instance_name")) or "not_available"},
        "plc_or_scada_state": {"status": plc_state, "value": "OT exports parsed" if plc_state != "not_available" else "not_available"},
        "message": "Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing." if modbus_seen and (register_state != "confirmed" or value_state != "confirmed") else None,
        "interpretation": interpretation,
    }


def _gt_node_label(ground_truth: dict, node_id: str) -> str:
    node = ((ground_truth or {}).get("nodes") or {}).get(node_id) or {}
    return str(node.get("label") or node_id or "not_available")


def _req_label(requirement: str) -> str:
    return _EDGE_REQ_LABELS.get(str(requirement or ""), str(requirement or "not_available").replace("_", " "))


def _temporal_resolvability_label(temporal_status: str) -> str:
    normalized = str(temporal_status or "unknown")
    mapping = {
        "supported": "resolved",
        "not_required": "not required",
        "unknown": "not resolved",
        "ambiguous": "ambiguous",
        "contradicted": "contradicted",
        "missing": "missing",
    }
    return mapping.get(normalized, normalized.replace("_", " "))


def _build_expected_causal_relations(ground_truth: dict, graph_payload: dict) -> list[dict]:
    expected_edges = list((ground_truth or {}).get("expected_edges") or [])
    graph_edges = list((graph_payload or {}).get("edges") or [])
    graph_by_id = {
        str(edge.get("expected_edge_id") or edge.get("edge_id") or ""): edge
        for edge in graph_edges
        if edge.get("expected_edge_id") or edge.get("edge_id")
    }
    relations: list[dict] = []
    for expected in expected_edges:
        edge_id = str(expected.get("edge_id") or "not_available")
        observed = graph_by_id.get(edge_id) or {}
        relation = {
            "edge_id": edge_id,
            "source_event": _gt_node_label(ground_truth, expected.get("source")),
            "target_event": _gt_node_label(ground_truth, expected.get("target")),
            "expected_evidence_source": ", ".join(_req_label(item) for item in (expected.get("required_evidence") or [])) or "not_available",
            "recovered_status": observed.get("support_status") or "not_evaluated",
            "support_level": observed.get("confidence") or "unknown",
            "degradation_reason": observed.get("status_reason")
            or "Fully recovered."
            if observed.get("support_status") == "recovered"
            else (observed.get("limitations") or [None])[0]
            or "No degradation reason was recorded.",
            "temporal_resolvability": _temporal_resolvability_label(observed.get("temporal_status")),
            "weight": expected.get("weight"),
            "evidence_refs": observed.get("evidence_refs") or [],
            "limitations": observed.get("limitations") or [],
        }
        relations.append(relation)
    return relations


def _build_weighted_cpr_details(ground_truth: dict, graph_payload: dict, metrics: dict, uncertainty: dict) -> dict:
    expected_edges = list((ground_truth or {}).get("expected_edges") or [])
    graph_edges = list((graph_payload or {}).get("edges") or [])
    graph_by_id = {
        str(edge.get("expected_edge_id") or edge.get("edge_id") or ""): edge
        for edge in graph_edges
        if edge.get("expected_edge_id") or edge.get("edge_id")
    }
    total_weight = 0.0
    recovered_weight = 0.0
    degraded_weight = 0.0
    ambiguous_weight = 0.0
    missing_weight = 0.0
    per_edge: list[dict] = []
    for expected in expected_edges:
        edge_id = str(expected.get("edge_id") or "")
        weight = float(expected.get("weight") or 1.0)
        total_weight += weight
        observed = graph_by_id.get(edge_id) or {}
        status = str(observed.get("support_status") or "missing")
        if status == "recovered":
            recovered_weight += weight
        elif status == "degraded":
            degraded_weight += weight
        elif status == "ambiguous":
            ambiguous_weight += weight
        else:
            missing_weight += weight
        per_edge.append(
            {
                "edge_id": edge_id,
                "weight": round(weight, 4),
                "support_status": status,
                "contribution_to_weighted_cpr": round(weight, 4) if status == "recovered" else 0.0,
            }
        )

    degraded_rate = float(metrics.get("degraded_edge_rate") or 0.0)
    ambiguous_rate = float(metrics.get("ambiguous_edge_rate") or 0.0)
    temporal_state = str(metrics.get("temporal_confidence_state") or ((uncertainty.get("temporal") or {}).get("temporal_confidence_state")) or "unknown")
    temporal_penalty = {"strong": 0.0, "limited": 0.05, "ambiguous": 0.12, "unknown": 0.15}.get(temporal_state, 0.15)
    degradation_penalty = round(degraded_rate * 0.08, 4)
    ambiguity_penalty = round(ambiguous_rate * 0.12, 4)

    return {
        "cpr_formula": "fully recovered expected causal edges / total expected causal edges",
        "weighted_cpr_formula": "recovered edge weight / total expected edge weight",
        "weighted_cpr_explanation": "Weighted CPR uses the scenario-defined edge weights only. Temporal and degradation penalties apply to reconstruction confidence, not to Weighted CPR itself.",
        "total_edge_weight": round(total_weight, 4),
        "recovered_edge_weight": round(recovered_weight, 4),
        "degraded_edge_weight": round(degraded_weight, 4),
        "ambiguous_edge_weight": round(ambiguous_weight, 4),
        "missing_edge_weight": round(missing_weight, 4),
        "penalty_applied": {
            "degradation_penalty": degradation_penalty,
            "ambiguity_penalty": ambiguity_penalty,
            "temporal_penalty": temporal_penalty,
            "total_penalty": round(degradation_penalty + ambiguity_penalty + temporal_penalty, 4),
            "note": "These penalties affect reconstruction confidence, not the raw Weighted CPR ratio.",
        },
        "final_weighted_score": metrics.get("weighted_cpr"),
        "per_edge": per_edge,
    }


def _summary_staleness(case_dir: Path, summary_path: Path) -> dict:
    summary_mtime = _mtime(summary_path)
    if not summary_mtime:
        return {
            "status": "not_generated",
            "reason": "Executive evidence lifecycle summary has not been generated yet.",
            "required_action": "generate executive summary",
            "source_label": "executive summary snapshot",
            "is_stale": False,
        }
    source_groups = {
        "causal reconstruction artifacts": [
            case_dir / "derived" / "reconstruction" / "causal_status.json",
            case_dir / "derived" / "reconstruction" / "causal_graph.json",
            case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json",
            case_dir / "derived" / "reconstruction" / "uncertainty_report.json",
        ],
        "multilayer analysis artifacts": [
            case_dir / "analysis" / "forensic_analysis_report.json",
            case_dir / "analysis" / "visual" / "analysis_visual_summary.json",
        ],
        "time synchronization artifacts": [
            case_dir / "metadata" / "time_sync.json",
            case_dir / "metadata" / "time_sync_before.json",
            case_dir / "metadata" / "time_sync_after.json",
        ],
    }
    newest_group = None
    newest_group_mtime = 0.0
    for label, paths in source_groups.items():
        group_mtime = max((_mtime(path) for path in paths if path.exists()), default=0.0)
        if group_mtime > newest_group_mtime:
            newest_group_mtime = group_mtime
            newest_group = label
    is_stale = bool(newest_group_mtime and newest_group_mtime > summary_mtime)
    if not is_stale:
        return {
            "status": "current",
            "reason": None,
            "required_action": None,
            "source_label": "executive summary snapshot",
            "is_stale": False,
        }
    if newest_group == "causal reconstruction artifacts":
        reason = "Causal reconstruction artifacts were modified after the executive summary was generated."
    elif newest_group == "multilayer analysis artifacts":
        reason = "Multilayer analysis artifacts were modified after the executive summary was generated."
    elif newest_group == "time synchronization artifacts":
        reason = "Time synchronization artifacts were modified after the executive summary was generated."
    else:
        reason = "Executive summary artifacts are older than one or more derived inputs."
    return {
        "status": "stale",
        "reason": reason,
        "required_action": "regenerate executive summary",
        "source_label": "executive summary snapshot",
        "is_stale": True,
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


def _build_causal_summary(case_id: str, case_dir: Path, bundle: dict, causal_status: dict, metrics: dict, uncertainty: dict, trigger_summary: dict) -> dict:
    ground_truth = _resolve_real_ground_truth(causal_status, bundle.get("scenario_ground_truth") or {})
    attack = _pick_attack(bundle, ground_truth)
    graph_payload = causal_graph_payload(case_id, case_dir) or {}
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
    mismatch_label = None
    path_status = "aligned_or_not_demonstrably_misaligned"
    scientific_interpretation = "No explicit trigger-path mismatch was established from the preserved artifacts."
    if not causal_attack_path_resolved:
        # Do not claim alignment - or misalignment - when the causal attack
        # path itself could not be resolved; that is a distinct, weaker claim.
        mismatch = "Trigger and causal attack path alignment cannot be confirmed from the current summary."
        path_status = "causal_path_not_resolved"
        scientific_interpretation = "The preserved case remains valid, but the reconstructed attack path itself is not fully resolvable from the current summary."
    elif trigger_label and "/" in trigger_label and causal_protocol.lower().startswith("modbus"):
        same_event_family = False
        mismatch_label = "multi-vector_acquisition_trigger_mismatch"
        path_status = "trigger_attack_mismatch"
        mismatch = (
            "The preserved case was triggered by a host or FIM-oriented alert, while the causal reconstruction "
            "evaluates an OT Modbus path. These paths are related only if an explicit cross-layer link is "
            "available. Otherwise, they must be interpreted separately. This is not an error. It is a "
            "scientific limitation and should be reported as such."
        )
        scientific_interpretation = "Valid case with acquisition-trigger limitation."
    else:
        same_event_family = True
    expected_relations = _build_expected_causal_relations(ground_truth, graph_payload)
    weighted_cpr_details = _build_weighted_cpr_details(ground_truth, graph_payload, metrics, uncertainty)
    degraded_edges = int(metrics.get("degraded_edges") or 0)
    expected_edges = int(metrics.get("expected_edges") or 0)
    interpretation_banner = "This case does not yet expose a usable expected causal model."
    if expected_edges:
        reasons = [
            f"{degraded_edges} of {expected_edges} expected causal relations are only partially supported",
        ]
        if same_event_family is False:
            reasons.append("the acquisition trigger is host or FIM-oriented while the reconstructed attack path is OT Modbus-oriented")
        if str(((uncertainty.get('temporal') or {}).get('causal_temporal_ordering_confidence') or 'unknown')) in {"limited", "ambiguous", "unknown"}:
            reasons.append("some causal timestamps are unavailable or not resolvable")
        interpretation_banner = (
            "This case is forensically analyzable and partially causally reconstructable. "
            "The evidence lifecycle completed successfully across the multilayer analysis. "
            f"However, the causal reconstruction is degraded because {'; '.join(reasons)}."
        )
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
        "source_label": "causal reconstruction artifacts",
        "ground_truth_path": ((causal_status.get("ground_truth_summary") or {}).get("ground_truth_path")),
        "why_expected_relations": {
            "title": "Why 8 expected causal relations?",
            "summary": (
                f"This case defines {len(expected_relations)} expected causal relations for the selected scenario. "
                "CPR measures how many of these relations were fully reconstructed from preserved and verifiable evidence. "
                f"In this case, {metrics.get('recovered_edges') or 0} relations were fully recovered and {metrics.get('degraded_edges') or 0} remain degraded due to partial, inferred, or temporally unresolved support."
            ),
            "relations": expected_relations,
        },
        "weighted_cpr_details": weighted_cpr_details,
        "interpretation_banner": interpretation_banner,
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
            "status": path_status,
            "mismatch_label": mismatch_label,
            "scientific_interpretation": scientific_interpretation,
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
    uncertainty_integrity = (uncertainty.get("integrity") or {})
    supported: list[str] = []
    degraded: list[str] = []
    unsupported: list[str] = []

    if integrity.get("manifest_present") and integrity.get("chain_of_custody_present"):
        supported.append("Evidence preservation: manifest and chain of custody are available.")
    if multilayer.get("execution_status") == "completed":
        supported.append(
            f"Forensic processing: {multilayer.get('layers_with_useful_output') or 0} of {multilayer.get('layers_expected') or 0} expected layers completed with useful output."
        )
    if (multilayer.get("timeline_entries") or 0) > 0 or (multilayer.get("cross_layer_findings") or 0) > 0:
        supported.append(
            f"Cross-layer analysis: timeline and cross-layer findings were generated ({multilayer.get('timeline_entries') or 0} timeline entries, {multilayer.get('cross_layer_findings') or 0} cross-layer findings)."
        )
    if str(causal.get("status")).startswith("completed"):
        supported.append(
            f"Causal reconstruction: {causal.get('recovered_edges') or 0} of {causal.get('expected_edges') or 0} expected causal relations were fully recovered and {causal.get('degraded_edges') or 0} remain degraded."
        )
    if int(causal.get("recovered_edges") or 0) > 0:
        supported.append("The causal reconstruction consumed preserved FOC and multilayer outputs instead of re-running forensic tools.")

    if uncertainty.get("causal_temporal_ordering_confidence") in {"ambiguous", "limited", "unknown"}:
        degraded.append(
            str(uncertainty.get("causal_temporal_ordering_reason"))
            if uncertainty.get("causal_temporal_ordering_reason")
            else "Causal temporal ordering confidence is reduced."
        )
    if int(causal.get("degraded_edges") or 0) > 0:
        degraded.append(f"{causal.get('degraded_edges')} causal edges remain degraded due to partial support.")
    if int(causal.get("ambiguous_edges") or 0) > 0:
        degraded.append(f"{causal.get('ambiguous_edges')} causal edges remain temporally ambiguous under the current uncertainty window.")
    if (causal.get("trigger_vs_causal_path") or {}).get("message"):
        degraded.append((causal.get("trigger_vs_causal_path") or {}).get("message"))
    if (causal.get("modbus_specificity") or {}).get("message"):
        degraded.append((causal.get("modbus_specificity") or {}).get("message"))
    if uncertainty_integrity.get("case_wide_integrity_status") not in {"completed", "verified", "ok"}:
        degraded.append("Case-wide integrity remains partial.")

    unsupported.extend(
        [
            "Absolute causality.",
            "Court-ready admissibility.",
            "Strong time-order causality under the current clock-offset uncertainty.",
            "Full production OT generalization.",
        ]
    )
    modbus_specificity = causal.get("modbus_specificity") or {}
    if (modbus_specificity.get("register") or {}).get("status") != "confirmed" or (modbus_specificity.get("value") or {}).get("status") != "confirmed":
        unsupported.append("Complete Modbus register and value causality at packet-level precision.")
    if (causal.get("trigger_vs_causal_path") or {}).get("same_event_family") is not True:
        unsupported.append("A direct OT alert to forensic acquisition link.")
    unsupported.append("Full semantic reconstruction if semantic artifacts have not been generated.")

    extract = summary.get("evidence_support_extract") or {}
    global_support_level = extract.get("global_support_level")
    extract_clause = ""
    if extract.get("status") == "available" and global_support_level:
        extract_clause = f" The normalized Evidence Support Extract assesses the controlling hypothesis as {str(global_support_level).replace('_', ' ')}."
        if global_support_level in {"moderate_support", "strong_support"}:
            supported.append(f"Moderate hypothesis support: the Evidence-Based Hypothesis Support layer assesses hypothesis H1 as {global_support_level.replace('_', ' ')} across independently-sourced layers.")
        elif global_support_level == "contradicted":
            degraded.append("The Evidence Support Extract found at least one contradiction against the controlling hypothesis.")
        else:
            degraded.append(f"The Evidence Support Extract assesses hypothesis H1 as only {str(global_support_level).replace('_', ' ')}.")

    summary_text = (
        "The preserved evidence supports a partial causal-forensic reconstruction of a controlled OT incident. "
        f"The evidence processing coverage is {multilayer.get('analysis_confidence') or 'unknown'} because the multilayer analysis {multilayer.get('execution_status') or 'remains unavailable'} and produced "
        f"useful outputs across {multilayer.get('layers_with_useful_output') or 0} layers. "
        f"The causal reconstruction recovered {causal.get('recovered_edges') or 0} of {causal.get('expected_edges') or 0} "
        f"expected causal relations and degraded {causal.get('degraded_edges') or 0} relations due to partial or inferred evidence. "
        f"The hypothesis receives {(extract.get('global_support_level') or 'unverified').replace('_', ' ')}, not strong support. "
        f"Causal temporal ordering confidence is {uncertainty.get('causal_temporal_ordering_confidence') or 'unknown'}, "
        f"case-wide integrity status is {uncertainty_integrity.get('case_wide_integrity_status') or uncertainty_integrity.get('integrity_status') or 'unknown'}, and the stated Modbus/trigger limitations remain."
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
    causal = _build_causal_summary(case_id, case_dir, bundle, causal_status, causal_metrics, causal_uncertainty, intervention)
    memory_detail = _build_memory_analysis_detail(case_dir)
    alert_triage = _build_alert_triage_summary(bundle, intervention, _json_load(case_dir / "analysis" / "07_alerts" / "alert_findings.json") or {})
    evidence_story = _build_evidence_story(case_dir)

    integrity["case_wide_integrity_completeness"] = ((uncertainty.get("integrity") or {}).get("case_wide_integrity_status")) or integrity.get("overall_status")
    integrity["case_wide_integrity_ratio"] = ((uncertainty.get("integrity") or {}).get("case_wide_integrity_ratio"))

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

    summary_status = _summary_staleness(case_dir, summary_path)

    execution_summary = {
        "overall_status": causal.get("status") or multilayer.get("execution_status") or "not_available",
        "evidence_lifecycle_status": evidence_lifecycle.get("status"),
        "multilayer_analysis_status": multilayer.get("execution_status"),
        "causal_reconstruction_status": causal.get("status"),
        "evidence_processing_coverage": multilayer.get("analysis_confidence") or "unknown",
        "evidence_analysis_confidence": multilayer.get("analysis_confidence") or "unknown",
        "forensic_reconstruction_confidence": visual_summary.get("forensic_reconstruction_status") or "unknown",
        "causal_interpretation_confidence": causal.get("causal_interpretation_confidence") or "unknown",
        "main_limitation": causal.get("main_limitation") or multilayer.get("main_limitation") or uncertainty.get("main_limitation"),
        "generated_report_path": analysis_status.get("forensic_analysis_report_path"),
        "source_label": "executive summary snapshot",
        "evidence_processing_interpretation": "The evidence processing coverage is strong, while the forensic reconstruction remains partial and the causal interpretation remains limited.",
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

    # Local import to avoid a module-level circular import: evidence_support.service
    # itself imports several helpers from this module.
    from .evidence_support.service import evidence_support_extract_stub

    summary = {
        "case_id": case_id,
        "source_case_name": entry.get("source_case_name"),
        "scenario_id": (bundle.get("foc_context_summary") or {}).get("scenario_id") or ((bundle.get("scenario_ground_truth") or {}).get("scenario_id")) or "unknown",
        "scenario_name": (bundle.get("foc_context_summary") or {}).get("scenario_name") or ((bundle.get("scenario_ground_truth") or {}).get("scenario_name")) or "unknown",
        "generated_at": utc_now(),
        "is_stale": bool(summary_status.get("is_stale")),
        "summary_status": summary_status,
        "case_path": relative_path(case_dir),
        "execution_summary": execution_summary,
        "trigger_summary": trigger_summary,
        "evidence_lifecycle": evidence_lifecycle,
        "multilayer_analysis_summary": multilayer,
        "causal_summary": causal,
        "uncertainty_summary": uncertainty,
        "integrity_summary": integrity,
        "evidence_support_extract": evidence_support_extract_stub(case_id, case_dir),
        "memory_analysis_detail": memory_detail,
        "alert_triage_summary": alert_triage,
        "evidence_based_reconstruction_story": evidence_story,
        "reports_and_artifacts": report_index,
        "panel_sources": {
            "executive_summary": {"source_label": "executive summary snapshot", "artifact_path": relative_path(summary_path)},
            "live_pipeline": {"source_label": "live pipeline status"},
            "causal_reconstruction": {"source_label": "causal reconstruction artifacts", "artifact_path": relative_path(case_dir / "derived" / "reconstruction" / "causal_status.json")},
            "evidence_support_extract": {"source_label": "evidence-based hypothesis support", "artifact_path": relative_path(case_dir / "derived" / "evidence_support" / "hypothesis_support_report.json")},
        },
        "final_forensic_conclusion": {},
        "limitations": [],
        "next_required_actions": [],
    }
    limitations, actions = _build_limitations_and_actions(summary)
    summary["limitations"] = limitations
    summary["next_required_actions"] = actions
    summary["final_forensic_conclusion"] = _build_final_conclusion(summary)

    summary["stale_reason"] = summary_status.get("reason")
    summary["required_action"] = summary_status.get("required_action")
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
        "current_phase_label": "Queued",
        "current_phase_detail": "Waiting to start the full evidence lifecycle pipeline.",
        "progress_percent": 0,
        "phases": [],
        "phase_trace": [],
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
    if job.get("hard_stop_locked") and not updates.pop("allow_post_stop_update", False):
        with _JOB_LOCK:
            _JOBS[job["job_id"]] = job
        _write_json(_job_path(case_dir, job["job_id"]), job)
        return
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
    job["current_phase_label"] = extra.get("label") or phase.get("label") or phase_name.replace("_", " ").title()
    job["current_phase_detail"] = extra.get("detail") or phase.get("summary") or phase.get("error_message") or job.get("current_phase_detail")
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


def request_lifecycle_cancel(job_id: str, *, force: bool = False) -> dict | None:
    payload = get_lifecycle_job(job_id)
    if not payload:
        return None
    case_path = Path(str(payload.get("case_path") or ""))
    if not case_path.is_absolute():
        repo_root = Path(__file__).resolve().parents[3]
        case_path = (repo_root / case_path).resolve() if str(case_path) else case_path
    if not case_path.is_dir():
        case_id = str(payload.get("case_id") or "")
        entry = get_case_entry(case_id) if case_id else None
        if entry:
            case_path = _case_dir_from_entry(entry)
    if not case_path or not Path(case_path).is_dir():
        return payload
    cancel_path = _job_cancel_path(Path(case_path), job_id)
    cancel_path.parent.mkdir(parents=True, exist_ok=True)
    cancel_path.write_text(utc_now(), encoding="utf-8")
    updates = {
        "cancel_requested": True,
        "cancel_requested_at": utc_now(),
        "status": "cancel_requested",
        "current_phase_detail": "A lifecycle cancellation request was received.",
    }
    if force:
        updates.update(
            {
                "force_stop_requested": True,
                "force_stop_requested_at": utc_now(),
                "status": "stopped",
                "finished_at": utc_now(),
                "current_phase": "force_stopped",
                "current_phase_label": "Force Stopped",
                "current_phase_detail": "A lifecycle force-stop request was received.",
                "progress_percent": 100,
                "hard_stop_locked": True,
            }
        )
    payload.update(updates)
    _set_job(payload, Path(case_path), **updates)
    return payload


def _job_cancel_requested(job: dict, case_dir: Path) -> tuple[bool, bool]:
    cancel_path = _job_cancel_path(case_dir, str(job.get("job_id") or ""))
    force = bool(job.get("force_stop_requested"))
    requested = force or bool(job.get("cancel_requested")) or cancel_path.exists()
    return requested, force


def _stop_lifecycle_job(job: dict, case_dir: Path, *, forced: bool, detail: str) -> None:
    status = "stopped" if forced else "cancelled"
    label = "Force Stopped" if forced else "Cancelled"
    _update_phase(job, case_dir, str(job.get("current_phase") or "lifecycle"), status, finished_at=utc_now(), label=job.get("current_phase_label") or label, detail=detail)
    _set_job(
        job,
        case_dir,
        status=status,
        finished_at=utc_now(),
        current_phase="force_stopped" if forced else "cancelled",
        current_phase_label=label,
        current_phase_detail=detail,
        progress_percent=100,
        hard_stop_locked=forced,
    )
    try:
        _job_cancel_path(case_dir, str(job.get("job_id") or "")).unlink()
    except Exception:
        pass


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


def _verify_preserved_evidence(case_dir: Path) -> dict:
    manifest_path = case_dir / "manifest.json"
    custody_path = case_dir / "chain_of_custody.log"
    pipeline_path = case_dir / "metadata" / "pipeline_events.jsonl"
    available = [relative_path(path) for path in (manifest_path, custody_path, pipeline_path) if path.exists()]
    blockers: list[str] = []
    warnings: list[str] = []
    if not manifest_path.exists():
        blockers.append("manifest.json is missing")
    if not custody_path.exists():
        warnings.append("chain_of_custody.log is missing")
    status = "completed"
    if blockers:
        status = "blocked"
    elif warnings:
        status = "partial"
    return {
        "status": status,
        "detail": "Preserved evidence references were validated before running the full lifecycle." if status == "completed" else "Preserved evidence is readable but one or more verification artifacts are incomplete." if status == "partial" else "Required preserved evidence artifacts are missing.",
        "input_artifacts": available,
        "output_artifacts": [],
        "artifacts_processed_count": len(available),
        "findings_generated_count": 0,
        "warnings": warnings,
        "blockers": blockers,
        "scientific_limitation_reason": blockers[0] if blockers else (warnings[0] if warnings else None),
    }


def _run_full_worker(job: dict, case_dir: Path, force_analysis: bool, strict: bool, degraded_ok: bool) -> None:
    case_id = job["case_id"]
    generated_artifacts: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    try:
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled before startup.")
            return
        _set_job(job, case_dir, status="running", started_at=utc_now(), current_phase="resolve_preserved_case", current_phase_label="Resolve preserved case", current_phase_detail=f"Preparing full evidence lifecycle execution for preserved case {case_id}.", progress_percent=2)
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="resolve_preserved_case",
            parent_phase_id=None,
            phase_label="Resolve preserved case",
            layer="orchestration",
            status="completed",
            started_at=job.get("started_at") or utc_now(),
            finished_at=utc_now(),
            output_artifacts_generated=[relative_path(case_dir)],
            artifacts_processed_count=1,
            findings_generated_count=0,
            detail=f"Resolved preserved case {case_id} at {relative_path(case_dir)}.",
        )

        _set_job(job, case_dir, progress_percent=8, current_phase="verify_preserved_evidence", current_phase_label="Verify preserved evidence", current_phase_detail="Checking manifest, custody, and preserved evidence references.")
        _update_phase(job, case_dir, "verify_preserved_evidence", "running", started_at=utc_now(), label="Verify preserved evidence", detail="Checking manifest, custody, and preserved evidence references.")
        verify_result = _verify_preserved_evidence(case_dir)
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="verify_preserved_evidence",
            parent_phase_id=None,
            phase_label="Verify preserved evidence",
            layer="verification",
            status=verify_result.get("status"),
            started_at=job.get("updated_at") or utc_now(),
            finished_at=utc_now(),
            input_artifacts_used=verify_result.get("input_artifacts"),
            output_artifacts_generated=verify_result.get("output_artifacts"),
            artifacts_processed_count=verify_result.get("artifacts_processed_count"),
            findings_generated_count=verify_result.get("findings_generated_count"),
            warnings=verify_result.get("warnings"),
            blockers=verify_result.get("blockers"),
            scientific_limitation_reason=verify_result.get("scientific_limitation_reason"),
            detail=verify_result.get("detail"),
        )
        _update_phase(job, case_dir, "verify_preserved_evidence", verify_result.get("status"), finished_at=utc_now(), label="Verify preserved evidence", detail=verify_result.get("detail"))
        if verify_result.get("status") == "blocked":
            errors.extend(list(verify_result.get("blockers") or ["Required preserved evidence artifacts are missing."]))
            _set_job(job, case_dir, status="failed", finished_at=utc_now(), current_phase="failed", current_phase_label="Verify preserved evidence", current_phase_detail=verify_result.get("detail"), progress_percent=100, errors=errors, warnings=warnings)
            return
        warnings.extend(list(verify_result.get("warnings") or []))
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after preserved evidence verification.")
            return

        _set_job(job, case_dir, progress_percent=14, current_phase="run_multilayer_analysis", current_phase_label="Run multilayer forensic analysis", current_phase_detail="Running the preserved-case forensic analysis layers.")
        _update_phase(job, case_dir, "run_multilayer_analysis", "running", started_at=utc_now(), label="Run multilayer forensic analysis", detail="Running the preserved-case forensic analysis layers.")
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="run_multilayer_analysis",
            parent_phase_id=None,
            phase_label="Run multilayer forensic analysis",
            layer="multilayer",
            status="running",
            started_at=utc_now(),
            input_artifacts_used=list(verify_result.get("input_artifacts") or []),
            detail="The multilayer forensic analysis pipeline has started.",
        )
        run_analysis(case_id, force=force_analysis)
        analysis_status = load_analysis_status(case_id)
        deadline = time.time() + 7200
        while time.time() < deadline:
            requested, forced = _job_cancel_requested(job, case_dir)
            if requested:
                try:
                    from .foc_case_analysis import _analysis_cancel_path

                    cancel_path = _analysis_cancel_path(case_dir)
                    cancel_path.parent.mkdir(parents=True, exist_ok=True)
                    cancel_path.write_text(utc_now(), encoding="utf-8")
                except Exception:
                    pass
                _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was stopped while multilayer analysis was running. A case-analysis cancellation request was also issued.")
                return
            analysis_status = load_analysis_status(case_id)
            _sync_multilayer_phase_trace(job, case_dir, case_id, analysis_status)
            current_state = str((analysis_status or {}).get("status") or "").lower()
            if current_state in {"completed", "partial", "failed"}:
                break
            time.sleep(_POLL_SECONDS)
        if str(analysis_status.get("status") or "").lower() == "failed":
            reason = "; ".join(str(item) for item in (analysis_status.get("errors") or []) if item) or "Multilayer analysis failed."
            errors.append(reason)
            _upsert_phase_trace(
                job,
                case_dir,
                case_id=case_id,
                phase_id="run_multilayer_analysis",
                parent_phase_id=None,
                phase_label="Run multilayer forensic analysis",
                layer="multilayer",
                status="failed",
                finished_at=utc_now(),
                output_artifacts_generated=[analysis_status.get("forensic_analysis_report_path")] if analysis_status.get("forensic_analysis_report_path") else [],
                blockers=[reason],
                scientific_limitation_reason=reason,
                detail=reason,
            )
            _update_phase(job, case_dir, "run_multilayer_analysis", "failed", finished_at=utc_now(), label="Run multilayer forensic analysis", detail=reason, artifact_path=analysis_status.get("forensic_analysis_report_path"))
            _set_job(job, case_dir, status="failed", finished_at=utc_now(), current_phase="failed", current_phase_label="Run multilayer forensic analysis", current_phase_detail=reason, progress_percent=100, errors=errors, warnings=warnings, phase_trace=job.get("phase_trace"))
            return
        analysis_final_status = str(analysis_status.get("status") or "completed")
        if analysis_status.get("forensic_analysis_report_path"):
            generated_artifacts.append(analysis_status.get("forensic_analysis_report_path"))
        if analysis_final_status == "partial":
            warnings.extend([str(item.get("message") or item) for item in (analysis_status.get("warnings") or []) if item])
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="run_multilayer_analysis",
            parent_phase_id=None,
            phase_label="Run multilayer forensic analysis",
            layer="multilayer",
            status="degraded" if analysis_final_status == "partial" else "completed",
            finished_at=utc_now(),
            output_artifacts_generated=[analysis_status.get("forensic_analysis_report_path")] if analysis_status.get("forensic_analysis_report_path") else [],
            artifacts_processed_count=len([item for item in ((analysis_status.get("output_files") or [])) if item]),
            findings_generated_count=None,
            warnings=[str(item.get("message") or item) for item in (analysis_status.get("warnings") or []) if item],
            scientific_limitation_reason=(
                str(((analysis_status.get("warnings") or [{}])[0]).get("message"))
                if analysis_status.get("warnings")
                else None
            ),
            detail="Multilayer analysis finalization completed.",
        )
        _update_phase(job, case_dir, "run_multilayer_analysis", analysis_final_status, finished_at=utc_now(), label="Run multilayer forensic analysis", detail="Multilayer analysis finalization completed.", artifact_path=analysis_status.get("forensic_analysis_report_path"))
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after multilayer analysis.")
            return

        _set_job(job, case_dir, progress_percent=52, current_phase="bootstrap_foc", current_phase_label="Bootstrap FOC", current_phase_detail="Bootstrapping FOC context from preserved artifacts.")
        _update_phase(job, case_dir, "bootstrap_foc", "running", started_at=utc_now(), label="Bootstrap FOC", detail="Bootstrapping FOC context from preserved artifacts.")
        bootstrap_result = bootstrap_existing_context(force=False)
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="bootstrap_foc",
            parent_phase_id=None,
            phase_label="Bootstrap FOC",
            layer="foc",
            status="completed",
            started_at=job.get("updated_at") or utc_now(),
            finished_at=utc_now(),
            output_artifacts_generated=[],
            findings_generated_count=0,
            detail=f"FOC bootstrap finished with status {bootstrap_result.get('status') or 'completed'}.",
        )
        _update_phase(job, case_dir, "bootstrap_foc", "completed", finished_at=utc_now(), label="Bootstrap FOC", detail=f"FOC bootstrap finished with status {bootstrap_result.get('status') or 'completed'}.")
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after FOC bootstrap.")
            return

        _set_job(job, case_dir, progress_percent=58, current_phase="regenerate_foc_context", current_phase_label="Regenerate FOC context", current_phase_detail="Refreshing generated FOC context artifacts.")
        _update_phase(job, case_dir, "regenerate_foc_context", "running", started_at=utc_now(), label="Regenerate FOC context", detail="Refreshing generated FOC context artifacts.")
        regenerate_manifest = regenerate_foc()
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="regenerate_foc_context",
            parent_phase_id=None,
            phase_label="Regenerate FOC context",
            layer="foc",
            status="completed",
            started_at=job.get("updated_at") or utc_now(),
            finished_at=utc_now(),
            output_artifacts_generated=[str(value) for value in (regenerate_manifest or {}).values() if isinstance(value, str) and value.endswith((".json", ".md", ".csv"))][:8],
            detail="FOC context artifacts were regenerated.",
        )
        _update_phase(job, case_dir, "regenerate_foc_context", "completed", finished_at=utc_now(), label="Regenerate FOC context", detail="FOC context artifacts were regenerated.")
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after FOC regeneration.")
            return

        _set_job(job, case_dir, progress_percent=64, current_phase="time_sync_and_timestamp_quality", current_phase_label="Time synchronization and timestamp quality assessment", current_phase_detail="Measuring clock offset and timestamp quality inputs.")
        _update_phase(job, case_dir, "time_sync_and_timestamp_quality", "running", started_at=utc_now(), label="Time synchronization and timestamp quality assessment", detail="Measuring clock offset and timestamp quality inputs.")
        run_time_sync(case_id, fix_time=False, maintenance_override=False)
        time_sync_status = _wait_for_terminal(case_id, load_time_sync_status, {"running"}, {"completed", "failed", "blocked_policy"})
        time_sync_trace_status = "completed"
        time_sync_blockers = []
        time_sync_warnings = []
        if str(time_sync_status.get("status")) == "failed":
            time_sync_trace_status = "partial"
            time_sync_warnings.append(str(time_sync_status.get("reason") or "Clock-offset measurement failed."))
            warnings.extend(time_sync_warnings)
        elif str(time_sync_status.get("status")) == "blocked_policy":
            time_sync_trace_status = "blocked"
            time_sync_blockers.append(str(time_sync_status.get("reason") or "Time synchronization assessment was blocked by policy."))
            warnings.extend(time_sync_blockers)
        else:
            output_json = ((time_sync_status.get("output_paths") or {}).get("json")) or relative_path(case_dir / "metadata" / "time_sync.json")
            if output_json:
                generated_artifacts.append(output_json)
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="time_synchronization_and_timestamp_quality_assessment",
            parent_phase_id=None,
            phase_label="Time synchronization and timestamp quality assessment",
            layer="time_sync",
            status=time_sync_trace_status,
            started_at=job.get("updated_at") or utc_now(),
            finished_at=utc_now(),
            output_artifacts_generated=[((time_sync_status.get("output_paths") or {}).get("json"))] if ((time_sync_status.get("output_paths") or {}).get("json")) else [],
            warnings=time_sync_warnings,
            blockers=time_sync_blockers,
            scientific_limitation_reason=(time_sync_warnings or time_sync_blockers or [None])[0],
            detail=str(time_sync_status.get("reason") or "Time synchronization and timestamp quality assessment completed."),
        )
        _update_phase(job, case_dir, "time_sync_and_timestamp_quality", time_sync_trace_status, finished_at=utc_now(), label="Time synchronization and timestamp quality assessment", detail=str(time_sync_status.get("reason") or "Time synchronization and timestamp quality assessment completed."), artifact_path=((time_sync_status.get("output_paths") or {}).get("json")))
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after time synchronization assessment.")
            return

        _set_job(job, case_dir, progress_percent=72, current_phase="run_causal_reconstruction", current_phase_label="Run causal reconstruction", current_phase_detail="Running causal reconstruction after multilayer outputs and time assessment.")
        analysis_gate = str(analysis_status.get("status") or "").lower()
        if analysis_gate not in {"completed", "partial"}:
            blocker_reason = "Causal reconstruction is blocked because multilayer forensic analysis did not produce usable outputs."
            warnings.append(blocker_reason)
            _upsert_phase_trace(
                job,
                case_dir,
                case_id=case_id,
                phase_id="run_causal_reconstruction",
                parent_phase_id=None,
                phase_label="Run causal reconstruction",
                layer="causal",
                status="blocked",
                started_at=utc_now(),
                finished_at=utc_now(),
                blockers=[blocker_reason],
                scientific_limitation_reason=blocker_reason,
                detail=blocker_reason,
            )
            _update_phase(job, case_dir, "run_causal_reconstruction", "blocked", finished_at=utc_now(), label="Run causal reconstruction", detail=blocker_reason)
        else:
            _update_phase(job, case_dir, "run_causal_reconstruction", "running", started_at=utc_now(), label="Run causal reconstruction", detail="Launching causal reconstruction with the refreshed FOC context.")
            run_causal_reconstruction(case_id=case_id, case_path=case_dir, strict=strict, degraded_ok=degraded_ok)
            causal_status = _wait_for_terminal(case_id, lambda cid: summarize_case_causal_state(cid, case_dir, analysis_status=analysis_status), {"running"}, {"completed", "completed_with_degradation", "failed", "blocked_missing_ground_truth", "blocked_missing_analysis", "ready_to_run"})
            causal_state = str(causal_status.get("status") or causal_status.get("state") or "")
            if causal_state in {"blocked_missing_ground_truth", "blocked_missing_analysis"}:
                blocker_reason = str(causal_status.get("reason") or "Causal reconstruction was blocked by missing required inputs.")
                warnings.append(blocker_reason)
                _upsert_phase_trace(
                    job,
                    case_dir,
                    case_id=case_id,
                    phase_id="run_causal_reconstruction",
                    parent_phase_id=None,
                    phase_label="Run causal reconstruction",
                    layer="causal",
                    status="blocked",
                    started_at=job.get("updated_at") or utc_now(),
                    finished_at=utc_now(),
                    blockers=[blocker_reason],
                    scientific_limitation_reason=blocker_reason,
                    detail=blocker_reason,
                )
                _update_phase(job, case_dir, "run_causal_reconstruction", "blocked", finished_at=utc_now(), label="Run causal reconstruction", detail=blocker_reason)
            elif causal_state == "failed":
                error_reason = str(causal_status.get("reason") or "Causal reconstruction failed.")
                errors.append(error_reason)
                _upsert_phase_trace(
                    job,
                    case_dir,
                    case_id=case_id,
                    phase_id="run_causal_reconstruction",
                    parent_phase_id=None,
                    phase_label="Run causal reconstruction",
                    layer="causal",
                    status="failed",
                    started_at=job.get("updated_at") or utc_now(),
                    finished_at=utc_now(),
                    blockers=[error_reason],
                    scientific_limitation_reason=error_reason,
                    detail=error_reason,
                )
                _update_phase(job, case_dir, "run_causal_reconstruction", "failed", finished_at=utc_now(), label="Run causal reconstruction", detail=error_reason)
            else:
                trace_status = "degraded" if causal_state == "completed_with_degradation" else "completed"
                reason = str(causal_status.get("reason") or "Causal reconstruction completed.")
                if trace_status == "degraded":
                    warnings.append(reason)
                _upsert_phase_trace(
                    job,
                    case_dir,
                    case_id=case_id,
                    phase_id="run_causal_reconstruction",
                    parent_phase_id=None,
                    phase_label="Run causal reconstruction",
                    layer="causal",
                    status=trace_status,
                    started_at=job.get("updated_at") or utc_now(),
                    finished_at=utc_now(),
                    output_artifacts_generated=list((causal_status.get("output_paths") or {}).values()),
                    findings_generated_count=int(causal_status.get("recovered_edges") or 0) if causal_status.get("recovered_edges") is not None else None,
                    warnings=[reason] if trace_status == "degraded" else [],
                    scientific_limitation_reason=reason if trace_status == "degraded" else None,
                    detail=reason,
                )
                _update_phase(job, case_dir, "run_causal_reconstruction", trace_status, finished_at=utc_now(), label="Run causal reconstruction", detail=reason, artifact_path=((causal_status.get("output_paths") or {}).get("causal_graph")))
                for value in (causal_status.get("output_paths") or {}).values():
                    if value:
                        generated_artifacts.append(value)
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after causal reconstruction.")
            return

        _set_job(job, case_dir, progress_percent=86, current_phase="run_evidence_based_hypothesis_support", current_phase_label="Run evidence-based hypothesis support", current_phase_detail="Generating normalized evidence-support and claimability outputs.")
        _update_phase(job, case_dir, "run_evidence_based_hypothesis_support", "running", started_at=utc_now(), label="Run evidence-based hypothesis support", detail="Generating normalized evidence-support and claimability outputs.")
        from .evidence_support.service import build_evidence_support  # local import to avoid circular import
        support_result = build_evidence_support(case_id)
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="run_evidence_based_hypothesis_support",
            parent_phase_id=None,
            phase_label="Run evidence-based hypothesis support",
            layer="hypothesis_support",
            status="completed",
            started_at=job.get("updated_at") or utc_now(),
            finished_at=utc_now(),
            output_artifacts_generated=[
                support_result.get("atoms_path"),
                support_result.get("evidence_triage_report_path"),
                support_result.get("cross_layer_support_matrix_path"),
                support_result.get("hypothesis_support_report_path"),
                support_result.get("forensic_storyline_path"),
                support_result.get("claimability_report_path"),
                support_result.get("counter_evidence_report_path"),
            ],
            findings_generated_count=support_result.get("total_atoms"),
            detail=f"Hypothesis support generated with global support level {support_result.get('global_support_level') or 'unknown'}.",
        )
        _update_phase(job, case_dir, "run_evidence_based_hypothesis_support", "completed", finished_at=utc_now(), label="Run evidence-based hypothesis support", detail=f"Hypothesis support generated with global support level {support_result.get('global_support_level') or 'unknown'}.", artifact_path=support_result.get("hypothesis_support_report_path"))
        for value in (
            "atoms_path",
            "evidence_triage_report_path",
            "cross_layer_support_matrix_path",
            "hypothesis_support_report_path",
            "forensic_storyline_path",
            "claimability_report_path",
            "counter_evidence_report_path",
        ):
            if support_result.get(value):
                generated_artifacts.append(support_result.get(value))
        requested, forced = _job_cancel_requested(job, case_dir)
        if requested:
            _stop_lifecycle_job(job, case_dir, forced=forced, detail="The full evidence lifecycle was cancelled after evidence-based hypothesis support generation.")
            return

        _set_job(job, case_dir, progress_percent=94, current_phase="generate_executive_summary", current_phase_label="Generate executive summary and lifecycle dashboard snapshot", current_phase_detail="Writing the executive evidence lifecycle summary snapshot.")
        _update_phase(job, case_dir, "generate_executive_summary", "running", started_at=utc_now(), label="Generate executive summary and lifecycle dashboard snapshot", detail="Writing the executive evidence lifecycle summary snapshot.")
        payload = generate_evidence_lifecycle_summary(case_id)
        generated_artifacts.append(payload.get("summary_path"))
        _upsert_phase_trace(
            job,
            case_dir,
            case_id=case_id,
            phase_id="generate_executive_summary_and_lifecycle_dashboard_snapshot",
            parent_phase_id=None,
            phase_label="Generate executive summary and lifecycle dashboard snapshot",
            layer="executive_summary",
            status="completed",
            started_at=job.get("updated_at") or utc_now(),
            finished_at=utc_now(),
            output_artifacts_generated=[payload.get("summary_path")],
            findings_generated_count=1,
            detail="Executive summary and lifecycle dashboard snapshot generated.",
        )
        _update_phase(job, case_dir, "generate_executive_summary", "completed", finished_at=utc_now(), label="Generate executive summary and lifecycle dashboard snapshot", detail="Executive summary and lifecycle dashboard snapshot generated.", artifact_path=payload.get("summary_path"))

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
            phase_trace=job.get("phase_trace"),
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
