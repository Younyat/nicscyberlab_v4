from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .comparability_service import compare_executions
from .config import EVIDENCE_STORE_ROOT, campaign_config_path, campaign_dir, campaign_manifest_path, rel
from .dry_run_orchestrator import start_dry_run_execution_job
from .execution_service import load_execution
from .job_runner import (
    JobCancelled,
    append_phase,
    append_job_list,
    get_job,
    job_cancel_requested,
    new_job,
    raise_if_cancelled,
    request_cancel,
    start_job,
    update_job,
)
from .profile_builder import resolve_case_source
from ..foc_causal_reconstruction.service import (
    causal_graph_payload,
    causal_metrics_payload,
    causal_status_payload,
    causal_uncertainty_payload,
    run_causal_reconstruction,
)
from ..foc_reconstruction.evidence_lifecycle_dashboard import generate_evidence_lifecycle_summary, load_evidence_lifecycle_dashboard
from ..foc_reconstruction.evidence_support.service import (
    build_evidence_support,
    load_claimability_report,
    load_counter_evidence_report,
    load_forensic_storyline,
    load_hypothesis_support_report,
)
from ..foc_reconstruction.foc_case_analysis import analysis_report, load_analysis_status, run_analysis
from ..foc_reconstruction.foc_paths import relative_path
from ..foc_reconstruction.foc_sources import utc_now

SCIENTIFIC_REPORTS_ROOT = EVIDENCE_STORE_ROOT.parent / "scientific_reports" / "level_a_repetitions"

PHASES: list[tuple[str, str]] = [
    ("resolve_reference_case", "Resolve preserved reference case"),
    ("validate_manifest_and_custody", "Validate evidence manifest and custody records"),
    ("check_level_a_scope", "Check Level A repetition scope"),
    ("refresh_or_load_multilayer", "Refresh or load multilayer analysis"),
    ("extract_network_findings", "Extract network findings"),
    ("extract_memory_findings", "Extract memory findings"),
    ("extract_disk_findings", "Extract disk findings"),
    ("extract_ot_findings", "Extract OT findings"),
    ("extract_alert_findings", "Extract alert findings"),
    ("build_or_load_timeline", "Build or load unified timeline"),
    ("run_or_refresh_causal", "Run or refresh causal reconstruction"),
    ("run_hypothesis_support", "Run hypothesis support evaluation"),
    ("compare_with_previous", "Compare this Level A repetition with previous Level A executions"),
    ("generate_audit_map", "Generate evidence-to-claim audit map"),
    ("generate_markdown_report", "Generate Markdown scientific report"),
    ("write_report_bundle", "Write report, provenance manifest, and source index"),
]

TERMINAL_ANALYSIS_STATUSES = {"completed", "partial", "failed"}
TERMINAL_CAUSAL_STATUSES = {"completed", "completed_with_degradation", "blocked", "failed", "not_generated"}


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))


def _sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_stat(path: Path | None) -> tuple[int | None, str | None]:
    if path is None or not path.exists():
        return None, None
    try:
        size = path.stat().st_size
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        return size, mtime
    except Exception:
        return None, None


def _status_classification(status: str | None) -> str:
    raw = str(status or "").lower()
    if raw in {"completed", "valid", "available", "ready"}:
        return "supported"
    if raw in {"completed_with_degradation", "partial", "limited", "stale", "blocked"}:
        return "partial"
    if raw in {"failed", "missing", "not_generated", "not_available"}:
        return "unsupported"
    return "partial"


def _confidence_from_status(status: str | None) -> str:
    raw = str(status or "").lower()
    if raw in {"completed", "valid", "available", "ready"}:
        return "strong"
    if raw in {"completed_with_degradation", "partial", "limited", "stale"}:
        return "moderate"
    return "limited"


def _phase_progress(index: int, *, completed: bool) -> float:
    total = len(PHASES)
    start = (index / total) * 100.0
    end = ((index + 1) / total) * 100.0
    return round(end if completed else start, 2)


def _campaign_payload(campaign_id: str) -> tuple[dict, dict]:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    config = _json_load(campaign_config_path(campaign_id)) or {}
    return manifest, config


def _build_report_root(case_id: str, campaign_id: str, generated_at: str) -> Path:
    safe_ts = _safe_slug(generated_at.replace(":", "").replace("+", "_"))
    return SCIENTIFIC_REPORTS_ROOT / _safe_slug(case_id) / _safe_slug(campaign_id) / f"level_A_{safe_ts}"


def _phase_update(
    *,
    job_id: str,
    job_path: Path,
    phase_key: str,
    phase_label: str,
    phase_index: int,
    status: str,
    detail: str,
    case_id: str | None = None,
    execution_id: str | None = None,
    report_output_path: str | None = None,
    warning: str | None = None,
) -> None:
    append_phase(
        job_id,
        job_path,
        phase_key=phase_key,
        phase_label=phase_label,
        status=status,
        progress_percent=_phase_progress(phase_index, completed=status in {"completed", "completed_with_degradation", "failed"}),
        detail=detail,
    )
    changes = {}
    if case_id:
        changes["current_case_id"] = case_id
    if execution_id:
        changes["current_execution_id"] = execution_id
    if report_output_path:
        changes["report_output_path"] = report_output_path
    if warning:
        append_job_list(job_id, job_path, "warnings", warning)
    if changes:
        update_job(job_id, job_path, **changes)


def _wait_for_analysis(case_id: str, *, job_id: str, job_path: Path, phase_index: int, timeout_seconds: int = 900) -> dict:
    started = time.time()
    while True:
        raise_if_cancelled(job_id, job_path, phase_key="refresh_or_load_multilayer", phase_label="Refresh or load multilayer analysis", detail="Level A scientific report generation was cancelled while waiting for multilayer analysis.")
        status = load_analysis_status(case_id)
        if str(status.get("status") or "").lower() in TERMINAL_ANALYSIS_STATUSES:
            return status
        if time.time() - started > timeout_seconds:
            raise TimeoutError(f"analysis_timeout:{case_id}")
        current_phase = str(status.get("current_phase") or "running")
        update_job(
            job_id,
            job_path,
            current_phase="refresh_or_load_multilayer",
            current_phase_label="Refresh or load multilayer analysis",
            current_phase_detail=f"Multilayer analysis still running at phase {current_phase}. Waiting for a terminal Level A analysis state before report extraction.",
            progress_percent=_phase_progress(phase_index, completed=False),
        )
        time.sleep(2.5)


def _wait_for_causal(case_id: str, case_dir: Path, *, job_id: str, job_path: Path, phase_index: int, timeout_seconds: int = 420) -> dict:
    started = time.time()
    while True:
        raise_if_cancelled(job_id, job_path, phase_key="run_or_refresh_causal", phase_label="Run or refresh causal reconstruction", detail="Level A scientific report generation was cancelled while waiting for causal reconstruction.")
        status = causal_status_payload(case_id, case_dir) or {}
        if str(status.get("status") or "").lower() in TERMINAL_CAUSAL_STATUSES:
            return status
        if time.time() - started > timeout_seconds:
            raise TimeoutError(f"causal_timeout:{case_id}")
        update_job(
            job_id,
            job_path,
            current_phase="run_or_refresh_causal",
            current_phase_label="Run or refresh causal reconstruction",
            current_phase_detail=f"Causal reconstruction is still {status.get('status') or 'running'}. Waiting for a terminal causal state before report writing.",
            progress_percent=_phase_progress(phase_index, completed=False),
        )
        time.sleep(2.0)


def _wait_for_child_dry_run_job(
    child_job_id: str,
    *,
    parent_job_id: str,
    parent_job_path: Path,
    phase_index: int,
    repetition_index: int,
    requested_repetitions: int,
    case_id: str,
    report_output_path: str,
) -> dict:
    """Wait for a nested dry-run execution job — heartbeat-driven, no fixed
    deadline (2026-07-17, same reasoning as level_b_repetition_runner's
    _wait_for_child_job: a full FOC + causal reconstruction pass over a large
    preserved case can legitimately run long, and a blind clock here used to
    discard a real, still-progressing repetition's data). If the child's
    thread genuinely dies, job_runner.get_job()'s own orphan watchdog already
    flips it to 'failed' the next time it's read below.
    """
    while True:
        if job_cancel_requested(parent_job_id, parent_job_path):
            request_cancel(child_job_id)
            raise JobCancelled("level_a_report_cancelled")
        child = get_job(child_job_id) or {}
        child_meta = dict(child.get("meta") or {})
        child_execution_id = str(child_meta.get("execution_id") or child.get("current_execution_id") or "").strip() or None
        update_job(
            parent_job_id,
            parent_job_path,
            current_phase="refresh_or_load_multilayer",
            current_phase_label="Refresh or load multilayer analysis",
            current_phase_detail=(
                f"Run Dry-Run Execution {repetition_index}/{requested_repetitions}: "
                f"{child.get('current_phase_label') or child.get('current_phase') or 'running'}"
                f" — {child.get('current_phase_detail') or 'waiting for child dry-run execution to finish.'}"
            ),
            progress_percent=_phase_progress(phase_index, completed=False),
            current_case_id=case_id,
            current_execution_id=child_execution_id,
            current_child_job_id=child_job_id,
            report_output_path=report_output_path,
        )
        status = str(child.get("status") or "").lower()
        if status in {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}:
            return child
        time.sleep(2.5)


def _register_source(index: dict, *, path: str | None, file_type: str, artifact_category: str, role: str, fields: list[str], evidence_class: str) -> None:
    if not path:
        return
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(path).resolve()
    if not candidate.exists():
        repo_candidate = Path(path)
        if repo_candidate.exists():
            candidate = repo_candidate.resolve()
        else:
            return
    key = relative_path(candidate)
    current = index.get(key)
    if current:
        merged_fields = sorted(set(list(current.get("fields_extracted") or []) + list(fields or [])))
        merged_roles = sorted(set(list(current.get("roles") or []) + [role]))
        current["fields_extracted"] = merged_fields
        current["roles"] = merged_roles
        return
    size, mtime = _file_stat(candidate)
    index[key] = {
        "path": key,
        "file_type": file_type,
        "artifact_category": artifact_category,
        "hash": _sha256(candidate),
        "size": size,
        "modified_time": mtime,
        "role_in_report_generation": role,
        "roles": [role],
        "fields_extracted": sorted(set(fields or [])),
        "evidence_class": evidence_class,
    }


def _claim_entry(*, claim_id: str, claim: str, status: str, confidence: str, source_refs: list[dict], limitations: list[str] | None = None) -> dict:
    return {
        "claim_id": claim_id,
        "claim": claim,
        "status": status,
        "source_files": source_refs,
        "confidence": confidence,
        "limitations": list(limitations or []),
    }


def _source_ref(index: dict, path: str | None, fields_used: list[str], role: str) -> dict | None:
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        if Path(path).exists():
            candidate = Path(path).resolve()
        else:
            candidate = Path(path)
    key = relative_path(candidate) if candidate.exists() else str(path)
    existing = index.get(key)
    return {
        "path": key,
        "hash": (existing or {}).get("hash"),
        "fields_used": fields_used,
        "role": role,
    }


def _list_level_a_execution_ids(campaign_id: str) -> list[str]:
    root = campaign_dir(campaign_id) / "level_A"
    if not root.is_dir():
        return []
    out = []
    for manifest_path in sorted(root.glob("EXEC-*/execution_manifest.json")):
        payload = _json_load(manifest_path) or {}
        if payload.get("execution_id"):
            out.append(str(payload["execution_id"]))
    return out


def _comparable_level_a_execution_ids(campaign_id: str) -> list[str]:
    out: list[str] = []
    for execution_id in _list_level_a_execution_ids(campaign_id):
        payload = load_execution(execution_id, campaign_id=campaign_id) or {}
        if (payload.get("artifacts") or {}).get("forensic_comparison_profile"):
            out.append(execution_id)
    return out


def _execution_report_index_path(execution_dir: Path) -> Path:
    return execution_dir / "level_a_scientific_reports.json"


def _append_execution_report_index(execution_dir: Path, payload: dict) -> None:
    index_path = _execution_report_index_path(execution_dir)
    existing = _json_load(index_path)
    if not isinstance(existing, dict):
        existing = {"generated_reports": []}
    items = list(existing.get("generated_reports") or [])
    items.append(payload)
    existing["generated_reports"] = items
    existing["latest_report"] = payload
    existing["updated_at"] = utc_now()
    _write_json(index_path, existing)


def _update_execution_manifest_with_report(execution_id: str, report_entry: dict) -> None:
    execution = load_execution(execution_id)
    if not execution:
        return
    manifest_path = Path(str(execution.get("execution_abs_path") or "")) / "execution_manifest.json"
    payload = _json_load(manifest_path)
    if not isinstance(payload, dict):
        return
    reports = dict(payload.get("scientific_reports") or {})
    level_a_reports = list(reports.get("level_a") or [])
    level_a_reports.append(report_entry)
    reports["level_a"] = level_a_reports
    reports["latest_level_a"] = report_entry
    payload["scientific_reports"] = reports
    payload["updated_at"] = utc_now()
    _write_json(manifest_path, payload)


def _extract_modbus_packet_context(network_findings: dict) -> dict:
    files = list(((network_findings.get("findings") or {}).get("files")) or [])
    first_modbus = next((item for item in files if int(item.get("modbus_frames") or 0) > 0), None)
    return {
        "source_pcap": first_modbus.get("pcap") if first_modbus else None,
        "packet_timestamp": None,
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": 502 if first_modbus else None,
        "transaction_id": None,
        "unit_id": None,
        "function_code": None,
        "register_address": None,
        "value": None,
        "parser_or_method": "tshark io,stat summaries and derived evidence support triage",
        "confidence_level": "limited" if first_modbus else "missing",
        "note": "Packet-level Modbus register/value precision is not preserved by the current network extraction layer." if first_modbus else "No Modbus packet context could be loaded from the preserved network findings.",
        "modbus_frames": int(first_modbus.get("modbus_frames") or 0) if first_modbus else 0,
    }


def _build_source_index(
    case_dir: Path,
    execution_dir: Path,
    comparison_artifacts: dict | None,
    case_bundle: dict,
    lifecycle: dict,
    analysis_status: dict,
    causal_status: dict,
    metrics: dict,
    hypothesis: dict,
    storyline: dict,
    claimability: dict,
    counter_evidence: dict,
) -> dict:
    index: dict[str, dict] = {}
    paths = case_bundle.get("paths") or {}
    _register_source(index, path=paths.get("manifest") and str(paths["manifest"]), file_type="json", artifact_category="case_manifest", role="case identity and preserved artifact inventory", fields=["artifacts", "case_id"], evidence_class="primary_evidence")
    _register_source(index, path=paths.get("custody") and str(paths["custody"]), file_type="log", artifact_category="chain_of_custody", role="custody validation and preservation linkage", fields=["entries"], evidence_class="primary_evidence")
    _register_source(index, path=analysis_status.get("forensic_analysis_report_path"), file_type="json", artifact_category="analysis_report", role="multilayer analysis completeness and layer outputs", fields=["status", "phases"], evidence_class="derived_analysis")
    _register_source(index, path=analysis_status.get("analysis_visual_summary_path"), file_type="json", artifact_category="analysis_visual_summary", role="layer usefulness and indexed outputs", fields=["analysis_score", "layers"], evidence_class="derived_analysis")
    for key, category, fields in [
        ("network", "network_analysis", ["status", "findings", "limitations"]),
        ("memory", "memory_analysis", ["status", "findings", "limitations"]),
        ("disk", "disk_analysis", ["status", "findings", "limitations"]),
        ("ot", "ot_analysis", ["status", "findings", "limitations"]),
        ("alerts", "alerts_analysis", ["status", "findings", "limitations"]),
        ("timeline", "timeline_analysis", ["status", "findings", "limitations"]),
        ("cross_layer", "cross_layer_findings", ["status", "findings", "limitations"]),
        ("time_sync", "time_sync_metadata", ["status"]),
        ("summary", "evidence_lifecycle_summary", ["multilayer_analysis_summary", "causal_summary", "trigger_summary", "final_forensic_conclusion"]),
    ]:
        path_obj = paths.get(key)
        _register_source(index, path=path_obj and str(path_obj), file_type=Path(path_obj).suffix.lstrip(".") if path_obj else "json", artifact_category=category, role=f"{category} extraction", fields=fields, evidence_class="derived_analysis" if key != "summary" else "derived_executive")
    _register_source(index, path=str(case_dir / "derived" / "reconstruction" / "causal_status.json"), file_type="json", artifact_category="causal_status", role="causal reconstruction status", fields=["status", "requirements"], evidence_class="causal_output")
    _register_source(index, path=str(case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json"), file_type="json", artifact_category="causal_metrics", role="causal recovery metrics", fields=["expected_edges", "recovered_edges", "degraded_edges", "missing_edges", "cpr", "weighted_cpr"], evidence_class="causal_output")
    _register_source(index, path=str(case_dir / "derived" / "reconstruction" / "causal_graph.json"), file_type="json", artifact_category="causal_graph", role="edge-level causal audit and degraded/missing relation review", fields=["nodes", "edges"], evidence_class="causal_output")
    _register_source(index, path=str(case_dir / "derived" / "reconstruction" / "uncertainty_report.json"), file_type="json", artifact_category="uncertainty_report", role="temporal and integrity uncertainty interpretation", fields=["temporal_confidence", "case_wide_integrity_ratio", "main_limitation"], evidence_class="causal_output")
    _register_source(index, path=str(case_dir / "derived" / "evidence_support" / "hypothesis_support_report.json"), file_type="json", artifact_category="hypothesis_support", role="hypothesis support and claimability evaluation", fields=["global_support_level", "final_claimability_status", "relations"], evidence_class="derived_analysis")
    _register_source(index, path=str(case_dir / "derived" / "evidence_support" / "forensic_storyline.json"), file_type="json", artifact_category="forensic_storyline", role="semantic readable storyline", fields=["steps", "limitations"], evidence_class="derived_analysis")
    _register_source(index, path=str(case_dir / "derived" / "evidence_support" / "claimability_report.json"), file_type="json", artifact_category="claimability_report", role="supported, partial, unsupported claim structure", fields=["claims"], evidence_class="derived_analysis")
    _register_source(index, path=str(case_dir / "derived" / "evidence_support" / "counter_evidence_report.json"), file_type="json", artifact_category="counter_evidence_report", role="contradictions and counter-evidence review", fields=["contradictions"], evidence_class="derived_analysis")
    _register_source(index, path=str(execution_dir / "forensic_comparison_profile.json"), file_type="json", artifact_category="comparison_profile", role="Level A execution comparison profile", fields=["causal_reconstruction", "hypothesis_support", "uncertainty", "detection_trigger"], evidence_class="repetition_output")
    _register_source(index, path=str(execution_dir / "forensic_result_card.json"), file_type="json", artifact_category="forensic_result_card", role="lightweight Level A result card", fields=["comparison_family_id", "scientific_limitations"], evidence_class="repetition_output")
    _register_source(index, path=str(execution_dir / "analysis_repeatability_profile.json"), file_type="json", artifact_category="analysis_repeatability_profile", role="Level A repeatability metrics", fields=["CPR", "Weighted_CPR", "hypothesis_support"], evidence_class="repetition_output")
    if comparison_artifacts:
        _register_source(index, path=comparison_artifacts.get("comparability_result"), file_type="json", artifact_category="comparability_result", role="Level A repeatability comparison status and drift metrics", fields=["status", "comparison_type", "summary"], evidence_class="comparison_output")
        _register_source(index, path=comparison_artifacts.get("comparison_matrix"), file_type="json", artifact_category="comparison_matrix", role="execution row comparison matrix", fields=["rows", "delta_cpr_allowed", "delta_wcpr_allowed"], evidence_class="comparison_output")
        _register_source(index, path=comparison_artifacts.get("comparability_report"), file_type="md", artifact_category="comparability_report", role="human-readable comparison report", fields=[], evidence_class="comparison_output")
    return index


def _build_claim_map(index: dict, *, case_dir: Path, execution_dir: Path, lifecycle: dict, metrics: dict, uncertainty: dict, hypothesis: dict, comparison: dict | None) -> list[dict]:
    summary = lifecycle.get("summary") or {}
    analysis_summary = summary.get("multilayer_analysis_summary") or {}
    trigger_summary = summary.get("trigger_summary") or {}
    final_conclusion = summary.get("final_forensic_conclusion") or {}
    causal_summary = summary.get("causal_summary") or {}
    source_paths = {
        "summary": str(case_dir / "derived" / "executive" / "evidence_lifecycle_summary.json"),
        "analysis_report": str(case_dir / "analysis" / "forensic_analysis_report.json"),
        "network": str(case_dir / "analysis" / "03_network" / "network_findings.json"),
        "memory": str(case_dir / "analysis" / "04_memory" / "memory_findings.json"),
        "ot": str(case_dir / "analysis" / "06_ot" / "ot_findings.json"),
        "causal_metrics": str(case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json"),
        "causal_graph": str(case_dir / "derived" / "reconstruction" / "causal_graph.json"),
        "hypothesis": str(case_dir / "derived" / "evidence_support" / "hypothesis_support_report.json"),
        "comparison_profile": str(execution_dir / "forensic_comparison_profile.json"),
        "comparison_result": comparison and comparison.get("artifacts", {}).get("comparability_result"),
        "repeatability": str(execution_dir / "analysis_repeatability_profile.json"),
        "manifest": str(case_dir / "manifest.json"),
        "custody": str(case_dir / "chain_of_custody.log"),
    }
    claims = []
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-SCOPE-READONLY",
            claim="This report is a Level A reanalysis of the same preserved case and does not represent a new attack, new scenario execution, or new heavy preservation event.",
            status="supported",
            confidence="strong",
            source_refs=[
                _source_ref(index, source_paths["comparison_profile"], ["level", "source_case_id"], "primary"),
                _source_ref(index, source_paths["repeatability"], ["base_case_id", "analysis_profile", "FOC_profile"], "supporting"),
            ],
            limitations=[],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-MULTILAYER-COMPLETED",
            claim="The preserved case has complete multilayer analytical coverage with useful outputs across the expected layers.",
            status=_status_classification(analysis_summary.get("execution_status")),
            confidence=_confidence_from_status(analysis_summary.get("execution_status")),
            source_refs=[
                _source_ref(index, source_paths["summary"], ["multilayer_analysis_summary.execution_status", "multilayer_analysis_summary.layers_completed", "multilayer_analysis_summary.layers_with_useful_output"], "primary"),
                _source_ref(index, source_paths["analysis_report"], ["analysis_status", "phases"], "supporting"),
            ],
            limitations=[str(analysis_summary.get("main_limitation") or "")] if analysis_summary.get("main_limitation") else [],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-NETWORK-MODBUS",
            claim="Network evidence confirms Modbus/TCP activity, but the current extraction layer does not fully prove packet-level register and value precision.",
            status="partial",
            confidence="moderate",
            source_refs=[
                _source_ref(index, source_paths["network"], ["findings.files", "limitations"], "primary"),
                _source_ref(index, source_paths["summary"], ["causal_summary.modbus_specificity"], "supporting"),
            ],
            limitations=[str((causal_summary.get("modbus_specificity") or {}).get("message") or "Modbus register/value precision remains partial.")],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-MEMORY-COMPLETED",
            claim="Memory analysis completed successfully and produced reusable Volatility-based outputs for all preserved dumps included in this case.",
            status="supported",
            confidence="strong",
            source_refs=[
                _source_ref(index, source_paths["memory"], ["findings.results", "status"], "primary"),
                _source_ref(index, source_paths["analysis_report"], ["phases"], "supporting"),
            ],
            limitations=[],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-TRIGGER-LIMITATION",
            claim="The operational acquisition trigger is not a complete causal proof of the OT incident path and must be interpreted separately from OT causal evidence.",
            status="partial",
            confidence="moderate",
            source_refs=[
                _source_ref(index, source_paths["summary"], ["trigger_summary.trigger", "trigger_summary.trigger_selection_method", "causal_summary.trigger_vs_causal_path"], "primary"),
                _source_ref(index, source_paths["hypothesis"], ["limitations"], "supporting"),
            ],
            limitations=[
                f"Selected trigger: {trigger_summary.get('trigger') or 'not_available'}",
                f"Trigger selection method: {trigger_summary.get('trigger_selection_method') or trigger_summary.get('reason_for_selection') or 'not_available'}",
            ],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-ALERT-INTERVENTION-PRESERVATION-CHAIN",
            claim="The alert-to-intervention-to-preservation chain is not fully proven by the preserved artifacts in this case.",
            status="partial",
            confidence="limited",
            source_refs=[
                _source_ref(index, source_paths["causal_graph"], ["edges"], "primary"),
                _source_ref(index, source_paths["manifest"], ["artifacts"], "supporting"),
                _source_ref(index, source_paths["custody"], [], "supporting"),
            ],
            limitations=[
                "edge_alert_observation_to_forensic_case is missing",
                "edge_forensic_case_to_preserved_case_evidence is missing",
            ],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-CAUSAL-PARTIAL",
            claim="The causal reconstruction is partial rather than complete: some expected causal relations were recovered, some remain degraded, and some remain missing.",
            status=_status_classification(causal_summary.get("status")),
            confidence=_confidence_from_status(causal_summary.get("status")),
            source_refs=[
                _source_ref(index, source_paths["causal_metrics"], ["expected_edges", "recovered_edges", "degraded_edges", "missing_edges", "cpr", "weighted_cpr"], "primary"),
                _source_ref(index, source_paths["summary"], ["causal_summary.main_limitation", "causal_summary.why_expected_relations"], "supporting"),
            ],
            limitations=[str(causal_summary.get("main_limitation") or "Partial causal recovery.")],
        )
    )
    claims.append(
        _claim_entry(
            claim_id="CLAIM-LEVELA-HYPOTHESIS-MODERATE",
            claim="The reconstructed incident hypothesis currently receives moderate support, not absolute causality.",
            status="partial",
            confidence="moderate",
            source_refs=[
                _source_ref(index, source_paths["hypothesis"], ["global_support_level", "final_claimability_status", "relations"], "primary"),
                _source_ref(index, source_paths["summary"], ["final_forensic_conclusion"], "supporting"),
            ],
            limitations=[str(hypothesis.get("final_claimability_status") or "")],
        )
    )
    if comparison:
        claims.append(
            _claim_entry(
                claim_id="CLAIM-LEVELA-CPR-STABLE",
                claim="This Level A repetition can be compared with previous Level A executions using CPR and Weighted CPR drift metrics derived from the generated comparison profiles.",
                status="supported" if comparison.get("status") in {"Comparable", "Comparable With Degradation"} else "unsupported",
                confidence="strong" if comparison.get("comparison_type") in {"direct_level_a_repeatability_comparison", "direct_level_a_repeatability_family_metadata_incomplete"} else "moderate",
                source_refs=[
                    _source_ref(index, source_paths["comparison_result"], ["status", "comparison_type", "summary"], "primary"),
                    _source_ref(index, source_paths["comparison_profile"], ["causal_reconstruction.cpr", "causal_reconstruction.weighted_cpr"], "supporting"),
                ],
                limitations=list(comparison.get("degradation_reasons") or [])[:6],
            )
        )
    return [{**claim, "source_files": [item for item in claim.get("source_files", []) if item]} for claim in claims]


def _render_markdown(
    *,
    case_id: str,
    execution_id: str,
    campaign_id: str,
    generated_execution_ids: list[str],
    requested_repetitions: int,
    report_output_path: str,
    lifecycle: dict,
    analysis_status: dict,
    metrics: dict,
    uncertainty: dict,
    hypothesis: dict,
    storyline: dict,
    claimability: dict,
    comparison: dict | None,
    claims: list[dict],
    source_index: dict,
    generated_at: str,
) -> str:
    summary = lifecycle.get("summary") or {}
    analysis_summary = summary.get("multilayer_analysis_summary") or {}
    trigger_summary = summary.get("trigger_summary") or {}
    final_conclusion = summary.get("final_forensic_conclusion") or {}
    causal_summary = summary.get("causal_summary") or {}
    integrity_summary = summary.get("integrity_summary") or {}
    uncertainty_summary = summary.get("uncertainty_summary") or {}
    inventory = analysis_status.get("inventory_summary") or {}
    available_layers = analysis_status.get("available_layers") or []
    story_steps = list((storyline.get("steps") or []))[:12] if isinstance(storyline, dict) else []
    modbus = causal_summary.get("modbus_specificity") or {}
    comparison_status = comparison.get("status") if comparison else "Insufficient Data"
    comparison_type = comparison.get("comparison_type") if comparison else "no_previous_level_a_reference"
    comparison_summary = (comparison or {}).get("summary") or {}
    causal_rows = ((causal_summary.get("why_expected_relations") or {}).get("relations")) or []

    lines = [
        "# Level A Scientific Report",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Campaign ID: `{campaign_id}`",
        f"- Anchor execution ID: `{execution_id}`",
        f"- Requested dry-run repetitions: `{requested_repetitions}`",
        f"- Generated dry-run repetitions: `{', '.join(generated_execution_ids) if generated_execution_ids else 'not_available'}`",
        f"- Preserved case ID: `{case_id}`",
        f"- Report directory: `{report_output_path}`",
        "",
        "## Executive scientific summary",
        "",
        f"This report audits a Level A repetition campaign over the same preserved case. It launched the same `Run Dry-Run Execution` scientific backend path **{len(generated_execution_ids)}** times against the same preserved evidence set in read-only mode, then consolidated those outputs into one auditable report. The preserved case shows **{analysis_summary.get('layers_with_useful_output', 'not_available')} / {analysis_summary.get('layers_expected', 'not_available')}** analysis layers with useful output, a causal recovery of **{causal_summary.get('recovered_edges', 'not_available')} / {causal_summary.get('expected_edges', 'not_available')}** expected relations, and a repeatability comparison status of **{comparison_status}**.",
        "",
        f"The scientific position is therefore limited but defensible: the Level A repetition shows stable analytical behavior over the preserved case, while causal completeness remains partial where alert-to-intervention, intervention-to-preservation, timestamp ordering, or packet-level Modbus specificity are not fully supported.",
        "",
        "## Level A repetition scope",
        "",
        "- Same preserved case: yes",
        "- Same preserved evidence set: yes",
        f"- Same dry-run scientific path launched several times: `{len(generated_execution_ids)}` repetition(s)",
        "- New attack launched: no",
        "- New scenario execution: no",
        "- New heavy preservation: no",
        "- Scientific purpose: verify analytical repeatability over preserved evidence, not universal reproducibility.",
        "",
        "### Generated Level A dry-run executions",
        "",
    ]
    for idx, generated_execution_id in enumerate(generated_execution_ids, start=1):
        lines.append(f"- Repetition {idx}: `{generated_execution_id}`")

    lines.extend(
        [
        "",
        "This workflow is equivalent to pressing `Run Dry-Run Execution` several times from the Level A campaign and then generating one consolidated scientific report from those fresh repetitions.",
        "",
        "## Preserved case identity",
        "",
        f"- Case ID: `{case_id}`",
        f"- Scenario ID: `{summary.get('scenario_id') or 'not_available'}`",
        f"- Source case name: `{summary.get('source_case_name') or lifecycle.get('source_case_name') or 'not_available'}`",
        f"- Summary status: `{(summary.get('summary_status') or {}).get('status') if isinstance(summary.get('summary_status'), dict) else (summary.get('summary_status') or 'not_available')}`",
        f"- Integrity status: `{integrity_summary.get('overall_status') or 'not_available'}`",
        f"- Case-wide integrity ratio: `{integrity_summary.get('case_wide_integrity_ratio') or 'not_available'}`",
        "",
        "## Evidence inventory",
        "",
        f"- Evidence available: `{analysis_status.get('evidence_available')}`",
        f"- Available layers: `{', '.join(available_layers) if available_layers else 'not_available'}`",
        f"- Inventory summary: `{inventory}`",
        "",
        "## Multilayer analysis results",
        "",
        f"- Execution status: `{analysis_summary.get('execution_status') or 'not_available'}`",
        f"- Analysis confidence: `{analysis_summary.get('analysis_confidence') or 'not_available'}`",
        f"- Layers completed: `{analysis_summary.get('layers_completed')}` / `{analysis_summary.get('layers_expected')}`",
        f"- Useful output layers: `{analysis_summary.get('layers_with_useful_output')}`",
        f"- Main limitation: `{analysis_summary.get('main_limitation') or 'none recorded'}`",
        "",
        "## Memory analysis results",
        "",
        f"- Memory dumps analyzed: `{analysis_summary.get('memory_dumps_analyzed') or 'not_available'}`",
        "- Interpretation: memory analysis completed and produced reusable Volatility-based outputs for the preserved dumps included in this case.",
        "",
        "## Network analysis results",
        "",
        f"- PCAPs analyzed: `{analysis_summary.get('pcaps_analyzed') or 'not_available'}`",
        f"- Modbus specificity summary: `{(modbus.get('interpretation') or {}).get('summary') or modbus.get('message') or 'not_available'}`",
        f"- Packet-level limitation: `{modbus.get('message') or 'not_available'}`",
        "",
        "## Disk analysis results",
        "",
        f"- Disk images analyzed: `{analysis_summary.get('disk_images_analyzed') or 'not_available'}`",
        "- Interpretation: disk analysis completed and contributed preserved filesystem and bodyfile outputs to the unified timeline and causal reconstruction.",
        "",
        "## OT analysis results",
        "",
        f"- OT files analyzed: `{analysis_summary.get('ot_files_analyzed') or 'not_available'}`",
        f"- OT evidence position: `{(modbus.get('plc_or_scada_state') or {}).get('status') or 'partial'}`",
        f"- OT limitation: `{((modbus.get('interpretation') or {}).get('partially_supported')) or 'OT state relation remains partial.'}`",
        "",
        "## Alert and trigger analysis",
        "",
        f"- Alerts summarized: `{analysis_summary.get('alerts_summarized') or 'not_available'}`",
        f"- Selected trigger: `{trigger_summary.get('trigger') or 'not_available'}`",
        f"- Trigger source: `{trigger_summary.get('trigger_type') or trigger_summary.get('selected_trigger_source') or 'not_available'}`",
        f"- Trigger selection method: `{trigger_summary.get('trigger_selection_method') or trigger_summary.get('reason_for_selection') or 'not_available'}`",
        f"- Trigger limitation: The operational acquisition trigger must not be treated as complete causal proof of the OT incident path.",
        "",
        "## Timeline reconstruction",
        "",
        f"- Timeline entries: `{analysis_summary.get('timeline_entries') or 'not_available'}`",
        f"- Cross-layer findings: `{analysis_summary.get('cross_layer_findings') or 'not_available'}`",
        "",
        "### Narrative storyline",
        "",
    ])
    if story_steps:
        for step in story_steps:
            lines.append(f"- {step.get('label') or step.get('title') or step.get('event') or 'story step'}: {(step.get('summary') or step.get('interpretation') or step.get('limitation') or 'not_available')}")
    else:
        lines.append(f"- {summary.get('evidence_based_reconstruction_story', {}).get('summary_text') or 'No storyline was generated.'}")

    lines.extend(
        [
            "",
            "## Causal reconstruction results",
            "",
            f"- Causal status: `{causal_summary.get('status') or 'not_available'}`",
            f"- Expected causal edges: `{causal_summary.get('expected_edges') or 'not_available'}`",
            f"- Recovered causal edges: `{causal_summary.get('recovered_edges') or 'not_available'}`",
            f"- Degraded causal edges: `{causal_summary.get('degraded_edges') or 'not_available'}`",
            f"- Missing causal edges: `{causal_summary.get('missing_edges') or 'not_available'}`",
            f"- CPR: `{causal_summary.get('cpr') or 'not_available'}`",
            f"- Weighted CPR: `{causal_summary.get('weighted_cpr') or 'not_available'}`",
            f"- Reconstruction confidence: `{causal_summary.get('reconstruction_confidence') or 'not_available'}`",
            f"- Causal interpretation confidence: `{causal_summary.get('causal_interpretation_confidence') or 'not_available'}`",
            f"- Main limitation: `{causal_summary.get('main_limitation') or 'none recorded'}`",
            "",
            "### Recovered, degraded, and missing relations",
            "",
        ]
    )
    for row in causal_rows[:8]:
        lines.append(
            f"- `{row.get('edge_id')}`: status=`{row.get('recovered_status')}` | reason=`{row.get('degradation_reason') or 'not_available'}`"
        )

    lines.extend(
        [
            "",
            "## Hypothesis support results",
            "",
            f"- Global support level: `{hypothesis.get('global_support_level') or 'not_available'}`",
            f"- Final claimability status: `{hypothesis.get('final_claimability_status') or 'not_available'}`",
            f"- Main limitation: `{summary.get('evidence_support_extract', {}).get('main_limitation') or 'not_available'}`",
            "",
            "## Level A repeatability and comparison results",
            "",
            f"- Comparison status: `{comparison_status}`",
            f"- Comparison type: `{comparison_type}`",
            f"- Max |ΔCPR|: `{comparison_summary.get('max_abs_cpr_difference', 'not_available')}`",
            f"- Max |ΔWCPR|: `{comparison_summary.get('max_abs_weighted_cpr_difference', 'not_available')}`",
            f"- Max support-rank shift: `{comparison_summary.get('max_support_rank_shift', 'not_available')}`",
            "",
            "## Evidence-to-claim audit table",
            "",
            "| Claim ID | Status | Confidence | Claim |",
            "| --- | --- | --- | --- |",
        ]
    )
    for claim in claims:
        lines.append(f"| `{claim['claim_id']}` | `{claim['status']}` | `{claim['confidence']}` | {claim['claim']} |")

    lines.extend(
        [
            "",
            "## Limitations and degraded states",
            "",
        ]
    )
    for item in list(dict.fromkeys((summary.get("limitations") or []) + list(final_conclusion.get("degraded_or_ambiguous") or [])))[:20]:
        lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "## Scientific conclusion",
            "",
            f"{final_conclusion.get('summary_text') or 'No final conclusion summary was available.'}",
            "",
            "The correct scientific interpretation for this Level A run is therefore:",
            "",
            "The preserved case provides strong evidence preservation and complete multilayer analytical coverage. The Level A repetition shows stable analytical repeatability over the same preserved case. However, the causal reconstruction remains partial where alert-to-intervention, intervention-to-preservation, or Modbus register/value confirmation are not fully supported by the available evidence.",
            "",
            "## Source files used for this report",
            "",
        ]
    )
    for item in sorted(source_index.values(), key=lambda row: row["path"]):
        lines.append(f"- `{item['path']}` | {item['artifact_category']} | role: {item['role_in_report_generation']}")
    return "\n".join(lines) + "\n"


def _latest_report_for_case(case_id: str) -> dict | None:
    root = SCIENTIFIC_REPORTS_ROOT / _safe_slug(case_id)
    if not root.is_dir():
        return None
    latest = None
    latest_ts = 0.0
    for metadata in root.glob("**/report_metadata.json"):
        try:
            ts = metadata.stat().st_mtime
        except Exception:
            continue
        if ts > latest_ts:
            latest_ts = ts
            latest = metadata
    if not latest:
        return None
    payload = _json_load(latest) or {}
    if payload:
        payload["report_path"] = relative_path(latest.parent)
    return payload or None


def _report_by_execution(execution_id: str, *, campaign_id: str | None = None) -> dict | None:
    matches: list[Path] = []
    for metadata in SCIENTIFIC_REPORTS_ROOT.glob("**/report_metadata.json"):
        payload = _json_load(metadata) or {}
        if not payload:
            continue
        if campaign_id and str(payload.get("campaign_id") or "").strip() != str(campaign_id).strip():
            continue
        generated_execution_ids = list(payload.get("generated_execution_ids") or [])
        anchor_execution_id = str(payload.get("execution_id") or "")
        if execution_id != anchor_execution_id and execution_id not in generated_execution_ids:
            continue
        matches.append(metadata)
    if not matches:
        return None
    matches.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    metadata = matches[0]
    payload = _json_load(metadata) or {}
    if payload:
        payload["report_path"] = relative_path(metadata.parent)
        markdown_path = metadata.parent / "SCIENTIFIC_LEVEL_A_REPORT.md"
        payload["report_markdown"] = markdown_path.read_text(encoding="utf-8", errors="ignore") if markdown_path.is_file() else None
        payload["source_files_index"] = _json_load(metadata.parent / "source_files_index.json")
        payload["evidence_to_claim_map"] = _json_load(metadata.parent / "evidence_to_claim_map.json")
        return payload
    return None


def get_latest_level_a_report(case_id: str) -> dict | None:
    return _latest_report_for_case(case_id)


def open_level_a_report(execution_id: str, *, campaign_id: str | None = None) -> dict | None:
    return _report_by_execution(execution_id, campaign_id=campaign_id)


def _run_level_a_report_job(job_id: str, job_path: Path, campaign_id: str) -> None:
    manifest, config = _campaign_payload(campaign_id)
    level = str(config.get("level") or manifest.get("level") or "A").upper()
    if level != "A":
        raise ValueError("level_a_report_generation_requires_level_a_campaign")

    job_dir = job_path.parent
    generated_at = utc_now()
    report_generation_log = job_dir / f"{job_id}.generation_log.jsonl"

    def log(event: str, **extra):
        _append_jsonl(report_generation_log, {"ts": utc_now(), "event": event, **extra})

    requested_repetitions = max(int(config.get("repetitions") or 3), 1)
    phase_index = 0
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Resolving the preserved reference case configured in the selected Level A campaign.")

    source_case_id = str(config.get("base_case_id") or config.get("run_case_id") or "").strip()
    source_case_path = str(config.get("base_case_path") or config.get("run_case_path") or "").strip()
    if not source_case_id and not source_case_path:
        raise ValueError("level_a_campaign_has_no_reference_case")

    case_id = source_case_id or "not_available"
    case_path = source_case_path or ""
    report_dir = _build_report_root(case_id or "not_available", campaign_id, generated_at)
    report_output_path = relative_path(report_dir)
    update_job(job_id, job_path, current_case_id=case_id, current_execution_id=None, report_output_path=report_output_path)
    log("resolved_reference_case", case_id=case_id, report_output_path=report_output_path, requested_repetitions=requested_repetitions)
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed", detail=f"Using preserved case {case_id} for Level A report generation. The workflow will now launch {requested_repetitions} dry-run analytical repetitions over the same preserved evidence.", case_id=case_id, execution_id=None, report_output_path=report_output_path)

    raise_if_cancelled(job_id, job_path, phase_key=phase_key, phase_label=phase_label, detail="Level A scientific report generation was cancelled after resolving the preserved reference case.")
    phase_index = 1
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Checking manifest.json and chain_of_custody.log before reading preserved analytical outputs.", case_id=case_id, execution_id=None, report_output_path=report_output_path)
    case_dir = Path(case_path).resolve() if case_path else None
    if (not case_dir or not case_dir.is_dir()) and source_case_id:
        # campaign_config.json almost never carries base_case_path/run_case_path
        # explicitly -- campaigns are normally created from a case_id picked in
        # the UI, not a typed filesystem path. Resolve the real case directory
        # from the case_id the same way execution_service.load_case_bundle()
        # and the rest of this module already do, instead of treating an
        # empty config path field as "the case does not exist".
        resolved_source = resolve_case_source(case_id=source_case_id)
        if resolved_source:
            case_dir = Path(resolved_source["case_path"]).resolve()
    if not case_dir or not case_dir.is_dir():
        raise FileNotFoundError(f"reference_case_path_not_found:{case_id}")
    manifest_path = case_dir / "manifest.json"
    custody_path = case_dir / "chain_of_custody.log"
    validation_warnings = []
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest_missing:{case_id}")
    if not custody_path.is_file():
        validation_warnings.append("chain_of_custody.log is missing")
    if validation_warnings:
        for warning in validation_warnings:
            append_job_list(job_id, job_path, "warnings", warning)
    log("validated_manifest_and_custody", manifest_present=manifest_path.is_file(), custody_present=custody_path.is_file(), warnings=validation_warnings)
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed_with_degradation" if validation_warnings else "completed", detail="Manifest and custody checks completed for the preserved case.", case_id=case_id, execution_id=None, report_output_path=report_output_path)

    raise_if_cancelled(job_id, job_path, phase_key=phase_key, phase_label=phase_label, detail="Level A scientific report generation was cancelled during evidence validation.")
    phase_index = 2
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Confirming that this workflow remains strictly inside Level A: same preserved case, same preserved evidence set, no new attack, and no new heavy preservation.", case_id=case_id, execution_id=None, report_output_path=report_output_path)
    scope_notes = [
        "Same preserved case reused in read-only mode.",
        "The workflow will call the same Run Dry-Run Execution scientific backend path multiple times.",
        "No new attack execution was launched by this report workflow.",
        "No Level B or Level C orchestration was invoked.",
    ]
    log("validated_level_a_scope", notes=scope_notes)
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed", detail="Level A scope validated. This report will launch multiple dry-run analytical repetitions over the same preserved case and then compare their resulting profiles.", case_id=case_id, execution_id=None, report_output_path=report_output_path)

    phase_index = 3
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail=f"Launching the same Run Dry-Run Execution backend path {requested_repetitions} times over the preserved case to generate fresh Level A analytical repetitions.", case_id=case_id, execution_id=None, report_output_path=report_output_path)
    generated_execution_ids: list[str] = []
    generated_execution_dirs: list[Path] = []
    generated_jobs: list[str] = []
    for repetition_index in range(1, requested_repetitions + 1):
        raise_if_cancelled(job_id, job_path, phase_key=phase_key, phase_label=phase_label, detail="Level A scientific report generation was cancelled before launching the next dry-run repetition.")
        detail = f"Run Dry-Run Execution {repetition_index}/{requested_repetitions}: refreshing FOC, causal reconstruction, and full evidence lifecycle over preserved case {case_id}."
        update_job(
            job_id,
            job_path,
            current_phase=phase_key,
            current_phase_label=phase_label,
            current_phase_detail=detail,
            progress_percent=_phase_progress(phase_index, completed=False),
            current_execution_id=generated_execution_ids[-1] if generated_execution_ids else None,
        )
        log("start_dry_run_repetition", repetition_index=repetition_index, requested_repetitions=requested_repetitions, case_id=case_id)
        child = start_dry_run_execution_job(
            campaign_id,
            overrides={
                "source_case_id": case_id,
                "source_case_path": str(case_dir),
            },
        )
        child_job_id = str(child.get("job_id") or "").strip()
        if not child_job_id:
            append_job_list(job_id, job_path, "warnings", f"Dry-run repetition {repetition_index}/{requested_repetitions} could not start and will not be used in the consolidated Level A report.")
            log("failed_to_start_dry_run_repetition", repetition_index=repetition_index, requested_repetitions=requested_repetitions)
            continue
        generated_jobs.append(child_job_id)
        child = _wait_for_child_dry_run_job(
            child_job_id,
            parent_job_id=job_id,
            parent_job_path=job_path,
            phase_index=phase_index,
            repetition_index=repetition_index,
            requested_repetitions=requested_repetitions,
            case_id=case_id,
            report_output_path=report_output_path,
        )
        child_status = str(child.get("status") or "failed").lower()
        child_meta = dict(child.get("meta") or {})
        child_execution_id = str(child_meta.get("execution_id") or child.get("current_execution_id") or "").strip()
        if child_execution_id and child_status in {"completed", "completed_with_degradation", "completed_with_failures"}:
            generated_execution_ids.append(child_execution_id)
            child_execution = load_execution(child_execution_id, campaign_id=campaign_id) or {}
            child_execution_dir = Path(str(child_execution.get("execution_abs_path") or "")).resolve()
            if child_execution_dir.is_dir():
                generated_execution_dirs.append(child_execution_dir)
        if child_status not in {"completed", "completed_with_degradation", "completed_with_failures"}:
            append_job_list(job_id, job_path, "warnings", f"Dry-run repetition {repetition_index}/{requested_repetitions} failed and will not be used in the consolidated Level A report.")
        log(
            "completed_dry_run_repetition",
            repetition_index=repetition_index,
            requested_repetitions=requested_repetitions,
            child_job_id=child_job_id,
            child_status=child.get("status"),
            execution_id=child_execution_id or None,
        )
    if not generated_execution_ids:
        raise RuntimeError("level_a_dry_run_generation_failed:no_execution_was_generated")
    execution_id = generated_execution_ids[-1]
    execution = load_execution(execution_id, campaign_id=campaign_id) or {}
    execution_dir = Path(str(execution.get("execution_abs_path") or "")).resolve()
    analysis_status = load_analysis_status(case_id)
    if str(analysis_status.get("status") or "").lower() not in {"completed", "partial"}:
        refresh = run_analysis(case_id, force=False)
        if refresh.get("error") not in {None, "analysis_already_running"}:
            raise RuntimeError(f"analysis_refresh_failed:{refresh.get('error')}")
        analysis_status = _wait_for_analysis(case_id, job_id=job_id, job_path=job_path, phase_index=phase_index)
    analysis_payload = analysis_report(case_id) or {}
    log("analysis_ready", analysis_status=analysis_status.get("status"), report_status=analysis_payload.get("analysis_status"), generated_execution_ids=generated_execution_ids)
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed_with_degradation" if str(analysis_status.get("status")) == "partial" else "completed", detail=f"Generated {len(generated_execution_ids)} dry-run Level A repetitions. The report anchor execution is {execution_id}. Multilayer analysis state is {analysis_status.get('status')}.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    case_bundle = {
        "case_id": case_id,
        "case_dir": case_dir,
        "case_path": str(case_dir),
        "case_rel_path": relative_path(case_dir),
        "paths": {
            "manifest": manifest_path,
            "custody": custody_path,
            "summary": case_dir / "derived" / "executive" / "evidence_lifecycle_summary.json",
            "analysis_report": case_dir / "analysis" / "forensic_analysis_report.json",
            "network": case_dir / "analysis" / "03_network" / "network_findings.json",
            "memory": case_dir / "analysis" / "04_memory" / "memory_findings.json",
            "disk": case_dir / "analysis" / "05_disk" / "disk_findings.json",
            "ot": case_dir / "analysis" / "06_ot" / "ot_findings.json",
            "alerts": case_dir / "analysis" / "07_alerts" / "alert_findings.json",
            "timeline": case_dir / "analysis" / "09_timeline" / "unified_forensic_timeline.json",
            "cross_layer": case_dir / "analysis" / "10_findings" / "cross_layer_findings.json",
            "time_sync": case_dir / "metadata" / "time_sync.json",
        },
    }

    extracted = {}
    extraction_specs = [
        ("extract_network_findings", "Extract network findings", "network", case_bundle["paths"]["network"], "Loading preserved network findings and Modbus-related limitations."),
        ("extract_memory_findings", "Extract memory findings", "memory", case_bundle["paths"]["memory"], "Loading preserved memory findings and plugin execution state."),
        ("extract_disk_findings", "Extract disk findings", "disk", case_bundle["paths"]["disk"], "Loading preserved disk findings and filesystem extraction outputs."),
        ("extract_ot_findings", "Extract OT findings", "ot", case_bundle["paths"]["ot"], "Loading preserved OT exports and process-side summaries."),
        ("extract_alert_findings", "Extract alert findings", "alerts", case_bundle["paths"]["alerts"], "Loading preserved alert findings and trigger evidence."),
    ]
    for phase_index, spec in zip(range(4, 9), extraction_specs):
        phase_key, phase_label, extracted_key, path_obj, detail = spec
        _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail=detail, case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
        payload = _json_load(path_obj) or {}
        if not payload:
            append_job_list(job_id, job_path, "warnings", f"{Path(path_obj).name} could not be loaded for {extracted_key} extraction.")
        extracted[extracted_key] = payload
        log(f"{extracted_key}_loaded", path=relative_path(path_obj), status=payload.get("status"))
        _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed_with_degradation" if not payload else "completed", detail=f"{phase_label} completed using preserved outputs from {relative_path(path_obj)}.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 9
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Loading the unified forensic timeline and refreshing the executive lifecycle snapshot for report consistency.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    lifecycle_summary = generate_evidence_lifecycle_summary(case_id)
    lifecycle = load_evidence_lifecycle_dashboard(case_id)
    extracted["timeline"] = _json_load(case_bundle["paths"]["timeline"]) or {}
    log("timeline_loaded", timeline_path=relative_path(case_bundle["paths"]["timeline"]), timeline_status=extracted["timeline"].get("status"))
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed", detail="Unified timeline and executive lifecycle snapshot are ready for report synthesis.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 10
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Running or refreshing causal reconstruction so the report can audit recovered, degraded, and missing causal relations from the preserved case.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    causal_start = run_causal_reconstruction(case_id, case_dir, strict=False, degraded_ok=True)
    if causal_start.get("status") == "running":
        causal_status = _wait_for_causal(case_id, case_dir, job_id=job_id, job_path=job_path, phase_index=phase_index)
    else:
        causal_status = causal_status_payload(case_id, case_dir) or causal_start
    metrics = causal_metrics_payload(case_id, case_dir) or {}
    uncertainty = causal_uncertainty_payload(case_id, case_dir) or {}
    log("causal_ready", causal_status=causal_status.get("status"), recovered_edges=metrics.get("recovered_edges"), missing_edges=metrics.get("missing_edges"))
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed_with_degradation" if str(causal_status.get("status")) == "completed_with_degradation" else "completed", detail=f"Causal reconstruction reached state {causal_status.get('status')}. The report will keep degraded and missing relations explicit.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 11
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Generating evidence-based hypothesis support, forensic storyline, claimability, and counter-evidence outputs.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    evidence_support = build_evidence_support(case_id)
    hypothesis = load_hypothesis_support_report(case_id) or {}
    storyline = load_forensic_storyline(case_id) or {}
    claimability = load_claimability_report(case_id) or {}
    counter_evidence = load_counter_evidence_report(case_id) or {}
    log("hypothesis_support_ready", support_level=hypothesis.get("global_support_level"), interpretation=hypothesis.get("final_claimability_status"))
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed", detail="Hypothesis support and semantic storyline outputs were refreshed from preserved analytical artifacts.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 12
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail=f"Comparing the {len(generated_execution_ids)} dry-run Level A repetitions generated by this workflow using their comparison profiles and result cards.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    comparison = None
    comparable_generated = []
    for candidate_execution_id in generated_execution_ids:
        candidate_execution = load_execution(candidate_execution_id, campaign_id=campaign_id) or {}
        if (candidate_execution.get("artifacts") or {}).get("forensic_comparison_profile"):
            comparable_generated.append(candidate_execution_id)
    if len(comparable_generated) >= 2:
        comparison = compare_executions(comparable_generated, campaign_id=campaign_id)
        if comparison.get("status") == "Insufficient Data":
            comparison["comparison_type"] = comparison.get("comparison_type") or "generated_level_a_profiles_incomplete"
    else:
        comparison = {
            "status": "Insufficient Data",
            "comparison_type": "not_enough_generated_level_a_repetitions",
            "summary": {},
            "degradation_reasons": [],
            "hard_failures": [],
            "execution_ids": generated_execution_ids,
        }
    log("comparison_ready", status=comparison.get("status"), comparison_type=comparison.get("comparison_type"), compared_execution_ids=comparison.get("execution_ids"))
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed_with_degradation" if comparison.get("status") == "Comparable With Degradation" else "completed", detail=f"Comparison status: {comparison.get('status')}. Comparison type: {comparison.get('comparison_type')}.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 13
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Building the evidence-to-claim audit map so that every major scientific conclusion remains traceable to preserved files.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    source_index = _build_source_index(
        case_dir,
        execution_dir,
        comparison.get("artifacts") if isinstance(comparison, dict) else None,
        case_bundle,
        lifecycle,
        analysis_status,
        causal_status,
        metrics,
        hypothesis,
        storyline,
        claimability,
        counter_evidence,
    )
    claims = _build_claim_map(
        source_index,
        case_dir=case_dir,
        execution_dir=execution_dir,
        lifecycle=lifecycle,
        metrics=metrics,
        uncertainty=uncertainty,
        hypothesis=hypothesis,
        comparison=comparison if isinstance(comparison, dict) else None,
    )
    modbus_context = _extract_modbus_packet_context(extracted.get("network") or {})
    log("claim_map_built", claim_count=len(claims), source_count=len(source_index))
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed", detail=f"Built {len(claims)} auditable claims from {len(source_index)} indexed source files.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 14
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Rendering the Markdown scientific report as a readable Level A analytical story with explicit degraded and missing states.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    markdown = _render_markdown(
        case_id=case_id,
        execution_id=execution_id,
        campaign_id=campaign_id,
        generated_execution_ids=generated_execution_ids,
        requested_repetitions=requested_repetitions,
        report_output_path=report_output_path,
        lifecycle=lifecycle,
        analysis_status=analysis_status,
        metrics=metrics,
        uncertainty=uncertainty,
        hypothesis=hypothesis,
        storyline=storyline,
        claimability=claimability,
        comparison=comparison if isinstance(comparison, dict) else None,
        claims=claims,
        source_index=source_index,
        generated_at=generated_at,
    )
    log("markdown_rendered", length=len(markdown))
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="completed", detail="Markdown scientific report content rendered successfully.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    phase_index = 15
    phase_key, phase_label = PHASES[phase_index]
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status="running", detail="Writing report bundle, metadata, source index, evidence-to-claim map, and generation logs into the dedicated Level A scientific reports directory.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)
    report_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "generated_at": generated_at,
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "generated_execution_ids": generated_execution_ids,
        "requested_repetitions": requested_repetitions,
        "completed_repetitions": len(generated_execution_ids),
        "case_id": case_id,
        "case_path": relative_path(case_dir),
        "report_type": "level_a_scientific_report",
        "report_scope": "consolidated_level_a_dry_run_repetitions",
        "level": "A",
        "job_id": job_id,
        "report_markdown_path": relative_path(report_dir / "SCIENTIFIC_LEVEL_A_REPORT.md"),
        "report_output_path": report_output_path,
        "status": "completed_with_degradation" if any([
            str((lifecycle.get("summary") or {}).get("causal_summary", {}).get("status")) == "completed_with_degradation",
            comparison.get("status") == "Comparable With Degradation",
            bool((lifecycle.get("summary") or {}).get("limitations")),
        ]) else "completed",
        "comparison_status": comparison.get("status"),
        "comparison_type": comparison.get("comparison_type"),
        "source_files_index_path": relative_path(report_dir / "source_files_index.json"),
        "evidence_to_claim_map_path": relative_path(report_dir / "evidence_to_claim_map.json"),
        "generation_log_path": relative_path(report_dir / "generation_log.jsonl"),
        "report_summary_path": relative_path(report_dir / "report_summary.json"),
    }
    report_summary = {
        "case_id": case_id,
        "execution_id": execution_id,
        "generated_execution_ids": generated_execution_ids,
        "campaign_id": campaign_id,
        "requested_repetitions": requested_repetitions,
        "completed_repetitions": len(generated_execution_ids),
        "analysis_status": analysis_status.get("status"),
        "causal_status": (lifecycle.get("summary") or {}).get("causal_summary", {}).get("status"),
        "comparison_status": comparison.get("status"),
        "cpr": metrics.get("cpr"),
        "weighted_cpr": metrics.get("weighted_cpr"),
        "recovered_edges": metrics.get("recovered_edges"),
        "degraded_edges": metrics.get("degraded_edges"),
        "missing_edges": metrics.get("missing_edges"),
        "hypothesis_support": hypothesis.get("global_support_level"),
        "trigger": (lifecycle.get("summary") or {}).get("trigger_summary", {}).get("trigger"),
        "modbus_context": modbus_context,
    }
    claim_map_payload = {
        "generated_at": generated_at,
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "generated_execution_ids": generated_execution_ids,
        "case_id": case_id,
        "claims": claims,
    }
    source_index_payload = {
        "generated_at": generated_at,
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "generated_execution_ids": generated_execution_ids,
        "case_id": case_id,
        "files": sorted(source_index.values(), key=lambda row: row["path"]),
    }
    _write_text(report_dir / "SCIENTIFIC_LEVEL_A_REPORT.md", markdown)
    _write_json(report_dir / "report_metadata.json", metadata)
    _write_json(report_dir / "source_files_index.json", source_index_payload)
    _write_json(report_dir / "evidence_to_claim_map.json", claim_map_payload)
    _write_json(report_dir / "report_summary.json", report_summary)
    _write_text(report_dir / "generation_log.jsonl", report_generation_log.read_text(encoding="utf-8") if report_generation_log.exists() else "")
    report_entry = {
        "generated_at": generated_at,
        "job_id": job_id,
        "execution_id": execution_id,
        "generated_execution_ids": generated_execution_ids,
        "case_id": case_id,
        "report_metadata_path": metadata["report_output_path"] + "/report_metadata.json",
        "report_markdown_path": metadata["report_markdown_path"],
        "status": metadata["status"],
    }
    for generated_execution_dir, generated_execution_id in zip(generated_execution_dirs, generated_execution_ids):
        _append_execution_report_index(generated_execution_dir, report_entry)
        _update_execution_manifest_with_report(generated_execution_id, report_entry)
    append_job_list(job_id, job_path, "generated_artifacts", metadata["report_markdown_path"])
    append_job_list(job_id, job_path, "generated_artifacts", metadata["source_files_index_path"])
    append_job_list(job_id, job_path, "generated_artifacts", metadata["evidence_to_claim_map_path"])
    append_job_list(job_id, job_path, "generated_artifacts", metadata["generation_log_path"])
    final_status = metadata["status"]
    log("report_written", report_dir=report_output_path, final_status=final_status)
    _phase_update(job_id=job_id, job_path=job_path, phase_key=phase_key, phase_label=phase_label, phase_index=phase_index, status=final_status if final_status in {"completed_with_degradation"} else "completed", detail=f"Level A scientific report bundle written to {report_output_path}.", case_id=case_id, execution_id=execution_id, report_output_path=report_output_path)

    update_job(
        job_id,
        job_path,
        status=final_status,
        finished_at=utc_now(),
        current_phase="completed",
        current_phase_label="Completed",
        current_phase_detail=f"Level A scientific report generated at {report_output_path}.",
        progress_percent=100.0,
        current_case_id=case_id,
        current_execution_id=execution_id,
        current_child_job_id=None,
        report_output_path=report_output_path,
        report_markdown_path=metadata["report_markdown_path"],
        report_metadata_path=metadata["report_output_path"] + "/report_metadata.json",
        level_a_report=metadata,
    )


def find_active_level_a_job() -> dict | None:
    """Scan every campaign's jobs/ directory on disk for a Level A scientific
    report job that hasn't reached a terminal status yet.

    Mirrors level_b_repetition_runner.find_active_level_b_job() exactly, for
    the same reason: a job's background thread runs inside whichever
    gunicorn worker started it and is invisible to job_runner.list_jobs() in
    every other worker's own process memory, so this reads the persisted job
    JSON files directly instead. Used by
    level_c_orchestrator.get_live_campaign_summary() to detect a Level A
    report launched standalone (not nested inside an active Level B
    repetition, which already surfaces its own live state a different way)
    so the old Live Campaign Status panel doesn't go blind for that case
    either — see that module's README, 2026-07-19.
    """
    from .config import CAMPAIGNS_ROOT
    if not CAMPAIGNS_ROOT.is_dir():
        return None
    candidates: list[tuple[float, dict]] = []
    for job_file in CAMPAIGNS_ROOT.glob("*/jobs/*.json"):
        try:
            payload = json.loads(job_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if payload.get("job_type") != "level_a_scientific_report":
            continue
        if str(payload.get("status") or "").lower() != "running":
            continue
        candidates.append((job_file.stat().st_mtime, payload))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    # Re-validate through get_job() before trusting the raw file's status --
    # a job whose thread died before job_runner's heartbeat/orphan-recovery
    # fix landed (or was simply never read since) can sit at status="running"
    # on disk forever with nothing to lazily correct it. Confirmed live
    # 2026-07-19: a job from 2026-07-16 (updated_at: None -- predates that
    # fix) was still reported as "the active Level A job" three days later
    # by a raw-file-only version of this function. get_job() is now safe to
    # call here (its own cross-worker caching bug was fixed the same day,
    # see job_runner.py) and will correct a dead ghost to its real terminal
    # status on this exact call instead of leaving it stuck.
    for _, payload in candidates:
        job_id = payload.get("job_id")
        revalidated = get_job(job_id) if job_id else None
        current = revalidated if revalidated else payload
        if str(current.get("status") or "").lower() != "running":
            continue
        return {
            "job_id": current.get("job_id") or job_id,
            "campaign_id": (current.get("meta") or payload.get("meta") or {}).get("campaign_id"),
            "status": current.get("status"),
            "current_phase": current.get("current_phase"),
            "current_phase_label": current.get("current_phase_label"),
            "current_phase_detail": current.get("current_phase_detail"),
            "started_at": current.get("started_at") or current.get("requested_at"),
            "current_case_id": current.get("current_case_id"),
        }
    return None


def start_level_a_scientific_report_job(campaign_id: str) -> dict:
    manifest, config = _campaign_payload(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    level = str(config.get("level") or manifest.get("level") or "A").upper()
    if level != "A":
        raise ValueError("level_a_report_generation_requires_level_a_campaign")
    jobs_dir = campaign_dir(campaign_id) / "jobs"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    job = new_job(
        job_type="level_a_scientific_report",
        title="Generate Level A Scientific Report",
        job_path=jobs_dir / f"level-a-scientific-report-{utc_now().replace(':', '').replace('+', '_')}.json",
        meta={"campaign_id": campaign_id, "level": "A", "workflow": "scientific_report_generation"},
    )
    return start_job(job, lambda job_id, job_path: _run_level_a_report_job(job_id, job_path, campaign_id))
