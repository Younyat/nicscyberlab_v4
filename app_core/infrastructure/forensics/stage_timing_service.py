"""
Real, evidence-grounded per-stage/per-target timing for a forensic case.

Reads timestamps this pipeline ALREADY records — pipeline_events.jsonl
(acquisition start/end events, already includes per-VM elapsed_s for
memory/disk, and the ot_export_progress events added 2026-07-16),
metadata/acquisition_profile.json (network context import), and
analysis/analysis_status.json (per-analysis-layer started_at/finished_at) —
and turns them into one unified timeline: what stage, on what target, how
long it has actually taken (or is still taking), and how that compares to
real historical durations for the same stage elsewhere in the evidence
store.

Nothing here changes pipeline control flow, writes back into case state, or
invents a number: if there isn't enough real history for a stage yet,
`expected_seconds` is None rather than a guess. Read-only aggregation only,
built for the "Live Campaign Status" panel's per-stage timers.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .forensics_api import EVIDENCE_ROOT, _read_jsonl_events, iso_to_epoch

_HISTORY_CACHE: dict[str, tuple[float, float | None]] = {}
_HISTORY_CACHE_TTL_SECONDS = 300
_HISTORY_MAX_CASES_SCANNED = 25

# (stage_key, label, start_event, {end_events...})
_ACQUISITION_STAGE_DEFS = [
    ("memory_acquisition", "Memory acquisition", "memory_start", {"memory_preserved", "memory_failed"}),
    ("disk_acquisition", "Disk acquisition", "disk_start", {"disk_preserved", "disk_failed"}),
    ("ot_export", "Network/OT (Modbus) export", "ot_export_start", {"ot_export_preserved"}),
]

_ANALYSIS_PHASE_LABELS = {
    "preflight_validation": "Analysis: pre-flight validation",
    "evidence_inventory": "Analysis: evidence inventory",
    "integrity_custody_validation": "Analysis: integrity & custody validation",
    "temporal_validation": "Analysis: temporal validation",
    "network_analysis": "Analysis: network layer",
    "memory_analysis": "Analysis: memory layer",
    "disk_analysis": "Analysis: disk layer",
    "ot_export_analysis": "Analysis: OT/Modbus layer",
    "alerts_detection_analysis": "Analysis: alerts/detection layer",
    "unified_forensic_timeline": "Analysis: unified timeline",
}


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _pair_target(meta: dict) -> str | None:
    return meta.get("vm_id") or meta.get("vm_ip") or meta.get("node_name")


def _fmt_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "unknown size"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _latest_matching_event(events: list[dict], event_name: str, run_id: str | None = None) -> dict | None:
    best = None
    best_epoch = -1.0
    for e in events:
        if e.get("event") != event_name:
            continue
        if run_id and e.get("run_id") and e.get("run_id") != run_id:
            continue
        epoch = e.get("ts_epoch") or iso_to_epoch(e.get("ts_utc") or "") or 0
        if epoch >= best_epoch:
            best, best_epoch = e, epoch
    return best


def _ot_export_progress_detail(events: list[dict], run_id: str | None) -> str | None:
    """Human-readable 'what is it actually doing right now' for a still-running
    ot_export stage, built from the real ot_export_progress events this
    pipeline already emits (network_context_importer.py) — no invented
    numbers, no client-side estimate. Explicitly built so a slow OT export
    isn't a silent, unexplained wait in the Live Campaign Status panel: it's
    usually just a lot of real network capture volume to parse, and this
    says so with real figures (file N/M, size of the file it's on, packets
    read so far) instead of leaving the user to go find pipeline_events.jsonl
    by hand.
    """
    progress = _latest_matching_event(events, "ot_export_progress", run_id)
    if not progress:
        return None
    meta = progress.get("meta") or {}
    file_index = meta.get("file_index")
    file_count = meta.get("file_count")
    packets = meta.get("total_packets_read_so_far")
    records = meta.get("records_exported_so_far")
    size_bytes = meta.get("pcap_size_bytes")
    parts = []
    if file_index and file_count:
        parts.append(f"file {file_index}/{file_count}")
        if size_bytes:
            parts.append(f"({_fmt_bytes(size_bytes)})")
    if packets is not None:
        parts.append(f"— {packets:,} packets read so far")
    if records is not None:
        parts.append(f"({records} OT/Modbus record(s) exported)")
    if not parts:
        return None
    return "Processing pcap " + " ".join(parts) + "."


def _acquisition_stage_entries(events: list[dict], now: float) -> list[dict]:
    entries: list[dict] = []
    for stage_key, label, start_evt, end_evts in _ACQUISITION_STAGE_DEFS:
        for start in (e for e in events if e.get("event") == start_evt):
            target = _pair_target(start.get("meta") or {})
            start_epoch = start.get("ts_epoch") or iso_to_epoch(start.get("ts_utc") or "")
            if not start_epoch:
                continue
            match = None
            match_epoch = None
            for end in events:
                if end.get("event") not in end_evts:
                    continue
                end_epoch = end.get("ts_epoch") or iso_to_epoch(end.get("ts_utc") or "")
                if not end_epoch or end_epoch < start_epoch:
                    continue
                end_target = _pair_target(end.get("meta") or {})
                if target and end_target and end_target != target:
                    continue
                if match_epoch is None or end_epoch < match_epoch:
                    match, match_epoch = end, end_epoch
            error_detail = None
            size_bytes = None
            target_ip = (start.get("meta") or {}).get("vm_ip")
            if match:
                status = "completed" if str(match.get("event") or "").endswith("preserved") else "failed"
                elapsed = match_epoch - start_epoch
                finished_at = match.get("ts_utc")
                match_meta = match.get("meta") or {}
                target_ip = match_meta.get("vm_ip") or target_ip
                # Real artifact size, already recorded on every memory_preserved/
                # disk_preserved event (meta.size, bytes) -- just never surfaced
                # before. 2026-07-19: user explicitly asked to see exactly what's
                # being preserved and how much it weighs, live, per host.
                if status == "completed":
                    size_bytes = match_meta.get("size")
                else:
                    error_detail = match_meta.get("reason") or match_meta.get("error")
            else:
                status = "running"
                elapsed = now - start_epoch
                finished_at = None
            progress_detail = None
            if status == "running" and stage_key == "ot_export":
                progress_detail = _ot_export_progress_detail(events, start.get("run_id"))
            entries.append({
                "stage_key": stage_key,
                "label": label,
                "target": target,
                "target_ip": target_ip,
                "status": status,
                "started_at": start.get("ts_utc"),
                "finished_at": finished_at,
                "elapsed_seconds": round(elapsed, 1),
                "size_bytes": size_bytes,
                "error_detail": error_detail,
                "progress_detail": progress_detail,
            })
    return entries


def _network_context_entry(case_dir: Path, now: float, events: list[dict]) -> dict | None:
    profile = _load_json(case_dir / "metadata" / "acquisition_profile.json")
    started = profile.get("network_context_import_started_utc")
    if not started:
        return None
    start_epoch = iso_to_epoch(started)
    if not start_epoch:
        return None
    finished = profile.get("network_context_import_completed_utc")
    finish_epoch = iso_to_epoch(finished) if finished else None
    status = "completed" if finish_epoch else "running"
    # ot_export runs as part of this phase (see acquisition_profile's
    # ot_export_started_utc/ot_export_completed_utc, both inside the
    # network_context_import window) — surface the same real progress here
    # too, since this is the entry the panel shows first while ot_export's
    # own row is easy to miss further down the list.
    progress_detail = _ot_export_progress_detail(events, None) if status == "running" else None
    return {
        "stage_key": "network_context_import",
        "label": "Network context import (pcap selection)",
        "target": None,
        "status": status,
        "started_at": started,
        "finished_at": finished,
        "elapsed_seconds": round((finish_epoch or now) - start_epoch, 1),
        "error_detail": None,
        "progress_detail": progress_detail,
    }


def _analysis_phase_entries(case_dir: Path, now: float) -> list[dict]:
    status = _load_json(case_dir / "analysis" / "analysis_status.json")
    phases = status.get("phases") or {}
    entries: list[dict] = []
    for phase_key, phase in phases.items():
        started = phase.get("started_at")
        if not started:
            continue
        start_epoch = iso_to_epoch(started)
        if not start_epoch:
            continue
        finished = phase.get("finished_at")
        finish_epoch = iso_to_epoch(finished) if finished else None
        phase_status = phase.get("status") or ("running" if not finish_epoch else "completed")
        errors = phase.get("errors") or []
        entries.append({
            "stage_key": f"analysis_{phase_key}",
            "label": _ANALYSIS_PHASE_LABELS.get(phase_key, f"Analysis: {phase_key}"),
            "target": None,
            "status": phase_status,
            "started_at": started,
            "finished_at": finished,
            "elapsed_seconds": round((finish_epoch or now) - start_epoch, 1),
            "error_detail": str(errors[0]) if errors else None,
            "progress_detail": None,
        })
    return entries


def _historical_median_seconds(stage_key: str) -> float | None:
    """Median real duration for stage_key across other completed occurrences
    found in the evidence store (bounded scan, cached for 5 min). Returns
    None — never a guessed number — if there isn't enough real history yet.
    """
    now = time.time()
    cached = _HISTORY_CACHE.get(stage_key)
    if cached and (now - cached[0]) < _HISTORY_CACHE_TTL_SECONDS:
        return cached[1]

    durations: list[float] = []
    try:
        case_dirs = sorted(
            (p for p in Path(EVIDENCE_ROOT).glob("CASE-*") if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:_HISTORY_MAX_CASES_SCANNED]
    except Exception:
        case_dirs = []

    for case_dir in case_dirs:
        for entry in get_case_stage_timeline(case_dir, _skip_baseline=True):
            if entry["stage_key"] == stage_key and entry["status"] == "completed" and entry.get("elapsed_seconds"):
                durations.append(entry["elapsed_seconds"])

    median = None
    if durations:
        durations.sort()
        n = len(durations)
        median = durations[n // 2] if n % 2 else (durations[n // 2 - 1] + durations[n // 2]) / 2.0
    _HISTORY_CACHE[stage_key] = (now, median)
    return median


def get_case_stage_timeline(case_dir: str | Path, *, _skip_baseline: bool = False) -> list[dict]:
    """Real per-stage/per-target timing for the given case directory.

    Each entry: stage_key, label, target (vm_id/vm_ip if applicable, else
    None), status (running/completed/failed), started_at, finished_at,
    elapsed_seconds (actual, computed from real timestamps), and — unless
    _skip_baseline — expected_seconds (real historical median, or None) and
    delayed (elapsed clearly beyond that median while still running).
    """
    case_dir = Path(case_dir)
    if not case_dir.is_dir():
        return []
    now = time.time()
    events = _read_jsonl_events(str(case_dir))
    entries: list[dict] = _acquisition_stage_entries(events, now)
    net_entry = _network_context_entry(case_dir, now, events)
    if net_entry:
        entries.append(net_entry)
    entries.extend(_analysis_phase_entries(case_dir, now))

    # Entries above are built stage-definition-order-then-appended (all
    # memory_acquisition, then all disk_acquisition, then network_context_
    # import, then analysis phases) -- NOT real chronological order. Real
    # acquisition order is memory -> network_context_import -> disk, so
    # network_context_import was displaying after disk despite happening
    # between them. Sort by real started_at so the panel reads top-to-bottom
    # the same way the work actually happened; entries with no parseable
    # timestamp sort last rather than raising.
    entries.sort(key=lambda e: iso_to_epoch(e.get("started_at") or "") or float("inf"))

    if not _skip_baseline:
        for entry in entries:
            expected = _historical_median_seconds(entry["stage_key"])
            entry["expected_seconds"] = expected
            entry["delayed"] = bool(
                expected
                and entry["status"] == "running"
                and entry.get("elapsed_seconds") is not None
                and entry["elapsed_seconds"] > expected * 1.5
            )
    return entries


def get_case_stage_timeline_by_case_id(case_id: str) -> list[dict]:
    """Same as get_case_stage_timeline, but resolves a case_id (including
    short aliases like 'case-1460a5d3') to its real directory first, reusing
    the same resolver the rest of the FOC reconstruction module already uses
    — no new alias logic invented here.
    """
    if not case_id:
        return []
    try:
        from ..foc_reconstruction.foc_case_analysis import get_case_entry, _case_dir_from_entry
        entry = get_case_entry(case_id)
        if not entry:
            return []
        case_dir = _case_dir_from_entry(entry)
    except Exception:
        return []
    return get_case_stage_timeline(case_dir)


# Layer findings files this pipeline already writes (analysis/foc_case_analysis.py)
# — same generic "read what's already there" approach as the rest of this module.
_ANALYSIS_LAYER_FINDINGS_FILES = {
    "memory": "analysis/04_memory/memory_findings.json",
    "disk": "analysis/05_disk/disk_findings.json",
    "network": "analysis/03_network/network_findings.json",
    "ot": "analysis/06_ot/ot_findings.json",
    "alerts": "analysis/07_alerts/alert_findings.json",
}

# Count-like fields to surface as a one-line human summary. Different layers use
# different names for "how many things did I analyze" — collecting whichever of
# these actually exists avoids writing one parser per layer's findings schema.
_FINDINGS_COUNT_KEYS = (
    "dumps_analyzed", "images_analyzed", "segments_analyzed",
    "records_exported", "alerts_analyzed", "events_analyzed", "records_analyzed",
)


def summarize_case_analysis_layers(case_dir: str | Path) -> list[dict]:
    """One real line per analysis layer: status, a compact 'what was
    analyzed' detail (whichever count field that layer's findings file
    happens to report), and the first real error if it failed. Read-only,
    same *_findings.json files the analysis pipeline already writes.
    """
    case_dir = Path(case_dir)
    out: list[dict] = []
    for layer, rel in _ANALYSIS_LAYER_FINDINGS_FILES.items():
        data = _load_json(case_dir / rel)
        if not isinstance(data, dict):
            continue
        findings = data.get("findings")
        detail_bits = []
        if isinstance(findings, dict):
            for key in _FINDINGS_COUNT_KEYS:
                if key in findings:
                    detail_bits.append(f"{key.replace('_', ' ')}={findings[key]}")
        errors = data.get("errors") or []
        out.append({
            "layer": layer,
            "status": data.get("status") or "unknown",
            "detail": ", ".join(detail_bits) if detail_bits else None,
            "error": str(errors[0]) if errors else None,
        })
    return out


def summarize_case_analysis_layers_by_case_id(case_id: str) -> list[dict]:
    if not case_id:
        return []
    try:
        from ..foc_reconstruction.foc_case_analysis import get_case_entry, _case_dir_from_entry
        entry = get_case_entry(case_id)
        if not entry:
            return []
        case_dir = _case_dir_from_entry(entry)
    except Exception:
        return []
    return summarize_case_analysis_layers(case_dir)
