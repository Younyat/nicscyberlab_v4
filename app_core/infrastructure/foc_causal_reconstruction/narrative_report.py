"""Per-execution, plain-language narrative explanation of the causal reconstruction result.

This module turns the same evidence already consulted by the causal evaluator
(`edge_evaluator.py` / `service.py`) into a human-readable account of *why* each
expected relation ended up recovered, degraded, ambiguous, or missing for one
execution — cross-referencing the general network-layer analysis, the OT-specific
export, the temporal-uncertainty inputs, and the independent attack ground-truth
records, instead of leaving the reader with only the terse `status_reason` string.

It is read-only with respect to primary evidence: it never modifies any preserved
artifact, only writes a new, additive report under `derived/executive/` in the
case directory. Any failure here must never break the acquisition/analysis/
reconstruction pipeline it is called from — every public entry point swallows
its own exceptions and returns None on failure.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .service import _build_case_context
from ..foc_reconstruction.foc_paths import project_path

SCHEMA = "nics_execution_narrative_report_v1"


def _load_json(path: Path):
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _parse_ts(value) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw).timestamp()
    except Exception:
        return None


def _fmt_ts(value) -> str:
    return str(value) if value else "not available"


def _read_causal_graph(case_path: Path) -> list[dict]:
    data = _load_json(case_path / "derived" / "reconstruction" / "causal_graph.json")
    return (data or {}).get("edges") or []


def _read_ot_export(case_path: Path) -> dict | None:
    industrial_dir = case_path / "industrial"
    if not industrial_dir.is_dir():
        return None
    files = sorted(industrial_dir.glob("ot_export_rolling_*.json"))
    return _load_json(files[-1]) if files else None


def _read_network_findings(case_path: Path) -> dict | None:
    return _load_json(case_path / "analysis" / "03_network" / "network_findings.json")


def _find_attack_record_for_execution(foc_context: dict, attack_started_at_utc, tolerance_seconds: float = 30.0) -> dict | None:
    """Find the specific attack_attestation record matching THIS execution, by nearest
    execution.started_at timestamp — not by generic ground-truth selector (which can match
    across hundreds of unrelated historical attack events sharing the same technique/scenario)."""
    target_ts = _parse_ts(attack_started_at_utc)
    if target_ts is None:
        return None
    attacks = (foc_context.get("attack_attestation") or {}).get("attacks") or []
    best = None
    best_delta = None
    for item in attacks:
        if not isinstance(item, dict):
            continue
        started_at = ((item.get("execution") or {}).get("started_at"))
        candidate_ts = _parse_ts(started_at)
        if candidate_ts is None:
            continue
        delta = abs(candidate_ts - target_ts)
        if best_delta is None or delta < best_delta:
            best, best_delta = item, delta
    if best is not None and best_delta is not None and best_delta <= tolerance_seconds:
        return best
    return None


def _resolve_ground_truth_evidence(attack_record: dict | None) -> dict:
    """Load the raw, independent attack ground-truth files for the matched attack event
    (outside the forensic case, outside the capture pipeline). Reads every JSON file in the
    attack's own output directory, not just the curated evidence_references subset — some
    real files (e.g. plc_state_restored.json) exist on disk but are not always listed there."""
    out: dict = {}
    if not isinstance(attack_record, dict):
        return out
    refs = attack_record.get("evidence_references") or []
    attack_dir = None
    for ref in refs:
        try:
            candidate = project_path(*str(ref).split("/")).parent
            if candidate.is_dir():
                attack_dir = candidate
                break
        except Exception:
            continue
    if attack_dir is None:
        for ref in refs:
            try:
                payload = _load_json(project_path(*str(ref).split("/")))
                if payload is not None:
                    out[Path(str(ref)).name] = payload
            except Exception:
                continue
        return out
    for file_path in sorted(attack_dir.glob("*.json")):
        payload = _load_json(file_path)
        if payload is not None:
            out[file_path.name] = payload
    return out


def _find_register_variable(plc_state: dict | None, register: int | None):
    if not isinstance(plc_state, dict) or register is None:
        return None, None
    for var_name, entry in (plc_state.get("variables") or {}).items():
        if isinstance(entry, dict) and entry.get("validated_modbus_address") == register:
            return var_name, entry.get("value")
    return None, None


def _capture_gap_analysis(ot_export: dict | None, write_start: float | None, write_end: float | None) -> dict:
    captures = (ot_export or {}).get("captures") or []
    windows = sorted({
        (c.get("segment_start_time"), c.get("segment_end_time"))
        for c in captures
        if c.get("segment_start_time") and c.get("segment_end_time")
    }, key=lambda w: str(w[0]))
    parsed = [(_parse_ts(a), _parse_ts(b), a, b) for a, b in windows]
    parsed = [p for p in parsed if p[0] is not None and p[1] is not None]
    gaps = []
    for i in range(len(parsed) - 1):
        gap_start_ts, gap_start_iso = parsed[i][1], parsed[i][3]
        gap_end_ts, gap_end_iso = parsed[i + 1][0], parsed[i + 1][2]
        if gap_end_ts > gap_start_ts:
            overlaps_write = (
                write_start is not None and write_end is not None
                and write_start < gap_end_ts and write_end > gap_start_ts
            )
            gaps.append({
                "gap_start_utc": gap_start_iso,
                "gap_end_utc": gap_end_iso,
                "gap_seconds": round(gap_end_ts - gap_start_ts, 3),
                "overlaps_write_window": bool(overlaps_write),
            })
    return {
        "segment_windows": [{"start_utc": a, "end_utc": b} for a, b in windows],
        "gaps": gaps,
    }


def _describe_ot_edge(edge: dict, gt_edge: dict, case_context: dict, case_path: Path, gt_evidence: dict, nts: dict | None) -> dict:
    network_ot_context = case_context.get("network_ot_context") or {}
    ot_export = _read_ot_export(case_path)
    network_findings = _read_network_findings(case_path)

    per_file_general = []
    for f in ((network_findings or {}).get("findings") or {}).get("files") or []:
        per_file_general.append({
            "pcap": Path(str(f.get("pcap") or "")).name,
            "total_frames": f.get("total_frames"),
            "modbus_frames": f.get("modbus_frames"),
        })

    write_start = _parse_ts((gt_evidence.get("plc_state_before.json") or {}).get("captured_at_utc"))
    write_end = _parse_ts((gt_evidence.get("plc_state_after.json") or {}).get("captured_at_utc"))
    gap_analysis = _capture_gap_analysis(ot_export, write_start, write_end)

    register = gt_edge.get("target_register")
    expected_value = gt_edge.get("expected_value")
    var_name, before_value = _find_register_variable(gt_evidence.get("plc_state_before.json"), register)
    _, after_value = _find_register_variable(gt_evidence.get("plc_state_after.json"), register)
    _, restored_value = _find_register_variable(gt_evidence.get("plc_state_restored.json"), register)

    ground_truth_confirms_change = (
        before_value is not None and after_value is not None and before_value != after_value
    )
    matches_expected = (expected_value is not None and after_value == expected_value)
    restored_to_baseline = (
        restored_value is not None and before_value is not None and restored_value == before_value
    )

    summary = (ot_export or {}).get("summary") or {}

    return {
        "kind": "ot_semantic_observation",
        "forensic_evidence": {
            "general_network_analysis": {
                "tool": (network_findings or {}).get("tool_used"),
                "per_file_frames_matching_port_502": per_file_general,
                "total_modbus_port_frames": network_ot_context.get("total_modbus_frames"),
                "note": "Counts every TCP segment matching port 502 across the full captured segment duration; does not attempt to decode a Modbus PDU or verify register/value content.",
            },
            "ot_specific_export": {
                "tool": "scapy (protocol-aware Modbus ADU decoder)",
                "source_mode": (ot_export or {}).get("source_mode"),
                "packets_seen_port_502_in_incident_window": summary.get("packets_seen_502"),
                "packets_with_tcp_payload": summary.get("payload_packets_seen"),
                "decoded_modbus_records": summary.get("records_exported"),
                "total_ot_records_used_by_evaluator": network_ot_context.get("total_ot_records"),
                "note": "Scoped to the case-bound incident window and requires an actual TCP payload to attempt Modbus ADU decoding; a port-502 packet with no payload (e.g. a bare ACK) cannot yield a record.",
            },
            "capture_segmentation": gap_analysis,
        },
        "ground_truth_cross_check": {
            "source": "independent attack-execution ground truth (outside the forensic case, outside the capture pipeline)",
            "evidence_files": sorted(gt_evidence.keys()),
            "target_register": register,
            "target_variable_name": var_name,
            "expected_value": expected_value,
            "value_before_write": before_value,
            "value_after_write": after_value,
            "value_after_rollback": restored_value,
            "ground_truth_confirms_register_changed": ground_truth_confirms_change,
            "ground_truth_value_matches_expected": matches_expected,
            "ground_truth_confirms_rollback_to_baseline": restored_to_baseline,
            "write_command_ok": ((gt_evidence.get("modbus_transaction_log.json") or {}).get("write_command") or {}).get("ok"),
        },
        "interpretation": (
            "The register change is independently confirmed by the platform's own ground-truth "
            "instrumentation (direct before/after/restored register reads taken outside the capture "
            "pipeline), not by the evidence preserved inside the forensic case. The causal evaluator "
            "deliberately does not accept ground-truth confirmation as a substitute for evidence "
            "recoverable from the case itself — only `total_ot_records` from the case's own OT export "
            "counts toward this edge's support_status. This is why the relation can be honestly reported "
            "as degraded/insufficient even though the underlying event is proven to have occurred."
        ),
    }


def _describe_temporal_edge(edge: dict, gt_edge: dict, case_context: dict, case_path: Path, nts: dict | None) -> dict:
    time_sync = _load_json(case_path / "metadata" / "time_sync.json") or {}
    ground_truth = case_context.get("ground_truth") or {}
    max_offset_ms = float(time_sync.get("max_clock_offset_ms") or 0.0)
    resolution_ms = float(ground_truth.get("timestamp_resolution_ms") or 1000.0)
    jitter_ms = float(ground_truth.get("acquisition_jitter_ms") or 1000.0)
    uncertainty_seconds = (max_offset_ms + resolution_ms + jitter_ms) / 1000.0

    src_ts = _parse_ts((nts or {}).get("detection_surface_hit_at_utc"))
    dst_ts = _parse_ts((nts or {}).get("alert_observed_at_utc"))
    delta = (dst_ts - src_ts) if (src_ts is not None and dst_ts is not None) else None

    identical_by_construction = (
        (nts or {}).get("detection_surface_hit_at_utc") == (nts or {}).get("alert_observed_at_utc")
        and not bool((nts or {}).get("suricata_timestamp_exported"))
    )

    return {
        "kind": "temporal_ordering",
        "inputs": {
            "detection_surface_hit_at_utc": (nts or {}).get("detection_surface_hit_at_utc"),
            "alert_observed_at_utc": (nts or {}).get("alert_observed_at_utc"),
            "delta_seconds": round(delta, 6) if delta is not None else None,
            "max_clock_offset_ms": max_offset_ms,
            "declared_timestamp_resolution_ms": resolution_ms,
            "declared_acquisition_jitter_ms": jitter_ms,
            "uncertainty_window_seconds": round(uncertainty_seconds, 3),
        },
        "architecture_note": (
            "detection_surface_hit_at_utc is assigned the same value as alert_observed_at_utc at "
            "acquisition time (metadata/normalized_causal_timestamps.json is built from a single Wazuh "
            "SIEM alert timestamp; Suricata's own engine-level detection timestamp is not exported "
            "independently — suricata_timestamp_exported is false). This makes delta == 0 by "
            "construction, which always falls inside the uncertainty window, so this specific relation "
            "is architecturally unable to resolve to 'supported' regardless of clock precision."
            if identical_by_construction else
            "The two timestamps in this execution came from independently exported sources."
        ),
    }


def _describe_generic_edge(edge: dict, gt_edge: dict, case_context: dict) -> dict:
    required = gt_edge.get("required_evidence") or []
    return {
        "kind": "generic",
        "required_evidence": required,
    }


def _edge_narrative(edge: dict, gt_edges_by_id: dict, case_context: dict, case_path: Path, gt_evidence: dict, nts: dict | None) -> dict:
    edge_id = edge.get("edge_id")
    gt_edge = gt_edges_by_id.get(edge_id) or {}
    if edge_id == "edge_ot_write_to_plc_state_observation":
        detail = _describe_ot_edge(edge, gt_edge, case_context, case_path, gt_evidence, nts)
    elif edge_id == "edge_detection_surface_to_alert_observation":
        detail = _describe_temporal_edge(edge, gt_edge, case_context, case_path, nts)
    else:
        detail = _describe_generic_edge(edge, gt_edge, case_context)
    return {
        "edge_id": edge_id,
        "meaning": gt_edge.get("meaning") or "(no ground-truth description available for this edge)",
        "support_status": edge.get("support_status"),
        "temporal_status": edge.get("temporal_status"),
        "status_reason": edge.get("status_reason"),
        "limitations": edge.get("limitations") or [],
        "detail": detail,
    }


def _render_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# Execution Narrative Report — {report.get('execution_id')} ({report.get('case_id')})")
    lines.append("")
    lines.append(f"Generated: {report.get('generated_at_utc')}")
    lines.append(f"Scenario: {report.get('scenario_id')}")
    counts = report.get("edge_counts") or {}
    lines.append(
        f"CPR (recovered/total): {report.get('cpr')} "
        f"(recovered={counts.get('recovered', 0)}, degraded={counts.get('degraded', 0)}, "
        f"ambiguous={counts.get('ambiguous', 0)}, missing={counts.get('missing', 0)})"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Relation | Status | Reason |")
    lines.append("|---|---|---|")
    for e in report.get("edges") or []:
        lines.append(f"| {e['meaning']} | `{e['support_status']}` | {e['status_reason'] or ''} |")
    lines.append("")
    lines.append("## Per-relation detail")
    for e in report.get("edges") or []:
        lines.append("")
        lines.append(f"### {e['meaning']}")
        lines.append(f"- **edge_id**: `{e['edge_id']}`")
        lines.append(f"- **support_status**: `{e['support_status']}`  **temporal_status**: `{e['temporal_status']}`")
        lines.append(f"- **status_reason**: {e['status_reason']}")
        if e["limitations"]:
            lines.append("- **limitations**:")
            for lim in e["limitations"]:
                lines.append(f"  - {lim}")
        detail = e.get("detail") or {}
        kind = detail.get("kind")
        if kind == "ot_semantic_observation":
            fe = detail["forensic_evidence"]
            gtc = detail["ground_truth_cross_check"]
            gen = fe["general_network_analysis"]
            ot = fe["ot_specific_export"]
            lines.append("")
            lines.append("  **Forensic evidence — general network analysis (whole captured segments):**")
            lines.append(f"  - Total frames matching port 502 across all captured segments: **{gen.get('total_modbus_port_frames')}**")
            for pf in gen.get("per_file_frames_matching_port_502") or []:
                lines.append(f"    - `{pf['pcap']}`: {pf['modbus_frames']} frames")
            lines.append(f"  - {gen.get('note')}")
            lines.append("")
            lines.append("  **Forensic evidence — OT-specific export (case-bound incident window):**")
            lines.append(f"  - Packets matching port 502 within the incident window: **{ot.get('packets_seen_port_502_in_incident_window')}**")
            lines.append(f"  - Of those, with an actual TCP payload: **{ot.get('packets_with_tcp_payload')}**")
            lines.append(f"  - Modbus records successfully decoded: **{ot.get('decoded_modbus_records')}**")
            lines.append(f"  - {ot.get('note')}")
            gaps = fe.get("capture_segmentation", {}).get("gaps") or []
            if gaps:
                lines.append("")
                lines.append("  **Capture segmentation gaps:**")
                for g in gaps:
                    flag = " — OVERLAPS THE WRITE WINDOW" if g["overlaps_write_window"] else ""
                    lines.append(f"  - {g['gap_start_utc']} → {g['gap_end_utc']} ({g['gap_seconds']}s){flag}")
            lines.append("")
            lines.append("  **Ground-truth cross-check (independent of the capture pipeline):**")
            lines.append(f"  - Target register: {gtc.get('target_register')} (`{gtc.get('target_variable_name')}`), expected value: {gtc.get('expected_value')}")
            lines.append(f"  - Value before write: {gtc.get('value_before_write')} → after write: {gtc.get('value_after_write')} → after rollback: {gtc.get('value_after_rollback')}")
            lines.append(f"  - Ground truth confirms the register changed: **{gtc.get('ground_truth_confirms_register_changed')}**")
            lines.append(f"  - Value after write matches the expected value: **{gtc.get('ground_truth_value_matches_expected')}**")
            lines.append(f"  - Rollback confirmed back to baseline: **{gtc.get('ground_truth_confirms_rollback_to_baseline')}**")
            lines.append("")
            lines.append(f"  **Interpretation:** {detail.get('interpretation')}")
        elif kind == "temporal_ordering":
            inp = detail["inputs"]
            lines.append("")
            lines.append("  **Temporal inputs:**")
            lines.append(f"  - detection_surface_hit_at_utc: {inp.get('detection_surface_hit_at_utc')}")
            lines.append(f"  - alert_observed_at_utc: {inp.get('alert_observed_at_utc')}")
            lines.append(f"  - delta: {inp.get('delta_seconds')}s, uncertainty window: {inp.get('uncertainty_window_seconds')}s "
                          f"(clock offset {inp.get('max_clock_offset_ms')}ms + resolution {inp.get('declared_timestamp_resolution_ms')}ms "
                          f"+ jitter {inp.get('declared_acquisition_jitter_ms')}ms)")
            lines.append(f"  - {detail.get('architecture_note')}")
        elif kind == "generic" and detail.get("required_evidence"):
            lines.append(f"  - Required evidence for this relation: {', '.join(detail['required_evidence'])}")
    return "\n".join(lines) + "\n"


def generate_execution_narrative_report(case_id: str, case_path, execution_id: str | None = None) -> dict | None:
    try:
        case_path = Path(case_path)
        edges = _read_causal_graph(case_path)
        if not edges:
            return None

        case_context = _build_case_context(case_id, case_path)
        ground_truth = case_context.get("ground_truth") or {}
        gt_edges_by_id = {e.get("edge_id"): e for e in (ground_truth.get("expected_edges") or []) if isinstance(e, dict)}
        nts = _load_json(case_path / "metadata" / "normalized_causal_timestamps.json")
        attack_record = _find_attack_record_for_execution(
            case_context.get("foc_context") or {}, (nts or {}).get("attack_started_at_utc")
        )
        gt_evidence = _resolve_ground_truth_evidence(attack_record)

        edge_reports = [
            _edge_narrative(e, gt_edges_by_id, case_context, case_path, gt_evidence, nts)
            for e in edges
        ]

        counts = {"recovered": 0, "degraded": 0, "ambiguous": 0, "missing": 0}
        for e in edges:
            status = e.get("support_status")
            if status in counts:
                counts[status] += 1
        total = len(edges)
        cpr = round(counts["recovered"] / total, 4) if total else None

        report = {
            "schema": SCHEMA,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "execution_id": execution_id or case_id,
            "case_id": case_id,
            "scenario_id": case_context.get("scenario_id"),
            "cpr": cpr,
            "edge_counts": counts,
            "edges": edge_reports,
        }

        out_dir = case_path / "derived" / "executive"
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / "execution_narrative_report.json"
        tmp_json = json_path.with_suffix(".tmp")
        tmp_json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        tmp_json.replace(json_path)

        md_path = out_dir / "execution_narrative_report.md"
        tmp_md = md_path.with_suffix(".tmp")
        tmp_md.write_text(_render_markdown(report), encoding="utf-8")
        tmp_md.replace(md_path)

        return report
    except Exception:
        return None
