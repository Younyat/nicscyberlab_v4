from __future__ import annotations

import re
from pathlib import Path

from ..evidence_lifecycle_dashboard import _build_integrity_summary, _json_load, relative_path
from .atoms import new_atom
from .tshark_modbus import extract_modbus_fields

_IP_IN_FILENAME = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
_WRITE_SIGNATURES = ("write",)


def _node_lookup(case_dir: Path) -> dict[str, dict]:
    payload = _json_load(case_dir / "metadata" / "time_sync.json") or {}
    nodes = payload.get("nodes") or []
    return {str(n.get("vm_id")): {"name": n.get("name"), "ip": n.get("ip")} for n in nodes if n.get("vm_id")}


def _node_for_ip(node_lookup: dict[str, dict], ip: str | None) -> dict:
    if not ip:
        return {}
    for info in node_lookup.values():
        if info.get("ip") == ip:
            return info
    return {}


def _read_bounded(path: Path, limit_bytes: int = 65536) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit_bytes)
    except Exception:
        return ""


def _parse_vol3_table(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    rows = [line for line in text.splitlines() if line.strip()]
    if not rows:
        return []
    if rows[0].lower().startswith("volatility"):
        rows = rows[1:]
    if not rows:
        return []
    header = rows[0].split("\t")
    out = []
    for line in rows[1:]:
        cols = line.split("\t")
        if len(cols) < len(header):
            cols = cols + [""] * (len(header) - len(cols))
        out.append(dict(zip(header, cols)))
    return out


# ---------------------------------------------------------------------------
# Memory triage
# ---------------------------------------------------------------------------

def triage_memory(case_dir: Path, case_id: str) -> list[dict]:
    findings = _json_load(case_dir / "analysis" / "04_memory" / "memory_findings.json") or {}
    results = ((findings.get("findings") or {}).get("results")) or []
    node_lookup = _node_lookup(case_dir)
    atoms: list[dict] = []
    for result in results:
        dump_id = str(result.get("dump_id") or "unknown")
        dump_path = str(result.get("dump") or "")
        ip_match = _IP_IN_FILENAME.search(dump_path)
        ip_address = ip_match.group(1) if ip_match else None
        node_info = node_lookup.get(dump_id) or _node_for_ip(node_lookup, ip_address)
        node_name = node_info.get("name") or dump_id
        output_dir = Path(result.get("output_dir") or "")
        kernel = result.get("detected_kernel") or "unknown kernel"

        pslist_rows = _parse_vol3_table(output_dir / "vol3_pslist.txt")
        atoms.append(
            new_atom(
                atom_id=f"memory_{dump_id}_pslist",
                case_id=case_id,
                evidence_layer="memory",
                source_artifact=relative_path(output_dir / "vol3_pslist.txt"),
                extraction_method="volatility3_pslist_text_parse",
                relation_to_hypothesis="runtime_process_context",
                support_direction="neutral",
                support_strength="indirect",
                event_type="process_list",
                observed_entity=node_name,
                observed_value=f"{len(pslist_rows)} processes observed in volatile memory (kernel: {kernel})",
                node=dump_id,
                node_role=node_name,
                ip_address=ip_address,
                timestamp_status="approximate",
                limitation="No attacker-specific process was declared in ground truth for this layer; process presence is contextual, not direct attack evidence.",
                raw_reference=[relative_path(output_dir / "vol3_pslist.txt")],
            )
        )

        sockstat_rows = _parse_vol3_table(output_dir / "vol3_sockstat.txt")
        established = [r for r in sockstat_rows if str(r.get("State") or "").strip() == "ESTABLISHED"]
        atoms.append(
            new_atom(
                atom_id=f"memory_{dump_id}_sockstat",
                case_id=case_id,
                evidence_layer="memory",
                source_artifact=relative_path(output_dir / "vol3_sockstat.txt"),
                extraction_method="volatility3_sockstat_text_parse",
                relation_to_hypothesis="runtime_network_context",
                support_direction="neutral",
                support_strength="indirect",
                event_type="socket_list",
                observed_entity=node_name,
                observed_value=f"{len(sockstat_rows)} sockets observed, {len(established)} ESTABLISHED",
                node=dump_id,
                node_role=node_name,
                ip_address=ip_address,
                timestamp_status="unavailable",
                limitation="Socket table is a point-in-time memory snapshot; it does not by itself confirm Modbus write activity.",
                raw_reference=[relative_path(output_dir / "vol3_sockstat.txt")],
            )
        )

        bash_rows = _parse_vol3_table(output_dir / "vol3_bash.txt")
        if bash_rows:
            relation = "acquisition_tooling" if any("lime" in str(r.get("Command") or "").lower() for r in bash_rows) else "host_shell_activity"
            atoms.append(
                new_atom(
                    atom_id=f"memory_{dump_id}_bash",
                    case_id=case_id,
                    evidence_layer="memory",
                    source_artifact=relative_path(output_dir / "vol3_bash.txt"),
                    extraction_method="volatility3_bash_text_parse",
                    relation_to_hypothesis=relation,
                    support_direction="neutral",
                    support_strength="indirect",
                    event_type="shell_history",
                    observed_entity=node_name,
                    observed_value=f"{len(bash_rows)} shell history entries recovered from memory",
                    node=dump_id,
                    node_role=node_name,
                    ip_address=ip_address,
                    timestamp_status="approximate",
                    limitation="Recovered shell history reflects acquisition tooling on this case's victim node, not OT attack-path activity." if relation == "acquisition_tooling" else None,
                    raw_reference=[relative_path(output_dir / "vol3_bash.txt")],
                )
            )
    return atoms


# ---------------------------------------------------------------------------
# Network triage
# ---------------------------------------------------------------------------

def triage_network(case_dir: Path, case_id: str) -> list[dict]:
    findings = _json_load(case_dir / "analysis" / "03_network" / "network_findings.json") or {}
    files = ((findings.get("findings") or {}).get("files")) or []
    atoms: list[dict] = []
    total_write_packets = 0
    total_modbus_frames = 0
    pcaps_checked = 0

    for entry in files:
        pcap_rel = str(entry.get("pcap") or "")
        modbus_frames = int(entry.get("modbus_frames") or 0)
        if modbus_frames <= 0:
            continue
        pcap_path = None
        for candidate in case_dir.rglob(Path(pcap_rel).name):
            pcap_path = candidate
            break
        if pcap_path is None:
            atoms.append(
                new_atom(
                    atom_id=f"network_{Path(pcap_rel).stem}_presence",
                    case_id=case_id,
                    evidence_layer="network",
                    source_artifact=pcap_rel,
                    extraction_method="network_findings_aggregate",
                    relation_to_hypothesis="modbus_protocol_presence",
                    support_direction="partially_supports",
                    support_strength="moderate",
                    event_type="modbus_tcp_observation",
                    observed_value=f"{modbus_frames} Modbus frames observed (aggregate count only; pcap file not resolvable for packet-level re-check)",
                    timestamp_status="unavailable",
                    limitation="Packet-level re-check could not locate the pcap file on disk; relying on the prior aggregate count only.",
                    raw_reference=[pcap_rel],
                )
            )
            continue
        pcaps_checked += 1
        tshark_result = extract_modbus_fields(pcap_path, case_dir)
        if tshark_result.get("error"):
            atoms.append(
                new_atom(
                    atom_id=f"network_{pcap_path.stem}_presence",
                    case_id=case_id,
                    evidence_layer="network",
                    source_artifact=relative_path(pcap_path),
                    extraction_method="network_findings_aggregate",
                    relation_to_hypothesis="modbus_protocol_presence",
                    support_direction="partially_supports",
                    support_strength="moderate",
                    event_type="modbus_tcp_observation",
                    observed_value=f"{modbus_frames} Modbus frames observed (aggregate count only)",
                    timestamp_status="unavailable",
                    limitation=f"Packet-level re-check failed: {tshark_result.get('error')}.",
                    raw_reference=[relative_path(pcap_path)],
                )
            )
            continue
        function_codes = tshark_result.get("function_codes") or {}
        write_count = int(tshark_result.get("write_function_count") or 0)
        total_write_packets += write_count
        total_modbus_frames += int(tshark_result.get("modbus_frame_count") or 0)
        atoms.append(
            new_atom(
                atom_id=f"network_{pcap_path.stem}_modbus",
                case_id=case_id,
                evidence_layer="network",
                source_artifact=relative_path(pcap_path),
                extraction_method="tshark_field_extraction",
                relation_to_hypothesis="modbus_protocol_and_function_code_presence",
                support_direction="partially_supports" if write_count == 0 else "supports",
                support_strength="moderate" if write_count == 0 else "strong",
                event_type="modbus_tcp_observation",
                observed_value=f"function codes observed: {function_codes}; write-function packets: {write_count}",
                timestamp=tshark_result.get("first_timestamp"),
                timestamp_status="precise" if tshark_result.get("first_timestamp") else "unavailable",
                limitation=None if write_count else "Protocol presence confirmed at packet level, but no write-function code (5/6/15/16) packet was found in this pcap.",
                raw_reference=[relative_path(pcap_path)],
            )
        )

    if pcaps_checked:
        atoms.append(
            new_atom(
                atom_id="network_write_function_absence",
                case_id=case_id,
                evidence_layer="network",
                source_artifact="analysis/03_network/network_findings.json",
                extraction_method="tshark_field_extraction_aggregate",
                relation_to_hypothesis="modbus_write_packet_confirmation",
                support_direction="contradicts",
                support_strength="strong",
                event_type="modbus_write_absence",
                observed_value=f"0 write-function packets across {pcaps_checked} preserved pcaps re-checked at packet level ({total_modbus_frames} total Modbus frames inspected)",
                timestamp_status="not_resolvable",
                limitation="This is a direct, packet-level negative result: register and value-level write confirmation is not supported by any preserved pcap in this case.",
                raw_reference=[str(f.get("pcap")) for f in files],
            )
        )
    return atoms


# ---------------------------------------------------------------------------
# Disk triage
# ---------------------------------------------------------------------------

def triage_disk(case_dir: Path, case_id: str) -> list[dict]:
    findings = _json_load(case_dir / "analysis" / "05_disk" / "disk_findings.json") or {}
    results = ((findings.get("findings") or {}).get("results")) or []
    atoms: list[dict] = []
    for result in results:
        disk_image = str(result.get("disk_image") or "unknown")
        produced = result.get("produced_files") or []
        recovered = [f for f in produced if "recovered_evidence" in str(f)]
        if not recovered:
            atoms.append(
                new_atom(
                    atom_id=f"disk_{Path(disk_image).stem}",
                    case_id=case_id,
                    evidence_layer="disk",
                    source_artifact=disk_image,
                    extraction_method="sleuthkit_produced_files_index",
                    relation_to_hypothesis="host_artifact_context",
                    support_direction="not_evaluable",
                    support_strength="unavailable",
                    event_type="disk_recovered_artifact",
                    observed_value="No recovered_evidence files were produced for this disk image.",
                    timestamp_status="unavailable",
                    limitation="Disk content reflects host/acquisition context, not the OT causal attack path; relation to trigger path is indirect at best.",
                    raw_reference=[disk_image],
                )
            )
            continue
        names = sorted({Path(f).name for f in recovered})
        detail_bits = []
        for ref in recovered:
            ref_path = Path(ref)
            if ref_path.name == "auth.log":
                text = _read_bounded(ref_path)
                failed = text.count("Failed password")
                detail_bits.append(f"auth.log: {len(text.splitlines())} lines read, {failed} 'Failed password' occurrences")
            elif ref_path.name == "passwd":
                text = _read_bounded(ref_path)
                detail_bits.append(f"passwd: {len([l for l in text.splitlines() if l.strip()])} accounts")
            elif "bash_history" in ref_path.name:
                text = _read_bounded(ref_path)
                detail_bits.append(f"{ref_path.name}: {len([l for l in text.splitlines() if l.strip()])} command lines")
        atoms.append(
            new_atom(
                atom_id=f"disk_{Path(disk_image).stem}",
                case_id=case_id,
                evidence_layer="disk",
                source_artifact=disk_image,
                extraction_method="sleuthkit_recovered_evidence_bounded_read",
                relation_to_hypothesis="host_artifact_context",
                support_direction="not_evaluable",
                support_strength="unavailable",
                event_type="disk_recovered_artifact",
                observed_value=f"recovered: {', '.join(names)}; {'; '.join(detail_bits)}",
                timestamp_status="unavailable",
                limitation="Disk content reflects host/acquisition context, not the OT causal attack path; relation to trigger path is indirect at best.",
                raw_reference=[str(r) for r in recovered],
            )
        )
    return atoms


# ---------------------------------------------------------------------------
# OT triage
# ---------------------------------------------------------------------------

def triage_ot(case_dir: Path, case_id: str) -> list[dict]:
    findings = _json_load(case_dir / "analysis" / "06_ot" / "ot_findings.json") or {}
    files = ((findings.get("findings") or {}).get("files")) or []
    function_codes = (findings.get("findings") or {}).get("function_codes") or {}
    atoms: list[dict] = []
    for entry in files:
        records = int(entry.get("records") or 0)
        if records <= 0:
            continue
        atoms.append(
            new_atom(
                atom_id=f"ot_{entry.get('vm_id')}_{Path(str(entry.get('file'))).stem}",
                case_id=case_id,
                evidence_layer="ot",
                source_artifact=str(entry.get("file") or ""),
                extraction_method="ot_export_record_count",
                relation_to_hypothesis="ot_state_export_presence",
                support_direction="partially_supports",
                support_strength="weak",
                event_type="ot_export_record_count",
                observed_value=f"{records} OT export records captured",
                node=str(entry.get("vm_id") or "not_available"),
                timestamp_status="unavailable",
                limitation="OT export record counts confirm export activity but contain no setpoint or process-value content.",
                raw_reference=[str(entry.get("file") or "")],
            )
        )
    write_codes_present = any(str(code) in {"5", "6", "15", "16"} for code in function_codes)
    atoms.append(
        new_atom(
            atom_id="ot_function_code_aggregate",
            case_id=case_id,
            evidence_layer="ot",
            source_artifact="analysis/06_ot/ot_findings.json",
            extraction_method="ot_function_code_tally",
            relation_to_hypothesis="ot_write_state_confirmation",
            support_direction="contradicts" if not write_codes_present else "supports",
            support_strength="strong",
            event_type="ot_function_code_aggregate",
            observed_value=f"function_codes={function_codes}; write-function codes (5/6/15/16) present: {write_codes_present}",
            timestamp_status="not_resolvable",
            limitation=None if write_codes_present else "OT export aggregates contain only read-function tallies; no setpoint or write-value content exists in this dataset.",
            raw_reference=["analysis/06_ot/ot_findings.json"],
        )
    )
    return atoms


# ---------------------------------------------------------------------------
# Alerts triage
# ---------------------------------------------------------------------------

def triage_alerts(case_dir: Path, case_id: str, causal_summary: dict) -> list[dict]:
    findings = _json_load(case_dir / "analysis" / "07_alerts" / "alert_findings.json") or {}
    top_signatures = (findings.get("findings") or {}).get("top_signatures") or {}
    atoms: list[dict] = []

    write_sig = next((k for k in top_signatures if "write" in k.lower() and "modbus" in k.lower()), None)
    if write_sig:
        atoms.append(
            new_atom(
                atom_id="alerts_modbus_write_signature",
                case_id=case_id,
                evidence_layer="alerts",
                source_artifact="analysis/07_alerts/alert_findings.json",
                extraction_method="alert_findings_top_signatures",
                relation_to_hypothesis="modbus_write_claim",
                support_direction="partially_supports",
                support_strength="weak",
                event_type="ids_signature_hit",
                observed_value=f"signature '{write_sig}': {top_signatures[write_sig]} hits",
                timestamp_status="unavailable",
                limitation="IDS signature name asserts a write; not confirmed at packet level (see network layer counter-evidence).",
                raw_reference=["analysis/07_alerts/alert_findings.json"],
            )
        )

    read_sig = next((k for k in top_signatures if "read" in k.lower() and "modbus" in k.lower()), None)
    if read_sig:
        atoms.append(
            new_atom(
                atom_id="alerts_modbus_read_signature",
                case_id=case_id,
                evidence_layer="alerts",
                source_artifact="analysis/07_alerts/alert_findings.json",
                extraction_method="alert_findings_top_signatures",
                relation_to_hypothesis="modbus_protocol_presence",
                support_direction="supports",
                support_strength="moderate",
                event_type="ids_signature_hit",
                observed_value=f"signature '{read_sig}': {top_signatures[read_sig]} hits",
                timestamp_status="unavailable",
                raw_reference=["analysis/07_alerts/alert_findings.json"],
            )
        )

    trigger_vs_causal = (causal_summary or {}).get("trigger_vs_causal_path") or {}
    if trigger_vs_causal.get("same_event_family") is False:
        atoms.append(
            new_atom(
                atom_id="alerts_trigger_causal_path_mismatch",
                case_id=case_id,
                evidence_layer="alerts",
                source_artifact="derived/executive/evidence_lifecycle_summary.json",
                extraction_method="reused_trigger_vs_causal_path_computation",
                relation_to_hypothesis="single_coherent_attack_path",
                support_direction="contradicts",
                support_strength="strong",
                event_type="trigger_causal_path_mismatch",
                observed_value=f"trigger='{trigger_vs_causal.get('trigger_path')}' vs causal_path='{trigger_vs_causal.get('causal_attack_path')}'",
                timestamp_status="not_resolvable",
                limitation=str(trigger_vs_causal.get("message") or ""),
                raw_reference=[str(trigger_vs_causal.get("mismatch_label") or "")],
            )
        )
    return atoms


# ---------------------------------------------------------------------------
# Timeline triage
# ---------------------------------------------------------------------------

_TIMELINE_NODE_MAP = {
    "case_created": "forensic_case",
    "acquire_start": "preserved_case_evidence",
    "acquire_preserved": "preserved_case_evidence",
    "case_digest_written": "preserved_case_evidence",
    "traffic_start": "network_modbus_write",
    "traffic_capture_started": "network_modbus_write",
    "ot_export_start": "plc_or_scada_state_observation",
    "ot_export_preserved": "plc_or_scada_state_observation",
}


def triage_timeline(case_dir: Path, case_id: str) -> list[dict]:
    payload = _json_load(case_dir / "analysis" / "09_timeline" / "unified_forensic_timeline.json") or {}
    events = payload.get("findings") or []
    atoms: list[dict] = []
    seen_event_types: set[str] = set()
    for event in events:
        event_type = str(event.get("event") or "")
        node_id = _TIMELINE_NODE_MAP.get(event_type)
        if not node_id or event_type in seen_event_types:
            continue
        seen_event_types.add(event_type)
        atoms.append(
            new_atom(
                atom_id=f"timeline_{event_type}",
                case_id=case_id,
                evidence_layer="timeline",
                source_artifact="analysis/09_timeline/unified_forensic_timeline.json",
                extraction_method="causal_node_anchored_timeline_match",
                relation_to_hypothesis=f"causal_node:{node_id}",
                support_direction="supports",
                support_strength="weak",
                event_type=event_type,
                observed_value=f"first observed at {event.get('timestamp')}",
                timestamp=event.get("timestamp"),
                timestamp_status="precise" if event.get("ts_epoch") else "approximate",
                raw_reference=["analysis/09_timeline/unified_forensic_timeline.json"],
            )
        )

    non_write_count = sum(1 for e in events if e.get("event") == "ot:non_write_function")
    if non_write_count:
        atoms.append(
            new_atom(
                atom_id="timeline_ot_non_write_function_aggregate",
                case_id=case_id,
                evidence_layer="timeline",
                source_artifact="analysis/09_timeline/unified_forensic_timeline.json",
                extraction_method="timeline_event_type_aggregate",
                relation_to_hypothesis="ot_write_state_confirmation",
                support_direction="contradicts",
                support_strength="strong",
                event_type="ot_non_write_function_aggregate",
                observed_value=f"{non_write_count} ot:non_write_function events recorded; 0 ot:write_function events present",
                timestamp_status="not_resolvable",
                limitation="Timeline is sourced only from custody/pipeline/ot_export; no network, alert, or memory-sourced timestamps are present in this case's unified timeline.",
                raw_reference=["analysis/09_timeline/unified_forensic_timeline.json"],
            )
        )
    return atoms


# ---------------------------------------------------------------------------
# Custody triage
# ---------------------------------------------------------------------------

def triage_custody(case_dir: Path, case_id: str, uncertainty: dict) -> list[dict]:
    integrity_summary = _build_integrity_summary(case_dir)
    integrity_block = (uncertainty or {}).get("integrity") or {}
    case_wide_ratio = integrity_block.get("case_wide_integrity_ratio")
    return [
        new_atom(
            atom_id="custody_integrity_summary",
            case_id=case_id,
            evidence_layer="custody",
            source_artifact="manifest.json",
            extraction_method="reused_integrity_summary_computation",
            relation_to_hypothesis="evidentiary_trust",
            support_direction="neutral",
            support_strength="indirect",
            event_type="custody_integrity_summary",
            observed_value=(
                f"{integrity_summary.get('artifacts_declared')} artifacts declared, "
                f"case_wide_integrity_ratio={case_wide_ratio}"
            ),
            timestamp_status="unavailable",
            limitation="Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis." if (case_wide_ratio or 1.0) >= 1.0 else f"Case-wide manifest validation is partial ({case_wide_ratio}); some artifacts remain hash-unvalidated.",
            raw_reference=["manifest.json", "chain_of_custody.log"],
        )
    ]


# ---------------------------------------------------------------------------
# Causal graph triage
# ---------------------------------------------------------------------------

_SUPPORT_STATUS_TO_DIRECTION = {
    "recovered": "supports",
    "degraded": "partially_supports",
    "ambiguous": "partially_supports",
    "missing": "not_evaluable",
}
_CONFIDENCE_TO_STRENGTH = {"high": "strong", "medium": "moderate", "low": "weak"}


def triage_causal_graph(case_dir: Path, case_id: str, causal_graph: dict) -> list[dict]:
    edges = (causal_graph or {}).get("edges") or []
    atoms: list[dict] = []
    for edge in edges:
        support_status = str(edge.get("support_status") or "missing")
        confidence = str(edge.get("confidence") or "low")
        limitations = edge.get("limitations") or []
        atoms.append(
            new_atom(
                atom_id=f"causal_{edge.get('edge_id')}",
                case_id=case_id,
                evidence_layer="causal_graph",
                source_artifact="derived/reconstruction/causal_graph.json",
                extraction_method="causal_edge_direct_mapping",
                relation_to_hypothesis=str(edge.get("relation_type") or "not_available"),
                support_direction=_SUPPORT_STATUS_TO_DIRECTION.get(support_status, "not_evaluable"),
                support_strength=_CONFIDENCE_TO_STRENGTH.get(confidence, "weak"),
                event_type="causal_edge",
                observed_entity=f"{edge.get('source')} -> {edge.get('target')}",
                observed_value=str(edge.get("meaning") or edge.get("status_reason") or "not_available"),
                timestamp_status="precise" if edge.get("temporal_status") == "supported" else ("not_resolvable" if edge.get("temporal_status") == "unknown" else "unavailable"),
                limitation=limitations[0] if limitations else None,
                raw_reference=list(edge.get("evidence_refs") or []),
            )
        )
    return atoms
