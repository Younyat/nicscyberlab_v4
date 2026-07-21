from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..foc_reconstruction.foc_case_analysis import _phase_evidence_inventory, _phase_integrity_custody


REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"
FULL_SCENARIO_CAPTURE_ROOT = REPO_ROOT / "app_core" / "infrastructure" / "ics_traffic" / "captures" / "full_scenario_captures"

DEFAULT_PRE_CONTEXT_SECONDS = 120
DEFAULT_POST_CONTEXT_SECONDS = 120
OPEN_SEGMENT_GRACE_SECONDS = 5
ACQUISITION_PROFILE_REL = "metadata/acquisition_profile.json"
NETWORK_CONTEXT_MANIFEST_REL = "network/traffic_preserved/network_context_manifest.json"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _iso_to_epoch(value: str | None) -> float | None:
    parsed = _parse_utc(value)
    return parsed.timestamp() if parsed else None


def _is_safe_case_dir(case_dir: str | Path) -> bool:
    try:
        candidate = Path(case_dir).resolve()
    except Exception:
        return False
    return str(candidate).startswith(str(EVIDENCE_ROOT.resolve()) + os.sep)


def _ensure_case_layout(case_dir: Path) -> None:
    required = [
        "metadata",
        "network",
        "network/traffic_preserved",
        "disk",
        "memory",
        "industrial",
        "analysis",
        "analysis/00_inventory",
        "analysis/01_integrity_custody",
    ]
    for rel in required:
        (case_dir / rel).mkdir(parents=True, exist_ok=True)
    events = case_dir / "metadata" / "pipeline_events.jsonl"
    if not events.exists():
        events.touch()
    manifest = case_dir / "manifest.json"
    if not manifest.exists():
        manifest.write_text(json.dumps({"case_dir": str(case_dir), "created_at": _utc_now_iso(), "artifacts": []}, indent=2), encoding="utf-8")
    custody = case_dir / "chain_of_custody.log"
    if not custody.exists():
        custody.touch()


def _json_load(path: Path):
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _events_path(case_dir: Path) -> Path:
    return case_dir / "metadata" / "pipeline_events.jsonl"


def _manifest_path(case_dir: Path) -> Path:
    return case_dir / "manifest.json"


def _custody_path(case_dir: Path) -> Path:
    return case_dir / "chain_of_custody.log"


def _read_manifest(case_dir: Path) -> dict:
    payload = _json_load(_manifest_path(case_dir))
    if isinstance(payload, dict):
        payload.setdefault("artifacts", [])
        return payload
    return {"case_dir": str(case_dir), "created_at": None, "artifacts": []}


def _write_manifest(case_dir: Path, manifest: dict) -> None:
    _write_json(_manifest_path(case_dir), manifest)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_last_custody_hash(case_dir: Path) -> str:
    path = _custody_path(case_dir)
    if not path.exists():
        return "0" * 64
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return "0" * 64
        payload = json.loads(lines[-1])
        return str(payload.get("entry_hash") or "0" * 64)
    except Exception:
        return "0" * 64


def _append_custody_entry(case_dir: Path, action: str, *, run_id: str, artifact_rel: str | None = None, outcome: str = "ok", details: dict | None = None) -> None:
    prev_hash = _read_last_custody_hash(case_dir)
    entry = {
        "ts_utc": _utc_now_iso(),
        "ts_epoch": time.time(),
        "run_id": run_id or "R1",
        "actor": "network_context_importer",
        "action": action,
        "artifact_rel": artifact_rel,
        "outcome": outcome,
        "details": details or {},
        "prev_hash": prev_hash,
    }
    payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    entry["entry_hash"] = hashlib.sha256(payload).hexdigest()
    with _custody_path(case_dir).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _append_case_event(case_dir: Path, event: str, *, run_id: str, meta: dict | None = None, ts_utc: str | None = None) -> None:
    ts = str(ts_utc or "").strip() or _utc_now_iso()
    payload = {
        "ts_utc": ts,
        "ts_epoch": _iso_to_epoch(ts) or time.time(),
        "event": event,
        "run_id": run_id or "R1",
        "meta": meta or {},
    }
    _append_jsonl(_events_path(case_dir), payload)


def _add_artifact_once(case_dir: Path, rel_path: str, artifact_type: str, *, sha256: str | None = None, size: int | None = None, extra: dict | None = None) -> bool:
    manifest = _read_manifest(case_dir)
    artifacts = manifest.setdefault("artifacts", [])
    normalized_rel = rel_path.replace("\\", "/")
    for item in artifacts:
        if str(item.get("rel_path") or "") == normalized_rel:
            return False
    payload = {
        "type": artifact_type,
        "rel_path": normalized_rel,
        "sha256": sha256,
        "size": size,
        "ts": _utc_now_iso(),
    }
    if extra:
        payload.update(extra)
    artifacts.append(payload)
    _write_manifest(case_dir, manifest)
    return True


def _register_small_case_artifact(case_dir: Path, rel_path: str, artifact_type: str) -> None:
    abs_path = case_dir / rel_path
    if not abs_path.exists():
        return
    size = abs_path.stat().st_size if abs_path.is_file() else None
    sha256 = _sha256_file(abs_path) if abs_path.is_file() else None
    _add_artifact_once(case_dir, rel_path, artifact_type, sha256=sha256, size=size)


def _refresh_case_reports(case_dir: Path) -> None:
    inventory = _phase_evidence_inventory(case_dir)
    integrity = _phase_integrity_custody(case_dir)
    _write_json(case_dir / "analysis" / "00_inventory" / "evidence_inventory.json", inventory)
    _write_json(case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json", integrity)
    _add_artifact_once(
        case_dir,
        "analysis/00_inventory/evidence_inventory.json",
        "evidence_inventory",
        sha256=_sha256_file(case_dir / "analysis" / "00_inventory" / "evidence_inventory.json"),
        size=(case_dir / "analysis" / "00_inventory" / "evidence_inventory.json").stat().st_size,
    )
    _add_artifact_once(
        case_dir,
        "analysis/01_integrity_custody/integrity_custody_report.json",
        "integrity_custody_report",
        sha256=_sha256_file(case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json"),
        size=(case_dir / "analysis" / "01_integrity_custody" / "integrity_custody_report.json").stat().st_size,
    )


def _utc_from_epoch(epoch_value: float | None, *, milliseconds: bool = False) -> str | None:
    if epoch_value is None:
        return None
    try:
        dt = datetime.fromtimestamp(float(epoch_value), tz=timezone.utc)
    except Exception:
        return None
    if milliseconds:
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_int(value, default=None):
    try:
        return int(value)
    except Exception:
        return default


def _iter_modbus_adus(payload: bytes):
    if not payload:
        return
    idx = 0
    total = len(payload)
    while idx + 8 <= total:
        protocol_id = (payload[idx + 2] << 8) | payload[idx + 3]
        if protocol_id != 0:
            idx += 1
            continue
        length = (payload[idx + 4] << 8) | payload[idx + 5]
        adu_len = 6 + length
        if length <= 1 or idx + adu_len > total:
            return
        yield payload[idx : idx + adu_len]
        idx += adu_len


def _decode_modbus_adu(adu: bytes):
    if not adu or len(adu) < 8:
        return None
    tid = (adu[0] << 8) | adu[1]
    pid = (adu[2] << 8) | adu[3]
    length = (adu[4] << 8) | adu[5]
    unit_id = adu[6]
    if pid != 0 or length <= 1:
        return None

    function_code = adu[7]
    data = adu[8:]
    record = {
        "tid": tid,
        "unit_id": unit_id,
        "fc": function_code,
        "mbap_len": length,
        "is_write": function_code in (0x05, 0x06, 0x0F, 0x10),
    }

    def u16(b0, b1):
        return (b0 << 8) | b1

    if function_code == 0x05 and len(data) >= 4:
        address = u16(data[0], data[1])
        value_raw = u16(data[2], data[3])
        record.update(
            {
                "op": "write_single_coil",
                "address": address,
                "value_raw": value_raw,
                "value": True if value_raw == 0xFF00 else False if value_raw == 0x0000 else None,
            }
        )
        return record

    if function_code == 0x06 and len(data) >= 4:
        address = u16(data[0], data[1])
        record.update({"op": "write_single_register", "address": address, "value": u16(data[2], data[3])})
        return record

    if function_code == 0x0F and len(data) >= 5:
        address = u16(data[0], data[1])
        quantity = u16(data[2], data[3])
        bytecount = data[4]
        values = data[5 : 5 + bytecount] if len(data) >= 5 + bytecount else b""
        record.update(
            {
                "op": "write_multiple_coils",
                "address": address,
                "quantity": quantity,
                "bytecount": bytecount,
                "values_hex": values.hex() if values else None,
            }
        )
        return record

    if function_code == 0x10 and len(data) >= 5:
        address = u16(data[0], data[1])
        quantity = u16(data[2], data[3])
        bytecount = data[4]
        values = data[5 : 5 + bytecount] if len(data) >= 5 + bytecount else b""
        registers = None
        if values and len(values) % 2 == 0:
            registers = [u16(values[i], values[i + 1]) for i in range(0, len(values), 2)]
        record.update(
            {
                "op": "write_multiple_registers",
                "address": address,
                "quantity": quantity,
                "bytecount": bytecount,
                "registers": registers,
                "values_hex": values.hex() if values else None,
            }
        )
        return record

    record.update(
        {
            "op": "non_write_function",
            "data_len": len(data),
            "data_hex_prefix": data[:16].hex() if data else None,
        }
    )
    return record


def _export_ot_from_preserved_segments(case_dir: Path, *, run_id: str, preserved_entries: list[dict]) -> dict:
    from scapy.all import IP, TCP, Raw, PcapReader

    source_entries = [item for item in preserved_entries if str(item.get("case_path") or "").strip()]
    if not source_entries:
        return {
            "status": "skipped_no_preserved_segments",
            "records_exported": 0,
            "ot_export_rel": None,
            "source_pcap_count": 0,
            "source_pcap_paths": [],
        }

    started_iso = _utc_now_iso()
    export_filename = f"ot_export_rolling_{run_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%SZ')}.json"
    export_rel = f"industrial/{export_filename}"
    export_path = case_dir / export_rel
    _append_case_event(
        case_dir,
        "ot_export_start",
        run_id=run_id,
        meta={
            "protocol": "modbus_tcp",
            "industrial_export_rel": export_rel,
            "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            "source_pcap_count": len(source_entries),
        },
        ts_utc=started_iso,
    )

    records: list[dict] = []
    file_summaries: list[dict] = []
    op_counts = Counter()
    fc_counts = Counter()
    packets_seen_502 = 0
    payload_packets_seen = 0
    first_epoch = None
    last_epoch = None
    max_records_cap = 200000
    total_packets_read = 0
    progress_heartbeat_every = 100000  # scapy parses pure-Python; this step can take a long
    # time on large captures with zero external feedback otherwise — surface periodic progress.
    packets_at_last_heartbeat = 0
    # Packet-count heartbeats alone assume a roughly steady processing rate;
    # scapy's actual speed varies a lot by packet complexity/hardware, so a
    # slow-but-legitimate run could go over _PRESERVATION_ORPHAN_GRACE_SECONDS
    # (forensics_api.py, 180s) between count-based heartbeats and get
    # mistaken for orphaned by the watchdog added 2026-07-16. Add a wall-clock
    # floor so a heartbeat always fires at least this often regardless of rate.
    heartbeat_time_floor_seconds = 60.0
    last_heartbeat_wall_time = time.time()

    try:
        for file_index, entry in enumerate(source_entries, start=1):
            rel_pcap = str(entry.get("case_path") or "")
            abs_pcap = case_dir / rel_pcap
            per_file_records = 0
            if not abs_pcap.is_file():
                file_summaries.append({"pcap_rel": rel_pcap, "status": "missing", "records_exported": 0})
                continue
            _append_case_event(
                case_dir,
                "ot_export_progress",
                run_id=run_id,
                meta={
                    "stage": "file_start",
                    "file_index": file_index,
                    "file_count": len(source_entries),
                    "pcap_rel": rel_pcap,
                    "pcap_size_bytes": entry.get("size"),
                    "total_packets_read_so_far": total_packets_read,
                    "records_exported_so_far": len(records),
                },
            )
            with PcapReader(str(abs_pcap)) as reader:
                for pkt in reader:
                    total_packets_read += 1
                    # Cheap sampling: only ask the clock every 5k packets, not every packet.
                    time_floor_due = (
                        total_packets_read % 5000 == 0
                        and (time.time() - last_heartbeat_wall_time) >= heartbeat_time_floor_seconds
                    )
                    if total_packets_read - packets_at_last_heartbeat >= progress_heartbeat_every or time_floor_due:
                        packets_at_last_heartbeat = total_packets_read
                        last_heartbeat_wall_time = time.time()
                        _append_case_event(
                            case_dir,
                            "ot_export_progress",
                            run_id=run_id,
                            meta={
                                "stage": "in_progress",
                                "file_index": file_index,
                                "file_count": len(source_entries),
                                "pcap_rel": rel_pcap,
                                "total_packets_read_so_far": total_packets_read,
                                "records_exported_so_far": len(records),
                            },
                        )
                    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                        continue
                    tcp = pkt[TCP]
                    sport = _safe_int(getattr(tcp, "sport", None), 0)
                    dport = _safe_int(getattr(tcp, "dport", None), 0)
                    if 502 not in (sport, dport):
                        continue
                    packets_seen_502 += 1
                    pkt_epoch = None
                    try:
                        pkt_epoch = float(getattr(pkt, "time", None))
                    except Exception:
                        pkt_epoch = None
                    if pkt_epoch is not None:
                        if first_epoch is None:
                            first_epoch = pkt_epoch
                        last_epoch = pkt_epoch
                    if not pkt.haslayer(Raw):
                        continue
                    raw_payload = bytes(pkt[Raw].load or b"")
                    if not raw_payload:
                        continue
                    payload_packets_seen += 1
                    for adu in _iter_modbus_adus(raw_payload):
                        decoded = _decode_modbus_adu(adu)
                        if not decoded:
                            continue
                        decoded.update(
                            {
                                "ts_epoch": pkt_epoch,
                                "ts_utc": _utc_from_epoch(pkt_epoch),
                                "ts_utc_ms": _utc_from_epoch(pkt_epoch, milliseconds=True),
                                "src_ip": pkt[IP].src,
                                "dst_ip": pkt[IP].dst,
                                "src_port": sport,
                                "dst_port": dport,
                                "direction": "to_server" if dport == 502 else "from_server" if sport == 502 else None,
                                "pcap_rel": rel_pcap,
                            }
                        )
                        if len(records) < max_records_cap:
                            records.append(decoded)
                        per_file_records += 1
                        op_counts[str(decoded.get("op") or "unknown")] += 1
                        fc_counts[str(decoded.get("fc") or "unknown")] += 1
            file_summaries.append(
                {
                    "pcap_rel": rel_pcap,
                    "status": "processed",
                    "records_exported": per_file_records,
                    "segment_start_time": entry.get("segment_start_time"),
                    "segment_end_time": entry.get("segment_end_time"),
                    "size": entry.get("size"),
                }
            )
            _append_case_event(
                case_dir,
                "ot_export_progress",
                run_id=run_id,
                meta={
                    "stage": "file_done",
                    "file_index": file_index,
                    "file_count": len(source_entries),
                    "pcap_rel": rel_pcap,
                    "records_exported_this_file": per_file_records,
                    "total_packets_read_so_far": total_packets_read,
                    "records_exported_so_far": len(records),
                },
            )

        payload = {
            "schema": "nics_ot_export_v1",
            "case_dir": str(case_dir),
            "run_id": run_id,
            "protocol": "modbus_tcp",
            "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            "captures": file_summaries,
            "summary": {
                "records_exported": len(records),
                "packets_seen_502": packets_seen_502,
                "payload_packets_seen": payload_packets_seen,
                "first_epoch": first_epoch,
                "last_epoch": last_epoch,
                "max_records_cap": max_records_cap,
                "truncated": len(records) >= max_records_cap,
                "source_pcap_count": len(source_entries),
                "operation_counts": dict(op_counts.most_common()),
                "function_code_counts": dict(fc_counts.most_common()),
            },
            "records": records,
            "generated_at_utc": _utc_now_iso(),
        }
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        size = export_path.stat().st_size
        sha256 = _sha256_file(export_path)
        _add_artifact_once(
            case_dir,
            export_rel,
            "industrial_ot_export_modbus_tcp",
            sha256=sha256,
            size=size,
            extra={
                "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
                "source_pcap_count": len(source_entries),
            },
        )
        _append_custody_entry(
            case_dir,
            "acquire_preserved",
            run_id=run_id,
            artifact_rel=export_rel,
            outcome="ok",
            details={
                "kind": "industrial_ot_export_modbus_tcp",
                "sha256": sha256,
                "size": size,
                "records_exported": len(records),
                "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            },
        )
        completed_iso = _utc_now_iso()
        update_acquisition_profile(
            case_dir,
            run_id=run_id,
            merge_fields={
                "ot_export_started_utc": started_iso,
                "ot_export_completed_utc": completed_iso,
                "ot_export_rel": export_rel,
                "ot_export_records_exported": len(records),
            },
        )
        _append_case_event(
            case_dir,
            "ot_export_preserved",
            run_id=run_id,
            meta={
                "protocol": "modbus_tcp",
                "industrial_export_rel": export_rel,
                "industrial_export_sha256": sha256,
                "industrial_export_size": size,
                "records_exported": len(records),
                "source_pcap_count": len(source_entries),
                "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            },
            ts_utc=completed_iso,
        )
        return {
            "status": "completed",
            "records_exported": len(records),
            "ot_export_rel": export_rel,
            "source_pcap_count": len(source_entries),
            "source_pcap_paths": [str(item.get("case_path") or "") for item in source_entries],
        }
    except Exception as exc:
        _append_custody_entry(
            case_dir,
            "acquire_failed",
            run_id=run_id,
            artifact_rel=export_rel,
            outcome="error",
            details={
                "kind": "industrial_ot_export_modbus_tcp",
                "reason": str(exc),
                "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            },
        )
        _append_case_event(
            case_dir,
            "ot_export_failed",
            run_id=run_id,
            meta={
                "protocol": "modbus_tcp",
                "industrial_export_rel": export_rel,
                "reason": str(exc),
                "source_pcap_count": len(source_entries),
                "source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import",
            },
        )
        return {
            "status": "failed",
            "records_exported": 0,
            "ot_export_rel": export_rel,
            "source_pcap_count": len(source_entries),
            "source_pcap_paths": [str(item.get("case_path") or "") for item in source_entries],
            "error": str(exc),
        }


def _load_acquisition_profile(case_dir: Path) -> dict:
    payload = _json_load(case_dir / ACQUISITION_PROFILE_REL)
    return payload if isinstance(payload, dict) else {}


def update_acquisition_profile(case_dir: str | Path, *, run_id: str = "R1", merge_fields: dict | None = None) -> dict:
    case_path = Path(case_dir).resolve()
    if not _is_safe_case_dir(case_path):
        raise ValueError("unsafe_case_dir")
    _ensure_case_layout(case_path)
    profile = _load_acquisition_profile(case_path)
    merge_fields = dict(merge_fields or {})
    profile.update({k: v for k, v in merge_fields.items() if v is not None})
    profile.setdefault("strategy", "volatile_first_with_continuous_network_context")
    profile.setdefault("selection_policy", "select pcap if pcap_start <= case_window_end and pcap_end >= case_window_start")
    profile.setdefault("open_segment_policy", "pending_until_rotation_closes")
    profile.setdefault("memory_priority_policy", "memory_before_network_context_import")
    profile.setdefault("source_capture_root", str(FULL_SCENARIO_CAPTURE_ROOT))
    _write_json(case_path / ACQUISITION_PROFILE_REL, profile)
    _register_small_case_artifact(case_path, ACQUISITION_PROFILE_REL, "acquisition_profile")
    _append_case_event(case_path, "acquisition_profile_updated", run_id=run_id, meta={"strategy": profile.get("strategy")})
    return profile


def initialize_volatile_first_acquisition(case_dir: str | Path, *, run_id: str = "R1", case_created_utc: str | None = None, acquisition_started_utc: str | None = None, trigger_time_utc: str | None = None, pre_context_seconds: int = DEFAULT_PRE_CONTEXT_SECONDS, post_context_seconds: int = DEFAULT_POST_CONTEXT_SECONDS, source_capture_root: str | None = None) -> dict:
    now_iso = _utc_now_iso()
    merge = {
        "strategy": "volatile_first_with_continuous_network_context",
        "case_created_utc": case_created_utc or now_iso,
        "acquisition_started_utc": acquisition_started_utc or now_iso,
        "trigger_time_utc": trigger_time_utc,
        "network_context_window": {
            "pre_context_seconds": int(pre_context_seconds),
            "post_context_seconds": int(post_context_seconds),
        },
        "source_capture_root": source_capture_root or str(FULL_SCENARIO_CAPTURE_ROOT),
        "selection_policy": "select pcap if pcap_start <= case_window_end and pcap_end >= case_window_start",
        "open_segment_policy": "pending_until_rotation_closes",
        "memory_priority_policy": "memory_before_network_context_import",
    }
    return update_acquisition_profile(case_dir, run_id=run_id, merge_fields=merge)


def _segment_meta(path: Path) -> dict | None:
    name = path.name
    if not (name.endswith(".pcap") or name.endswith(".pcapng")):
        return None
    parts = name.split("_")
    if len(parts) < 4:
        return None
    try:
        iface = "_".join(parts[:-3])
        date_part = parts[-3]
        time_part = parts[-2]
        duration_part = parts[-1]
        duration_s = int(duration_part.split("s", 1)[0].split(".", 1)[0])
        start = datetime.strptime(f"{date_part}_{time_part}", "%Y%m%d_%H%M%SZ").replace(tzinfo=timezone.utc)
        end = start + timedelta(seconds=duration_s)
        return {
            "path": path,
            "interface": iface,
            "segment_start_time": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "segment_end_time": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "segment_start_epoch": start.timestamp(),
            "segment_end_epoch": end.timestamp(),
            "duration_seconds": duration_s,
            "date_bucket": date_part,
        }
    except Exception:
        return None


def _iter_date_dirs(root: Path, start_dt: datetime, end_dt: datetime):
    cursor = start_dt.date()
    end_date = end_dt.date()
    while cursor <= end_date:
        candidate = root / cursor.strftime("%Y%m%d")
        if candidate.is_dir():
            yield candidate
        cursor += timedelta(days=1)


def _select_overlapping_segments(source_root: Path, start_dt: datetime, end_dt: datetime) -> list[dict]:
    selected: list[dict] = []
    for date_dir in _iter_date_dirs(source_root, start_dt, end_dt):
        for candidate in date_dir.rglob("*.pcap*"):
            if not candidate.is_file():
                continue
            meta = _segment_meta(candidate)
            if not meta:
                continue
            if meta["segment_start_epoch"] <= end_dt.timestamp() and meta["segment_end_epoch"] >= start_dt.timestamp():
                selected.append(meta)
    selected.sort(key=lambda item: (item["segment_start_epoch"], item["interface"], str(item["path"])))
    return selected


def _is_open_segment(segment: dict, *, now: datetime, grace_seconds: int = OPEN_SEGMENT_GRACE_SECONDS) -> bool:
    end_dt = _parse_utc(segment.get("segment_end_time"))
    if not end_dt:
        return True
    return now < (end_dt + timedelta(seconds=grace_seconds))


def _preserve_file(src: Path, dst: Path) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        return "existing"
    try:
        subprocess.run(["cp", "--reflink=always", "--preserve=timestamps,mode", str(src), str(dst)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "reflink"
    except Exception:
        pass
    try:
        if src.stat().st_dev == dst.parent.stat().st_dev:
            os.link(src, dst)
            return "hardlink"
    except Exception:
        pass
    try:
        shutil.copy2(src, dst)
        return "copy"
    except Exception:
        subprocess.run(["rsync", "-a", str(src), str(dst)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "copy"


def import_continuous_network_context(
    case_dir: str | Path,
    *,
    run_id: str = "R1",
    trigger_time_utc: str | None = None,
    case_created_utc: str | None = None,
    acquisition_started_utc: str | None = None,
    memory_started_utc: str | None = None,
    memory_completed_utc: str | None = None,
    network_context_import_started_utc: str | None = None,
    post_context_seconds: int = DEFAULT_POST_CONTEXT_SECONDS,
    pre_context_seconds: int = DEFAULT_PRE_CONTEXT_SECONDS,
    source_capture_root: str | Path | None = None,
) -> dict:
    case_path = Path(case_dir).resolve()
    if not _is_safe_case_dir(case_path):
        raise ValueError("unsafe_case_dir")
    _ensure_case_layout(case_path)

    source_root = Path(source_capture_root or FULL_SCENARIO_CAPTURE_ROOT).resolve()
    if not source_root.is_dir():
        raise FileNotFoundError(f"capture_root_not_found:{source_root}")

    now_iso = _utc_now_iso()
    profile = initialize_volatile_first_acquisition(
        case_path,
        run_id=run_id,
        case_created_utc=case_created_utc,
        acquisition_started_utc=acquisition_started_utc,
        trigger_time_utc=trigger_time_utc,
        pre_context_seconds=pre_context_seconds,
        post_context_seconds=post_context_seconds,
        source_capture_root=str(source_root),
    )
    started_iso = network_context_import_started_utc or now_iso
    profile = update_acquisition_profile(case_path, run_id=run_id, merge_fields={
        "memory_started_utc": memory_started_utc or profile.get("memory_started_utc"),
        "memory_completed_utc": memory_completed_utc or profile.get("memory_completed_utc"),
        "network_context_import_started_utc": started_iso,
    })

    trigger_dt = _parse_utc(trigger_time_utc or profile.get("trigger_time_utc"))
    acquisition_dt = _parse_utc(acquisition_started_utc or profile.get("acquisition_started_utc") or profile.get("case_created_utc")) or _utc_now()
    memory_completed_dt = _parse_utc(memory_completed_utc or profile.get("memory_completed_utc")) or _utc_now()
    window_anchor = trigger_dt or acquisition_dt
    # 2026-07-19: window is now a FIXED trigger +/- pre/post_context_seconds,
    # not trigger -> memory_acquisition_completion + post_context_seconds.
    # The latter (kept below, commented, in case this needs reverting) made
    # the real window scale with how long memory acquisition took (3 nodes,
    # observed 8-15+ min combined), pulling in far more pcap segments than
    # the nominal "120s either side" suggested -- confirmed live: a trigger
    # at 22:36:43 with memory finishing at 22:47:37 produced a ~15min window
    # (18 segments) instead of the intended ~4min one, dominating both
    # acquisition and analysis time for no evidentiary requirement anyone
    # had actually asked for. User explicitly chose speed over the wider
    # window's "catches network activity during a long memory acquisition
    # too" coverage -- this is a real trade-off, not a bug fix, flagged here
    # so it's not silently reverted later without knowing why it changed.
    window_start_anchor = window_anchor
    window_end_anchor = window_anchor
    window_normalization = "standard"
    # window_end_anchor = memory_completed_dt  # pre-2026-07-19 behavior
    window_start = window_start_anchor - timedelta(seconds=int(pre_context_seconds))
    window_end = window_end_anchor + timedelta(seconds=int(post_context_seconds))

    update_acquisition_profile(case_path, run_id=run_id, merge_fields={
        "network_context_window": {
            "pre_context_seconds": int(pre_context_seconds),
            "post_context_seconds": int(post_context_seconds),
            "case_window_start_utc": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "case_window_end_utc": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anchor_time_utc": window_anchor.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anchor_kind": "trigger_time_utc" if trigger_dt else "acquisition_started_utc",
            "window_normalization": window_normalization,
        },
    })

    _append_case_event(case_path, "network_context_import_started", run_id=run_id, meta={
        "source_capture_root": str(source_root),
        "case_window_start_utc": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_window_end_utc": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "selection_policy": "pcap_start <= case_window_end and pcap_end >= case_window_start",
    }, ts_utc=started_iso)

    selected = _select_overlapping_segments(source_root, window_start, window_end)
    manifest_path = case_path / NETWORK_CONTEXT_MANIFEST_REL
    preserved_entries: list[dict] = []
    pending_entries: list[dict] = []
    now_dt = _utc_now()

    for segment in selected:
        rel_src = os.path.relpath(segment["path"], source_root).replace("\\", "/")
        rel_dst = f"network/traffic_preserved/full_scenario_captures/{rel_src}"
        entry = {
            "source_capture_root": str(source_root),
            "original_path": str(segment["path"]),
            "case_path": rel_dst,
            "interface": segment["interface"],
            "segment_start_time": segment["segment_start_time"],
            "segment_end_time": segment["segment_end_time"],
            "selection_policy": "pcap_start <= case_window_end and pcap_end >= case_window_start",
            "import_time_utc": _utc_now_iso(),
        }
        if _is_open_segment(segment, now=now_dt):
            entry.update({
                "status": "pending_open_segment",
                "preservation_mode": None,
                "size": None,
                "sha256": None,
                "integrity_status": "pending_until_rotation_closes",
            })
            pending_entries.append(entry)
            continue

        dst_path = case_path / rel_dst
        mode = _preserve_file(segment["path"], dst_path)
        sha256 = _sha256_file(dst_path)
        size = dst_path.stat().st_size
        entry.update({
            "status": "preserved",
            "preservation_mode": mode,
            "size": size,
            "sha256": sha256,
            "integrity_status": "hashed",
        })
        preserved_entries.append(entry)
        added = _add_artifact_once(case_path, rel_dst, "network_pcap", sha256=sha256, size=size, extra={
            "source_capture_root": str(source_root),
            "original_path": str(segment["path"]),
            "preservation_mode": mode,
            "interface": segment["interface"],
            "segment_start_time": segment["segment_start_time"],
            "segment_end_time": segment["segment_end_time"],
        })
        _append_custody_entry(
            case_path,
            "network_context_segment_preserved",
            run_id=run_id,
            artifact_rel=rel_dst,
            outcome="ok",
            details={
                "original_path": str(segment["path"]),
                "preservation_mode": mode,
                "sha256": sha256,
                "added_to_manifest": added,
            },
        )

    manifest_payload = {
        "source_capture_root": str(source_root),
        "case_id": case_path.name,
        "generated_at_utc": _utc_now_iso(),
        "selection_policy": "pcap_start <= case_window_end and pcap_end >= case_window_start",
        "open_segment_policy": "pending_until_rotation_closes",
        "network_context_window": {
            "case_window_start_utc": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "case_window_end_utc": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "trigger_time_utc": trigger_time_utc or profile.get("trigger_time_utc"),
            "memory_completed_utc": memory_completed_utc or profile.get("memory_completed_utc"),
            "pre_context_seconds": int(pre_context_seconds),
            "post_context_seconds": int(post_context_seconds),
            "window_normalization": window_normalization,
        },
        "preserved_segments": preserved_entries,
        "pending_segments": pending_entries,
        "summary": {
            "selected_segments": len(selected),
            "preserved_segments": len(preserved_entries),
            "pending_segments": len(pending_entries),
            "preserved_total_bytes": sum(int(item.get("size") or 0) for item in preserved_entries),
        },
    }
    _write_json(manifest_path, manifest_payload)
    _register_small_case_artifact(case_path, NETWORK_CONTEXT_MANIFEST_REL, "network_context_manifest")
    _append_custody_entry(case_path, "network_context_manifest_written", run_id=run_id, artifact_rel=NETWORK_CONTEXT_MANIFEST_REL, outcome="ok", details={"preserved_segments": len(preserved_entries), "pending_segments": len(pending_entries)})

    ot_export_result = _export_ot_from_preserved_segments(case_path, run_id=run_id, preserved_entries=preserved_entries)

    completed_iso = _utc_now_iso()
    update_acquisition_profile(case_path, run_id=run_id, merge_fields={
        "network_context_import_completed_utc": completed_iso,
        "network_context_manifest_path": NETWORK_CONTEXT_MANIFEST_REL,
        "network_context_import_summary": manifest_payload["summary"],
        "source_capture_root": str(source_root),
        "ot_export_status": ot_export_result.get("status"),
    })
    _refresh_case_reports(case_path)
    _append_case_event(case_path, "network_context_import_completed", run_id=run_id, meta=manifest_payload["summary"], ts_utc=completed_iso)

    return {
        "result": "ok",
        "case_dir": str(case_path),
        "case_id": case_path.name,
        "source_capture_root": str(source_root),
        "network_context_manifest_rel": NETWORK_CONTEXT_MANIFEST_REL,
        "selected_segments": len(selected),
        "preserved_segments": len(preserved_entries),
        "pending_segments": len(pending_entries),
        "preserved_total_bytes": manifest_payload["summary"]["preserved_total_bytes"],
        "strategy": "volatile_first_with_continuous_network_context",
        "case_window_start_utc": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_window_end_utc": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ot_export": ot_export_result,
    }
