from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
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
    window_start = window_anchor - timedelta(seconds=int(pre_context_seconds))
    window_end = memory_completed_dt + timedelta(seconds=int(post_context_seconds))

    update_acquisition_profile(case_path, run_id=run_id, merge_fields={
        "network_context_window": {
            "pre_context_seconds": int(pre_context_seconds),
            "post_context_seconds": int(post_context_seconds),
            "case_window_start_utc": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "case_window_end_utc": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anchor_time_utc": window_anchor.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anchor_kind": "trigger_time_utc" if trigger_dt else "acquisition_started_utc",
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

    completed_iso = _utc_now_iso()
    update_acquisition_profile(case_path, run_id=run_id, merge_fields={
        "network_context_import_completed_utc": completed_iso,
        "network_context_manifest_path": NETWORK_CONTEXT_MANIFEST_REL,
        "network_context_import_summary": manifest_payload["summary"],
        "source_capture_root": str(source_root),
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
    }
