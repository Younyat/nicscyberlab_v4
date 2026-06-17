import json
import logging
import os
import shutil
import subprocess
import threading
import uuid
import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .foc_config import HASH_REASONABLE_BINARY_MAX_BYTES
from .foc_hashing import hash_file
from .foc_manifest_manager import read_generated_json, regenerate_foc
from .foc_paths import project_path, relative_path
from .foc_sources import utc_now

logger = logging.getLogger(__name__)

CASE_ROOT = project_path("app_core", "infrastructure", "forensics", "evidence_store")
FORENSICS_SCRIPTS_DIR = project_path("app_core", "infrastructure", "forensics", "scripts")
PROJECT_SCRIPT_DIR = project_path()
VOL3_SYMBOLS_DIR = Path("/home/younes/vol3_symbols_cache/symbols/linux")

ANALYSIS_PHASES = [
    ("preflight_validation", "Pre-flight validation", None),
    ("evidence_inventory", "Evidence inventory", "00_inventory/evidence_inventory.json"),
    ("integrity_custody_validation", "Integrity and custody validation", "01_integrity_custody/integrity_custody_report.json"),
    ("temporal_validation", "Temporal validation", "02_time_validation/clock_offset_report.json"),
    ("network_analysis", "Network analysis", "03_network/network_findings.json"),
    ("memory_analysis", "Memory analysis", "04_memory/memory_findings.json"),
    ("disk_analysis", "Disk analysis", "05_disk/disk_findings.json"),
    ("ot_export_analysis", "OT export analysis", "06_ot/ot_findings.json"),
    ("alerts_detection_analysis", "Alerts and detection analysis", "07_alerts/alert_findings.json"),
    ("pipeline_custody_analysis", "Pipeline and custody analysis", "08_pipeline_custody/pipeline_findings.json"),
    ("unified_forensic_timeline", "Unified forensic timeline", "09_timeline/unified_forensic_timeline.json"),
    ("cross_layer_findings", "Cross-layer findings", "10_findings/cross_layer_findings.json"),
    ("forensic_analysis_report_generation", "Forensic Analysis Report generation", "forensic_analysis_report.json"),
    ("foc_readiness_update", "FOC readiness update", "foc_readiness_update.json"),
]

_ANALYSIS_STATE_LOCK = threading.Lock()
_RUNNING_ANALYSES: dict[str, threading.Thread] = {}


def _json_load(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _jsonl_load(path: Path) -> list[dict]:
    out: list[dict] = []
    if not path.is_file():
        return out
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                out.append(payload)
    return out


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)
    tmp.replace(path)


def _safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "item"))


def _parse_ts(value) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    if normalized.endswith("+0000") or normalized.endswith("-0000"):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _which(*candidates: str) -> str | None:
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _phase_labels() -> dict[str, str]:
    return {key: label for key, label, _ in ANALYSIS_PHASES}


def _phase_output_rel(phase_key: str) -> str | None:
    for key, _, rel in ANALYSIS_PHASES:
        if key == phase_key:
            return rel
    return None


def _case_dir_from_entry(case_entry: dict) -> Path:
    case_path = str(case_entry.get("path") or "").strip()
    if case_path:
        return project_path(*case_path.split("/"))
    return CASE_ROOT / str(case_entry.get("source_case_name") or "")


def _analysis_dir(case_dir: Path) -> Path:
    return case_dir / "analysis"


def _analysis_status_path(case_dir: Path) -> Path:
    return _analysis_dir(case_dir) / "analysis_status.json"


def _analysis_logs_dir(case_dir: Path) -> Path:
    return _analysis_dir(case_dir) / "logs"


def _phase_log_paths(case_dir: Path, phase_key: str) -> tuple[Path, Path]:
    base = _analysis_logs_dir(case_dir) / phase_key
    return base.with_suffix(".stdout.log"), base.with_suffix(".stderr.log")


def _phase_output_path(case_dir: Path, phase_key: str) -> Path | None:
    rel = _phase_output_rel(phase_key)
    if not rel:
        if phase_key == "preflight_validation":
            return _analysis_dir(case_dir) / "preflight_validation.json"
        return None
    return _analysis_dir(case_dir) / rel


def _list_case_entries() -> list[dict]:
    cases_index = read_generated_json(project_path("foc-reconstruction", "indexes", "cases_index.json")) or {}
    cases = cases_index.get("cases") if isinstance(cases_index, dict) else None
    if isinstance(cases, list) and cases:
        return cases
    out = []
    for case_dir in sorted(CASE_ROOT.glob("CASE-*")):
        out.append(
            {
                "case_id": f"case-{hashlib.sha1(case_dir.name.encode('utf-8')).hexdigest()[:8]}",
                "source_case_name": case_dir.name,
                "path": relative_path(case_dir),
                "artifacts_count": 0,
                "manifest_path": f"{relative_path(case_dir)}/manifest.json",
                "pipeline_path": f"{relative_path(case_dir)}/metadata/pipeline_events.jsonl",
                "custody_path": f"{relative_path(case_dir)}/chain_of_custody.log",
                "target_node_ids": [],
                "target_instance_ids": [],
            }
        )
    return out


def get_case_entry(case_id: str) -> dict | None:
    for entry in _list_case_entries():
        if str(entry.get("case_id")) == str(case_id):
            return entry
    return None


def _artifact_inventory(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "manifest.json") or {}
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    artifacts = artifacts if isinstance(artifacts, list) else []
    counts = Counter(str(item.get("type") or "unknown") for item in artifacts if isinstance(item, dict))
    return {
        "manifest_present": (case_dir / "manifest.json").is_file(),
        "custody_present": (case_dir / "chain_of_custody.log").is_file(),
        "pipeline_present": (case_dir / "metadata" / "pipeline_events.jsonl").is_file(),
        "analysis_dir_present": _analysis_dir(case_dir).exists(),
        "analysis_dir_writable": os.access(_analysis_dir(case_dir), os.W_OK) if _analysis_dir(case_dir).exists() else os.access(case_dir, os.W_OK),
        "artifacts_total": len(artifacts),
        "artifact_type_counts": dict(sorted(counts.items())),
        "layers": {
            "network": bool(counts.get("pcap")),
            "memory": bool(counts.get("memory_lime")),
            "disk": bool(counts.get("disk_raw")),
            "ot_exports": bool(counts.get("industrial_ot_export_modbus_tcp")),
            "alerts": any((case_dir / "alerts").glob("*.json")),
            "chain_of_custody": (case_dir / "chain_of_custody.log").is_file(),
            "time_sync": bool(counts.get("time_sync")) or (case_dir / "metadata" / "time_sync.json").is_file(),
        },
    }


def _default_analysis_status(case_entry: dict) -> dict:
    case_dir = _case_dir_from_entry(case_entry)
    inventory = _artifact_inventory(case_dir)
    analysis_dir = _analysis_dir(case_dir)
    report_path = analysis_dir / "forensic_analysis_report.json"
    manifest_path = analysis_dir / "forensic_analysis_manifest.json"
    status = "not_started"
    if report_path.is_file():
        status = "completed"
    elif analysis_dir.exists() and any(analysis_dir.iterdir()):
        status = "partial"
    return {
        "case_id": case_entry.get("case_id"),
        "analysis_id": None,
        "started_at": None,
        "updated_at": utc_now(),
        "finished_at": None,
        "status": status,
        "current_phase": None,
        "phases": {},
        "completed_phases": [],
        "failed_phases": [],
        "skipped_phases": [],
        "progress_percent": 0,
        "errors": [],
        "warnings": [],
        "output_files": [],
        "case_path": relative_path(case_dir),
        "analysis_dir": relative_path(analysis_dir),
        "forensic_analysis_report_path": relative_path(report_path) if report_path.exists() else None,
        "forensic_analysis_manifest_path": relative_path(manifest_path) if manifest_path.exists() else None,
        "evidence_available": inventory["artifacts_total"] > 0,
        "available_layers": inventory["layers"],
        "inventory_summary": inventory["artifact_type_counts"],
    }


def load_analysis_status(case_id: str) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(case_entry)
    status_path = _analysis_status_path(case_dir)
    payload = _json_load(status_path)
    if not isinstance(payload, dict):
        return _default_analysis_status(case_entry)
    payload.setdefault("case_id", case_id)
    payload.setdefault("case_path", relative_path(case_dir))
    payload.setdefault("analysis_dir", relative_path(_analysis_dir(case_dir)))
    report_path = _analysis_dir(case_dir) / "forensic_analysis_report.json"
    manifest_path = _analysis_dir(case_dir) / "forensic_analysis_manifest.json"
    payload["forensic_analysis_report_path"] = relative_path(report_path) if report_path.exists() else None
    payload["forensic_analysis_manifest_path"] = relative_path(manifest_path) if manifest_path.exists() else None
    inventory = _artifact_inventory(case_dir)
    payload["available_layers"] = inventory["layers"]
    payload["inventory_summary"] = inventory["artifact_type_counts"]
    payload["evidence_available"] = inventory["artifacts_total"] > 0
    return payload


def _write_status(case_dir: Path, status: dict) -> None:
    status["updated_at"] = utc_now()
    status["completed_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")) == "completed"]
    status["failed_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")).startswith("failed")]
    status["skipped_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")).startswith("skipped")]
    _write_json(_analysis_status_path(case_dir), status)


def _init_status(case_entry: dict, force: bool = False) -> dict:
    case_dir = _case_dir_from_entry(case_entry)
    analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
    phases = {}
    for key, label, rel in ANALYSIS_PHASES:
        phases[key] = {
            "phase": key,
            "label": label,
            "status": "pending",
            "output_path": relative_path(_phase_output_path(case_dir, key)) if _phase_output_path(case_dir, key) else None,
            "stdout_path": relative_path(_phase_log_paths(case_dir, key)[0]),
            "stderr_path": relative_path(_phase_log_paths(case_dir, key)[1]),
        }
    status = {
        "case_id": case_entry.get("case_id"),
        "analysis_id": analysis_id,
        "started_at": utc_now(),
        "updated_at": utc_now(),
        "finished_at": None,
        "status": "running",
        "current_phase": "preflight_validation",
        "phases": phases,
        "completed_phases": [],
        "failed_phases": [],
        "skipped_phases": [],
        "progress_percent": 0,
        "errors": [],
        "warnings": [],
        "output_files": [],
        "case_path": relative_path(case_dir),
        "analysis_dir": relative_path(_analysis_dir(case_dir)),
        "force_rerun": bool(force),
    }
    _analysis_dir(case_dir).mkdir(parents=True, exist_ok=True)
    _analysis_logs_dir(case_dir).mkdir(parents=True, exist_ok=True)
    _write_status(case_dir, status)
    return status


def _set_phase_status(case_dir: Path, status: dict, phase_key: str, phase_status: str, extra: dict | None = None) -> None:
    phase = (status.get("phases") or {}).get(phase_key) or {}
    phase["status"] = phase_status
    if extra:
        phase.update(extra)
    status["phases"][phase_key] = phase
    phase_states = [str(item.get("status") or "") for item in (status.get("phases") or {}).values()]
    completed = len([item for item in phase_states if item == "completed"])
    skipped = len([item for item in phase_states if item.startswith("skipped")])
    failed = len([item for item in phase_states if item.startswith("failed")])
    total = max(1, len(ANALYSIS_PHASES))
    status["progress_percent"] = round(((completed + skipped + failed) / total) * 100, 2)
    _write_status(case_dir, status)


def _record_phase_transition(case_dir: Path, status: dict, phase_key: str, phase_status: str, extra: dict | None = None) -> None:
    status["current_phase"] = phase_key if phase_status == "running" else status.get("current_phase")
    _set_phase_status(case_dir, status, phase_key, phase_status, extra=extra)


def _run_command(command: list[str], cwd: Path, stdout_path: Path, stderr_path: Path) -> tuple[int, str | None]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
        proc = subprocess.run(command, cwd=str(cwd), stdout=out, stderr=err, text=True)
    return proc.returncode, None


def _validate_phase_payload(payload: dict) -> tuple[bool, str | None]:
    if not isinstance(payload, dict):
        return False, "phase output is not a JSON object"
    if "status" not in payload:
        return False, "missing status field"
    if "input_artifacts" not in payload:
        return False, "missing input_artifacts field"
    if "findings" not in payload and "limitations" not in payload and "errors" not in payload:
        return False, "missing findings/limitations/errors field"
    if payload.get("status", "").startswith("skipped"):
        if "not_executed_reason" not in payload:
            return False, "missing not_executed_reason field"
    else:
        if "tool_used" not in payload:
            return False, "missing tool_used field"
    return True, None


def _finalize_phase_output(case_dir: Path, status: dict, phase_key: str, payload: dict) -> dict:
    output_path = _phase_output_path(case_dir, phase_key)
    if output_path:
        _write_json(output_path, payload)
    valid, reason = _validate_phase_payload(payload)
    if not valid:
        raise RuntimeError(f"{phase_key} validation failed: {reason}")
    if output_path:
        status["output_files"].append(relative_path(output_path))
    return payload


def _case_paths(case_dir: Path) -> dict:
    return {
        "manifest": case_dir / "manifest.json",
        "custody": case_dir / "chain_of_custody.log",
        "pipeline": case_dir / "metadata" / "pipeline_events.jsonl",
        "time_sync": case_dir / "metadata" / "time_sync.json",
        "alerts": sorted((case_dir / "alerts").glob("*.json")),
        "pcaps": sorted((case_dir / "network").rglob("*.pcap")),
        "memory": sorted((case_dir / "memory").glob("*.lime")),
        "disks": sorted((case_dir / "disk").glob("*.raw")),
        "ot_exports": sorted((case_dir / "industrial").glob("ot_export_*.json")),
    }


def _build_preflight(case_entry: dict, case_dir: Path) -> dict:
    paths = _case_paths(case_dir)
    analysis_dir = _analysis_dir(case_dir)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    tools = {
        "tshark": _which("tshark"),
        "volatility3": _which("volatility3", "vol"),
        "mmls": _which("mmls"),
        "fsstat": _which("fsstat"),
        "fls": _which("fls"),
        "mactime": _which("mactime"),
        "strings": _which("strings"),
        "python3": _which("python3"),
    }
    scripts = {
        "analyze_network_pcap.sh": FORENSICS_SCRIPTS_DIR / "analyze_network_pcap.sh",
        "analyze_memory_vol3.sh": FORENSICS_SCRIPTS_DIR / "analyze_memory_vol3.sh",
        "analyze_disk_tsk.sh": FORENSICS_SCRIPTS_DIR / "analyze_disk_tsk.sh",
        "build_case_timeline.py": FORENSICS_SCRIPTS_DIR / "build_case_timeline.py",
        "e2_max_clock_offset.sh": PROJECT_SCRIPT_DIR / "e2_max_clock_offset.sh",
    }
    script_checks = {name: {"path": relative_path(path), "available": path.is_file()} for name, path in scripts.items()}
    required_ok = all(
        [
            case_dir.is_dir(),
            paths["manifest"].is_file(),
            paths["custody"].is_file(),
            os.access(case_dir, os.R_OK),
            os.access(analysis_dir, os.W_OK),
        ]
    )
    warnings = []
    if not paths["pipeline"].is_file():
        warnings.append("pipeline_events.jsonl not found; some temporal and custody context will be partial")
    if not paths["time_sync"].is_file():
        warnings.append("time_sync.json not found; temporal validation may be skipped")
    for tool_name in ("tshark", "volatility3", "mmls", "fsstat", "fls", "mactime"):
        if not tools.get(tool_name):
            warnings.append(f"{tool_name} not available; one or more layers may be skipped or fail")
    status = "completed" if required_ok else "failed"
    return {
        "phase": "preflight_validation",
        "status": status,
        "input_artifacts": [
            relative_path(paths["manifest"]) if paths["manifest"].exists() else "missing",
            relative_path(paths["custody"]) if paths["custody"].exists() else "missing",
            relative_path(paths["pipeline"]) if paths["pipeline"].exists() else "missing",
        ],
        "tool_used": "python3",
        "findings": {
            "case_exists": case_dir.is_dir(),
            "manifest_exists": paths["manifest"].is_file(),
            "chain_of_custody_exists": paths["custody"].is_file(),
            "evidence_store_exists": case_dir.is_dir(),
            "analysis_directory": relative_path(analysis_dir),
            "analysis_directory_writable": os.access(analysis_dir, os.W_OK),
            "case_readable": os.access(case_dir, os.R_OK),
            "tools": tools,
            "scripts": script_checks,
            "symbols_dir": str(VOL3_SYMBOLS_DIR),
            "symbols_dir_exists": VOL3_SYMBOLS_DIR.is_dir(),
        },
        "limitations": warnings,
        "errors": [] if required_ok else ["Case directory, manifest, chain of custody, or analysis directory permissions are invalid."],
        "mandatory_requirements_ok": required_ok,
    }


def _phase_evidence_inventory(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "manifest.json") or {}
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    artifacts = artifacts if isinstance(artifacts, list) else []
    counts = Counter(str(item.get("type") or "unknown") for item in artifacts if isinstance(item, dict))
    return {
        "phase": "evidence_inventory",
        "status": "completed",
        "input_artifacts": [relative_path(case_dir / "manifest.json")],
        "tool_used": "python3",
        "findings": {
            "case_dir": relative_path(case_dir),
            "artifacts_total": len(artifacts),
            "artifact_type_counts": dict(sorted(counts.items())),
            "layers_available": _artifact_inventory(case_dir)["layers"],
        },
        "limitations": [],
        "errors": [],
    }


def _phase_integrity_custody(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "manifest.json") or {}
    custody = _jsonl_load(case_dir / "chain_of_custody.log")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    artifacts = artifacts if isinstance(artifacts, list) else []
    missing = []
    validated = []
    skipped_hash = []
    for item in artifacts:
        rel = str(item.get("rel_path") or "")
        artifact_path = case_dir / rel
        if not artifact_path.exists():
            missing.append(rel)
            continue
        expected_hash = str(item.get("sha256") or "").strip()
        if artifact_path.is_file() and artifact_path.stat().st_size <= HASH_REASONABLE_BINARY_MAX_BYTES and expected_hash:
            actual = hash_file(artifact_path)
            validated.append({"rel_path": rel, "sha256_match": actual == expected_hash, "sha256": actual})
        else:
            skipped_hash.append(rel)
    chain_ok = True
    prev = "0" * 64
    for entry in custody:
        if str(entry.get("prev_hash") or "") != prev:
            chain_ok = False
            break
        prev = str(entry.get("entry_hash") or prev)
    status = "completed" if not missing and chain_ok else "partial"
    return {
        "phase": "integrity_custody_validation",
        "status": status,
        "input_artifacts": [
            relative_path(case_dir / "manifest.json"),
            relative_path(case_dir / "chain_of_custody.log"),
        ],
        "tool_used": "python3",
        "findings": {
            "manifest_artifacts_total": len(artifacts),
            "missing_artifacts": missing,
            "hash_validated_artifacts": len(validated),
            "hash_skipped_large_or_nohash": skipped_hash,
            "custody_events": len(custody),
            "custody_chain_valid": chain_ok,
        },
        "limitations": [
            "Large binary artifacts are not rehashed during this phase to avoid unnecessary latency; manifest-preserved hashes are trusted unless the file is small enough for direct validation."
        ],
        "errors": [] if not missing and chain_ok else ["Integrity or custody validation reported missing artifacts or a broken custody chain."],
    }


def _phase_temporal_validation(case_dir: Path) -> dict:
    time_sync_path = case_dir / "metadata" / "time_sync.json"
    if not time_sync_path.is_file():
        return {
            "phase": "temporal_validation",
            "status": "skipped_no_time_sync_artifact",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved time_sync.json was found for this case."],
            "errors": [],
            "not_executed_reason": "No preserved time_sync artifact found for this case.",
        }
    payload = _json_load(time_sync_path) or {}
    max_offset = payload.get("max_offset_ms")
    generated_at = payload.get("generated_at_utc")
    return {
        "phase": "temporal_validation",
        "status": "completed",
        "input_artifacts": [relative_path(time_sync_path)],
        "tool_used": "python3",
        "findings": {
            "generated_at_utc": generated_at,
            "max_offset_ms": max_offset,
            "time_sync_schema": payload.get("schema"),
            "synchronized": "System clock synchronized: yes" in str((payload.get("raw") or {}).get("timedatectl") or ""),
        },
        "limitations": [] if max_offset is not None else ["time_sync artifact exists but max_offset_ms is not available"],
        "errors": [],
    }


def _phase_network(case_dir: Path) -> dict:
    pcaps = sorted((case_dir / "network").rglob("*.pcap"))
    if not pcaps:
        return {
            "phase": "network_analysis",
            "status": "skipped_no_network_evidence",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved PCAP files were found for this case."],
            "errors": [],
            "not_executed_reason": "No RAW network evidence was found for this case.",
        }
    tshark = _which("tshark")
    if not tshark:
        return {
            "phase": "network_analysis",
            "status": "failed_missing_dependency",
            "input_artifacts": [relative_path(p) for p in pcaps],
            "findings": {},
            "limitations": [],
            "errors": ["Tool tshark not found"],
            "not_executed_reason": "tshark is required to analyze preserved PCAP files.",
            "tool_used": "not_available",
        }
    findings = []
    out_root = _analysis_dir(case_dir) / "03_network"
    def _parse_frames(log_path: Path) -> int:
        text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
        for line in text.splitlines():
            if "<>" in line and "|" in line:
                match = re.search(r"\|\s*([\d]+)\s*\|\s*([\d]+)\s*\|", line)
                if match:
                    try:
                        return int(match.group(1))
                    except Exception:
                        return 0
        return 0
    for pcap in pcaps:
        slug = _safe_slug(pcap.stem)
        detail_dir = out_root / "by_pcap" / slug
        detail_dir.mkdir(parents=True, exist_ok=True)
        total_cmd = [tshark, "-r", str(pcap), "-q", "-z", "io,stat,0"]
        total_rc, _ = _run_command(total_cmd, case_dir, detail_dir / "frames.stdout.log", detail_dir / "frames.stderr.log")
        modbus_cmd = [tshark, "-r", str(pcap), "-Y", "tcp.port==502", "-q", "-z", "io,stat,0"]
        modbus_rc, _ = _run_command(modbus_cmd, case_dir, detail_dir / "modbus.stdout.log", detail_dir / "modbus.stderr.log")
        total_frames = _parse_frames(detail_dir / "frames.stdout.log") if total_rc == 0 else 0
        modbus_frames = _parse_frames(detail_dir / "modbus.stdout.log") if modbus_rc == 0 else 0
        findings.append(
            {
                "pcap": relative_path(pcap),
                "size_bytes": pcap.stat().st_size,
                "total_frames": total_frames,
                "modbus_frames": modbus_frames,
                "tool_used": "tshark",
                "commands": [total_cmd, modbus_cmd],
                "stdout_paths": [
                    relative_path(detail_dir / "frames.stdout.log"),
                    relative_path(detail_dir / "modbus.stdout.log"),
                ],
                "stderr_paths": [
                    relative_path(detail_dir / "frames.stderr.log"),
                    relative_path(detail_dir / "modbus.stderr.log"),
                ],
            }
        )
    return {
        "phase": "network_analysis",
        "status": "completed",
        "input_artifacts": [relative_path(p) for p in pcaps],
        "tool_used": "tshark",
        "findings": {
            "pcaps_analyzed": len(findings),
            "files": findings,
        },
        "limitations": ["This phase performs lightweight tshark-based summaries and does not replace full manual packet-forensics review."],
        "errors": [],
    }


def _phase_memory(case_dir: Path) -> dict:
    dumps = sorted((case_dir / "memory").glob("*.lime"))
    if not dumps:
        return {
            "phase": "memory_analysis",
            "status": "skipped_no_memory_dump",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved memory dump was found for this case."],
            "errors": [],
            "not_executed_reason": "No LiME memory dump was found for this case.",
        }
    vol_cmd = _which("volatility3", "vol")
    script_path = FORENSICS_SCRIPTS_DIR / "analyze_memory_vol3.sh"
    if not vol_cmd or not script_path.is_file() or not VOL3_SYMBOLS_DIR.is_dir():
        return {
            "phase": "memory_analysis",
            "status": "failed_missing_dependency",
            "input_artifacts": [relative_path(p) for p in dumps],
            "findings": {},
            "limitations": [],
            "errors": [
                "Tool volatility3 not found" if not vol_cmd else "Volatility symbols directory not found" if not VOL3_SYMBOLS_DIR.is_dir() else "Memory analysis script not found"
            ],
            "not_executed_reason": "volatility3, symbols cache, or analyze_memory_vol3.sh is not available.",
            "tool_used": "not_available",
        }
    results = []
    for dump_file in dumps:
        vm_id = _safe_slug(dump_file.stem)
        stdout_path, stderr_path = _phase_log_paths(case_dir, f"memory_analysis_{vm_id}")
        cmd = ["bash", str(script_path), str(case_dir), str(dump_file), "unused", vol_cmd, vm_id]
        rc, _ = _run_command(cmd, case_dir, stdout_path, stderr_path)
        out_dir = _analysis_dir(case_dir) / "vol3" / vm_id
        produced = sorted(str(p.name) for p in out_dir.glob("*"))
        results.append(
            {
                "dump": relative_path(dump_file),
                "vm_id": vm_id,
                "command": cmd,
                "exit_code": rc,
                "stdout_path": relative_path(stdout_path),
                "stderr_path": relative_path(stderr_path),
                "output_dir": relative_path(out_dir),
                "produced_files": produced,
            }
        )
    failed = [item for item in results if item["exit_code"] != 0]
    return {
        "phase": "memory_analysis",
        "status": "completed" if not failed else "partial",
        "input_artifacts": [relative_path(p) for p in dumps],
        "tool_used": "volatility3",
        "findings": {
            "dumps_analyzed": len(results),
            "results": results,
        },
        "limitations": [] if not failed else ["One or more memory-analysis helper executions exited non-zero; inspect stdout/stderr logs for details."],
        "errors": [] if not failed else [f"{len(failed)} memory-analysis executions exited non-zero"],
    }


def _phase_disk(case_dir: Path) -> dict:
    raws = sorted((case_dir / "disk").glob("*.raw"))
    if not raws:
        return {
            "phase": "disk_analysis",
            "status": "skipped_no_disk_image",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved RAW disk image was found for this case."],
            "errors": [],
            "not_executed_reason": "No RAW disk image found for this case.",
        }
    required_tools = {"mmls": _which("mmls"), "fsstat": _which("fsstat"), "fls": _which("fls"), "mactime": _which("mactime"), "strings": _which("strings")}
    script_path = FORENSICS_SCRIPTS_DIR / "analyze_disk_tsk.sh"
    if not script_path.is_file() or not all(required_tools.values()):
        missing = [name for name, value in required_tools.items() if not value]
        if not script_path.is_file():
            missing.append("analyze_disk_tsk.sh")
        return {
            "phase": "disk_analysis",
            "status": "failed_missing_dependency",
            "input_artifacts": [relative_path(p) for p in raws],
            "findings": {},
            "limitations": [],
            "errors": [f"Missing dependency: {name}" for name in missing],
            "not_executed_reason": "One or more Sleuth Kit dependencies are missing.",
            "tool_used": "not_available",
        }
    results = []
    for raw in raws:
        slug = _safe_slug(raw.stem)
        out_dir = _analysis_dir(case_dir) / "05_disk" / slug
        stdout_path, stderr_path = _phase_log_paths(case_dir, f"disk_analysis_{slug}")
        cmd = ["bash", str(script_path), str(case_dir), str(raw), str(out_dir)]
        rc, _ = _run_command(cmd, case_dir, stdout_path, stderr_path)
        results.append(
            {
                "disk_image": relative_path(raw),
                "command": cmd,
                "exit_code": rc,
                "stdout_path": relative_path(stdout_path),
                "stderr_path": relative_path(stderr_path),
                "output_dir": relative_path(out_dir),
                "produced_files": sorted(relative_path(p) for p in out_dir.rglob("*") if p.is_file())[:50],
            }
        )
    failed = [item for item in results if item["exit_code"] != 0]
    return {
        "phase": "disk_analysis",
        "status": "completed" if not failed else "partial",
        "input_artifacts": [relative_path(p) for p in raws],
        "tool_used": "sleuthkit",
        "findings": {
            "disk_images_analyzed": len(results),
            "results": results,
        },
        "limitations": [] if not failed else ["One or more disk-analysis helper executions exited non-zero; inspect stdout/stderr logs for details."],
        "errors": [] if not failed else [f"{len(failed)} disk-analysis executions exited non-zero"],
    }


def _phase_ot(case_dir: Path) -> dict:
    exports = sorted((case_dir / "industrial").glob("ot_export_*.json"))
    if not exports:
        return {
            "phase": "ot_export_analysis",
            "status": "skipped_no_ot_export",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved OT export was found for this case."],
            "errors": [],
            "not_executed_reason": "No OT export files were found for this case.",
        }
    op_counts = Counter()
    fc_counts = Counter()
    observations = []
    for export_path in exports:
        data = _json_load(export_path) or {}
        records = data.get("records") if isinstance(data, dict) else []
        records = records if isinstance(records, list) else []
        for record in records:
            op_counts[str(record.get("op") or "unknown")] += 1
            fc_counts[str(record.get("fc") or "unknown")] += 1
        observations.append(
            {
                "file": relative_path(export_path),
                "vm_id": data.get("vm_id"),
                "run_id": data.get("run_id"),
                "records": len(records),
            }
        )
    return {
        "phase": "ot_export_analysis",
        "status": "completed",
        "input_artifacts": [relative_path(p) for p in exports],
        "tool_used": "python3",
        "findings": {
            "files": observations,
            "operations": dict(op_counts.most_common()),
            "function_codes": dict(fc_counts.most_common()),
        },
        "limitations": [],
        "errors": [],
    }


def _phase_alerts(case_dir: Path) -> dict:
    alerts = sorted((case_dir / "alerts").glob("*.json"))
    if not alerts:
        return {
            "phase": "alerts_detection_analysis",
            "status": "skipped_no_alerts",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved alert files were found for this case."],
            "errors": [],
            "not_executed_reason": "No preserved alert JSON files were found for this case.",
        }
    severity = Counter()
    collectors = Counter()
    protocols = Counter()
    rules = Counter()
    signatures = Counter()
    sensors = Counter()
    for alert_path in alerts:
        data = _json_load(alert_path) or {}
        severity[str(data.get("rule_level") or data.get("severity") or "unknown")] += 1
        collectors[str(data.get("source") or "unknown")] += 1
        protocols[str(data.get("protocol") or "unknown")] += 1
        rules[str(data.get("rule_id") or "unknown")] += 1
        signatures[str(data.get("signature") or "unknown")] += 1
        raw = data.get("raw") or {}
        sensors[str((raw.get("rule") or {}).get("groups", ["unknown"])[0] if isinstance(raw.get("rule"), dict) else "unknown")] += 1
    return {
        "phase": "alerts_detection_analysis",
        "status": "completed",
        "input_artifacts": [relative_path(p) for p in alerts[:50]] + (["..."] if len(alerts) > 50 else []),
        "tool_used": "python3",
        "findings": {
            "alerts_total": len(alerts),
            "severity_distribution": dict(severity.most_common()),
            "collectors": dict(collectors.most_common()),
            "protocols": dict(protocols.most_common()),
            "top_rules": dict(rules.most_common(20)),
            "top_signatures": dict(signatures.most_common(20)),
            "rule_group_distribution": dict(sensors.most_common()),
        },
        "limitations": ["This phase summarizes preserved alerts and does not replace full analyst review of every individual event."],
        "errors": [],
    }


def _phase_pipeline_custody(case_dir: Path) -> dict:
    pipeline_events = _jsonl_load(case_dir / "metadata" / "pipeline_events.jsonl")
    custody_events = _jsonl_load(case_dir / "chain_of_custody.log")
    if not pipeline_events and not custody_events:
        return {
            "phase": "pipeline_custody_analysis",
            "status": "skipped_no_pipeline_or_custody",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No pipeline or custody logs were found for this case."],
            "errors": [],
            "not_executed_reason": "Neither pipeline_events.jsonl nor chain_of_custody.log was found.",
        }
    pipeline_counts = Counter(str(item.get("event") or item.get("event_type") or "unknown") for item in pipeline_events)
    custody_actions = Counter(str(item.get("action") or "unknown") for item in custody_events)
    custody_actors = Counter(str(item.get("actor") or "unknown") for item in custody_events)
    return {
        "phase": "pipeline_custody_analysis",
        "status": "completed",
        "input_artifacts": [
            relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").exists() else "missing",
            relative_path(case_dir / "chain_of_custody.log") if (case_dir / "chain_of_custody.log").exists() else "missing",
        ],
        "tool_used": "python3",
        "findings": {
            "pipeline_events_total": len(pipeline_events),
            "pipeline_event_distribution": dict(pipeline_counts.most_common()),
            "custody_events_total": len(custody_events),
            "custody_action_distribution": dict(custody_actions.most_common()),
            "custody_actor_distribution": dict(custody_actors.most_common()),
        },
        "limitations": [],
        "errors": [],
    }


def _phase_timeline(case_dir: Path) -> dict:
    timeline_out = _analysis_dir(case_dir) / "09_timeline" / "unified_forensic_timeline.json"
    timeline_out.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for event in _jsonl_load(case_dir / "metadata" / "pipeline_events.jsonl"):
        rows.append(
            {
                "timestamp": event.get("ts_utc"),
                "ts_epoch": event.get("ts_epoch"),
                "source": "pipeline",
                "event": event.get("event") or event.get("event_type"),
                "details": event.get("meta") or {},
            }
        )
    for event in _jsonl_load(case_dir / "chain_of_custody.log"):
        rows.append(
            {
                "timestamp": event.get("ts_utc"),
                "ts_epoch": event.get("ts_epoch"),
                "source": "custody",
                "event": event.get("action"),
                "details": {"actor": event.get("actor"), "artifact_rel": event.get("artifact_rel"), "outcome": event.get("outcome")},
            }
        )
    for export_path in sorted((case_dir / "industrial").glob("ot_export_*.json")):
        data = _json_load(export_path) or {}
        for record in data.get("records") or []:
            rows.append(
                {
                    "timestamp": record.get("ts_utc_ms") or record.get("ts_utc"),
                    "ts_epoch": record.get("ts_epoch"),
                    "source": "ot_export",
                    "event": f"ot:{record.get('op') or 'unknown'}",
                    "details": {
                        "fc": record.get("fc"),
                        "address": record.get("address"),
                        "value": record.get("value"),
                        "src_ip": record.get("src_ip"),
                        "dst_ip": record.get("dst_ip"),
                    },
                }
            )
    rows = [row for row in rows if row.get("timestamp") or row.get("ts_epoch")]
    rows.sort(key=lambda item: (_parse_ts(item.get("timestamp")) if item.get("timestamp") else None) or float(item.get("ts_epoch") or 0.0))
    return {
        "phase": "unified_forensic_timeline",
        "status": "completed" if rows else "partial",
        "input_artifacts": [
            relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").exists() else "missing",
            relative_path(case_dir / "chain_of_custody.log") if (case_dir / "chain_of_custody.log").exists() else "missing",
        ],
        "tool_used": "python3",
        "findings": rows,
        "limitations": [] if rows else ["No timestamped rows were recovered from preserved pipeline, custody, or OT-export sources."],
        "errors": [],
    }


def _phase_cross_layer(case_dir: Path) -> dict:
    alerts = _json_load(_analysis_dir(case_dir) / "07_alerts" / "alert_findings.json") or {}
    ot = _json_load(_analysis_dir(case_dir) / "06_ot" / "ot_findings.json") or {}
    network = _json_load(_analysis_dir(case_dir) / "03_network" / "network_findings.json") or {}
    time_validation = _json_load(_analysis_dir(case_dir) / "02_time_validation" / "clock_offset_report.json") or {}
    findings = []
    top_signatures = (alerts.get("findings") or {}).get("top_signatures") or {}
    ot_ops = (ot.get("findings") or {}).get("operations") or {}
    modbus_frames = sum(int((item or {}).get("modbus_frames") or 0) for item in ((network.get("findings") or {}).get("files") or []))
    if modbus_frames and ot_ops:
        findings.append(
            {
                "finding": "Preserved PCAP evidence and OT exports both indicate Modbus activity for this case.",
                "evidence_refs": [
                    relative_path(_analysis_dir(case_dir) / "03_network" / "network_findings.json"),
                    relative_path(_analysis_dir(case_dir) / "06_ot" / "ot_findings.json"),
                ],
                "confidence": "medium",
            }
        )
    if any("/etc/shadow_backup" in str(k) for k in top_signatures.keys()):
        findings.append(
            {
                "finding": "High-severity file-integrity activity was preserved and should be interpreted together with disk and memory layers if available.",
                "evidence_refs": [relative_path(_analysis_dir(case_dir) / "07_alerts" / "alert_findings.json")],
                "confidence": "medium",
            }
        )
    max_offset = (time_validation.get("findings") or {}).get("max_offset_ms")
    if isinstance(max_offset, (int, float)) and max_offset > 1000:
        findings.append(
            {
                "finding": "Clock offset is materially high; timeline interpretation should account for temporal uncertainty.",
                "evidence_refs": [relative_path(_analysis_dir(case_dir) / "02_time_validation" / "clock_offset_report.json")],
                "confidence": "high",
            }
        )
    return {
        "phase": "cross_layer_findings",
        "status": "completed",
        "input_artifacts": [
            relative_path(_analysis_dir(case_dir) / "03_network" / "network_findings.json"),
            relative_path(_analysis_dir(case_dir) / "06_ot" / "ot_findings.json"),
            relative_path(_analysis_dir(case_dir) / "07_alerts" / "alert_findings.json"),
        ],
        "tool_used": "python3",
        "findings": findings,
        "limitations": ["Cross-layer findings are conservative and only rely on outputs generated during this analysis workflow."],
        "errors": [],
    }


def _phase_final_report(case_entry: dict, case_dir: Path, status: dict) -> dict:
    report_path = _analysis_dir(case_dir) / "forensic_analysis_report.json"
    manifest_path = _analysis_dir(case_dir) / "forensic_analysis_manifest.json"
    summary_path = _analysis_dir(case_dir) / "forensic_analysis_summary.md"
    phase_statuses = {key: (status.get("phases") or {}).get(key, {}).get("status") for key, _, _ in ANALYSIS_PHASES}
    failed = [key for key, value in phase_statuses.items() if str(value).startswith("failed")]
    skipped = [key for key, value in phase_statuses.items() if str(value).startswith("skipped")]
    report = {
        "case_id": case_entry.get("case_id"),
        "source_case_name": case_entry.get("source_case_name"),
        "generated_at": utc_now(),
        "analysis_id": status.get("analysis_id"),
        "analysis_status": "completed" if not failed else "partial",
        "status_note": "Forensic analysis completed with some skipped or failed layers." if failed or skipped else "Forensic analysis completed successfully.",
        "input_artifacts": [
            relative_path(case_dir / "manifest.json"),
            relative_path(case_dir / "chain_of_custody.log"),
            relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").exists() else "missing",
        ],
        "findings": {
            "completed_phases": status.get("completed_phases") or [],
            "failed_phases": status.get("failed_phases") or [],
            "skipped_phases": status.get("skipped_phases") or [],
        },
        "limitations": [
            "Semantic and causal reconstruction remain blocked until explicitly generated in later phases.",
            "Skipped layers indicate missing evidence or missing dependencies, not fabricated success.",
        ],
        "errors": status.get("errors") or [],
        "tool_used": "python3",
        "related_outputs": [path for path in status.get("output_files") if path.endswith(".json")],
    }
    _write_json(report_path, report)
    _write_json(
        manifest_path,
        {
            "case_id": case_entry.get("case_id"),
            "analysis_id": status.get("analysis_id"),
            "generated_at": report["generated_at"],
            "status": report["analysis_status"],
            "report_path": relative_path(report_path),
            "summary_path": relative_path(summary_path),
            "phases": {key: (status.get("phases") or {}).get(key, {}).get("status") for key, _, _ in ANALYSIS_PHASES},
        },
    )
    summary_lines = [
        f"# Forensic Analysis Summary for {case_entry.get('source_case_name')}",
        "",
        f"- Case ID: `{case_entry.get('case_id')}`",
        f"- Analysis ID: `{status.get('analysis_id')}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Overall analysis status: `{report['analysis_status']}`",
        "",
        "## Phase Status",
        "",
    ]
    for key, label, _ in ANALYSIS_PHASES:
        summary_lines.append(f"- `{label}`: `{phase_statuses.get(key, 'unknown')}`")
    summary_lines.extend(
        [
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
        ]
    )
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    status["output_files"].append(relative_path(manifest_path))
    status["output_files"].append(relative_path(summary_path))
    return {
        "phase": "forensic_analysis_report_generation",
        "status": "completed" if not failed else "partial",
        "input_artifacts": report["input_artifacts"],
        "tool_used": "python3",
        "findings": {
            "report_path": relative_path(report_path),
            "manifest_path": relative_path(manifest_path),
            "summary_path": relative_path(summary_path),
            "analysis_status": report["analysis_status"],
        },
        "limitations": report["limitations"],
        "errors": report["errors"],
    }


def _phase_foc_refresh(case_dir: Path) -> dict:
    manifest = regenerate_foc()
    return {
        "phase": "foc_readiness_update",
        "status": "completed",
        "input_artifacts": [relative_path(_analysis_dir(case_dir) / "forensic_analysis_report.json")],
        "tool_used": "python3",
        "findings": {
            "foc_manifest_updated_at": manifest.get("updated_at"),
            "scenario_id": manifest.get("scenario_id"),
            "generation_status": manifest.get("generation_status"),
        },
        "limitations": ["Causal reconstruction remains intentionally blocked after forensic analysis completion."],
        "errors": [],
    }


def _run_phase(case_entry: dict, case_dir: Path, status: dict, phase_key: str) -> dict:
    if phase_key == "preflight_validation":
        return _build_preflight(case_entry, case_dir)
    if phase_key == "evidence_inventory":
        return _phase_evidence_inventory(case_dir)
    if phase_key == "integrity_custody_validation":
        return _phase_integrity_custody(case_dir)
    if phase_key == "temporal_validation":
        return _phase_temporal_validation(case_dir)
    if phase_key == "network_analysis":
        return _phase_network(case_dir)
    if phase_key == "memory_analysis":
        return _phase_memory(case_dir)
    if phase_key == "disk_analysis":
        return _phase_disk(case_dir)
    if phase_key == "ot_export_analysis":
        return _phase_ot(case_dir)
    if phase_key == "alerts_detection_analysis":
        return _phase_alerts(case_dir)
    if phase_key == "pipeline_custody_analysis":
        return _phase_pipeline_custody(case_dir)
    if phase_key == "unified_forensic_timeline":
        return _phase_timeline(case_dir)
    if phase_key == "cross_layer_findings":
        return _phase_cross_layer(case_dir)
    if phase_key == "forensic_analysis_report_generation":
        return _phase_final_report(case_entry, case_dir, status)
    if phase_key == "foc_readiness_update":
        return _phase_foc_refresh(case_dir)
    raise KeyError(f"Unknown phase: {phase_key}")


def _worker(case_entry: dict, force: bool) -> None:
    case_id = str(case_entry.get("case_id"))
    case_dir = _case_dir_from_entry(case_entry)
    status = _init_status(case_entry, force=force)
    try:
        for phase_key, label, _ in ANALYSIS_PHASES:
            _record_phase_transition(case_dir, status, phase_key, "running", {"started_at": utc_now()})
            try:
                payload = _run_phase(case_entry, case_dir, status, phase_key)
                payload = _finalize_phase_output(case_dir, status, phase_key, payload)
                phase_status = str(payload.get("status") or "completed")
                extra = {
                    "finished_at": utc_now(),
                    "output_path": relative_path(_phase_output_path(case_dir, phase_key)) if _phase_output_path(case_dir, phase_key) else None,
                    "errors": payload.get("errors") or [],
                    "limitations": payload.get("limitations") or [],
                }
                if phase_status.startswith("failed"):
                    status["errors"].append({"phase": phase_key, "message": "; ".join(payload.get("errors") or [phase_status])})
                elif phase_status.startswith("skipped"):
                    status["warnings"].append({"phase": phase_key, "message": payload.get("not_executed_reason") or phase_status})
                _set_phase_status(case_dir, status, phase_key, phase_status, extra=extra)
            except Exception as exc:
                logger.warning("FOC analysis phase failed case=%s phase=%s: %s", case_id, phase_key, exc, exc_info=True)
                stdout_path, stderr_path = _phase_log_paths(case_dir, phase_key)
                error_payload = {
                    "phase": phase_key,
                    "status": "failed",
                    "input_artifacts": [],
                    "tool_used": "not_available",
                    "findings": {},
                    "limitations": [],
                    "errors": [str(exc)],
                }
                output_path = _phase_output_path(case_dir, phase_key)
                if output_path:
                    _write_json(output_path, error_payload)
                status["errors"].append(
                    {
                        "phase": phase_key,
                        "command": None,
                        "exit_code": None,
                        "stdout_path": relative_path(stdout_path),
                        "stderr_path": relative_path(stderr_path),
                        "error_message": str(exc),
                        "failed_input_artifact": None,
                        "suggested_debug_action": "Open debug details to inspect the exact command, stderr and expected output.",
                    }
                )
                _set_phase_status(
                    case_dir,
                    status,
                    phase_key,
                    "failed",
                    extra={
                        "finished_at": utc_now(),
                        "output_path": relative_path(output_path) if output_path else None,
                        "stderr_path": relative_path(stderr_path),
                    },
                )
        if status.get("failed_phases"):
            status["status"] = "partial" if (case_dir / "analysis" / "forensic_analysis_report.json").is_file() else "failed"
        else:
            status["status"] = "completed"
        status["finished_at"] = utc_now()
    finally:
        status["current_phase"] = None
        _write_status(case_dir, status)
        with _ANALYSIS_STATE_LOCK:
            _RUNNING_ANALYSES.pop(case_id, None)


def run_analysis(case_id: str, force: bool = False) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    current = load_analysis_status(case_id)
    with _ANALYSIS_STATE_LOCK:
        thread = _RUNNING_ANALYSES.get(case_id)
        if thread and thread.is_alive():
            return {"error": "analysis_already_running", "case_id": case_id}
        if current.get("status") == "running":
            return {"error": "analysis_already_running", "case_id": case_id}
        worker = threading.Thread(target=_worker, args=(case_entry, force), daemon=True, name=f"foc-analysis-{case_id}")
        _RUNNING_ANALYSES[case_id] = worker
        worker.start()
    return {"result": "started", "case_id": case_id, "force": force}


def validate_analysis(case_id: str) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(case_entry)
    status = load_analysis_status(case_id)
    phases = status.get("phases") or {}
    validation = []
    for phase_key, _, _ in ANALYSIS_PHASES:
        output_path = _phase_output_path(case_dir, phase_key)
        if not output_path or not output_path.exists():
            validation.append({"phase": phase_key, "status": "missing_output", "output_path": relative_path(output_path) if output_path else None})
            continue
        payload = _json_load(output_path)
        ok, reason = _validate_phase_payload(payload if isinstance(payload, dict) else {})
        validation.append({"phase": phase_key, "status": "valid" if ok else "invalid", "reason": reason, "output_path": relative_path(output_path)})
    return {
        "case_id": case_id,
        "validated_at": utc_now(),
        "status": status.get("status"),
        "validation": validation,
    }


def analysis_logs(case_id: str) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(case_entry)
    logs = []
    for stdout_path in sorted(_analysis_logs_dir(case_dir).glob("*.stdout.log")):
        stderr_path = stdout_path.with_name(stdout_path.name.replace(".stdout.log", ".stderr.log"))
        tail_stdout = "\n".join(stdout_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:]) if stdout_path.exists() else ""
        tail_stderr = "\n".join(stderr_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:]) if stderr_path.exists() else ""
        logs.append(
            {
                "phase": stdout_path.name.replace(".stdout.log", ""),
                "stdout_path": relative_path(stdout_path),
                "stderr_path": relative_path(stderr_path),
                "stdout_tail": tail_stdout,
                "stderr_tail": tail_stderr,
            }
        )
    return {"case_id": case_id, "logs": logs}


def analysis_report(case_id: str) -> dict | None:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return None
    case_dir = _case_dir_from_entry(case_entry)
    report_path = _analysis_dir(case_dir) / "forensic_analysis_report.json"
    report = _json_load(report_path)
    if not isinstance(report, dict):
        return None
    summary_path = _analysis_dir(case_dir) / "forensic_analysis_summary.md"
    report["summary_path"] = relative_path(summary_path) if summary_path.exists() else None
    report["summary_preview"] = summary_path.read_text(encoding="utf-8", errors="ignore")[:4000] if summary_path.exists() else None
    return report


def cases_with_analysis_state() -> dict:
    enriched = []
    for entry in _list_case_entries():
        status = load_analysis_status(str(entry.get("case_id")))
        inventory = _artifact_inventory(_case_dir_from_entry(entry))
        enriched.append(
            {
                **entry,
                "analysis_status": status.get("status"),
                "analysis_ready_to_run": bool(inventory["artifacts_total"]),
                "available_layers": inventory["layers"],
                "inventory_summary": inventory["artifact_type_counts"],
                "analysis_report_path": status.get("forensic_analysis_report_path"),
            }
        )
    return {"generated_at": utc_now(), "cases": enriched}
