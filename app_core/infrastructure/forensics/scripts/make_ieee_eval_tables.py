#!/usr/bin/env python3
"""
analyze_case.py
---------------
Professional DFIR-case analyzer for NICS CyberLab evidence_store.

What it does (grounded, no fabrication):
- Reads CASE-*/manifest.json + metadata/pipeline_events.jsonl
- Computes operational metrics (M2, M3, M4) from logged ts_epoch and artifact sizes
- Extracts alert invariants from CASE/alerts/*.json (preferred) or alerts_store (best-effort)
- Computes evidence-quality flags (E1, E3, E4) and reads time_sync max_offset_ms (E2) if present
- Verifies custody hash chaining (E3-custody) if chain_of_custody.log exists
- Produces a single JSON payload and can write it to a file via --out
- Adds a stable "summary" section (table_view) to make filling tables easy

Extended in this version:
- Reads IR preserved inputs from:
    metadata/ir/inputs/scenario/scenario_file.json
    metadata/ir/inputs/tools-installer/installed/*.json
    metadata/ir/inputs/tools-installer-tmp/*.json
- Writes FSR inputs analysis into:
    CASE-*/metadata/fsr/fsr_inputs_<run_id>.json
  Optionally also writes a full bundle:
    CASE-*/metadata/fsr/fsr_bundle_<run_id>.json
  Optionally also writes a copy into:
    CASE-*/analysis/analyze_case_<run_id>.json

Preservation controls for newly written files (if enabled via flags):
- Registers written artifacts in CASE/manifest.json
- Appends pipeline events into CASE/metadata/pipeline_events.jsonl
- Appends chain-of-custody entries into CASE/chain_of_custody.log (hash-chained)
- Updates CASE digest in CASE/metadata/case_digest_<run_id>.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# Time + hashing helpers
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now_epoch() -> float:
    return float(datetime.now(timezone.utc).timestamp())


def sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def iso_to_epoch(iso_utc: str) -> float:
    """
    Convert ISO UTC to epoch (UTC).
    Supports:
      - 2026-03-01T21:22:54Z
      - 2026-03-01T21:22:59.275Z
      - 2026-03-01T21:22:59.275+00:00
      - 2026-03-01T21:22:59.275+0000
    """
    s = (iso_utc or "").strip()
    if not s:
        return 0.0
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            if len(s) >= 5 and (s[-5] in ["+", "-"]) and s[-3] != ":":
                s = s[:-2] + ":" + s[-2:]
            dt = datetime.fromisoformat(s)
        return dt.astimezone(timezone.utc).timestamp()
    except Exception:
        return 0.0


# ============================================================
# IO helpers
# ============================================================

def read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def read_jsonl(path: str) -> List[dict]:
    out: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def append_jsonl(path: str, obj: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        return True
    except Exception:
        return False


def write_json_atomic(path: str, obj: Any) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def list_json_files(dir_path: str) -> List[str]:
    if not dir_path or not os.path.isdir(dir_path):
        return []
    files = []
    for fn in os.listdir(dir_path):
        if fn.lower().endswith(".json"):
            files.append(os.path.join(dir_path, fn))
    files.sort()
    return files


# ============================================================
# CASE selection
# ============================================================

def parse_case_ts(case_name: str) -> Optional[datetime]:
    # CASE-YYYYMMDD-HHMMSS...
    try:
        core = case_name.split("-")
        if len(core) < 3:
            return None
        ymd = core[1]
        hms = core[2]
        dt = datetime.strptime(ymd + hms, "%Y%m%d%H%M%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def pick_cases(evidence_root: str, limit: int) -> List[str]:
    if not os.path.isdir(evidence_root):
        return []
    cases: List[str] = []
    for name in os.listdir(evidence_root):
        if not name.startswith("CASE-"):
            continue
        p = os.path.join(evidence_root, name)
        if os.path.isdir(p):
            cases.append(name)

    cases.sort(
        key=lambda n: parse_case_ts(n) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return cases[: max(0, limit)]


def resolve_evidence_root(path_in: str) -> str:
    """
    Fixes the common mistake: running from app_core/infrastructure/forensics/scripts/
    and passing a relative --evidence-root that becomes nested incorrectly.
    """
    p = os.path.abspath(path_in)
    if os.path.isdir(p):
        return p

    # Try relative to repo root by walking up a few levels
    # scripts/ -> forensics/ -> infrastructure/ -> app_core/ -> repo
    cwd = os.path.abspath(os.getcwd())
    candidates = []
    for up in range(0, 8):
        base = cwd
        for _ in range(up):
            base = os.path.abspath(os.path.join(base, os.pardir))
        candidates.append(os.path.abspath(os.path.join(base, path_in)))

    for c in candidates:
        if os.path.isdir(c) and any(x.startswith("CASE-") for x in os.listdir(c)):
            return c

    return p


# ============================================================
# Events helpers
# ============================================================

def _event_ts_epoch(e: dict) -> Optional[float]:
    try:
        v = e.get("ts_epoch")
        if v is None:
            ts_utc = (e.get("ts_utc") or "").strip()
            if ts_utc:
                x = float(iso_to_epoch(ts_utc))
                return x if x > 0 else None
            return None
        x = float(v)
        return x if x > 0 else None
    except Exception:
        return None


def find_first_event(events: List[dict], run_id: str, event_name: str) -> Optional[dict]:
    for e in events:
        if (e.get("run_id") == run_id) and (e.get("event") == event_name):
            return e
    return None


def find_last_event(events: List[dict], run_id: str, event_name: str) -> Optional[dict]:
    best: Optional[dict] = None
    best_ts: Optional[float] = None
    for e in events:
        if (e.get("run_id") != run_id) or (e.get("event") != event_name):
            continue
        ts = _event_ts_epoch(e)
        if ts is None:
            best = e
            continue
        if best_ts is None or ts > best_ts:
            best = e
            best_ts = ts
    return best


def find_event_any(events: List[dict], run_id: str, names: List[str], mode: str = "first") -> Optional[dict]:
    for name in names:
        if mode == "last":
            e = find_last_event(events, run_id, name)
        else:
            e = find_first_event(events, run_id, name)
        if e is not None:
            return e
    return None


def latency_s(alert: Optional[dict], other: Optional[dict]) -> Optional[float]:
    if not alert or not other:
        return None
    try:
        a = float(_event_ts_epoch(alert) or 0)
        b = float(_event_ts_epoch(other) or 0)
        if a <= 0 or b <= 0:
            return None
        return round(b - a, 3)
    except Exception:
        return None


# ============================================================
# Manifest + pipeline + custody + digest (NEW)
# ============================================================

def _manifest_path(case_dir: str) -> str:
    return os.path.join(case_dir, "manifest.json")


def _pipeline_path(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata", "pipeline_events.jsonl")


def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")


def load_manifest(case_dir: str) -> dict:
    p = _manifest_path(case_dir)
    m = read_json(p) or {}
    if "artifacts" not in m or not isinstance(m.get("artifacts"), list):
        m["artifacts"] = []
    return m


def save_manifest_atomic(case_dir: str, manifest: dict) -> bool:
    return write_json_atomic(_manifest_path(case_dir), manifest)


def manifest_has_artifact(case_dir: str, rel_path: str, artifact_type: str) -> bool:
    m = load_manifest(case_dir)
    for a in (m.get("artifacts") or []):
        if not isinstance(a, dict):
            continue
        if str(a.get("rel_path") or "") == rel_path and str(a.get("type") or "") == artifact_type:
            return True
    return False


def add_artifact_to_manifest(
    case_dir: str,
    rel_path: str,
    artifact_type: str,
    sha256: Optional[str],
    size: Optional[int],
) -> bool:
    """
    Adds an artifact record to manifest.json in an idempotent way.
    """
    try:
        if manifest_has_artifact(case_dir, rel_path, artifact_type):
            return True

        m = load_manifest(case_dir)
        entry = {
            "rel_path": rel_path,
            "type": artifact_type,
            "sha256": sha256,
            "size": int(size) if isinstance(size, int) or (isinstance(size, str) and str(size).isdigit()) else size,
            "added_at_utc": utc_now_iso(),
        }
        m["artifacts"].append(entry)
        return save_manifest_atomic(case_dir, m)
    except Exception:
        return False


def append_pipeline_event(case_dir: str, event: str, run_id: str, meta: Optional[dict]) -> bool:
    """
    Appends a pipeline event to metadata/pipeline_events.jsonl.
    Idempotency: we do NOT enforce strict uniqueness here by default because events are a log.
    """
    obj = {
        "ts_utc": utc_now_iso(),
        "ts_epoch": utc_now_epoch(),
        "run_id": run_id,
        "event": event,
        "meta": meta or {},
    }
    return append_jsonl(_pipeline_path(case_dir), obj)


def _read_last_custody_hash(case_dir: str) -> str:
    """
    Returns last entry_hash in chain_of_custody.log, else zeros.
    """
    p = _custody_path(case_dir)
    if not os.path.isfile(p):
        return "0" * 64
    try:
        last = None
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = (line or "").strip()
                if not line:
                    continue
                last = line
        if not last:
            return "0" * 64
        obj = json.loads(last)
        h = str(obj.get("entry_hash") or "")
        return h if len(h) == 64 else ("0" * 64)
    except Exception:
        return "0" * 64


def append_custody_entry(
    case_dir: str,
    action: str,
    actor: str,
    run_id: str,
    artifact_rel: Optional[str],
    details: Optional[dict],
) -> bool:
    """
    Appends a hash-chained custody entry line into chain_of_custody.log.
    Compatible with verify_custody_chain() below.
    """
    try:
        prev_hash = _read_last_custody_hash(case_dir)
        entry_wo_hash = {
            "ts_utc": utc_now_iso(),
            "ts_epoch": utc_now_epoch(),
            "run_id": run_id,
            "action": action,
            "actor": actor,
            "artifact_rel": artifact_rel,
            "details": details or {},
            "prev_hash": prev_hash,
        }
        payload = json.dumps(entry_wo_hash, sort_keys=True, ensure_ascii=False).encode("utf-8")
        entry_hash = sha256_bytes(payload)
        entry = dict(entry_wo_hash)
        entry["entry_hash"] = entry_hash
        return append_jsonl(_custody_path(case_dir), entry)
    except Exception:
        return False


def write_case_digest(case_dir: str, run_id: str, extra: Optional[dict] = None) -> bool:
    """
    Writes a simple case digest to metadata/case_digest_<run_id>.json.
    Includes sha256 of:
      - manifest.json
      - metadata/pipeline_events.jsonl
      - chain_of_custody.log
    And per-artifact snapshot from manifest.
    """
    try:
        run_id = (run_id or "R1").strip() or "R1"
        manifest_p = _manifest_path(case_dir)
        pipeline_p = _pipeline_path(case_dir)
        custody_p = _custody_path(case_dir)

        m = load_manifest(case_dir)

        dig = {
            "schema": "nics_case_digest_v1",
            "generated_at_utc": utc_now_iso(),
            "run_id": run_id,
            "case_dir": case_dir,
            "files": {
                "manifest_json": {"rel": "manifest.json", "sha256": sha256_file(manifest_p)},
                "pipeline_events_jsonl": {"rel": "metadata/pipeline_events.jsonl", "sha256": sha256_file(pipeline_p) if os.path.exists(pipeline_p) else None},
                "chain_of_custody_log": {"rel": "chain_of_custody.log", "sha256": sha256_file(custody_p) if os.path.exists(custody_p) else None},
            },
            "manifest_snapshot": {
                "artifacts_count": len(m.get("artifacts") or []),
                "artifacts": [
                    {
                        "rel_path": a.get("rel_path"),
                        "type": a.get("type"),
                        "sha256": a.get("sha256"),
                        "size": a.get("size"),
                    }
                    for a in (m.get("artifacts") or [])
                    if isinstance(a, dict)
                ],
            },
            "extra": extra or {},
        }

        out_abs = os.path.join(case_dir, "metadata", f"case_digest_{run_id}.json")
        return write_json_atomic(out_abs, dig)
    except Exception:
        return False


def register_written_artifact(
    case_dir: str,
    run_id: str,
    rel_path: str,
    artifact_type: str,
    event_name: str,
    actor: str = "analyze_case",
    meta_extra: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    End-to-end registration:
      - compute sha256 + size
      - add to manifest
      - append pipeline event
      - append custody entry
      - update digest
    Idempotency:
      - manifest is idempotent
      - custody/event are appended (log); you can disable duplicates by checking manifest first.
    """
    out_abs = os.path.join(case_dir, rel_path)
    sha = sha256_file(out_abs)
    try:
        size = int(os.path.getsize(out_abs))
    except Exception:
        size = None

    already = manifest_has_artifact(case_dir, rel_path, artifact_type)

    # Always ensure manifest has it (idempotent)
    ok_manifest = add_artifact_to_manifest(case_dir, rel_path, artifact_type, sha, size)

    # If it was already in manifest, skip log spam
    ok_event = True
    ok_custody = True
    if not already:
        meta = {"rel": rel_path, "sha256": sha, "size": size}
        if meta_extra:
            meta.update(meta_extra)
        ok_event = append_pipeline_event(case_dir, event_name, run_id, meta)
        ok_custody = append_custody_entry(
            case_dir,
            action=event_name,
            actor=actor,
            run_id=run_id,
            artifact_rel=rel_path,
            details={"sha256": sha, "size": size, **(meta_extra or {})},
        )

    ok_digest = write_case_digest(case_dir, run_id=run_id, extra={"updated_by": actor})

    return {
        "rel": rel_path,
        "type": artifact_type,
        "sha256": sha,
        "size": size,
        "already_in_manifest": already,
        "ok_manifest": ok_manifest,
        "ok_event": ok_event,
        "ok_custody": ok_custody,
        "ok_digest": ok_digest,
    }


# ============================================================
# Sizes / artifacts
# ============================================================

def bytes_to_gib(b: Optional[int]) -> Optional[float]:
    if b is None:
        return None
    try:
        return round(float(b) / (1024.0 ** 3), 2)
    except Exception:
        return None


def _walk_pcaps(root_dir: str) -> List[str]:
    pcaps: List[str] = []
    if not root_dir or not os.path.isdir(root_dir):
        return pcaps
    for base, _dirs, files in os.walk(root_dir):
        for fn in files:
            if fn.lower().endswith(".pcap"):
                pcaps.append(os.path.join(base, fn))
    pcaps.sort()
    return pcaps


def _pcap_mtime_range(pcaps: List[str]) -> Tuple[Optional[float], Optional[float]]:
    if not pcaps:
        return (None, None)
    mtimes: List[float] = []
    for p in pcaps:
        try:
            mtimes.append(float(os.path.getmtime(p)))
        except Exception:
            continue
    if not mtimes:
        return (None, None)
    return (min(mtimes), max(mtimes))


def manifest_sizes(manifest: dict, case_dir: str) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {"pcap": [], "mem": [], "disk": [], "ot": []}

    for a in (manifest or {}).get("artifacts", []) or []:
        if not isinstance(a, dict):
            continue
        rp = str(a.get("rel_path") or "")
        sz = a.get("size")
        if sz is None:
            continue
        try:
            sz_i = int(sz)
        except Exception:
            continue

        low = rp.lower()
        if low.startswith("network/") and low.endswith(".pcap"):
            out["pcap"].append(sz_i)
        elif low.startswith("memory/") and (low.endswith(".lime") or "memdump" in low):
            out["mem"].append(sz_i)
        elif low.startswith("disk/") and (low.endswith(".raw") or "disk.final" in low or low.endswith(".qcow2")):
            out["disk"].append(sz_i)
        elif low.startswith("industrial/"):
            out["ot"].append(sz_i)

    if not out["pcap"]:
        pcaps = _walk_pcaps(os.path.join(case_dir, "network"))
        for p in pcaps:
            try:
                out["pcap"].append(int(os.path.getsize(p)))
            except Exception:
                continue

    return out


# ============================================================
# Failures / retries
# ============================================================

def count_failures(events: List[dict], run_id: str) -> int:
    c = 0
    for e in events:
        if e.get("run_id") != run_id:
            continue
        ev = str(e.get("event") or "")
        if ev.endswith("_failed") or "failed" in ev:
            c += 1
    return c


# ============================================================
# FSR inputs analysis (NEW)
# ============================================================

def analyze_ir_preserved_inputs(case_dir: str) -> Dict[str, Any]:
    """
    Reads and summarizes IR-preserved inputs already copied into CASE:
      - metadata/ir/inputs/scenario/scenario_file.json
      - metadata/ir/inputs/tools-installer/installed/*.json
      - metadata/ir/inputs/tools-installer-tmp/*.json
    """
    base = os.path.join(case_dir, "metadata", "ir", "inputs")

    scenario_abs = os.path.join(base, "scenario", "scenario_file.json")
    installed_dir = os.path.join(base, "tools-installer", "installed")
    tmp_dir = os.path.join(base, "tools-installer-tmp")

    out: Dict[str, Any] = {
        "paths": {
            "scenario": "metadata/ir/inputs/scenario/scenario_file.json",
            "installed_dir": "metadata/ir/inputs/tools-installer/installed",
            "tmp_dir": "metadata/ir/inputs/tools-installer-tmp",
        },
        "scenario": {
            "present": os.path.isfile(scenario_abs),
            "nodes_count": None,
            "edges_count": None,
            "scenario_name": None,
        },
        "tools_installed": {
            "dir_present": os.path.isdir(installed_dir),
            "json_count": 0,
            "files": [],
            "tool_names_union": [],
        },
        "tools_tmp": {
            "dir_present": os.path.isdir(tmp_dir),
            "json_count": 0,
            "files": [],
            "tool_names_union": [],
        },
    }

    # scenario summary
    if os.path.isfile(scenario_abs):
        s = read_json(scenario_abs) or {}
        out["scenario"]["scenario_name"] = s.get("scenario_name") or s.get("name") or "file"
        nodes = s.get("nodes")
        edges = s.get("edges")
        out["scenario"]["nodes_count"] = len(nodes) if isinstance(nodes, list) else None
        out["scenario"]["edges_count"] = len(edges) if isinstance(edges, list) else None

    def extract_tools_from_obj(obj: dict) -> List[str]:
        names: List[str] = []
        it = obj.get("installed_tools")
        if isinstance(it, dict):
            for k in it.keys():
                if k:
                    names.append(str(k))

        t = obj.get("tools")
        if isinstance(t, dict):
            for k in t.keys():
                if k:
                    names.append(str(k))
        elif isinstance(t, list):
            for x in t:
                if x:
                    names.append(str(x))

        seen = set()
        outn = []
        for n in names:
            if n not in seen:
                seen.add(n)
                outn.append(n)
        return outn

    installed_files = list_json_files(installed_dir)
    out["tools_installed"]["files"] = [os.path.basename(p) for p in installed_files]
    out["tools_installed"]["json_count"] = len(installed_files)

    inst_union: List[str] = []
    for p in installed_files:
        o = read_json(p)
        if isinstance(o, dict):
            inst_union.extend(extract_tools_from_obj(o))
    out["tools_installed"]["tool_names_union"] = sorted(set(inst_union))

    tmp_files = list_json_files(tmp_dir)
    out["tools_tmp"]["files"] = [os.path.basename(p) for p in tmp_files]
    out["tools_tmp"]["json_count"] = len(tmp_files)

    tmp_union: List[str] = []
    for p in tmp_files:
        o = read_json(p)
        if isinstance(o, dict):
            tmp_union.extend(extract_tools_from_obj(o))
    out["tools_tmp"]["tool_names_union"] = sorted(set(tmp_union))

    return out


def write_fsr_inputs_to_case(case_dir: str, run_id: str, fsr_inputs: Dict[str, Any], bundle: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Writes:
      - metadata/fsr/fsr_inputs_<run_id>.json
    Optionally:
      - metadata/fsr/fsr_bundle_<run_id>.json

    Returns absolute paths and write status.
    """
    run_id = (run_id or "R1").strip() or "R1"
    out_dir = os.path.join(case_dir, "metadata", "fsr")
    os.makedirs(out_dir, exist_ok=True)

    out_inputs_abs = os.path.join(out_dir, f"fsr_inputs_{run_id}.json")
    ok_inputs = write_json_atomic(out_inputs_abs, {
        "schema": "nics_fsr_inputs_v1",
        "generated_at_utc": utc_now_iso(),
        "run_id": run_id,
        "case_dir": case_dir,
        "inputs": fsr_inputs,
    })

    out_bundle_abs = None
    ok_bundle = None
    if bundle is not None:
        out_bundle_abs = os.path.join(out_dir, f"fsr_bundle_{run_id}.json")
        ok_bundle = write_json_atomic(out_bundle_abs, bundle)

    return {
        "written": {
            "fsr_inputs": {"path": out_inputs_abs, "ok": ok_inputs},
            "fsr_bundle": {"path": out_bundle_abs, "ok": ok_bundle},
        }
    }


def write_analysis_copy_to_case(case_dir: str, run_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    run_id = (run_id or "R1").strip() or "R1"
    out_abs = os.path.join(case_dir, "analysis", f"analyze_case_{run_id}.json")
    ok = write_json_atomic(out_abs, payload)
    return {"path": out_abs, "ok": ok}


# ============================================================
# Alerts invariants
# ============================================================

def pick_latest_alerts_store(alerts_root: str) -> Optional[str]:
    if not alerts_root or not os.path.isdir(alerts_root):
        return None
    dirs = []
    for name in os.listdir(alerts_root):
        if name.startswith("ALERTS-"):
            p = os.path.join(alerts_root, name)
            if os.path.isdir(p):
                dirs.append(name)
    if not dirs:
        return None
    dirs.sort(reverse=True)
    return os.path.join(alerts_root, dirs[0])


def extract_alert_invariants_from_obj(obj: dict) -> Dict[str, str]:
    inv: Dict[str, str] = {}
    inv["alert_utc"] = str(obj.get("ts_utc") or obj.get("timestamp") or "")
    inv["wazuh_rule_id"] = str(obj.get("rule_id") or (obj.get("rule", {}) or {}).get("id") or "")
    inv["wazuh_level"] = str(obj.get("rule_level") or (obj.get("rule", {}) or {}).get("level") or "")
    inv["signature"] = str(obj.get("signature") or (obj.get("rule", {}) or {}).get("description") or "")
    inv["protocol"] = str(obj.get("protocol") or (obj.get("data", {}) or {}).get("proto") or "")

    try:
        src = obj.get("src", {}) or {}
        dst = obj.get("dst", {}) or {}
        inv["direction"] = f"{src.get('ip','')} -> {dst.get('ip','')}".strip()
    except Exception:
        inv["direction"] = ""

    agent = obj.get("agent", {}) or {}
    inv["agent"] = f"{agent.get('name','')} ({agent.get('ip','')})".strip()

    sid = obj.get("signature_id") or obj.get("sig_id") or (obj.get("rule", {}) or {}).get("id")
    if sid is not None:
        inv["suricata_signature_id"] = str(sid)
    rev = obj.get("rev")
    if rev is not None:
        inv["suricata_rev"] = str(rev)

    if obj.get("event_id"):
        inv["event_id"] = str(obj.get("event_id"))

    return inv


def _pick_best_alert_from_alerts_store(alerts_root: str, alert_epoch_anchor: Optional[float], window_s: int = 120) -> Optional[dict]:
    latest = pick_latest_alerts_store(alerts_root)
    if not latest:
        return None

    alerts_jsonl = os.path.join(latest, "alerts.jsonl")
    events = read_jsonl(alerts_jsonl)
    if not events:
        return None

    def lvl(obj: dict) -> int:
        v = obj.get("rule_level")
        try:
            return int(v) if v is not None else -1
        except Exception:
            return -1

    def ts(obj: dict) -> Optional[float]:
        if obj.get("ts_epoch") is not None:
            try:
                return float(obj.get("ts_epoch"))
            except Exception:
                pass
        t = (obj.get("ts_utc") or "").strip()
        if t:
            x = iso_to_epoch(t)
            return x if x > 0 else None
        return None

    if alert_epoch_anchor is not None and alert_epoch_anchor > 0:
        cand: List[Tuple[int, float, dict]] = []
        for obj in events:
            if not isinstance(obj, dict):
                continue
            t = ts(obj)
            if t is None:
                continue
            dist = abs(t - alert_epoch_anchor)
            if dist <= float(window_s):
                cand.append((lvl(obj), dist, obj))
        if cand:
            # choose highest level, then nearest
            cand.sort(key=lambda x: (x[0], -x[1]), reverse=True)
            top_lvl = cand[0][0]
            same = [c for c in cand if c[0] == top_lvl]
            same.sort(key=lambda x: x[1])
            return same[0][2]

    best = None
    best_level = -1
    best_ts = None
    for obj in events:
        if not isinstance(obj, dict):
            continue
        l = lvl(obj)
        t = ts(obj)
        if l > best_level:
            best_level, best_ts, best = l, t, obj
        elif l == best_level:
            if alert_epoch_anchor and t is not None:
                if best_ts is None:
                    best_ts, best = t, obj
                else:
                    if abs(t - alert_epoch_anchor) < abs(best_ts - alert_epoch_anchor):
                        best_ts, best = t, obj
            else:
                if t is not None and (best_ts is None or t < best_ts):
                    best_ts, best = t, obj
    return best


def extract_alert_invariants(case_dir: str, alerts_root: Optional[str], alert_epoch_anchor: Optional[float]) -> Dict[str, str]:
    alerts_dir = os.path.join(case_dir, "alerts")
    best_obj = None
    best_level = -1
    best_ts = None

    if os.path.isdir(alerts_dir):
        files = [f for f in os.listdir(alerts_dir) if f.endswith(".json")]
        files.sort()
        for fn in files:
            obj = read_json(os.path.join(alerts_dir, fn))
            if not isinstance(obj, dict):
                continue

            lvl = obj.get("rule_level")
            try:
                lvl_i = int(lvl) if lvl is not None else -1
            except Exception:
                lvl_i = -1

            ts = obj.get("ts_epoch")
            try:
                ts_f = float(ts) if ts is not None else None
            except Exception:
                ts_f = None

            if lvl_i > best_level:
                best_level, best_ts, best_obj = lvl_i, ts_f, obj
            elif lvl_i == best_level and ts_f is not None and (best_ts is None or ts_f < best_ts):
                best_ts, best_obj = ts_f, obj

        if best_obj:
            return extract_alert_invariants_from_obj(best_obj)

    if alerts_root:
        picked = _pick_best_alert_from_alerts_store(alerts_root, alert_epoch_anchor, window_s=120)
        if picked:
            return extract_alert_invariants_from_obj(picked)

    return {}


# ============================================================
# Time sync (E2) + custody verify (E3)
# ============================================================

def read_e2_max_offset_ms(case_dir: str) -> Optional[float]:
    p = os.path.join(case_dir, "metadata", "time_sync.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        v = data.get("max_offset_ms", None)
        return float(v) if v is not None else None
    except Exception:
        return None


def verify_custody_chain(case_dir: str) -> Optional[bool]:
    path = os.path.join(case_dir, "chain_of_custody.log")
    if not os.path.isfile(path):
        return None

    def sha256_hex(b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()

    prev_expected = "0" * 64
    any_line = False

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = (line or "").strip()
                if not line:
                    continue
                any_line = True
                try:
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        return False
                except Exception:
                    return False

                prev = str(entry.get("prev_hash") or "")
                if prev != prev_expected:
                    return False

                entry_wo = dict(entry)
                entry_hash = str(entry_wo.pop("entry_hash", "") or "")
                payload = json.dumps(entry_wo, sort_keys=True, ensure_ascii=False).encode("utf-8")
                computed = sha256_hex(payload)
                if entry_hash != computed:
                    return False

                prev_expected = entry_hash

        return True if any_line else None
    except Exception:
        return None


# ============================================================
# Evidence quality (E1..E4)
# ============================================================

def evidence_quality(case_dir: str, manifest: dict) -> Dict[str, Any]:
    def has_prefix(pref: str) -> bool:
        for a in (manifest or {}).get("artifacts", []) or []:
            if not isinstance(a, dict):
                continue
            rp = str(a.get("rel_path") or "")
            if rp.startswith(pref):
                return True
        return False

    def has_type(t: str) -> bool:
        for a in (manifest or {}).get("artifacts", []) or []:
            if not isinstance(a, dict):
                continue
            if str(a.get("type") or "") == t:
                return True
        return False

    e1_manifest = os.path.isfile(os.path.join(case_dir, "manifest.json"))
    e1_disk = bool(os.path.isdir(os.path.join(case_dir, "disk")) or has_prefix("disk/") or has_type("disk_raw"))
    network_dir = os.path.join(case_dir, "network")
    e1_network = bool(os.path.isdir(network_dir) or has_prefix("network/") or bool(_walk_pcaps(network_dir)))
    e1_required = bool(e1_manifest and e1_disk and e1_network)

    e2 = read_e2_max_offset_ms(case_dir)

    sha_any = any(bool(a.get("sha256")) for a in (manifest or {}).get("artifacts", []) or [] if isinstance(a, dict))
    custody_ok = verify_custody_chain(case_dir)
    e4 = bool(os.path.isdir(os.path.join(case_dir, "derived")) and os.path.isdir(os.path.join(case_dir, "analysis")))

    return {
        "e1_required_present": e1_required,
        "e1_has_disk": e1_disk,
        "e1_has_network": e1_network,
        "e2_max_offset_skew_ms": e2,
        "e3_manifest_has_sha256": bool(sha_any),
        "e3_custody_chained_verified": custody_ok,
        "e4_primary_derived_separation": e4,
    }


# ============================================================
# PCAP inference fallback
# ============================================================

def _infer_pcap_events_from_files(case_dir: str, run_id: str) -> Tuple[Optional[dict], Optional[dict], bool]:
    pcaps = _walk_pcaps(os.path.join(case_dir, "network"))
    if not pcaps:
        return (None, None, False)

    mn, mx = _pcap_mtime_range(pcaps)
    if mn is None or mx is None:
        return (None, None, False)

    start_ev = {"run_id": run_id, "event": "pcap_start_inferred", "ts_epoch": mn}
    pres_ev = {"run_id": run_id, "event": "pcap_preserved_inferred", "ts_epoch": mx}
    return (start_ev, pres_ev, True)


# ============================================================
# T_first_sealed / T_case_sealed
# ============================================================

def _sealed_epochs(events: List[dict], run_id: str) -> List[float]:
    sealed_names = {
        "traffic_stopped",
        "ot_export_preserved",
        "memory_preserved",
        "disk_preserved",
    }
    out: List[float] = []
    for e in events:
        if e.get("run_id") != run_id:
            continue
        if str(e.get("event") or "") not in sealed_names:
            continue
        ts = _event_ts_epoch(e)
        if ts is not None:
            out.append(ts)
    out.sort()
    return out


def _t_first_case_sealed_s(alert_ev: Optional[dict], events: List[dict], run_id: str) -> Tuple[Optional[float], Optional[float]]:
    if not alert_ev:
        return (None, None)
    a = _event_ts_epoch(alert_ev)
    if a is None or a <= 0:
        return (None, None)

    sealed = _sealed_epochs(events, run_id)
    if not sealed:
        return (None, None)

    first = None
    last = None
    for ts in sealed:
        if ts >= a:
            first = ts
            break
    for ts in reversed(sealed):
        if ts >= a:
            last = ts
            break

    if first is None or last is None:
        return (None, None)
    return (round(first - a, 3), round(last - a, 3))


# ============================================================
# Per-VM M2 breakdown
# ============================================================

def _per_vm_m2(events: List[dict], run_id: str, alert_ev: Optional[dict]) -> Dict[str, Any]:
    a = _event_ts_epoch(alert_ev) if alert_ev else None
    if a is None or a <= 0:
        return {}

    def vm_id_of(e: dict) -> Optional[str]:
        meta = e.get("meta") or {}
        if isinstance(meta, dict):
            v = meta.get("vm_id")
            return str(v) if v else None
        return None

    by_vm: Dict[str, List[dict]] = {}
    for e in events:
        if e.get("run_id") != run_id:
            continue
        vid = vm_id_of(e)
        if not vid:
            continue
        by_vm.setdefault(vid, []).append(e)

    def first(vm_events: List[dict], name: str) -> Optional[dict]:
        for e in vm_events:
            if e.get("event") == name:
                return e
        return None

    def last(vm_events: List[dict], name: str) -> Optional[dict]:
        best = None
        best_ts = None
        for e in vm_events:
            if e.get("event") != name:
                continue
            ts = _event_ts_epoch(e)
            if ts is None:
                best = e
                continue
            if best_ts is None or ts > best_ts:
                best, best_ts = e, ts
        return best

    out: Dict[str, Any] = {}
    for vid, lst in by_vm.items():
        lst_sorted = sorted(lst, key=lambda x: _event_ts_epoch(x) or 0.0)

        t_start = first(lst_sorted, "traffic_capture_started") or first(lst_sorted, "traffic_start")
        t_stop = last(lst_sorted, "traffic_stopped") or last(lst_sorted, "traffic_capture_stopped")

        ot_pres = last(lst_sorted, "ot_export_preserved")

        mem_start = first(lst_sorted, "memory_start")
        mem_pres = last(lst_sorted, "memory_preserved")
        disk_start = first(lst_sorted, "disk_start")
        disk_pres = last(lst_sorted, "disk_preserved")

        def dt(ev: Optional[dict]) -> Optional[float]:
            if not ev:
                return None
            ts = _event_ts_epoch(ev)
            if ts is None:
                return None
            return round(ts - a, 3)

        out[vid] = {
            "traffic": {
                "alert_to_capture_start_s": dt(t_start),
                "alert_to_traffic_stopped_s": dt(t_stop),
                "pcap_rel": ((t_stop or {}).get("meta") or {}).get("pcap_rel") if isinstance((t_stop or {}).get("meta"), dict) else None,
                "packets_written": ((t_stop or {}).get("meta") or {}).get("packets_written") if isinstance((t_stop or {}).get("meta"), dict) else None,
                "capture_duration_s": ((t_stop or {}).get("meta") or {}).get("capture_duration_s") if isinstance((t_stop or {}).get("meta"), dict) else None,
            },
            "ot_export": {
                "alert_to_ot_export_preserved_s": dt(ot_pres),
                "industrial_export_rel": ((ot_pres or {}).get("meta") or {}).get("industrial_export_rel") if isinstance((ot_pres or {}).get("meta"), dict) else None,
                "records_exported": ((ot_pres or {}).get("meta") or {}).get("records_exported") if isinstance((ot_pres or {}).get("meta"), dict) else None,
            },
            "memory": {
                "alert_to_memory_start_s": dt(mem_start),
                "alert_to_memory_preserved_s": dt(mem_pres),
                "mem_rel": ((mem_pres or {}).get("meta") or {}).get("rel") if isinstance((mem_pres or {}).get("meta"), dict) else None,
                "size": ((mem_pres or {}).get("meta") or {}).get("size") if isinstance((mem_pres or {}).get("meta"), dict) else None,
            },
            "disk": {
                "alert_to_disk_start_s": dt(disk_start),
                "alert_to_disk_preserved_s": dt(disk_pres),
                "disk_rel": ((disk_pres or {}).get("meta") or {}).get("rel") if isinstance((disk_pres or {}).get("meta"), dict) else None,
                "size": ((disk_pres or {}).get("meta") or {}).get("size") if isinstance((disk_pres or {}).get("meta"), dict) else None,
            },
        }

    return out


# ============================================================
# Summary builder (for table filling via JSON)
# ============================================================

def build_summary(rows: List[dict]) -> dict:
    runs = []
    for r in rows:
        runs.append({
            "case": r.get("case"),
            "case_path": r.get("case_path"),
            "run_id": r.get("run_id"),
            "m1": r.get("m1"),
            "m2": r.get("m2"),
            "m3": r.get("m3"),
            "m4": r.get("m4"),
            "evidence_quality": r.get("evidence_quality"),
            "invariants": r.get("invariants"),
            "fsr_inputs": r.get("fsr_inputs"),
            "debug": r.get("debug"),
            "notes": r.get("notes", []),
        })

    def at(i: int) -> Optional[dict]:
        return runs[i] if i < len(runs) else None

    return {
        "runs": runs,
        "table_view": {
            "run1": at(0),
            "run2": at(1),
            "run3": at(2),
        },
    }


# ============================================================
# Core: build record per case/run
# ============================================================

def build_run_record(case_dir: str, case_name: str, run_id: str, alerts_root: Optional[str]) -> Dict[str, Any]:
    manifest = read_json(os.path.join(case_dir, "manifest.json")) or {}
    events = read_jsonl(os.path.join(case_dir, "metadata", "pipeline_events.jsonl"))

    notes: List[str] = []

    alert = find_event_any(events, run_id, ["alert"], mode="first")
    if not alert:
        notes.append("alert event not found in metadata/pipeline_events.jsonl (M2 latencies may be null)")

    alert_epoch_anchor = _event_ts_epoch(alert) if alert else None

    mem_start = find_event_any(events, run_id, ["memory_start"], mode="first")
    mem_pres = find_event_any(events, run_id, ["memory_preserved"], mode="last")
    disk_start = find_event_any(events, run_id, ["disk_start"], mode="first")
    disk_pres = find_event_any(events, run_id, ["disk_preserved"], mode="last")

    pcap_start = find_event_any(events, run_id, ["pcap_start", "traffic_capture_started", "traffic_start"], mode="first")
    pcap_pres = find_event_any(events, run_id, ["pcap_preserved", "traffic_stopped", "traffic_capture_stopped"], mode="last")

    inferred = False
    if pcap_start is None or pcap_pres is None:
        inf_start, inf_pres, inf_flag = _infer_pcap_events_from_files(case_dir, run_id)
        inferred = inf_flag
        if inf_flag:
            notes.append("pcap timings inferred from filesystem mtime (events not logged)")
        if pcap_start is None:
            pcap_start = inf_start
        if pcap_pres is None:
            pcap_pres = inf_pres

    ot_pres = find_event_any(events, run_id, ["ot_export_preserved"], mode="last")
    t_first_sealed_s, t_case_sealed_s = _t_first_case_sealed_s(alert, events, run_id)

    sizes = manifest_sizes(manifest, case_dir)
    inv = extract_alert_invariants(case_dir, alerts_root, alert_epoch_anchor)
    eq = evidence_quality(case_dir, manifest)
    m2_per_vm = _per_vm_m2(events, run_id, alert)

    fsr_inputs = analyze_ir_preserved_inputs(case_dir)

    def _pcap_source(ev: Optional[dict]) -> str:
        if inferred:
            return "inferred"
        if not ev:
            return "missing"
        name = str(ev.get("event") or "")
        if name.startswith("pcap_") or "traffic" in name:
            return "logged"
        return "unknown"

    return {
        "case": case_name,
        "case_path": case_dir,
        "run_id": run_id,
        "notes": notes,
        "debug": {
            "pcap_events_inferred_from_fs": inferred,
            "has_alert_event": bool(alert),
            "events_count": len(events),
            "alerts_source": (
                "case/alerts"
                if os.path.isdir(os.path.join(case_dir, "alerts")) and os.listdir(os.path.join(case_dir, "alerts"))
                else ("alerts_store" if alerts_root else "none")
            ),
        },
        "m1": {
            "deploy_time_s": None,
            "teardown_redeploy_time_s": None,
        },
        "m2": {
            "alert_to_pcap_start_s": latency_s(alert, pcap_start),
            "alert_to_pcap_preserved_s": latency_s(alert, pcap_pres),
            "alert_to_memory_start_s": latency_s(alert, mem_start),
            "alert_to_memory_preserved_s": latency_s(alert, mem_pres),
            "alert_to_disk_start_s": latency_s(alert, disk_start),
            "alert_to_disk_preserved_s": latency_s(alert, disk_pres),
            "alert_to_ot_export_preserved_s": latency_s(alert, ot_pres),
            "pcap_start_source": _pcap_source(pcap_start),
            "pcap_preserved_source": _pcap_source(pcap_pres),
            "t_first_sealed_s": t_first_sealed_s,
            "t_case_sealed_s": t_case_sealed_s,
            "m2_per_vm": m2_per_vm,
        },
        "m3": {
            "pcap_sizes_bytes": sizes["pcap"],
            "pcap_count": len(sizes["pcap"]),
            "pcap_total_bytes": sum(sizes["pcap"]) if sizes["pcap"] else None,
            "memory_max_gib": bytes_to_gib(max(sizes["mem"]) if sizes["mem"] else None),
            "disk_max_gib": bytes_to_gib(max(sizes["disk"]) if sizes["disk"] else None),
            "ot_max_bytes": (max(sizes["ot"]) if sizes["ot"] else None),
        },
        "m4": {
            "failures_count": count_failures(events, run_id),
        },
        "evidence_quality": eq,
        "invariants": inv,
        "fsr_inputs": fsr_inputs,
    }


# ============================================================
# Output formats (kept for compatibility)
# ============================================================

def output_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def output_jsonl(rows: List[dict]) -> None:
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))


def flatten_for_csv(r: Dict[str, Any]) -> Dict[str, Any]:
    inv = r.get("invariants") or {}
    m1 = r.get("m1") or {}
    m2 = r.get("m2") or {}
    m3 = r.get("m3") or {}
    m4 = r.get("m4") or {}
    eq = r.get("evidence_quality") or {}
    dbg = r.get("debug") or {}
    fsr = r.get("fsr_inputs") or {}

    scenario = (fsr.get("scenario") or {})
    ti = (fsr.get("tools_installed") or {})
    tt = (fsr.get("tools_tmp") or {})

    return {
        "case": r.get("case"),
        "run_id": r.get("run_id"),
        "case_path": r.get("case_path"),

        "m1_deploy_time_s": m1.get("deploy_time_s"),
        "m1_teardown_redeploy_time_s": m1.get("teardown_redeploy_time_s"),

        "m2_alert_to_pcap_start_s": m2.get("alert_to_pcap_start_s"),
        "m2_alert_to_pcap_preserved_s": m2.get("alert_to_pcap_preserved_s"),
        "m2_alert_to_memory_start_s": m2.get("alert_to_memory_start_s"),
        "m2_alert_to_memory_preserved_s": m2.get("alert_to_memory_preserved_s"),
        "m2_alert_to_disk_start_s": m2.get("alert_to_disk_start_s"),
        "m2_alert_to_disk_preserved_s": m2.get("alert_to_disk_preserved_s"),
        "m2_alert_to_ot_export_preserved_s": m2.get("alert_to_ot_export_preserved_s"),
        "m2_pcap_start_source": m2.get("pcap_start_source"),
        "m2_pcap_preserved_source": m2.get("pcap_preserved_source"),
        "m2_t_first_sealed_s": m2.get("t_first_sealed_s"),
        "m2_t_case_sealed_s": m2.get("t_case_sealed_s"),

        "m3_pcap_sizes_bytes": ";".join(str(x) for x in (m3.get("pcap_sizes_bytes") or [])),
        "m3_pcap_count": m3.get("pcap_count"),
        "m3_pcap_total_bytes": m3.get("pcap_total_bytes"),
        "m3_memory_max_gib": m3.get("memory_max_gib"),
        "m3_disk_max_gib": m3.get("disk_max_gib"),
        "m3_ot_max_bytes": m3.get("ot_max_bytes"),

        "m4_failures_count": m4.get("failures_count"),

        "e1_required_present": eq.get("e1_required_present"),
        "e1_has_disk": eq.get("e1_has_disk"),
        "e1_has_network": eq.get("e1_has_network"),
        "e2_max_offset_skew_ms": eq.get("e2_max_offset_skew_ms"),
        "e3_manifest_has_sha256": eq.get("e3_manifest_has_sha256"),
        "e3_custody_chained_verified": eq.get("e3_custody_chained_verified"),
        "e4_primary_derived_separation": eq.get("e4_primary_derived_separation"),

        "inv_alert_utc": inv.get("alert_utc"),
        "inv_wazuh_rule_id": inv.get("wazuh_rule_id"),
        "inv_wazuh_level": inv.get("wazuh_level"),
        "inv_signature": inv.get("signature"),
        "inv_protocol": inv.get("protocol"),
        "inv_direction": inv.get("direction"),
        "inv_agent": inv.get("agent"),
        "inv_event_id": inv.get("event_id"),

        "debug_pcap_inferred": dbg.get("pcap_events_inferred_from_fs"),
        "debug_has_alert_event": dbg.get("has_alert_event"),
        "debug_events_count": dbg.get("events_count"),
        "debug_alerts_source": dbg.get("alerts_source"),

        "fsr_scenario_present": scenario.get("present"),
        "fsr_scenario_nodes_count": scenario.get("nodes_count"),
        "fsr_scenario_edges_count": scenario.get("edges_count"),
        "fsr_installed_json_count": ti.get("json_count"),
        "fsr_tmp_json_count": tt.get("json_count"),
    }


def output_csv(rows: List[dict]) -> None:
    flat = [flatten_for_csv(r) for r in rows]
    if not flat:
        return
    fieldnames = list(flat[0].keys())
    w = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    w.writeheader()
    for r in flat:
        w.writerow(r)


# ============================================================
# Main
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze NICS evidence_store CASE-* directories and extract DFIR metrics.")
    ap.add_argument("--evidence-root", required=True, help="Path to evidence_store (contains CASE-* directories).")
    ap.add_argument("--limit", type=int, default=1, help="How many newest cases to analyze (default: 1).")
    ap.add_argument("--run-id", default="R1", help="Run identifier inside pipeline_events.jsonl (default: R1).")
    ap.add_argument("--alerts-root", default=None, help="Path to alerts_store (optional). If omitted, auto-detect.")
    ap.add_argument("--format", choices=["json", "jsonl", "csv"], default="json", help="Output format (stdout).")
    ap.add_argument("--out", default=None, help="Write a single JSON file to this path (optional).")

    # Write into CASE
    ap.add_argument("--write-case-fsr", action="store_true", help="Write FSR inputs analysis into CASE-*/metadata/fsr/.")
    ap.add_argument("--write-case-fsr-bundle", action="store_true", help="Also write full bundle JSON into CASE-*/metadata/fsr/.")
    ap.add_argument("--write-case-analysis-copy", action="store_true", help="Also write a copy of final payload into CASE-*/analysis/.")

    # NEW: register written artifacts in manifest/pipeline/custody/digest
    ap.add_argument("--register-written-artifacts", action="store_true",
                    help="When writing files into CASE, also register them in manifest, pipeline_events, chain_of_custody, and update digest.")

    args = ap.parse_args()

    evidence_root = resolve_evidence_root(args.evidence_root)
    cases = pick_cases(evidence_root, args.limit)
    if not cases:
        payload = {"error": "no CASE-* directories found", "evidence_root": evidence_root}
        if args.out:
            out_path = os.path.abspath(args.out)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        else:
            output_json(payload)
        return

    alerts_root = args.alerts_root
    if alerts_root is None:
        parent = os.path.abspath(os.path.join(evidence_root, os.pardir))
        cand = os.path.join(parent, "alerts_store")
        alerts_root = cand if os.path.isdir(cand) else None
    elif alerts_root:
        alerts_root = os.path.abspath(alerts_root)

    rows: List[dict] = []
    for c in cases:
        case_dir = os.path.join(evidence_root, c)
        rows.append(build_run_record(case_dir, c, args.run_id, alerts_root))

    payload = {
        "evidence_root": evidence_root,
        "alerts_root": alerts_root,
        "limit": args.limit,
        "run_id": args.run_id,
        "cases": rows,
        "summary": build_summary(rows),
    }

    # Write into CASE
    if args.write_case_fsr or args.write_case_fsr_bundle or args.write_case_analysis_copy:
        for r in rows:
            case_dir = r.get("case_path")
            run_id = (r.get("run_id") or args.run_id or "R1").strip() or "R1"
            if not case_dir or not os.path.isdir(case_dir):
                continue

            written_paths: List[Tuple[str, str, str]] = []
            # (rel_path, artifact_type, event_name)

            if args.write_case_fsr or args.write_case_fsr_bundle:
                fsr_inputs = r.get("fsr_inputs") or {}
                bundle = payload if args.write_case_fsr_bundle else None
                res = write_fsr_inputs_to_case(case_dir, run_id, fsr_inputs, bundle=bundle)

                fsr_inputs_abs = ((res.get("written") or {}).get("fsr_inputs") or {}).get("path")
                if fsr_inputs_abs:
                    rel = os.path.relpath(fsr_inputs_abs, case_dir)
                    written_paths.append((rel, "fsr_inputs", "fsr_inputs_written"))

                fsr_bundle_abs = ((res.get("written") or {}).get("fsr_bundle") or {}).get("path")
                if fsr_bundle_abs:
                    rel = os.path.relpath(fsr_bundle_abs, case_dir)
                    written_paths.append((rel, "fsr_bundle", "fsr_bundle_written"))

            if args.write_case_analysis_copy:
                res = write_analysis_copy_to_case(case_dir, run_id, payload)
                abs_p = res.get("path")
                if abs_p:
                    rel = os.path.relpath(abs_p, case_dir)
                    written_paths.append((rel, "analysis_report", "analysis_report_written"))

            if args.register_written_artifacts:
                for rel_path, a_type, ev in written_paths:
                    register_written_artifact(
                        case_dir=case_dir,
                        run_id=run_id,
                        rel_path=rel_path,
                        artifact_type=a_type,
                        event_name=ev,
                        actor="analyze_case",
                        meta_extra={"run_id": run_id},
                    )

    # Always one JSON file if --out is provided
    if args.out:
        out_path = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return

    if args.format == "json":
        output_json(payload)
    elif args.format == "jsonl":
        output_jsonl(rows)
    else:
        output_csv(rows)


if __name__ == "__main__":
    main()