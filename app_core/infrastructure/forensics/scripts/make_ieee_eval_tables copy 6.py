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

Notes:
- M1 (deploy/teardown) is not computable unless you log deploy events. This script reports None for M1.
- PCAP start/preserved: uses explicit pcap_* events if present; otherwise falls back to traffic_capture_*;
  otherwise infers by filesystem mtime range (marked as inferred in debug fields + m2 sources).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------
# IO helpers
# ---------------------------

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


# ---------------------------
# CASE selection
# ---------------------------

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


# ---------------------------
# Events helpers
# ---------------------------

def _event_ts_epoch(e: dict) -> Optional[float]:
    try:
        v = e.get("ts_epoch")
        if v is None:
            return None
        x = float(v)
        return x if x > 0 else None
    except Exception:
        return None


def find_first_event(events: List[dict], run_id: str, event_name: str) -> Optional[dict]:
    """First occurrence in file order."""
    for e in events:
        if (e.get("run_id") == run_id) and (e.get("event") == event_name):
            return e
    return None


def find_last_event(events: List[dict], run_id: str, event_name: str) -> Optional[dict]:
    """Last occurrence by ts_epoch (fallback: file order if ts missing)."""
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


def find_event_any(
    events: List[dict],
    run_id: str,
    names: List[str],
    mode: str = "first",
) -> Optional[dict]:
    """
    Try multiple event names in priority order.
    mode:
      - "first": returns first matching event (per chosen name, in file order)
      - "last": returns last by ts_epoch (per chosen name)
    """
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
        a = float(alert.get("ts_epoch") or 0)
        b = float(other.get("ts_epoch") or 0)
        if a <= 0 or b <= 0:
            return None
        return round(b - a, 3)
    except Exception:
        return None


# ---------------------------
# Sizes / artifacts
# ---------------------------

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
    """
    1) manifest.json artifacts if present.
    2) PCAP fallback to filesystem:
       - CASE/network/traffic_preserved/**.pcap
       - CASE/network/**.pcap
    """
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
        preserve_root = os.path.join(case_dir, "network", "traffic_preserved", "full_scenario_captures")
        pcaps = _walk_pcaps(preserve_root)
        if not pcaps:
            pcaps = _walk_pcaps(os.path.join(case_dir, "network"))
        for p in pcaps:
            try:
                out["pcap"].append(int(os.path.getsize(p)))
            except Exception:
                continue

    return out


# ---------------------------
# Failures / retries
# ---------------------------

def count_failures(events: List[dict], run_id: str) -> int:
    c = 0
    for e in events:
        if e.get("run_id") != run_id:
            continue
        ev = str(e.get("event") or "")
        if ev.endswith("_failed") or "failed" in ev:
            c += 1
    return c


# ---------------------------
# Alerts invariants
# ---------------------------

def pick_latest_alerts_store(alerts_root: str) -> Optional[str]:
    """
    alerts_root/
      ALERTS-YYYYMMDD-HHMMSSZ/
        alerts.jsonl
        triage.jsonl
    """
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

    return inv


def extract_alert_invariants(case_dir: str, alerts_root: Optional[str]) -> Dict[str, str]:
    """
    Preferred: CASE/alerts/*.json (choose representative alert: max rule_level, then earliest ts_epoch).
    Fallback: latest alerts_store ALERTS-.../alerts.jsonl (choose max rule_level).
    """
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
        latest = pick_latest_alerts_store(alerts_root)
        if latest:
            alerts_jsonl = os.path.join(latest, "alerts.jsonl")
            events = read_jsonl(alerts_jsonl)
            if events:
                best = None
                best_level = -1
                for obj in events:
                    if not isinstance(obj, dict):
                        continue
                    lvl = obj.get("rule_level")
                    try:
                        lvl_i = int(lvl) if lvl is not None else -1
                    except Exception:
                        lvl_i = -1
                    if lvl_i > best_level:
                        best_level, best = lvl_i, obj
                if best:
                    return extract_alert_invariants_from_obj(best)

    return {}


# ---------------------------
# Time sync (E2) + custody verify (E3)
# ---------------------------




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
    """
    Best-effort verification of chain_of_custody.log hash chaining.
    Returns:
      - True if all entries verify
      - False if any mismatch
      - None if file missing/empty/unreadable
    """
    path = os.path.join(case_dir, "chain_of_custody.log")
    if not os.path.isfile(path):
        return None

    try:
        import hashlib
    except Exception:
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


# ---------------------------
# Evidence quality (E1..E4)
# ---------------------------

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
    preserve_root = os.path.join(network_dir, "traffic_preserved", "full_scenario_captures")
    e1_network = bool(os.path.isdir(network_dir) or has_prefix("network/") or bool(_walk_pcaps(preserve_root)))
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


# ---------------------------
# PCAP inference fallback
# ---------------------------

def _infer_pcap_events_from_files(case_dir: str, run_id: str) -> Tuple[Optional[dict], Optional[dict], bool]:
    """
    If pcap_start/pcap_preserved are missing, infer from filesystem mtime.
    Returns (start_event, preserved_event, inferred_flag).
    """
    preserve_root = os.path.join(case_dir, "network", "traffic_preserved", "full_scenario_captures")
    pcaps = _walk_pcaps(preserve_root)
    if not pcaps:
        pcaps = _walk_pcaps(os.path.join(case_dir, "network"))
    if not pcaps:
        return (None, None, False)

    mn, mx = _pcap_mtime_range(pcaps)
    if mn is None or mx is None:
        return (None, None, False)

    start_ev = {"run_id": run_id, "event": "pcap_start_inferred", "ts_epoch": mn}
    pres_ev = {"run_id": run_id, "event": "pcap_preserved_inferred", "ts_epoch": mx}
    return (start_ev, pres_ev, True)


# ---------------------------
# Summary builder (for table filling via JSON)
# ---------------------------

def build_summary(rows: List[dict]) -> dict:
    """
    Stable JSON view for tables:
      summary.runs: list of per-case records
      summary.table_view: run1/run2/run3 shortcut views (or None)
    """
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


# ---------------------------
# Core: build record per case/run
# ---------------------------

def build_run_record(case_dir: str, case_name: str, run_id: str, alerts_root: Optional[str]) -> Dict[str, Any]:
    manifest = read_json(os.path.join(case_dir, "manifest.json")) or {}
    events = read_jsonl(os.path.join(case_dir, "metadata", "pipeline_events.jsonl"))

    notes: List[str] = []

    # alert baseline (from pipeline if present; otherwise absent -> latencies None)
    alert = find_event_any(events, run_id, ["alert"], mode="first")
    if not alert:
        notes.append("alert event not found in metadata/pipeline_events.jsonl (M2 latencies may be null)")

    # memory and disk
    mem_start = find_event_any(events, run_id, ["memory_start"], mode="first")
    mem_pres = find_event_any(events, run_id, ["memory_preserved"], mode="last")
    disk_start = find_event_any(events, run_id, ["disk_start"], mode="first")
    disk_pres = find_event_any(events, run_id, ["disk_preserved"], mode="last")

    # pcap start/preserved (prefer explicit, then traffic_* events, else infer)
    pcap_start = find_event_any(
        events,
        run_id,
        ["pcap_start", "traffic_capture_started", "traffic_start"],
        mode="first",
    )
    pcap_pres = find_event_any(
        events,
        run_id,
        ["pcap_preserved", "traffic_stopped", "traffic_capture_stopped"],
        mode="last",
    )

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

    sizes = manifest_sizes(manifest, case_dir)
    inv = extract_alert_invariants(case_dir, alerts_root)
    eq = evidence_quality(case_dir, manifest)

    # pcap timing sources
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
    }


# ---------------------------
# Output formats (kept for compatibility)
# ---------------------------

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

        "debug_pcap_inferred": dbg.get("pcap_events_inferred_from_fs"),
        "debug_has_alert_event": dbg.get("has_alert_event"),
        "debug_events_count": dbg.get("events_count"),
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


# ---------------------------
# Main
# ---------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze NICS evidence_store CASE-* directories and extract DFIR metrics.")
    ap.add_argument("--evidence-root", required=True, help="Path to evidence_store (contains CASE-* directories).")
    ap.add_argument("--limit", type=int, default=1, help="How many newest cases to analyze (default: 1).")
    ap.add_argument("--run-id", default="R1", help="Run identifier inside pipeline_events.jsonl (default: R1).")
    ap.add_argument("--alerts-root", default=None, help="Path to alerts_store (optional). If omitted, auto-detect.")
    ap.add_argument("--format", choices=["json", "jsonl", "csv"], default="json", help="Output format (stdout).")
    ap.add_argument("--out", default=None, help="Write a single JSON file to this path (optional).")
    args = ap.parse_args()

    evidence_root = os.path.abspath(args.evidence_root)
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

    # Always one JSON file if --out is provided
    if args.out:
        out_path = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return

    # Backward compatible stdout formats
    if args.format == "json":
        output_json(payload)
    elif args.format == "jsonl":
        output_jsonl(rows)
    else:
        output_csv(rows)


if __name__ == "__main__":
    main()