#!/usr/bin/env python3
import argparse
import csv
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
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
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return out


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


def find_event(events: List[dict], run_id: str, event_name: str) -> Optional[dict]:
    for e in events:
        if e.get("run_id") == run_id and e.get("event") == event_name:
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


def bytes_to_gib(b: Optional[int]) -> Optional[float]:
    if b is None:
        return None
    try:
        return round(float(b) / (1024.0**3), 2)
    except Exception:
        return None


def manifest_sizes(manifest: dict) -> Dict[str, List[int]]:
    # agrupa por layer heurística usando rel_path prefijo
    out: Dict[str, List[int]] = {"pcap": [], "mem": [], "disk": [], "ot": []}
    for a in (manifest or {}).get("artifacts", []) or []:
        rp = str(a.get("rel_path") or "")
        sz = a.get("size")
        if sz is None:
            continue
        try:
            sz = int(sz)
        except Exception:
            continue

        low = rp.lower()
        if low.startswith("network/") and low.endswith(".pcap"):
            out["pcap"].append(sz)
        elif low.startswith("memory/") and (low.endswith(".lime") or "memdump" in low):
            out["mem"].append(sz)
        elif low.startswith("disk/") and (low.endswith(".raw") or "disk.final" in low or ".qcow2" in low):
            out["disk"].append(sz)
        elif low.startswith("industrial/"):
            out["ot"].append(sz)
    return out


def count_failures(events: List[dict], run_id: str) -> int:
    c = 0
    for e in events:
        if e.get("run_id") != run_id:
            continue
        ev = str(e.get("event") or "")
        if ev.endswith("_failed") or "failed" in ev:
            c += 1
    return c


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
    return inv


def extract_alert_invariants(case_dir: str, alerts_root: Optional[str]) -> Dict[str, str]:
    """
    1) Intenta CASE/.../alerts/*.json (si existe)
    2) Si no existe, intenta alerts_store más reciente: ALERTS-.../alerts.jsonl (primer evento)
    """
    # 1) case alerts/
    inv: Dict[str, str] = {}
    alerts_dir = os.path.join(case_dir, "alerts")
    if os.path.isdir(alerts_dir):
        files = [f for f in os.listdir(alerts_dir) if f.endswith(".json")]
        files.sort()
        if files:
            obj = read_json(os.path.join(alerts_dir, files[0]))
            if isinstance(obj, dict):
                return extract_alert_invariants_from_obj(obj)

    # 2) alerts_store latest
    if alerts_root:
        latest = pick_latest_alerts_store(alerts_root)
        if latest:
            alerts_jsonl = os.path.join(latest, "alerts.jsonl")
            events = read_jsonl(alerts_jsonl)
            if events:
                obj0 = events[0]
                if isinstance(obj0, dict):
                    return extract_alert_invariants_from_obj(obj0)

    return inv


def evidence_quality(case_dir: str, manifest: dict) -> Dict[str, Any]:
    def has_prefix(pref: str) -> bool:
        for a in (manifest or {}).get("artifacts", []) or []:
            rp = str(a.get("rel_path") or "")
            if rp.startswith(pref):
                return True
        return False

    def has_type(t: str) -> bool:
        for a in (manifest or {}).get("artifacts", []) or []:
            if str(a.get("type") or "") == t:
                return True
        return False

    # E1: artefactos mínimos
    e1 = all(
        [
            os.path.isfile(os.path.join(case_dir, "manifest.json")),
            os.path.isdir(os.path.join(case_dir, "disk")) or has_prefix("disk/") or has_type("disk_raw"),
        ]
    )
    # red opcional pero normalmente esperada si hay captura
    e1_network = os.path.isdir(os.path.join(case_dir, "network")) or has_prefix("network/")
    # alert folder puede no estar en CASE; no lo usamos para tumbar E1
    # E3 sha256 presente en algún artefacto
    sha_any = any(bool(a.get("sha256")) for a in (manifest or {}).get("artifacts", []) or [])
    # E4 separación: derived/ o analysis/
    e4 = os.path.isdir(os.path.join(case_dir, "derived")) or os.path.isdir(os.path.join(case_dir, "analysis"))

    return {
        "e1_required_present": bool(e1 and e1_network),
        "e1_has_disk": bool(os.path.isdir(os.path.join(case_dir, "disk")) or has_prefix("disk/") or has_type("disk_raw")),
        "e1_has_network": bool(e1_network),
        "e2_max_offset_skew_ms": None,  # si lo exportas a metadata luego se rellena aquí
        "e3_manifest_has_sha256": bool(sha_any),
        "e3_custody_chained_verified": None,  # si implementas verificación encadenada, lo conectas aquí
        "e4_primary_derived_separation": bool(e4),
    }


def build_run_record(case_dir: str, case_name: str, run_id: str, alerts_root: Optional[str]) -> Dict[str, Any]:
    manifest = read_json(os.path.join(case_dir, "manifest.json")) or {}
    events = read_jsonl(os.path.join(case_dir, "metadata", "pipeline_events.jsonl"))

    alert = find_event(events, run_id, "alert")
    mem_start = find_event(events, run_id, "memory_start")
    mem_pres = find_event(events, run_id, "memory_preserved")
    disk_start = find_event(events, run_id, "disk_start")
    disk_pres = find_event(events, run_id, "disk_preserved")
   




       
    pcap_start = (
        find_event(events, run_id, "pcap_start")
        or find_event(events, run_id, "traffic_capture_started")
        or find_event(events, run_id, "traffic_start")
    )

    pcap_pres = (
        find_event(events, run_id, "pcap_preserved")
        or find_event(events, run_id, "traffic_stopped")
        or find_event(events, run_id, "traffic_capture_stopped")
    )



    ot_pres = find_event(events, run_id, "ot_export_preserved")

    sizes = manifest_sizes(manifest)

    inv = extract_alert_invariants(case_dir, alerts_root)
    eq = evidence_quality(case_dir, manifest)

    return {
        "case": case_name,
        "case_path": case_dir,
        "run_id": run_id,
        "m2": {
            "alert_to_pcap_start_s": latency_s(alert, pcap_start),
            "alert_to_pcap_preserved_s": latency_s(alert, pcap_pres),
            "alert_to_memory_start_s": latency_s(alert, mem_start),
            "alert_to_memory_preserved_s": latency_s(alert, mem_pres),
            "alert_to_disk_start_s": latency_s(alert, disk_start),
            "alert_to_disk_preserved_s": latency_s(alert, disk_pres),
            "alert_to_ot_export_preserved_s": latency_s(alert, ot_pres),
        },
        "m3": {
            "pcap_sizes_bytes": sizes["pcap"],
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


def output_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def output_jsonl(rows: List[dict]) -> None:
    for r in rows:
        print(json.dumps(r, ensure_ascii=False))


def flatten_for_csv(r: Dict[str, Any]) -> Dict[str, Any]:
    # columnas planas para CSV (solo lo útil)
    inv = r.get("invariants") or {}
    m2 = r.get("m2") or {}
    m3 = r.get("m3") or {}
    m4 = r.get("m4") or {}
    eq = r.get("evidence_quality") or {}

    out: Dict[str, Any] = {
        "case": r.get("case"),
        "run_id": r.get("run_id"),
        "case_path": r.get("case_path"),
        "m2_alert_to_pcap_start_s": m2.get("alert_to_pcap_start_s"),
        "m2_alert_to_pcap_preserved_s": m2.get("alert_to_pcap_preserved_s"),
        "m2_alert_to_memory_start_s": m2.get("alert_to_memory_start_s"),
        "m2_alert_to_memory_preserved_s": m2.get("alert_to_memory_preserved_s"),
        "m2_alert_to_disk_start_s": m2.get("alert_to_disk_start_s"),
        "m2_alert_to_disk_preserved_s": m2.get("alert_to_disk_preserved_s"),
        "m2_alert_to_ot_export_preserved_s": m2.get("alert_to_ot_export_preserved_s"),
        "m3_pcap_sizes_bytes": ";".join(str(x) for x in (m3.get("pcap_sizes_bytes") or [])),
        "m3_memory_max_gib": m3.get("memory_max_gib"),
        "m3_disk_max_gib": m3.get("disk_max_gib"),
        "m3_ot_max_bytes": m3.get("ot_max_bytes"),
        "m4_failures_count": m4.get("failures_count"),
        "e1_required_present": eq.get("e1_required_present"),
        "e1_has_disk": eq.get("e1_has_disk"),
        "e1_has_network": eq.get("e1_has_network"),
        "e3_manifest_has_sha256": eq.get("e3_manifest_has_sha256"),
        "e4_primary_derived_separation": eq.get("e4_primary_derived_separation"),
        "inv_alert_utc": inv.get("alert_utc"),
        "inv_wazuh_rule_id": inv.get("wazuh_rule_id"),
        "inv_wazuh_level": inv.get("wazuh_level"),
        "inv_signature": inv.get("signature"),
        "inv_protocol": inv.get("protocol"),
        "inv_direction": inv.get("direction"),
        "inv_agent": inv.get("agent"),
    }
    return out


def output_csv(rows: List[dict]) -> None:
    flat = [flatten_for_csv(r) for r in rows]
    if not flat:
        return
    fieldnames = list(flat[0].keys())
    w = csv.DictWriter(os.sys.stdout, fieldnames=fieldnames)
    w.writeheader()
    for r in flat:
        w.writerow(r)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--limit", type=int, default=1)
    ap.add_argument("--run-id", default="R1", help="Run identifier inside pipeline_events.jsonl (default: R1)")
    ap.add_argument("--alerts-root", default=None, help="Path to forensics/alerts_store (optional). If omitted, auto-detect.")
    ap.add_argument("--format", choices=["json", "jsonl", "csv"], default="json")
    args = ap.parse_args()

    cases = pick_cases(args.evidence_root, args.limit)
    if not cases:
        output_json({"error": "no CASE-* directories found", "evidence_root": args.evidence_root})
        return

    # Auto-detect alerts_root as sibling of evidence_root: .../forensics/evidence_store -> .../forensics/alerts_store
    alerts_root = args.alerts_root
    if alerts_root is None:
        parent = os.path.abspath(os.path.join(args.evidence_root, os.pardir))
        cand = os.path.join(parent, "alerts_store")
        alerts_root = cand if os.path.isdir(cand) else None

    rows: List[dict] = []
    for c in cases:
        case_dir = os.path.join(args.evidence_root, c)
        rows.append(build_run_record(case_dir, c, args.run_id, alerts_root))

    if args.format == "json":
        output_json(
            {
                "evidence_root": args.evidence_root,
                "alerts_root": alerts_root,
                "limit": args.limit,
                "run_id": args.run_id,
                "cases": rows,
            }
        )
    elif args.format == "jsonl":
        output_jsonl(rows)
    else:
        output_csv(rows)


if __name__ == "__main__":
    main()