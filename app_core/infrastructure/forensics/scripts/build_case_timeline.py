#!/usr/bin/env python3
import os, json, glob
from datetime import datetime, timezone  # <-- CAMBIO: añade timezone

TRAFFIC_EVENTS_PREFIX = (
    "traffic_",          # traffic_start, traffic_capture_started, traffic_stopped, etc.
)
TRAFFIC_EVENTS_EXACT = {
    "ot_export_start",
    "ot_export_preserved",
    "ot_export_failed",
}

def read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

def iso_to_epoch(iso):
    # <-- CAMBIO: interpretar ISO como UTC real (no hora local)
    try:
        if not iso:
            return None
        if iso.endswith("Z"):
            iso = iso[:-1]
        if "." in iso:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)  # <-- CLAVE
        return dt.timestamp()
    except Exception:
        return None

def is_traffic_event(ev: str) -> bool:
    if not ev:
        return False
    if ev in TRAFFIC_EVENTS_EXACT:
        return True
    return any(ev.startswith(p) for p in TRAFFIC_EVENTS_PREFIX)

def main(case_dir):
    events_path = os.path.join(case_dir, "metadata", "pipeline_events.jsonl")

    rows = []

    # 1) pipeline events (solo tráfico/OT)
    for e in read_jsonl(events_path):
        ev = e.get("event")
        if not is_traffic_event(ev):
            continue

        ts_epoch = e.get("ts_epoch")
        ts_utc = e.get("ts_utc_ms") or e.get("ts_utc")
        if ts_epoch is None and ts_utc:
            ts_epoch = iso_to_epoch(ts_utc)

        rows.append({
            "source": "pipeline_events",
            "ts_epoch": ts_epoch,
            "ts_utc": ts_utc,
            "run_id": e.get("run_id"),
            "event": ev,
            "meta": e.get("meta", {}),
        })

    # 2) OT exports (derivado de tráfico Modbus)
    for ot_path in glob.glob(os.path.join(case_dir, "industrial", "ot_export_*.json")):
        try:
            ot = json.load(open(ot_path, "r", encoding="utf-8"))
            run_id = ot.get("run_id")
            vm_id = ot.get("vm_id")
            for r in (ot.get("records") or []):
                ts_epoch = r.get("ts_epoch")
                rows.append({
                    "source": "ot_export",
                    "ts_epoch": ts_epoch,
                    "ts_utc": r.get("ts_utc_ms") or r.get("ts_utc"),
                    "run_id": run_id,
                    "event": f"ot:{r.get('op')}",
                    "meta": {
                        "vm_id": vm_id,
                        "fc": r.get("fc"),
                        "address": r.get("address"),
                        "value": r.get("value"),
                        "registers": r.get("registers"),
                        "src_ip": r.get("src_ip"),
                        "dst_ip": r.get("dst_ip"),
                        "direction": r.get("direction"),
                    }
                })
        except Exception:
            continue

    # Ordenar por ts_epoch (None al final)
    rows.sort(key=lambda x: (x["ts_epoch"] is None, x["ts_epoch"] or 0.0))

    out_dir = os.path.join(case_dir, "analysis", "timeline_traffic_ot")
    os.makedirs(out_dir, exist_ok=True)
    out_json = os.path.join(out_dir, "timeline_traffic_ot.json")
    out_csv  = os.path.join(out_dir, "timeline_traffic_ot.csv")

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    # CSV simple
    def esc(s):
        s = "" if s is None else str(s)
        return '"' + s.replace('"', '""') + '"'

    with open(out_csv, "w", encoding="utf-8") as f:
        f.write("ts_epoch,ts_utc,source,run_id,event,meta\n")
        for r in rows:
            f.write(",".join([
                str(r.get("ts_epoch") or ""),
                esc(r.get("ts_utc") or ""),
                esc(r.get("source") or ""),
                esc(r.get("run_id") or ""),
                esc(r.get("event") or ""),
                esc(json.dumps(r.get("meta", {}), ensure_ascii=False)),
            ]) + "\n")

    print(out_dir)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: build_case_timeline.py <CASE_DIR>")
        sys.exit(1)
    main(sys.argv[1])
