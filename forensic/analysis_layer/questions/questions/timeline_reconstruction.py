#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


def _safe_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


def _iso_from_epoch(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.isoformat()


class TimelineReconstruction:
    """
    Question:
    Build a unified forensic timeline from collected evidence.

    Strategy:
      - Normalize events from:
          * network modbus frames (facts["modbus_frames"])
          * industrial snapshots (facts["industrial"])
          * system snapshots (facts["system_snapshots_raw"] optional)
      - Output sorted event list with minimal, evidence-based fields.

    Output:
      - events: list of {utc, source, type, details, confidence, evidence_ref}
      - stats: counts per type
    """

    def run(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        events: List[Dict[str, Any]] = []

        # 1) Network: Modbus frames
        events.extend(self._events_from_modbus_frames(facts.get("modbus_frames", [])))

        # 2) Industrial snapshots
        events.extend(self._events_from_industrial_snapshots(facts.get("industrial", {})))

        # 3) System snapshots raw (optional)
        raw_snaps = facts.get("system_snapshots_raw", [])
        if raw_snaps:
            events.extend(self._events_from_system_snapshots(raw_snaps))

        # Sort
        events_sorted = sorted(
            [e for e in events if e.get("epoch") is not None],
            key=lambda e: e["epoch"]
        )

        # Convert epoch to UTC ISO for output
        for e in events_sorted:
            e["utc"] = _iso_from_epoch(e["epoch"])
            del e["epoch"]

        stats = {}
        for e in events_sorted:
            t = e.get("type", "unknown")
            stats[t] = stats.get(t, 0) + 1

        verdict = "COMPLETED" if events_sorted else "EMPTY"

        return {
            "question": "timeline_reconstruction",
            "answer": verdict,
            "stats": stats,
            "events": events_sorted
        }

    def _events_from_modbus_frames(self, frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for f in frames:
            epoch = _safe_float(f.get("timestamp"))
            if epoch is None:
                continue

            func = f.get("function")
            kind = "modbus_unknown"
            confidence = "medium"

            if func in (3, 4):
                kind = "modbus_read"
            elif func in (5, 6, 15, 16):
                kind = "modbus_write"
            elif func is None:
                kind = "modbus_unknown"
                confidence = "low"

            out.append({
                "epoch": epoch,
                "source": "network",
                "type": kind,
                "confidence": confidence,
                "details": {
                    "unit_id": f.get("unit_id"),
                    "function": func,
                    "src": f.get("source_ip"),
                    "dst": f.get("destination_ip"),
                },
                "evidence_ref": {
                    "kind": "frame",
                    "pcap": f.get("pcap_file"),   # if you add it later in extractor
                }
            })

        return out

    def _events_from_industrial_snapshots(self, industrial: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        # We don't have real timestamps inside mbpoll outputs by default.
        # So we approximate timeline anchor based on case ordering:
        # - If you later store acquisition_utc per evidence item, we can use it here.
        snapshots = industrial.get("snapshots", [])

        for snap in snapshots:
            # Try to parse timestamp from filename if present
            # Example: modbus_host-forensic-node_1768907791.txt
            fname = snap.get("file", "")
            epoch = self._epoch_from_filename(fname)

            if epoch is None:
                # fallback: we keep it but without proper ordering anchor
                continue

            lines = snap.get("lines", [])
            timeout = any("timeout" in (ln or "").lower() for ln in lines)
            exception = any("exception" in (ln or "").lower() for ln in lines)

            out.append({
                "epoch": epoch,
                "source": "industrial",
                "type": "modbus_snapshot",
                "confidence": "medium",
                "details": {
                    "file": fname,
                    "lines": len(lines),
                    "timeout_detected": timeout,
                    "exception_detected": exception
                },
                "evidence_ref": {
                    "kind": "file",
                    "path": fname
                }
            })

        return out

    def _events_from_system_snapshots(self, snaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        for snap in snaps:
            # If you store created_utc, use it; otherwise skip
            created_utc = snap.get("created_utc")
            epoch = self._epoch_from_iso(created_utc)
            if epoch is None:
                continue

            who = snap.get("source", "system")
            cmds = snap.get("commands", {})

            # Minimal: record system snapshot anchor
            out.append({
                "epoch": epoch,
                "source": "system",
                "type": "system_snapshot",
                "confidence": "high",
                "details": {
                    "host": who,
                    "processes_present": bool((cmds.get("ps", {}) or {}).get("stdout")),
                    "connections_present": bool((cmds.get("ss", {}) or {}).get("stdout")),
                },
                "evidence_ref": {
                    "kind": "snapshot",
                    "host": who
                }
            })

        return out

    @staticmethod
    def _epoch_from_filename(fname: str) -> Optional[float]:
        # looks for _<epoch>.txt
        m = None
        try:
            m = __import__("re").search(r"_(\d{9,})\.", fname)
        except Exception:
            return None
        if not m:
            return None
        return _safe_float(m.group(1))

    @staticmethod
    def _epoch_from_iso(iso_str: Optional[str]) -> Optional[float]:
        if not iso_str:
            return None
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None
