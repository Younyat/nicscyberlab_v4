import os
import json
import uuid
import time
from datetime import datetime, timezone
from typing import Any, Dict


# Carpeta de salida (FORensics), aunque el módulo viva en MONITOR
FORENSICS_ALERTS_BASE = os.path.abspath("app_core/infrastructure/forensics/alerts_store")


def _utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _append_jsonl(path: str, obj: Dict[str, Any]) -> None:
    _safe_mkdir(os.path.dirname(path))
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


class AlertsLogger:
    """
    Pre-case detection log:
      - Primary: alerts.jsonl (normalizado + raw)
      - Derived: triage.jsonl (score/severity/decision)
    """

    def __init__(self, base_dir: str = FORENSICS_ALERTS_BASE):
        self.base_dir = os.path.abspath(base_dir)
        _safe_mkdir(self.base_dir)
        self.session_id = self._ensure_session()

    def _ensure_session(self) -> str:
        sid = f"ALERTS-{_utc_now_compact()}"
        sdir = os.path.join(self.base_dir, sid)
        _safe_mkdir(sdir)

        meta_path = os.path.join(sdir, "session.json")
        if not os.path.exists(meta_path):
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session_id": sid,
                        "ts_utc_created": _utc_now_iso(),
                        "note": "Pre-case detection log (primary alerts + derived triage).",
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        return sid

    def _paths(self) -> Dict[str, str]:
        sdir = os.path.join(self.base_dir, self.session_id)
        return {
            "alerts": os.path.join(sdir, "alerts.jsonl"),
            "triage": os.path.join(sdir, "triage.jsonl"),
        }

    def compute_severity(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        score = 10
        reasons = {}

        source = (ev.get("source") or "").lower()
        if source == "suricata":
            score += 25
        elif source == "wazuh":
            score += 20
        elif source == "icmp_sensor":
            score += 10
        reasons["source"] = source or "unknown"

        level = ev.get("rule_level")
        if isinstance(level, int):
            score += min(40, level * 3)
            reasons["rule_level"] = level

        proto = (ev.get("protocol") or "").lower()
        if proto in {"modbus", "s7comm", "dnp3", "bacnet", "opcua", "profinet"}:
            score += 25
            reasons["ot_protocol"] = proto
        elif proto in {"icmp", "ip"}:
            score += 5

        score = max(0, min(100, int(score)))

        if score >= 80:
            sev = "CRITICAL"
        elif score >= 60:
            sev = "HIGH"
        elif score >= 35:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        return {
            "score_0_100": score,
            "severity": sev,
            "recommend_forensics": score >= 60,
            "reasons": reasons,
        }

    def log_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        paths = self._paths()

        event_id = ev.get("event_id") or uuid.uuid4().hex
        ts_utc = ev.get("ts_utc") or _utc_now_iso()
        ts_epoch = ev.get("ts_epoch")
        if ts_epoch is None:
            ts_epoch = time.time()

        primary = {
            "event_id": event_id,
            "ts_utc": ts_utc,
            "ts_epoch": ts_epoch,
            "source": ev.get("source", "unknown"),
            "alert_type": ev.get("alert_type", "unknown"),
            "protocol": ev.get("protocol", "unknown"),
            "src": ev.get("src", {}),
            "dst": ev.get("dst", {}),
            "rule_id": ev.get("rule_id"),
            "rule_level": ev.get("rule_level"),
            "signature": ev.get("signature"),
            "agent": ev.get("agent"),
            "raw": ev.get("raw"),
        }
        _append_jsonl(paths["alerts"], primary)

        triage = self.compute_severity(primary)
        derived = {
            "event_id": event_id,
            "ts_utc": _utc_now_iso(),
            **triage,
        }
        _append_jsonl(paths["triage"], derived)

        return {"primary": primary, "triage": triage}
