import os
import json
import uuid
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional


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
      - Derived: triage.jsonl (native score / severity / decision)
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
        """
        Usa el score nativo de la fuente cuando esté disponible.
        Para Wazuh:
          - native_score = rule_level
          - native_scale = wazuh_rule_level_0_16

        No inventa score_0_100.
        """
        source = (ev.get("source") or "").lower()
        reasons = {"source": source or "unknown"}

        if source == "wazuh":
            level = ev.get("rule_level")

            try:
                level = int(level)
            except Exception:
                level = None

            reasons["rule_level"] = level

            if level is None:
                return {
                    "native_score": None,
                    "native_scale": "wazuh_rule_level_0_16",
                    "severity": "UNKNOWN",
                    "recommend_forensics": False,
                    "reasons": reasons,
                }

            # Clasificación visual simple basada en el propio nivel nativo.
           
            if level >= 12:
                sev = "CRITICAL"
            elif level >= 7:
                sev = "HIGH"
            elif level >= 5:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            return {
                "native_score": level,
                "native_scale": "wazuh_rule_level_0_16",
                "severity": sev,
                "recommend_forensics": level >= 10,
                "reasons": reasons,
            }

        # Para fuentes no-Wazuh, dejamos constancia pero no inventamos score.
        return {
            "native_score": None,
            "native_scale": "none",
            "severity": "UNKNOWN",
            "recommend_forensics": False,
            "reasons": reasons,
        }

    def log_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        paths = self._paths()

        event_id = ev.get("event_id") or uuid.uuid4().hex

        # 1) ts_utc (fuente de verdad)
        ts_utc = ev.get("ts_utc") or _utc_now_iso()

        # 2) ts_epoch coherente: si no viene, lo derivamos de ts_utc (UTC)
        ts_epoch = ev.get("ts_epoch")
        if ts_epoch is None:
            derived = iso_to_epoch(ts_utc)
            ts_epoch = derived if derived > 0 else time.time()

        # 3) Construir PRIMARY
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

        # 4) Guardar PRIMARY en alerts_store
        _append_jsonl(paths["alerts"], primary)

        # 5) Guardar DERIVED triage
        triage = self.compute_severity(primary)
        derived = {
            "event_id": event_id,
            "ts_utc": _utc_now_iso(),
            **triage,
        }
        _append_jsonl(paths["triage"], derived)

        # 6) Si el caller nos pasa case_dir, guardamos el PRIMARY dentro del CASE
        case_rel = None
        case_dir = (ev.get("case_dir") or "").strip()

        # Fallback: si no viene case_dir, usa el CASE activo
        if not case_dir:
            case_dir = _read_active_case_dir() or ""

        if case_dir:
            case_rel = _write_case_alert(case_dir, primary)

        # 7) Respuesta
        return {
            "primary": primary,
            "triage": triage,
            "case_rel": case_rel,
            "session_id": self.session_id,
        }


def iso_to_epoch(iso_utc: str) -> float:
    """
    Convierte timestamps ISO UTC a epoch (UTC).
    Soporta:
      - 2026-02-19T15:31:06Z
      - 2026-02-19T15:31:06.029+0000
      - 2026-02-19T15:31:06.029+00:00
    """
    s = (iso_utc or "").strip()
    if not s:
        return 0.0

    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            # normaliza +0000 -> +00:00
            if len(s) >= 5 and (s[-5] in ["+", "-"]) and s[-3] != ":":
                s = s[:-2] + ":" + s[-2:]
            dt = datetime.fromisoformat(s)

        return dt.astimezone(timezone.utc).timestamp()
    except Exception:
        return 0.0


def _atomic_write_json(path: str, obj: Dict[str, Any]) -> None:
    """
    Escritura atómica para evitar ficheros corruptos si el proceso muere.
    """
    tmp = f"{path}.tmp"
    _safe_mkdir(os.path.dirname(path))
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _write_case_alert(case_dir: str, alert_obj: Dict[str, Any]) -> Optional[str]:
    """
    Guarda el alert PRIMARY dentro del CASE:
      CASE/.../alerts/event_<event_id>.json
    Devuelve rel_path o None si no se pudo.
    """
    try:
        if not case_dir:
            return None
        case_dir = os.path.abspath(case_dir)
        if not os.path.isdir(case_dir):
            return None

        alerts_dir = os.path.join(case_dir, "alerts")
        _safe_mkdir(alerts_dir)

        event_id = str(alert_obj.get("event_id") or "").strip()
        if not event_id:
            return None

        filename = f"event_{event_id}.json"
        abs_path = os.path.join(alerts_dir, filename)

        _atomic_write_json(abs_path, alert_obj)

        return os.path.join("alerts", filename)
    except Exception:
        return None


def attach_alert_to_case(case_dir: str, alert_event_id: str, base_dir: str = FORENSICS_ALERTS_BASE) -> Optional[str]:
    """
    Copia/adjunta al CASE un alert ya existente en alerts_store, buscándolo por event_id.
    - Busca recursivamente en alerts_store/ALERTS-*/alerts.jsonl
    - Cuando lo encuentra, escribe CASE/alerts/event_<id>.json
    Devuelve rel_path dentro del CASE o None si no se encuentra/no se pudo.
    """
    case_dir = os.path.abspath(case_dir or "")
    if not case_dir or not os.path.isdir(case_dir):
        return None

    alert_event_id = (alert_event_id or "").strip()
    if not alert_event_id:
        return None

    base_dir = os.path.abspath(base_dir or "")
    if not os.path.isdir(base_dir):
        return None

    sessions = []
    for name in os.listdir(base_dir):
        if name.startswith("ALERTS-"):
            p = os.path.join(base_dir, name)
            if os.path.isdir(p):
                sessions.append(p)
    sessions.sort(reverse=True)

    for sdir in sessions:
        alerts_path = os.path.join(sdir, "alerts.jsonl")
        if not os.path.isfile(alerts_path):
            continue
        try:
            with open(alerts_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = (line or "").strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("event_id") or "").strip() == alert_event_id:
                        return _write_case_alert(case_dir, obj)
        except Exception:
            continue

    return None


ACTIVE_CASE_PTR = os.path.abspath("app_core/infrastructure/forensics/evidence_store/_active_case.txt")


def _read_active_case_dir() -> Optional[str]:
    """
    Lee el CASE activo desde evidence_store/_active_case.txt.
    Devuelve ruta absoluta o None.
    """
    try:
        if not os.path.isfile(ACTIVE_CASE_PTR):
            return None
        with open(ACTIVE_CASE_PTR, "r", encoding="utf-8") as f:
            p = (f.readline() or "").strip()
        if not p:
            return None
        p = os.path.abspath(p)
        return p if os.path.isdir(p) else None
    except Exception:
        return None