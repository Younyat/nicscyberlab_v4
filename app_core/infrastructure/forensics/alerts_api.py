import os
import json
from flask import Blueprint, jsonify, request

ALERTS_API_BP = Blueprint("alerts_api", __name__)

FORENSICS_ALERTS_BASE = os.path.abspath("app_core/infrastructure/forensics/alerts_store")


def _list_sessions(base_dir: str):
    if not os.path.isdir(base_dir):
        return []
    items = []
    for name in os.listdir(base_dir):
        p = os.path.join(base_dir, name)
        if os.path.isdir(p) and name.startswith("ALERTS-"):
            items.append(name)
    # orden lexicográfico sirve porque ALERTS-YYYYMMDD-HHMMSSZ
    return sorted(items)


def _tail_jsonl(path: str, limit: int):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines() if ln.strip()]
    lines = lines[-limit:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def _pick_session_with_data(base_dir: str, sessions: list[str]) -> str | None:
    """
    Elige la sesión más reciente que tenga alerts.jsonl existente y no vacío.
    """
    for sid in reversed(sessions):
        alerts_path = os.path.join(base_dir, sid, "alerts.jsonl")
        if os.path.isfile(alerts_path) and os.path.getsize(alerts_path) > 0:
            return sid
    return None


@ALERTS_API_BP.route("/api/forensics/alerts/latest", methods=["GET"])
def latest_alerts():
    # limit
    try:
        limit = int(request.args.get("limit", "30"))
    except Exception:
        limit = 30
    limit = max(1, min(200, limit))

    sessions = _list_sessions(FORENSICS_ALERTS_BASE)
    if not sessions:
        return jsonify({"alerts": [], "session_id": None})

    # (opcional) permitir forzar sesión desde el cliente
    requested_sid = (request.args.get("session_id") or "").strip()
    if requested_sid and requested_sid in sessions:
        session_id = requested_sid
    else:
        # por defecto: sesión más reciente con datos
        session_id = _pick_session_with_data(FORENSICS_ALERTS_BASE, sessions)

        # si no hay ninguna con datos, devolvemos vacío pero informamos la más reciente existente
        if not session_id:
            return jsonify({"alerts": [], "session_id": sessions[-1]})

    sdir = os.path.join(FORENSICS_ALERTS_BASE, session_id)

    alerts_path = os.path.join(sdir, "alerts.jsonl")
    triage_path = os.path.join(sdir, "triage.jsonl")

    alerts = _tail_jsonl(alerts_path, limit)

    # triage puede tener más líneas (ej. recalculado), por eso leemos más
    triage = _tail_jsonl(triage_path, limit * 4)

    triage_by_id = {}
    for t in triage:
        eid = t.get("event_id")
        if eid:
            triage_by_id[eid] = t

    # Enriquecer con severity
    enriched = []
    for a in alerts:
        eid = a.get("event_id")
        item = dict(a)
        t = triage_by_id.get(eid, {})
        item["severity"] = t.get("severity")
        item["score_0_100"] = t.get("score_0_100")
        item["recommend_forensics"] = t.get("recommend_forensics")
        enriched.append(item)

    # más reciente primero
    enriched = list(reversed(enriched))

    return jsonify({"alerts": enriched, "session_id": session_id})
