import json
import logging
import time
from pathlib import Path

from .foc_config import FOC_OUTPUT_DIR, GENERATED_FILES, ensure_output_layout
from .foc_sources import utc_now

logger = logging.getLogger(__name__)

EVENTS_LOG = FOC_OUTPUT_DIR / "cache" / "foc_events.jsonl"

WATCHED_PATHS = [
    Path("scenario/scenario_file.json"),
    Path("scenario/deployment_status.json"),
    Path("scenario/destroy_status.json"),
    Path("industrial-scenario/state/industrial_state.json"),
    Path("industrial-scenario/scenarios"),
    Path("tools-installer-tmp"),
    Path("tools-installer/installed"),
    Path("tools-installer/logs"),
    Path("app_core/infrastructure/attack/outputs"),
    Path("app_core/infrastructure/forensics/alerts_store"),
    Path("app_core/infrastructure/forensics/evidence_store"),
]


def _safe_stat_signature(path: Path) -> tuple:
    try:
        if not path.exists():
            return ("missing",)
        if path.is_file():
            st = path.stat()
            return ("file", st.st_mtime, st.st_size)
        items = list(path.rglob("*"))
        latest = 0.0
        files = 0
        total_size = 0
        for item in items:
            try:
                st = item.stat()
                latest = max(latest, st.st_mtime)
                if item.is_file():
                    files += 1
                    total_size += st.st_size
            except Exception:
                continue
        return ("dir", len(items), files, total_size, latest)
    except Exception as exc:
        return ("error", str(exc))


def snapshot_watch_state() -> dict:
    return {str(path): _safe_stat_signature(path) for path in WATCHED_PATHS}


def record_foc_event(event_type: str, payload: dict | None = None) -> dict:
    ensure_output_layout()
    entry = {
        "ts_utc": utc_now(),
        "event_type": event_type,
        "payload": payload or {},
    }
    with EVENTS_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def safe_notify_foc(event_type: str, payload: dict | None = None) -> None:
    try:
        record_foc_event(event_type, payload)
    except Exception as exc:
        logger.warning("FOC notification failed: %s", exc)


def iter_events_since(offset: int = 0) -> tuple[list[dict], int]:
    ensure_output_layout()
    entries: list[dict] = []
    current = 0
    if not EVENTS_LOG.exists():
        return entries, current
    with EVENTS_LOG.open("r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh, start=1):
            current = idx
            if idx <= offset:
                continue
            line = (line or "").strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception:
                continue
    return entries, current
