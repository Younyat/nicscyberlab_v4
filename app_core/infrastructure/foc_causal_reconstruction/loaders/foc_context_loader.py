from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from ..config import FOC_ROOT

# `attestations/alert_correlation.json` alone is ~100MB for a populated lab.
# load_foc_context() is called on every causal status poll (not only on
# explicit runs), so re-parsing it unconditionally was the dominant latency
# source in the causal cockpit. Cache the assembled context per foc_root,
# invalidated by mtime on the tracked source files (correct-by-construction)
# with a short TTL as a secondary safety net, mirroring the same pattern
# already used for the FOC dashboard payload in foc_endpoints.py.
_CONTEXT_CACHE_TTL_SECONDS = 30.0
_context_cache: dict[str, dict] = {}
_context_cache_lock = threading.Lock()


def _load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def load_foc_context(foc_root: Path | None = None) -> dict:
    root = Path(foc_root or FOC_ROOT)
    attestations_dir = root / "attestations"
    validation_dir = root / "validation"
    tracked_paths = (
        root / "foc_manifest.json",
        attestations_dir / "attack_attestation.json",
        attestations_dir / "detection_attestation.json",
        attestations_dir / "alert_correlation.json",
        attestations_dir / "alert_correlation_summary.json",
        attestations_dir / "forensic_intervention.json",
        attestations_dir / "forensic_analysis_manifest.json",
        attestations_dir / "foc_context_summary.json",
        attestations_dir / "case_manifest_link.json",
        attestations_dir / "scenario_ground_truth.json",
        validation_dir / "foc_readiness_report.json",
    )
    mtimes = tuple(_file_mtime(path) for path in tracked_paths)
    cache_key = str(root)
    now = time.time()
    with _context_cache_lock:
        cached = _context_cache.get(cache_key)
        if cached and cached["mtimes"] == mtimes and (now - cached["ts"]) < _CONTEXT_CACHE_TTL_SECONDS:
            return cached["payload"]

    payload = _build_foc_context(root)

    with _context_cache_lock:
        _context_cache[cache_key] = {"ts": now, "mtimes": mtimes, "payload": payload}
    return payload


def _build_foc_context(root: Path) -> dict:
    manifest = _load_json(root / "foc_manifest.json") or {}
    attestations_dir = root / "attestations"
    validation_dir = root / "validation"
    payload = {
        "root": root,
        "manifest": manifest,
        "artifact_references": dict(manifest.get("derived_context") or {}),
        "attack_attestation": _load_json(attestations_dir / "attack_attestation.json") or {},
        "detection_attestation": _load_json(attestations_dir / "detection_attestation.json") or {},
        "alert_correlation": _load_json(attestations_dir / "alert_correlation.json") or {},
        "alert_correlation_summary": _load_json(attestations_dir / "alert_correlation_summary.json") or {},
        "forensic_intervention": _load_json(attestations_dir / "forensic_intervention.json") or {},
        "forensic_analysis_manifest": _load_json(attestations_dir / "forensic_analysis_manifest.json") or {},
        "foc_context_summary": _load_json(attestations_dir / "foc_context_summary.json") or {},
        "case_manifest_link": _load_json(attestations_dir / "case_manifest_link.json") or {},
        "preserved_ground_truth": _load_json(attestations_dir / "scenario_ground_truth.json") or {},
        "readiness_report": _load_json(validation_dir / "foc_readiness_report.json") or {},
    }
    summary = payload["foc_context_summary"] if isinstance(payload["foc_context_summary"], dict) else {}
    preserved_ground_truth = payload["preserved_ground_truth"] if isinstance(payload["preserved_ground_truth"], dict) else {}
    manifest = payload["manifest"] if isinstance(payload["manifest"], dict) else {}
    payload["scenario_id"] = (
        summary.get("scenario_id")
        or preserved_ground_truth.get("scenario_id")
        or manifest.get("scenario_id")
        or "unknown"
    )
    payload["scenario_name"] = (
        summary.get("scenario_name")
        or preserved_ground_truth.get("scenario_name")
        or "unknown"
    )
    return payload
