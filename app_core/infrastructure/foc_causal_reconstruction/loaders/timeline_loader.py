from __future__ import annotations

from pathlib import Path


def load_timeline_context(case_path: Path, analysis_summary: dict) -> dict:
    timeline = analysis_summary.get("timeline") if isinstance(analysis_summary, dict) else {}
    temporal_report = analysis_summary.get("temporal_report") if isinstance(analysis_summary, dict) else {}
    time_sync = analysis_summary.get("time_sync") if isinstance(analysis_summary, dict) else {}
    time_sync_before = analysis_summary.get("time_sync_before") if isinstance(analysis_summary, dict) else {}
    time_sync_after = analysis_summary.get("time_sync_after") if isinstance(analysis_summary, dict) else {}
    return {
        "timeline_path": case_path / "analysis" / "09_timeline" / "unified_forensic_timeline.json",
        "timeline": timeline if isinstance(timeline, dict) else {},
        "temporal_report": temporal_report if isinstance(temporal_report, dict) else {},
        "time_sync": time_sync if isinstance(time_sync, dict) else {},
        "time_sync_before": time_sync_before if isinstance(time_sync_before, dict) else {},
        "time_sync_after": time_sync_after if isinstance(time_sync_after, dict) else {},
    }
