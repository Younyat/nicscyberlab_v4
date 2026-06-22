from __future__ import annotations

from pathlib import Path


def load_timeline_context(case_path: Path, analysis_summary: dict) -> dict:
    timeline = analysis_summary.get("timeline") if isinstance(analysis_summary, dict) else {}
    temporal_report = analysis_summary.get("temporal_report") if isinstance(analysis_summary, dict) else {}
    return {
        "timeline_path": case_path / "analysis" / "09_timeline" / "unified_forensic_timeline.json",
        "timeline": timeline if isinstance(timeline, dict) else {},
        "temporal_report": temporal_report if isinstance(temporal_report, dict) else {},
    }
