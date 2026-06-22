from __future__ import annotations

import json
from pathlib import Path


def _load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_analysis_summary(case_path: Path) -> dict:
    analysis_dir = case_path / "analysis"
    return {
        "analysis_dir": analysis_dir,
        "forensic_analysis_report": _load_json(analysis_dir / "forensic_analysis_report.json") or {},
        "analysis_visual_summary": _load_json(analysis_dir / "visual" / "analysis_visual_summary.json") or {},
        "forensic_analysis_manifest": _load_json(analysis_dir / "forensic_analysis_manifest.json") or {},
        "integrity_report": _load_json(analysis_dir / "01_integrity_custody" / "integrity_custody_report.json") or {},
        "temporal_report": _load_json(analysis_dir / "02_time_validation" / "clock_offset_report.json") or {},
        "timeline": _load_json(analysis_dir / "09_timeline" / "unified_forensic_timeline.json") or {},
        "cross_layer_findings": _load_json(analysis_dir / "10_findings" / "cross_layer_findings.json") or {},
        "memory_findings": _load_json(analysis_dir / "04_memory" / "memory_findings.json") or {},
    }
