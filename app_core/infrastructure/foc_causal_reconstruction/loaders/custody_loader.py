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


def load_custody_context(case_path: Path, foc_context: dict, analysis_summary: dict) -> dict:
    manifest_path = case_path / "manifest.json"
    custody_path = case_path / "chain_of_custody.log"
    integrity_report = analysis_summary.get("integrity_report") if isinstance(analysis_summary, dict) else {}
    findings = integrity_report.get("findings") if isinstance(integrity_report, dict) else {}
    case_manifest_link = foc_context.get("case_manifest_link") if isinstance(foc_context, dict) else {}
    links = []
    if isinstance(case_manifest_link, dict):
        links = case_manifest_link.get("linked_artifacts") or case_manifest_link.get("links") or []
    links = links if isinstance(links, list) else []
    return {
        "manifest_path": manifest_path,
        "manifest_present": manifest_path.is_file(),
        "manifest": _load_json(manifest_path) or {},
        "chain_of_custody_path": custody_path,
        "chain_of_custody_present": custody_path.is_file(),
        "case_manifest_link": case_manifest_link if isinstance(case_manifest_link, dict) else {},
        "case_links_for_case": [item for item in links if str(item.get("case_id")) == str(case_path.name) or str(item.get("manifest_path") or "").endswith(f"{case_path.name}/manifest.json")],
        "integrity_report": integrity_report if isinstance(integrity_report, dict) else {},
        "custody_chain_valid": bool(findings.get("custody_chain_valid")) if isinstance(findings, dict) else False,
        "missing_artifacts": findings.get("missing_artifacts") if isinstance(findings, dict) else [],
        "hash_validated_artifacts": findings.get("hash_validated_artifacts") if isinstance(findings, dict) else 0,
        "manifest_artifacts_total": findings.get("manifest_artifacts_total") if isinstance(findings, dict) else 0,
    }
