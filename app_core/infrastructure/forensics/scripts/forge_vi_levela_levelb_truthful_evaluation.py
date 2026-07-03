#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_ROOT = Path(__file__).resolve().parents[4]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from app_core.infrastructure.forensics.scripts import forge_vi_levelb_table_reconstruction as lb


REPO_ROOT = lb.REPO_ROOT
EVIDENCE_ROOT = lb.EVIDENCE_ROOT
CAMPAIGNS_ROOT = lb.CAMPAIGNS_ROOT
VALIDATION_ROOT = lb.VALIDATION_ROOT
SCIENTIFIC_REPORTS_ROOT = (
    REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "scientific_reports" / "level_a_repetitions"
)


OUTPUT_FILES = {
    "evaluation_report": "FORGE-VI_LevelA_LevelB_Truthful_Evaluation_Report.md",
    "table_values": "FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json",
    "data_provenance": "FORGE-VI_LevelA_LevelB_Truthful_Data_Provenance.csv",
    "availability_matrix": "FORGE-VI_LevelA_LevelB_Truthful_Data_Availability_Matrix.csv",
    "gap_report": "FORGE-VI_LevelA_LevelB_Truthful_Gap_Report.md",
    "paper_tables": "FORGE-VI_LevelA_LevelB_Truthful_Paper_Tables.md",
    "rerun_plan": "FORGE-VI_LevelA_LevelB_Rerun_Readiness_Plan.md",
    "report_metadata": "report_metadata.json",
}


def rel(path: Path | str | None) -> str:
    return lb.rel(path)


def load_json(path: Path | str | None) -> dict | list | None:
    return lb.load_json(path)


def load_jsonl(path: Path | str | None) -> list[dict]:
    return lb.load_jsonl(path)


def metric_display(value: Any) -> str:
    return lb.metric_display(value)


def not_available(reason: str = "not available in current artifacts") -> str:
    return reason


def markdown_escape(value: Any) -> str:
    return lb.markdown_escape(value)


def mean_value(values: list[float]) -> float | None:
    return lb.mean_value(values)


def sample_std(values: list[float]) -> float | None:
    return lb.sample_std(values)


def sha256_file(path: Path | str | None) -> str | None:
    return lb.sha256_file(path)


@dataclass
class LevelAExecutionAudit:
    campaign_id: str
    execution_id: str
    source_case_id: str
    campaign_manifest: dict
    execution_manifest: dict
    report_metadata: dict
    report_summary: dict
    forensic_result_card: dict
    forensic_comparison_profile: dict
    preservation_profile: dict
    analysis_repeatability_profile: dict
    parent_level_b_campaign_id: str | None
    parent_level_b_execution_id: str | None
    source_scope: str


def _coerce_bool_text(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value in (None, ""):
        return not_available()
    return str(value)


def _markdown_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return "_No rows available._"
    header = "| " + " | ".join(columns) + " |"
    sep = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = [
        "| " + " | ".join(markdown_escape(row.get(col, "")) for col in columns) + " |"
        for row in rows
    ]
    return "\n".join([header, sep, *body])


def _write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in columns})


def _truthful_output_dir() -> Path:
    return VALIDATION_ROOT / f"forge_vi_levela_levelb_truthful_evaluation_{lb.utc_now_compact().replace(':', '').replace('.', '_')}"


def _parent_level_b_mapping(level_b_audits: list[lb.ExecutionAudit]) -> dict[str, dict[str, str]]:
    mapping: dict[str, dict[str, str]] = {}
    for audit in level_b_audits:
        nested = audit.nested_level_a or {}
        campaign_id = str(nested.get("campaign_id") or "").strip()
        if not campaign_id:
            continue
        mapping[campaign_id] = {
            "parent_level_b_campaign_id": audit.campaign_id,
            "parent_level_b_execution_id": audit.execution_id,
            "source_case_id": audit.case_id,
        }
    return mapping


def _latest_level_a_report_metadata() -> dict[str, Path]:
    latest: dict[str, tuple[str, Path]] = {}
    for path in sorted(SCIENTIFIC_REPORTS_ROOT.glob("case-*/CMP-*/level_A_*/report_metadata.json")):
        payload = load_json(path)
        if not isinstance(payload, dict):
            continue
        campaign_id = str(payload.get("campaign_id") or "").strip()
        generated_at = str(payload.get("generated_at") or "").strip()
        if not campaign_id:
            continue
        current = latest.get(campaign_id)
        if current is None or generated_at > current[0]:
            latest[campaign_id] = (generated_at, path)
    return {campaign_id: path for campaign_id, (_ts, path) in latest.items()}


def load_level_a_audits(level_b_audits: list[lb.ExecutionAudit]) -> list[LevelAExecutionAudit]:
    parent_mapping = _parent_level_b_mapping(level_b_audits)
    report_metadata_paths = _latest_level_a_report_metadata()
    audits: list[LevelAExecutionAudit] = []
    for manifest_path in sorted(CAMPAIGNS_ROOT.glob("CMP-*/campaign_manifest.json")):
        campaign_manifest = load_json(manifest_path)
        if not isinstance(campaign_manifest, dict):
            continue
        if str(campaign_manifest.get("level") or "").upper() != "A":
            continue
        campaign_id = str(campaign_manifest.get("campaign_id") or manifest_path.parent.name)
        report_metadata = load_json(report_metadata_paths.get(campaign_id)) if campaign_id in report_metadata_paths else {}
        report_metadata = report_metadata if isinstance(report_metadata, dict) else {}
        report_summary_path = report_metadata.get("report_summary_path")
        report_summary = load_json(REPO_ROOT / str(report_summary_path)) if report_summary_path else {}
        report_summary = report_summary if isinstance(report_summary, dict) else {}
        parent = parent_mapping.get(campaign_id) or {}
        source_scope = "analysis over Level B case" if parent else "standalone Level A"
        for execution_manifest_path in sorted(manifest_path.parent.glob("level_A/EXEC-*/execution_manifest.json")):
            execution_manifest = load_json(execution_manifest_path)
            if not isinstance(execution_manifest, dict):
                continue
            exec_root = execution_manifest_path.parent
            forensic_result_card = load_json(exec_root / "forensic_result_card.json") or {}
            forensic_comparison_profile = load_json(exec_root / "forensic_comparison_profile.json") or {}
            preservation_profile = load_json(exec_root / "preservation_profile.json") or {}
            analysis_repeatability_profile = load_json(exec_root / "analysis_repeatability_profile.json") or {}
            audits.append(
                LevelAExecutionAudit(
                    campaign_id=campaign_id,
                    execution_id=str(execution_manifest.get("execution_id") or exec_root.name),
                    source_case_id=str(
                        execution_manifest.get("source_case_id")
                        or forensic_result_card.get("case_id")
                        or parent.get("source_case_id")
                        or ""
                    ),
                    campaign_manifest=campaign_manifest,
                    execution_manifest=execution_manifest,
                    report_metadata=report_metadata,
                    report_summary=report_summary,
                    forensic_result_card=forensic_result_card if isinstance(forensic_result_card, dict) else {},
                    forensic_comparison_profile=forensic_comparison_profile if isinstance(forensic_comparison_profile, dict) else {},
                    preservation_profile=preservation_profile if isinstance(preservation_profile, dict) else {},
                    analysis_repeatability_profile=analysis_repeatability_profile if isinstance(analysis_repeatability_profile, dict) else {},
                    parent_level_b_campaign_id=parent.get("parent_level_b_campaign_id"),
                    parent_level_b_execution_id=parent.get("parent_level_b_execution_id"),
                    source_scope=source_scope,
                )
            )
    return audits


def _group_level_a_by_campaign(audits: list[LevelAExecutionAudit]) -> dict[str, list[LevelAExecutionAudit]]:
    grouped: dict[str, list[LevelAExecutionAudit]] = {}
    for audit in audits:
        grouped.setdefault(audit.campaign_id, []).append(audit)
    for items in grouped.values():
        items.sort(key=lambda item: item.execution_id)
    return grouped


def _accepted_level_a(audit: LevelAExecutionAudit) -> tuple[str, str]:
    status = str(audit.execution_manifest.get("status") or audit.report_metadata.get("status") or "").lower()
    if status.startswith("completed"):
        return "accepted", ""
    return "excluded", "execution did not complete successfully enough to support stability comparison"


def _accepted_level_b(audit: lb.ExecutionAudit, accepted_ids: set[str]) -> tuple[str, str]:
    if audit.execution_id in accepted_ids:
        return "accepted", ""
    has_manifest = bool(audit.bundle_root and (audit.bundle_root / "manifest.json").is_file())
    status = str(audit.execution_manifest.get("status") or audit.level_b_report.get("execution_status") or "").lower()
    if status in {"failed", "error"} or not has_manifest:
        return "excluded", "failed Level B execution / no preserved case artifacts"
    return "excluded", "not included in the higher-level Level B comparison set"


def _accepted_level_b_audits(level_b_audits: list[lb.ExecutionAudit], accepted_ids: set[str]) -> list[lb.ExecutionAudit]:
    return [audit for audit in level_b_audits if audit.execution_id in accepted_ids]


def _excluded_level_b_audits(level_b_audits: list[lb.ExecutionAudit], accepted_ids: set[str]) -> list[lb.ExecutionAudit]:
    return [audit for audit in level_b_audits if audit.execution_id not in accepted_ids]


def _case_directory_alias(audit: lb.ExecutionAudit) -> str:
    for candidate in (
        audit.execution_manifest.get("run_case_path"),
        audit.execution_manifest.get("planned_case_path"),
        audit.forensic_result_card.get("case_path"),
        audit.forensic_result_card.get("run_case_path"),
    ):
        value = str(candidate or "").strip()
        if value:
            return value
    return not_available()


def _case_directory_mapping_note(audit: lb.ExecutionAudit) -> str:
    alias = _case_directory_alias(audit)
    if alias == not_available():
        return not_available()
    alias_name = Path(alias).name
    case_id = str(audit.case_id or "").strip()
    status = str(
        audit.execution_manifest.get("status")
        or audit.validation_entry.get("status")
        or audit.forensic_result_card.get("status")
        or ""
    ).strip().lower()
    if status == "failed":
        return (
            "Source artifacts record this preserved directory in run_case_path even though the "
            "Level B execution failed; keep it as provenance only, not as an accepted case mapping."
        )
    if case_id and case_id not in alias_name:
        return (
            "The retained lightweight bundle uses the Level B case_id, while the source artifacts "
            "resolve to this preserved heavy-case directory via run_case_path; treat this as an explicit alias mapping."
        )
    return "The preserved case directory matches the source artifact mapping for this execution."


def _case_directory_mapping_note_for_report(audit: lb.ExecutionAudit, accepted_ids: set[str] | None = None) -> str:
    if accepted_ids is not None:
        accepted_or_excluded, _ = _accepted_level_b(audit, accepted_ids)
        if accepted_or_excluded != "accepted":
            return (
                "Source artifacts record this preserved directory in run_case_path even though the "
                "Level B execution is excluded; keep it as provenance only, not as an accepted case mapping."
            )
    return _case_directory_mapping_note(audit)


def _level_a_manifest_hash(audit: LevelAExecutionAudit) -> str:
    for candidate in (
        ((audit.forensic_result_card.get("preservation_summary") or {}).get("manifest_sha256")),
        ((audit.forensic_comparison_profile.get("preservation_summary") or {}).get("manifest_sha256")),
        audit.preservation_profile.get("manifest_sha256"),
    ):
        value = str(candidate or "").strip()
        if value:
            return value
    return not_available()


def _level_a_case_digest(audit: LevelAExecutionAudit) -> str:
    case_digest = str(
        ((audit.forensic_result_card.get("acquisition_scope") or {}).get("case_digest_hash"))
        or audit.forensic_result_card.get("case_digest_hash")
        or ""
    ).strip()
    return case_digest or not_available()


def _level_a_outputs_generated(audit: LevelAExecutionAudit) -> str:
    layers = list(audit.forensic_result_card.get("evidence_layers_available") or [])
    return ", ".join(layers) if layers else not_available()


def _level_a_reconstruction_outputs_generated(audit: LevelAExecutionAudit) -> str:
    outputs = [
        name
        for name in [
            "reconstruction_metrics",
            "causal_status",
            "hypothesis_support_report",
            "forensic_storyline",
            "claimability_report",
        ]
        if name in list(audit.forensic_result_card.get("evidence_layers_available") or [])
    ]
    return ", ".join(outputs) if outputs else not_available()


def _level_a_table_a(level_a_audits: list[LevelAExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in level_a_audits:
        accepted, exclusion = _accepted_level_a(audit)
        rows.append(
            {
                "level_a_campaign_id": audit.campaign_id,
                "source_case_id": audit.source_case_id or not_available(),
                "analysis_run_id": audit.execution_id,
                "analysis_iteration_id": audit.execution_id,
                "analysis_pipeline_version": str(
                    audit.forensic_result_card.get("analysis_profile_id")
                    or audit.analysis_repeatability_profile.get("analysis_profile")
                    or not_available()
                ),
                "input_manifest_hash": _level_a_manifest_hash(audit),
                "input_case_digest": _level_a_case_digest(audit),
                "started_at_utc": str(audit.execution_manifest.get("created_at") or not_available()),
                "ended_at_utc": str(audit.execution_manifest.get("updated_at") or not_available()),
                "status": str(audit.execution_manifest.get("status") or audit.report_metadata.get("status") or not_available()),
                "accepted_or_excluded": accepted,
                "exclusion_reason": exclusion,
                "source_scope": audit.source_scope,
                "git_commit": not_available(),
            }
        )
    return rows


def _level_a_table_b(level_a_audits: list[LevelAExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    grouped = _group_level_a_by_campaign(level_a_audits)
    for campaign_id, items in grouped.items():
        previous: dict[str, Any] | None = None
        for audit in items:
            current = {
                "expected_relations": audit.forensic_result_card.get("recovered_edges", 0)
                + audit.forensic_result_card.get("degraded_edges", 0)
                + audit.forensic_result_card.get("missing_edges", 0),
                "recovered_relations": audit.forensic_result_card.get("recovered_edges", not_available()),
                "degraded_relations": audit.forensic_result_card.get("degraded_edges", not_available()),
                "ambiguous_relations": audit.forensic_result_card.get("ambiguous_edges", 0),
                "missing_relations": audit.forensic_result_card.get("missing_edges", not_available()),
                "CPR": audit.analysis_repeatability_profile.get("CPR", audit.report_summary.get("cpr", not_available())),
                "WCPR": audit.analysis_repeatability_profile.get("Weighted_CPR", audit.report_summary.get("weighted_cpr", not_available())),
                "recoverability_label": str(
                    audit.forensic_result_card.get("final_conclusion_class")
                    or audit.analysis_repeatability_profile.get("final_conclusion_class")
                    or not_available()
                ),
                "scientific_confidence": str(
                    audit.forensic_result_card.get("hypothesis_support")
                    or audit.analysis_repeatability_profile.get("hypothesis_support")
                    or not_available()
                ),
                "temporal_confidence": not_available("not computed by current pipeline"),
                "integrity_completeness": "full verification"
                if bool((audit.forensic_result_card.get("preservation_summary") or {}).get("manifest_available"))
                else not_available(),
            }
            changed = False
            reason = ""
            if previous is not None:
                diffs = [key for key, value in current.items() if previous.get(key) != value]
                changed = bool(diffs)
                if diffs:
                    reason = "metric_changed=" + ", ".join(diffs)
            rows.append(
                {
                    "source_case_id": audit.source_case_id or not_available(),
                    "analysis_run_id": audit.execution_id,
                    **current,
                    "changed_from_previous_iteration": changed,
                    "change_reason": reason or ("not applicable" if previous is None else ""),
                    "level_a_campaign_id": campaign_id,
                    "source_scope": audit.source_scope,
                }
            )
            previous = current
    return rows


def _augment_level_b_table_c(level_b_audits: list[lb.ExecutionAudit], accepted_ids: set[str]) -> list[dict]:
    base = lb.build_table1(level_b_audits, accepted_ids)
    by_exec = {audit.execution_id: audit for audit in level_b_audits}
    rows: list[dict] = []
    for row in base:
        audit = by_exec[row["rep_id"]]
        nested = audit.nested_level_a or {}
        accepted_or_excluded, exclusion_reason = _accepted_level_b(audit, accepted_ids)
        rows.append(
            {
                "rep_id": row["rep_id"],
                "case_id": row["case_id"],
                "run_id": row["run_id"],
                "campaign_id": row["campaign_id"],
                "scenario_id": row["scenario_id"],
                "deployment_id": row["deployment_id"],
                "attack_profile_id": row["attack_profile_id"],
                "attack_profile_version": row["attack_profile_version"],
                "acquisition_profile_id": row["acquisition_profile_id"],
                "procedure_version": row["procedure_version"],
                "analysis_pipeline_version": str(
                    audit.forensic_result_card.get("analysis_profile_id")
                    or not_available()
                ),
                "git_commit": not_available(),
                "started_at_utc": row["started_at_utc"],
                "ended_at_utc": row["ended_at_utc"],
                "status": row["status"],
                "accepted_or_excluded": accepted_or_excluded,
                "exclusion_reason": exclusion_reason,
                "nested_level_a_campaign_id": str(nested.get("campaign_id") or not_available()),
                "nested_level_a_status": str(((nested.get("report") or {}).get("status")) or not_available()),
                "nested_level_a_report_path": str(((nested.get("report") or {}).get("report_markdown_path")) or not_available()),
                "case_directory_alias": _case_directory_alias(audit),
                "case_directory_mapping_note": _case_directory_mapping_note_for_report(audit, accepted_ids),
            }
        )
    return rows


def _augment_level_b_table_d(level_b_audits: list[lb.ExecutionAudit], accepted_ids: set[str]) -> list[dict]:
    base = lb.build_table2(level_b_audits)
    by_exec = {audit.execution_id: audit for audit in level_b_audits}
    rows: list[dict] = []
    for row in base:
        audit = by_exec[row["rep_id"]]
        accepted_or_excluded, _ = _accepted_level_b(audit, accepted_ids)
        failed_or_incomplete = accepted_or_excluded != "accepted"
        rows.append(
            {
                "rep_id": row["rep_id"],
                "case_id": row["case_id"],
                "scenario_type": row["scenario_type"],
                "incident_class": row["incident_class"],
                "MITRE ATT&CK for ICS technique": row["MITRE ATT&CK for ICS technique"],
                "source_role": row["source_role"],
                "source_ip": row["source_ip"],
                "target_role": row["target_role"],
                "target_ip": row["target_ip"],
                "protocol": row["protocol"],
                "port": row["port"],
                "declared_modbus_function": row["declared_modbus_function"] or not_available(),
                "packet_confirmed_modbus_function": not_available("not computed by current pipeline"),
                "declared_register_or_address": row["declared_modbus_target_address"] or not_available(),
                "packet_confirmed_register_or_address": not_available("not computed by current pipeline"),
                "declared_value": row["declared_expected_value"] or not_available(),
                "packet_confirmed_value": not_available("not computed by current pipeline"),
                "expected_control_effect": row["expected_control_effect"],
                "actual_observed_control_effect": not_available("not computed by current pipeline"),
                "detection_path": row["detection_path"],
                "suricata_rule_id": row["suricata_rule_id"],
                "suricata_signature": row["suricata_signature"],
                "wazuh_rule_id": "not computed by current pipeline",
                "wazuh_alert_id": "not computed by current pipeline",
                "attack_log_path": row["attack_log_path"],
                "attack_log_sha256": row["attack_log_sha256"],
                "data_category": (
                    "failed execution; incident specification incomplete"
                    if failed_or_incomplete
                    else "declared but not packet-confirmed"
                    if "declared but not packet-confirmed" in str(row["declared_modbus_target_address"])
                    or "declared but not packet-confirmed" in str(row["declared_expected_value"])
                    else "directly observed"
                ),
            }
        )
    return rows


def _level_b_table_e(level_b_audits: list[lb.ExecutionAudit]) -> list[dict]:
    base = lb.build_table3(level_b_audits)
    by_case = {audit.case_id: audit for audit in level_b_audits}
    rows: list[dict] = []
    for row in base:
        audit = by_case.get(str(row["case_id"]))
        manifest_rows = lb.latest_manifest_by_rel(audit) if audit else []
        network_rows = [item for item in manifest_rows if str(item.get("rel_path") or "").startswith("network/")]
        pcap_rows = [
            item
            for item in network_rows
            if str(item.get("rel_path") or "").lower().endswith((".pcap", ".pcapng"))
        ]
        rows.append(
            {
                "case_id": row["case_id"],
                "network_artifact_count": row["network_artifact_count"],
                "network_total_size_bytes": row["network_total_size_bytes"],
                "network_metadata_artifact_count": len(network_rows),
                "pcap_artifact_count": len(pcap_rows),
                "pcap_total_size_bytes": sum(int(item.get("size_bytes") or 0) for item in pcap_rows),
                "network_context_manifest_present": bool(audit and audit.bundle_root and (audit.bundle_root / "network" / "traffic_preserved" / "network_context_manifest.json").is_file()),
                "memory_artifact_count": row["memory_artifact_count"],
                "memory_total_size_bytes": row["memory_total_size_bytes"],
                "disk_artifact_count": row["disk_artifact_count"],
                "disk_total_size_bytes": row["disk_total_size_bytes"],
                "industrial_artifact_count": row["industrial_artifact_count"],
                "industrial_total_size_bytes": row["industrial_total_size_bytes"],
                "alerts_artifact_count": row["alerts_artifact_count"],
                "metadata_artifact_count": row["metadata_artifact_count"],
                "derived_artifact_count": row["derived_artifact_count"],
                "manifest_present": row["manifest_present"],
                "custody_log_present": row["custody_log_present"],
                "pipeline_events_present": row["pipeline_events_present"],
            }
        )
    return rows


def _level_b_table_f(level_b_audits: list[lb.ExecutionAudit]) -> list[dict]:
    base = lb.build_table8_case(level_b_audits)
    by_case = {audit.case_id: audit for audit in level_b_audits}
    rows: list[dict] = []
    for row in base:
        audit = by_case.get(str(row["case_id"]))
        findings = ((audit.integrity_report.get("findings") or {}) if audit else {})
        missing = list(findings.get("missing_artifacts") or [])
        skipped = list(findings.get("hash_skipped_large_or_nohash") or [])
        custody_valid = findings.get("custody_chain_valid")
        if missing or custody_valid is False:
            manifest_status = "failed verification"
        elif skipped:
            manifest_status = "partial verification, because large artifacts were skipped"
        elif custody_valid is True:
            manifest_status = "full verification"
        else:
            manifest_status = "not computed by current pipeline"
        limitation = ""
        if str(row.get("industrial_ot_evidence_preservation_status") or "") != "directly observed":
            limitation = "Industrial / OT export is not preserved in the current Level B artifacts."
        elif manifest_status != "full verification":
            limitation = "Manifest or custody verification is not complete."
        if manifest_status == "partial verification, because large artifacts were skipped":
            limitation = (
                (limitation + " " if limitation else "")
                + "Integrity verification is partial because large artifacts were skipped; custody-chain validity does not imply full byte-level rehash of every artifact."
            ).strip()
        rows.append(
            {
                "case_id": row["case_id"],
                "network_evidence_preservation": str(row.get("network_evidence_preservation_status") or not_available()),
                "trigger_alert_preservation": str(row.get("trigger_alert_preservation_status") or not_available()),
                "industrial_ot_evidence_preservation": str(row.get("industrial_ot_evidence_preservation_status") or "not available in current artifacts"),
                "host_evidence_preservation": str(row.get("host_evidence_preservation_status") or not_available()),
                "manifest_and_custody_verification": manifest_status,
                "main_limitation": limitation or "",
            }
        )
    return rows


def _level_b_table_g(level_b_audits: list[lb.ExecutionAudit]) -> list[dict]:
    base = lb.build_table4(level_b_audits)
    by_case = {audit.case_id: audit for audit in level_b_audits}
    reconstruction_by_case = {
        str(row["case_id"]): row
        for row in lb.build_table9_case(level_b_audits)
    }
    rows: list[dict] = []
    for row in base:
        audit = by_case.get(str(row["case_id"]))
        deduped_artifacts = lb.latest_manifest_by_rel(audit) if audit else []
        findings = ((audit.integrity_report.get("findings") or {}) if audit else {})
        skipped = list(findings.get("hash_skipped_large_or_nohash") or [])
        status = str(row["manifest_verification_status"] or "")
        reconstruction = reconstruction_by_case.get(str(row["case_id"]), {})
        if status == "verified":
            mode = "full verification"
        elif status == "verified_with_large_artifact_skip":
            mode = "partial verification, because large artifacts were skipped"
        elif status == "failed_or_incomplete":
            mode = "failed verification"
        else:
            mode = "not computed by current pipeline"
        rows.append(
            {
                "case_id": row["case_id"],
                "manifest_verification_mode": mode,
                "manifest_declared_artifacts": len(deduped_artifacts),
                "manifest_deduped_artifacts": len(deduped_artifacts),
                "manifest_verification_attempted_artifacts": row["manifest_verified_artifacts"],
                "manifest_verified_artifacts": row["manifest_verified_artifacts"],
                "manifest_skipped_artifacts": len(skipped),
                "manifest_failed_artifacts": row["manifest_failed_artifacts"],
                "manifest_missing_artifacts": row["manifest_missing_artifacts"],
                "custody_chain_valid": row["custody_chain_verification_status"],
                "custody_event_count": row["custody_event_count"],
                "hash_chain_errors": row["hash_chain_errors"],
                "primary_derived_separation_verified": row["primary_derived_separation_verified"],
                "full_rehash_performed": False if skipped else True,
                "large_artifact_skip_enabled": bool(skipped),
                "integrity_verification_ratio": reconstruction.get("integrity_completeness", "not available in current artifacts"),
            }
        )
    return rows


def _level_b_table_h(level_b_audits: list[lb.ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in level_b_audits:
        times = lb.case_level_times(audit)
        network_import_preserved = lb.event_time(audit, "network_context_import_completed", first=False) or str(
            ((load_json(audit.bundle_root / "metadata" / "acquisition_profile.json") or {}).get("network_context_import_completed_utc"))
            or ""
        ).strip() or None
        trigger = times["trigger_time_utc"]
        industrial_start = times["industrial_export_start_utc"]
        row = {
            "case_id": audit.case_id,
            "trigger_time_utc": trigger or not_available(),
            "memory_acquisition_start_utc": times["memory_acquisition_start_utc"] or not_available(),
            "memory_preserved_utc": times["memory_preserved_utc"] or not_available(),
            "network_context_import_preserved_utc": network_import_preserved or not_available(),
            "industrial_export_preserved_utc": times["industrial_export_preserved_utc"] or not_available(),
            "disk_snapshot_start_utc": times["disk_snapshot_start_utc"] or not_available(),
            "disk_snapshot_preserved_utc": times["disk_snapshot_preserved_utc"] or not_available(),
            "first_primary_artifact_sealed_utc": times["first_primary_artifact_sealed_utc"] or not_available(),
            "full_case_sealed_utc": times["full_case_sealed_utc"] or not_available(),
            "alert_to_memory_start_s": times["alert_to_memory_start_s"] if times["alert_to_memory_start_s"] is not None else not_available(),
            "alert_to_memory_preserved_s": times["alert_to_memory_preserved_s"] if times["alert_to_memory_preserved_s"] is not None else not_available(),
            "alert_to_network_context_import_preserved_s": lb.seconds_between(trigger, network_import_preserved)
            if trigger and network_import_preserved
            else not_available(),
            "alert_to_industrial_export_start_s": lb.seconds_between(trigger, industrial_start)
            if trigger and industrial_start
            else not_available(),
            "alert_to_industrial_export_preserved_s": times["alert_to_industrial_export_preserved_s"]
            if times["alert_to_industrial_export_preserved_s"] is not None
            else not_available(),
            "alert_to_disk_snapshot_start_s": times["alert_to_disk_snapshot_start_s"] if times["alert_to_disk_snapshot_start_s"] is not None else not_available(),
            "alert_to_disk_snapshot_preserved_s": times["alert_to_disk_snapshot_preserved_s"] if times["alert_to_disk_snapshot_preserved_s"] is not None else not_available(),
            "T_first_sealed_s": times["T_first_sealed_s"] if times["T_first_sealed_s"] is not None else not_available(),
            "T_case_sealed_s": times["T_case_sealed_s"] if times["T_case_sealed_s"] is not None else not_available(),
        }
        rows.append(row)
    return rows


def _aggregate_metric_rows(
    *,
    level: str,
    metric_names: list[str],
    rows: list[dict],
    level_case_ids: list[str],
    data_category_map: dict[str, str] | None = None,
) -> list[dict]:
    data_category_map = data_category_map or {}
    result: list[dict] = []
    for metric_name in metric_names:
        values: list[float] = []
        missing: list[str] = []
        for row in rows:
            value = row.get(metric_name)
            if isinstance(value, (int, float)):
                values.append(float(value))
            else:
                missing.append(str(row.get("case_id") or row.get("analysis_run_id") or row.get("level_a_campaign_id") or level))
        result.append(
            {
                "level": level,
                "metric_name": metric_name,
                "mean": mean_value(values) if values else not_available(),
                "sample_standard_deviation": sample_std(values) if len(values) >= 2 else not_available(),
                "minimum": round(min(values), 6) if values else not_available(),
                "maximum": round(max(values), 6) if values else not_available(),
                "denominator_n": len(values),
                "excluded_cases": "",
                "missing_cases": ", ".join(missing),
                "data_category": data_category_map.get(metric_name, "computed from existing artifacts"),
            }
        )
    return result


def _level_b_table_i(level_b_table_e: list[dict], level_b_table_h: list[dict], level_b_audits: list[lb.ExecutionAudit], accepted_ids: set[str]) -> list[dict]:
    accepted_case_ids = [audit.case_id for audit in level_b_audits if audit.execution_id in accepted_ids]
    accepted_artifacts = [row for row in level_b_table_e if row["case_id"] in accepted_case_ids]
    accepted_timings = [row for row in level_b_table_h if row["case_id"] in accepted_case_ids]
    rows = _aggregate_metric_rows(
        level="Level B cases",
        metric_names=[
            "alert_to_memory_start_s",
            "alert_to_memory_preserved_s",
            "alert_to_network_context_import_preserved_s",
            "alert_to_industrial_export_preserved_s",
            "alert_to_disk_snapshot_start_s",
            "alert_to_disk_snapshot_preserved_s",
            "T_first_sealed_s",
            "T_case_sealed_s",
        ],
        rows=accepted_timings,
        level_case_ids=accepted_case_ids,
    )
    rows.extend(
        _aggregate_metric_rows(
            level="Level B cases",
            metric_names=[
                "network_total_size_bytes",
                "memory_total_size_bytes",
                "disk_total_size_bytes",
                "industrial_total_size_bytes",
            ],
            rows=accepted_artifacts,
            level_case_ids=accepted_case_ids,
            data_category_map={"industrial_total_size_bytes": "not available in current artifacts"},
        )
    )
    retry_values: list[float] = []
    for audit in level_b_audits:
        if audit.execution_id not in accepted_ids:
            continue
        failed_events = [event for event in audit.pipeline_events if str(event.get("event") or "").endswith("_failed")]
        retries = max(int(audit.level_b_report.get("trigger_attempts_total") or 1) - 1, 0)
        retry_values.append(float(len(failed_events) + retries))
    rows.append(
        {
            "level": "Level B cases",
            "metric_name": "retries_or_failures_count",
            "mean": mean_value(retry_values) if retry_values else not_available(),
            "sample_standard_deviation": sample_std(retry_values) if len(retry_values) >= 2 else not_available(),
            "minimum": round(min(retry_values), 6) if retry_values else not_available(),
            "maximum": round(max(retry_values), 6) if retry_values else not_available(),
            "denominator_n": len(retry_values),
            "excluded_cases": "",
            "missing_cases": "",
            "data_category": "computed from existing artifacts",
        }
    )
    return rows


def _level_b_table_j(level_b_audits: list[lb.ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for row in lb.build_table7(level_b_audits):
        numeric = row["max_clock_offset_s"]
        rows.append(
            {
                "case_id": row["case_id"],
                "time_sync_status": row["time_sync_status"],
                "nodes_measured": row["nodes_measured"],
                "nodes_failed": row["nodes_failed"],
                "max_clock_offset_s": numeric,
                "worst_node": row["worst_node"],
                "correction_applied": row["correction_applied"],
                "mean_clock_offset_s": not_available("not computed by current pipeline"),
                "time_sync_report_path": row["time_sync_report_path"],
                "time_sync_timestamp_utc": not_available("not computed by current pipeline"),
            }
        )
    return rows


def _level_k_and_l(
    level_b_audits: list[lb.ExecutionAudit],
    level_a_audits: list[LevelAExecutionAudit],
) -> tuple[list[dict], list[dict]]:
    level_b_case = {
        str(row["case_id"]): row
        for row in lb.build_table9_case(level_b_audits)
    }
    level_b_rel = lb.build_table9_relations(level_b_audits)
    rel_by_case: dict[str, list[dict]] = {}
    for row in level_b_rel:
        rel_by_case.setdefault(str(row["case_id"]), []).append(row)

    def _counts(rows: list[dict]) -> dict[str, Any]:
        expected = len(rows)
        recovered = sum(1 for item in rows if str(item.get("relation_state")) == "recovered")
        degraded = sum(1 for item in rows if str(item.get("relation_state")) == "degraded")
        ambiguous = sum(1 for item in rows if str(item.get("relation_state")) == "ambiguous")
        missing = sum(1 for item in rows if str(item.get("relation_state")) == "missing")
        total_weight = 0.0
        recovered_weight = 0.0
        have_weights = False
        for item in rows:
            try:
                weight = float(item.get("relation_weight"))
            except Exception:
                continue
            have_weights = True
            total_weight += weight
            if str(item.get("relation_state")) == "recovered":
                recovered_weight += weight
        return {
            "expected_relations": expected,
            "recovered_relations": recovered,
            "degraded_relations": degraded,
            "ambiguous_relations": ambiguous,
            "missing_relations": missing,
            "CPR": round(recovered / expected, 6) if expected else not_available(),
            "WCPR": round(recovered_weight / total_weight, 6) if have_weights and total_weight > 0 else not_available(),
        }

    table_l: list[dict] = []
    for row in level_b_rel:
        table_l.append(
            {
                "level": "Level B case",
                "case_id": row["case_id"],
                "analysis_run_id": not_available("not applicable under active acquisition profile"),
                "relation_id": row["relation_id"],
                "relation_description": row["relation_description"],
                "relation_state": row["relation_state"],
                "relation_weight": row["relation_weight"],
                "evidence_refs": row["evidence_refs"],
                "timestamp_available": row["timestamp_available"],
                "timestamp_resolvable": row["timestamp_resolvable"],
                "integrity_verified": row["integrity_verified"],
                "degradation_reason": row["degradation_reason"],
                "missing_reason": row["missing_reason"],
                "classification_rationale": str(row["relation_state"]),
            }
        )
    for audit in level_a_audits:
        for row in rel_by_case.get(audit.source_case_id, []):
            table_l.append(
                {
                    "level": audit.source_scope,
                    "case_id": audit.source_case_id,
                    "analysis_run_id": audit.execution_id,
                    "relation_id": row["relation_id"],
                    "relation_description": row["relation_description"],
                    "relation_state": row["relation_state"],
                    "relation_weight": row["relation_weight"],
                    "evidence_refs": row["evidence_refs"],
                    "timestamp_available": row["timestamp_available"],
                    "timestamp_resolvable": row["timestamp_resolvable"],
                    "integrity_verified": row["integrity_verified"],
                    "degradation_reason": row["degradation_reason"],
                    "missing_reason": row["missing_reason"],
                    "classification_rationale": "linked read-only from the preserved source case during analysis over Level B case",
                }
            )

    table_k: list[dict] = []
    for case_id, rows in rel_by_case.items():
        base = level_b_case.get(case_id, {})
        table_k.append(
            {
                "level": "Level B case",
                "case_id": case_id,
                "analysis_run_id": not_available("not applicable under active acquisition profile"),
                **_counts(rows),
                "recoverability_label": base.get("recoverability_label", not_available()),
                "scientific_confidence": base.get("scientific_confidence", not_available()),
                "temporal_confidence": base.get("temporal_confidence", not_available()),
                "integrity_completeness": base.get("integrity_completeness", not_available()),
            }
        )
    for audit in level_a_audits:
        source_rows = rel_by_case.get(audit.source_case_id, [])
        base = level_b_case.get(audit.source_case_id, {})
        table_k.append(
            {
                "level": audit.source_scope,
                "case_id": audit.source_case_id,
                "analysis_run_id": audit.execution_id,
                **_counts(source_rows),
                "recoverability_label": audit.analysis_repeatability_profile.get("final_conclusion_class", not_available()),
                "scientific_confidence": audit.analysis_repeatability_profile.get("hypothesis_support", not_available()),
                "temporal_confidence": base.get("temporal_confidence", not_available("linked from preserved Level B source case")),
                "integrity_completeness": base.get("integrity_completeness", not_available()),
            }
        )
    return table_k, table_l


def _truthful_level_b_case_specific_sections(level_b_audits: list[lb.ExecutionAudit]) -> list[str]:
    if not level_b_audits:
        return ["## Case-specific Causal Path and Metric Interpretation", "", "_No Level B cases available._"]
    return lb.build_case_specific_causal_sections(
        level_b_audits,
        {
            "table5": lb.build_table5(level_b_audits),
            "table8_case": lb.build_table8_case(level_b_audits),
            "table9_case": lb.build_table9_case(level_b_audits),
        },
    )


def _truthful_nested_level_a_causal_section(
    level_a_audits: list[LevelAExecutionAudit],
    level_b_audits: list[lb.ExecutionAudit],
) -> list[str]:
    nested_audits = [
        audit
        for audit in level_a_audits
        if audit.source_scope == "analysis over Level B case"
    ]
    if not nested_audits:
        return ["## Nested Level A Causal Interpretation", "", "_No nested Level A over Level B cases available._"]

    parent_by_case = {audit.case_id: audit for audit in level_b_audits}
    rows: list[dict] = []
    for audit in sorted(
        nested_audits,
        key=lambda item: (item.source_case_id, item.campaign_id, item.execution_id),
    ):
        parent = parent_by_case.get(audit.source_case_id)
        relation_rows = lb.relation_rows_for_audit(parent) if parent else []
        rows.append(
            {
                "source_case_id": audit.source_case_id or not_available(),
                "analysis_run_id": audit.execution_id,
                "parent_level_b_execution_id": audit.parent_level_b_execution_id or not_available(),
                "reused_relation_rows": len(relation_rows) if relation_rows else not_available(),
                "CPR": audit.analysis_repeatability_profile.get("CPR", not_available()),
                "WCPR": audit.analysis_repeatability_profile.get("Weighted_CPR", not_available()),
                "recoverability_label": audit.analysis_repeatability_profile.get(
                    "final_conclusion_class",
                    not_available(),
                ),
                "scientific_confidence": audit.analysis_repeatability_profile.get(
                    "hypothesis_support",
                    not_available(),
                ),
                "causal_state_source": "linked read-only from preserved Level B source case",
                "interpretation": "Not an independent acquisition; relation-level semantics remain anchored to the preserved source case and Table L duplicates those states intentionally.",
            }
        )

    return [
        "## Nested Level A Causal Interpretation",
        "",
        "Nested Level A rows in this package are analysis runs over already preserved Level B source cases. They do not contribute new acquisition-side causal observations and must be interpreted as read-only reconstructions over the inherited source-case evidence.",
        "",
        _markdown_table(
            rows,
            [
                "source_case_id",
                "analysis_run_id",
                "parent_level_b_execution_id",
                "reused_relation_rows",
                "CPR",
                "WCPR",
                "recoverability_label",
                "scientific_confidence",
                "causal_state_source",
                "interpretation",
            ],
        ),
        "",
        "Interpretation rules for nested Level A over Level B cases:",
        "- `recovered/degraded/missing` relation states remain those of the preserved Level B source case, because no new preservation event occurred.",
        "- `CPR` and `WCPR` in nested Level A rows describe analysis outputs over the inherited case, not an independent acquisition denominator.",
        "- If the source Level B case lacks packet-level Modbus confirmation or OT export, the nested Level A run cannot upgrade that relation to `recovered` without new preserved evidence.",
    ]


def _truthful_case_specific_causal_sections(
    level_b_audits: list[lb.ExecutionAudit],
    level_a_audits: list[LevelAExecutionAudit],
) -> list[str]:
    return [
        "## Interpretation Guardrails",
        "- Memory and disk preservation in the current accepted Level B cases remains real preserved host evidence and should be read as such.",
        "- Analysis and derived outputs are retained in lightweight bundles, but nested Level A over Level B cases are still read-only analyses over preserved source cases rather than independent acquisitions.",
        "- Network context may exist as context only; when `preserved_segments=0`, it must not be presented as confirmed packet-level Modbus evidence.",
        "- OT export remains unavailable in the current affected cases unless explicitly preserved, so OT-dependent causal relations must remain `missing` rather than being promoted by inference.",
        "- The recovered/degraded/missing semantics below intentionally match the dedicated Level B reconstruction report so both packages stay scientifically aligned.",
        "",
        *_truthful_level_b_case_specific_sections(level_b_audits),
        "",
        *_truthful_nested_level_a_causal_section(level_a_audits, level_b_audits),
    ]


def _level_a_table_b_from_table_k(level_a_audits: list[LevelAExecutionAudit], table_k: list[dict]) -> list[dict]:
    rows: list[dict] = []
    nested_rows = [
        row
        for row in table_k
        if str(row.get("level")) == "analysis over Level B case"
    ]
    by_exec = {audit.execution_id: audit for audit in level_a_audits}
    grouped: dict[str, list[dict]] = {}
    for row in nested_rows:
        audit = by_exec.get(str(row.get("analysis_run_id")))
        campaign_id = audit.campaign_id if audit else "not available in current artifacts"
        grouped.setdefault(campaign_id, []).append(row)
    for campaign_id, items in grouped.items():
        items.sort(key=lambda item: str(item.get("analysis_run_id") or ""))
        previous: dict[str, Any] | None = None
        for row in items:
            current = {
                "expected_relations": row["expected_relations"],
                "recovered_relations": row["recovered_relations"],
                "degraded_relations": row["degraded_relations"],
                "ambiguous_relations": row["ambiguous_relations"],
                "missing_relations": row["missing_relations"],
                "CPR": row["CPR"],
                "WCPR": row["WCPR"],
                "recoverability_label": row["recoverability_label"],
                "scientific_confidence": row["scientific_confidence"],
                "temporal_confidence": row["temporal_confidence"],
                "integrity_completeness": row["integrity_completeness"],
            }
            diffs = [key for key, value in current.items() if previous is not None and previous.get(key) != value]
            rows.append(
                {
                    "source_case_id": row["case_id"],
                    "analysis_run_id": row["analysis_run_id"],
                    **current,
                    "changed_from_previous_iteration": bool(diffs),
                    "change_reason": ("metric_changed=" + ", ".join(diffs)) if diffs else ("not applicable" if previous is None else ""),
                    "level_a_campaign_id": campaign_id,
                    "source_scope": "analysis over Level B case",
                }
            )
            previous = current
    return rows


def _nested_level_a_stability_flags(table_b: list[dict]) -> dict[str, Any]:
    rows = [row for row in table_b if str(row.get("source_scope")) == "analysis over Level B case"]
    structural_keys = {
        (
            row.get("expected_relations"),
            row.get("recovered_relations"),
            row.get("degraded_relations"),
            row.get("ambiguous_relations"),
            row.get("missing_relations"),
            row.get("CPR"),
            row.get("WCPR"),
        )
        for row in rows
    }
    interpretive_keys = {
        (
            row.get("recoverability_label"),
            row.get("scientific_confidence"),
            row.get("temporal_confidence"),
            row.get("integrity_completeness"),
        )
        for row in rows
    }
    return {
        "count": len(rows),
        "structural_stable": len(structural_keys) <= 1 if rows else False,
        "interpretive_labels_changed": len(interpretive_keys) > 1,
    }


def _scientific_usability(
    *,
    level_a_standalone_count: int,
    level_b_accepted_count: int,
    industrial_available: bool,
    level_a_nested_table_b: list[dict],
) -> list[dict]:
    nested_flags = _nested_level_a_stability_flags(level_a_nested_table_b)
    return [
        {
            "metric_or_table": "repetition index",
            "usable_for_final_paper": level_b_accepted_count >= 6,
            "usable_only_as_preliminary_audit": level_b_accepted_count > 0 and level_b_accepted_count < 6,
            "main_limitation": f"accepted Level B denominator is n={level_b_accepted_count}",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": False,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": level_b_accepted_count < 6,
        },
        {
            "metric_or_table": "incident specification",
            "usable_for_final_paper": False,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": "packet-level Modbus confirmation is not preserved in the current accepted artifacts and the raw-alert Wazuh binding is not preserved as a defensible case link",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": True,
            "requires_acquisition_or_preservation_change": True,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": True,
        },
        {
            "metric_or_table": "artifact summary",
            "usable_for_final_paper": level_b_accepted_count >= 6,
            "usable_only_as_preliminary_audit": level_b_accepted_count > 0 and level_b_accepted_count < 6,
            "main_limitation": f"current denominator is n={level_b_accepted_count}",
            "requires_only_reporting_fix": True,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": False,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": level_b_accepted_count < 6,
        },
        {
            "metric_or_table": "manifest/custody verification",
            "usable_for_final_paper": False,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": "verification remains partial when large artifacts are skipped and hash mismatch vs missing artifact counts are not separated",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": True,
            "requires_acquisition_or_preservation_change": False,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": False,
        },
        {
            "metric_or_table": "timing metrics",
            "usable_for_final_paper": industrial_available and level_b_accepted_count >= 6,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": "industrial export timestamps are missing and denominator is limited",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": True,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": True,
        },
        {
            "metric_or_table": "Level A analysis stability over preserved source case",
            "usable_for_final_paper": nested_flags["count"] >= 6 and nested_flags["structural_stable"] and not nested_flags["interpretive_labels_changed"],
            "usable_only_as_preliminary_audit": nested_flags["count"] > 0,
            "main_limitation": (
                "structural metrics are stable over the 6 nested Level A runs, but interpretive labels changed between EXEC-0001 and later iterations and verification semantics remain partial"
                if nested_flags["count"] >= 6 and nested_flags["interpretive_labels_changed"]
                else "no repeated nested Level A analysis set large enough for stability interpretation is available"
            ),
            "requires_only_reporting_fix": False,
            "requires_analysis_change": nested_flags["interpretive_labels_changed"],
            "requires_acquisition_or_preservation_change": False,
            "requires_fresh_level_a_campaign": nested_flags["count"] < 6,
            "requires_fresh_level_b_campaign": False,
        },
        {
            "metric_or_table": "industrial / OT evidence preservation",
            "usable_for_final_paper": industrial_available,
            "usable_only_as_preliminary_audit": not industrial_available,
            "main_limitation": "OT export is not preserved in the current Level B cases",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": True,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": True,
        },
        {
            "metric_or_table": "causal reconstruction summary",
            "usable_for_final_paper": False,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": "current evidence set yields systematic missing/degraded relations and denominator is limited",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": True,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": True,
        },
        {
            "metric_or_table": "relation-level reconstruction table",
            "usable_for_final_paper": False,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": "relation rows are available, but some evidence refs depend on linked source-case outputs and OT export is missing",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": True,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": True,
        },
        {
            "metric_or_table": "CPR",
            "usable_for_final_paper": False,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": f"current CPR values are available, but only over n={level_b_accepted_count} accepted Level B case(s)",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": False,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": level_b_accepted_count < 6,
        },
        {
            "metric_or_table": "WCPR",
            "usable_for_final_paper": False,
            "usable_only_as_preliminary_audit": True,
            "main_limitation": f"current weighted values are available, but only over n={level_b_accepted_count} accepted Level B case(s)",
            "requires_only_reporting_fix": False,
            "requires_analysis_change": False,
            "requires_acquisition_or_preservation_change": False,
            "requires_fresh_level_a_campaign": False,
            "requires_fresh_level_b_campaign": level_b_accepted_count < 6,
        },
    ]


def _decision(
    level_a_standalone_count: int,
    level_b_accepted_count: int,
    industrial_available: bool,
    level_a_nested_table_b: list[dict],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    nested_flags = _nested_level_a_stability_flags(level_a_nested_table_b)
    if nested_flags["count"] >= 6 and nested_flags["structural_stable"]:
        reasons.append("nested Level A structural metrics are stable over 6 runs on the preserved source case")
    if nested_flags["interpretive_labels_changed"]:
        reasons.append("nested Level A interpretive labels changed between EXEC-0001 and later iterations")
    if level_b_accepted_count < 6:
        reasons.append(f"Level B accepted denominator is only n={level_b_accepted_count}")
    if not industrial_available:
        reasons.append("OT/industrial export is not preserved in the current Level B artifacts")
    reasons.append("packet-level Modbus confirmation and defensible Wazuh trigger mapping are not preserved/computed strongly enough for final claims")
    if level_b_accepted_count < 6 or not industrial_available:
        return "Decision D: a fresh Level B campaign is required before final Level B paper claims.", reasons
    return "Decision B: current artifacts are sufficient only for preliminary Level A/Level B audit.", reasons


def _level_a_over_level_b_breakdown(level_a_audits: list[LevelAExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in sorted(
        [item for item in level_a_audits if item.source_scope == "analysis over Level B case"],
        key=lambda item: (item.source_case_id, item.campaign_id, item.execution_id),
    ):
        rows.append(
            {
                "source_case_id": audit.source_case_id,
                "parent_level_b_campaign_id": audit.parent_level_b_campaign_id or not_available(),
                "parent_level_b_execution_id": audit.parent_level_b_execution_id or not_available(),
                "level_a_campaign_id": audit.campaign_id,
                "analysis_run_id": audit.execution_id,
                "analysis_iteration_id": audit.execution_id,
                "status": str(audit.execution_manifest.get("status") or audit.report_metadata.get("status") or not_available()),
                "denominator_scope": "Counts toward N_A_over_Level_B_cases",
            }
        )
    return rows


def _package_consistency_summary(
    *,
    tables: dict[str, list[dict]],
    decision: str,
    option: str,
    level_a_total: int,
    level_a_accepted: int,
    level_a_excluded: int,
    level_a_over_level_b: int,
    level_b_total: int,
    level_b_accepted: int,
    level_b_excluded: int,
) -> list[dict]:
    table_a = tables["Table A"]
    table_c = tables["Table C"]
    accepted_table_c = [row for row in table_c if str(row.get("accepted_or_excluded")) == "accepted"]
    unique_level_b_cases = {str(row["case_id"]) for row in accepted_table_c}
    unique_level_b_campaigns = {str(row["campaign_id"]) for row in table_c}
    nested_level_a_campaigns = {str(row["nested_level_a_campaign_id"]) for row in accepted_table_c}
    table_a_case_ids = {str(row["source_case_id"]) for row in table_a}
    checks = [
        {
            "check_name": "Decision consistency",
            "status": "pass" if decision.startswith("Decision ") and option.startswith("Option ") else "fail",
            "detail": f"Decision='{decision}' Option='{option}'",
        },
        {
            "check_name": "Level A standalone denominator consistency",
            "status": "pass" if level_a_total == level_a_accepted + level_a_excluded else "fail",
            "detail": f"N_A_total={level_a_total}, N_A_accepted={level_a_accepted}, N_A_excluded={level_a_excluded}",
        },
        {
            "check_name": "Level B denominator consistency",
            "status": "pass" if level_b_total == level_b_accepted + level_b_excluded else "fail",
            "detail": f"N_B_total={level_b_total}, N_B_accepted={level_b_accepted}, N_B_excluded={level_b_excluded}",
        },
        {
            "check_name": "Nested Level A count consistency",
            "status": "pass" if level_a_over_level_b == len(table_a) else "fail",
            "detail": f"N_A_over_Level_B_cases={level_a_over_level_b}, Table A rows={len(table_a)}",
        },
        {
            "check_name": "Level B case index consistency",
            "status": "pass" if level_b_accepted == len(accepted_table_c) == len(unique_level_b_cases) else "fail",
            "detail": f"N_B_accepted={level_b_accepted}, accepted Table C rows={len(accepted_table_c)}, unique_case_ids={len(unique_level_b_cases)}",
        },
        {
            "check_name": "Parent-child campaign linkage consistency",
            "status": "pass" if len(nested_level_a_campaigns) == len(unique_level_b_cases) else "fail",
            "detail": f"Level B campaign(s)={sorted(unique_level_b_campaigns)}, nested Level A campaigns={sorted(nested_level_a_campaigns)}",
        },
        {
            "check_name": "Case ID reuse consistency",
            "status": "pass" if table_a_case_ids == unique_level_b_cases else "fail",
            "detail": f"Table A source_case_ids={sorted(table_a_case_ids)}, Table C case_ids={sorted(unique_level_b_cases)}",
        },
    ]
    return checks


def _what_can_be_used_sections(
    *,
    level_a_total: int,
    level_b_accepted: int,
    industrial_available: bool,
    level_a_nested_table_b: list[dict],
) -> dict[str, list[str]]:
    nested_flags = _nested_level_a_stability_flags(level_a_nested_table_b)
    return {
        "What can be used now": [
            f"Preliminary Level B reporting over n={level_b_accepted} accepted cases.",
            f"Analysis-over-Level-B-case stability reporting for the {nested_flags['count']} nested Level A executions.",
            "Artifact summaries, trigger alert preservation, host evidence preservation, timing metrics where present, and partial manifest/custody verification status.",
            "CPR and WCPR values as preliminary metrics, with explicit denominator and limitation statements. The current WCPR is the preserved recovered-only pipeline variant unless the final paper adopts the same weighting.",
        ],
        "What is preliminary only": [
            f"All Level B aggregate metrics, because the current accepted denominator is n={level_b_accepted} and not N_B=6.",
            "All Level A rows in the current package, because they are analysis over Level B cases rather than independent acquisition repetitions.",
            "Incident specification fields tied to Modbus function/register/value, because they remain declared but not packet-confirmed.",
            "Manifest/custody interpretation, because verification is partial when large artifacts are skipped.",
        ],
        "What cannot be used as final paper claims": [
            "Any claim that Level A interpretive labels are fully stable, because EXEC-0001 differs from EXEC-0002..EXEC-0006.",
            "Any claim that industrial / OT evidence preservation passed for the current Level B cases, because OT export is not preserved.",
            "Any claim that packet-level Modbus function/register/value or defensible Wazuh trigger IDs were directly observed.",
            "Any claim that the current dataset supports a final N_B=6 evaluation.",
        ],
        "What must be rerun": [
            "A fresh homogeneous Level B campaign if final Level B tables are required.",
            f"A fresh Level B campaign after any acquisition/preservation/analysis change that affects comparability, because the current n={level_b_accepted} accepted case(s) must remain preliminary audit only.",
        ],
    }


def _accepted_level_b_case_rows(table_c: list[dict]) -> list[dict]:
    return [row for row in table_c if str(row.get("accepted_or_excluded")) == "accepted"]


def _excluded_level_b_execution_rows(table_c: list[dict]) -> list[dict]:
    return [row for row in table_c if str(row.get("accepted_or_excluded")) != "accepted"]


def _case_alias_rows(level_b_audits: list[lb.ExecutionAudit], accepted_ids: set[str]) -> list[dict]:
    rows: list[dict] = []
    for audit in level_b_audits:
        rows.append(
            {
                "execution_id": audit.execution_id,
                "case_id": audit.case_id,
                "preserved_case_directory": _case_directory_alias(audit),
                "retained_bundle_path": rel(audit.bundle_root) if audit.bundle_root else not_available(),
                "mapping_note": _case_directory_mapping_note_for_report(audit, accepted_ids),
            }
        )
    return rows


def _level_a_stability_note_rows(table_b: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for row in table_b:
        grouped.setdefault(str(row.get("level_a_campaign_id") or "not_available"), []).append(row)
    rows: list[dict] = []
    for campaign_id, items in grouped.items():
        items.sort(key=lambda item: str(item.get("analysis_run_id") or ""))
        structural_keys = {
            (
                row.get("expected_relations"),
                row.get("recovered_relations"),
                row.get("degraded_relations"),
                row.get("ambiguous_relations"),
                row.get("missing_relations"),
                row.get("CPR"),
                row.get("WCPR"),
            )
            for row in items
        }
        interpretive_labels = [
            f"{row.get('analysis_run_id')}: {row.get('recoverability_label')} / {row.get('scientific_confidence')}"
            for row in items
        ]
        rows.append(
            {
                "level_a_campaign_id": campaign_id,
                "source_case_id": str(items[0].get("source_case_id") or not_available()) if items else not_available(),
                "run_count": len(items),
                "structural_metrics_stable": len(structural_keys) <= 1,
                "interpretive_labels_changed": len(set(interpretive_labels)) > 1,
                "interpretive_label_trace": " ; ".join(interpretive_labels),
                "interpretation": (
                    "Level A structural metrics are stable, but interpretive labels changed between EXEC-0001 and later iterations."
                    if len(structural_keys) <= 1 and len(set(interpretive_labels)) > 1
                    else "No interpretive-label drift was detected in the nested Level A rows."
                ),
            }
        )
    return rows


def _build_provenance_rows(
    tables: dict[str, list[dict]],
    level_a_audits: list[LevelAExecutionAudit],
    level_b_audits: list[lb.ExecutionAudit],
) -> list[dict]:
    level_a_by_exec = {audit.execution_id: audit for audit in level_a_audits}
    level_b_by_case = {audit.case_id: audit for audit in level_b_audits}
    rows: list[dict] = []
    for row in tables["Table A"]:
        audit = level_a_by_exec.get(str(row["analysis_run_id"]))
        if not audit:
            continue
        rows.extend(
            [
                {
                    "table_name": "Table A",
                    "row_id": row["analysis_run_id"],
                    "metric_name": "input_manifest_hash",
                    "value": row["input_manifest_hash"],
                    "data_category": "directly observed" if row["input_manifest_hash"] != not_available() else "not available in current artifacts",
                    "source_file": rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_A" / audit.execution_id / "forensic_result_card.json"),
                    "source_field": "preservation_summary.manifest_sha256",
                    "case_id_or_level": audit.source_case_id,
                    "aggregation_needed": "false",
                    "aggregation_formula": "",
                    "notes": audit.source_scope,
                },
                {
                    "table_name": "Table A",
                    "row_id": row["analysis_run_id"],
                    "metric_name": "analysis_pipeline_version",
                    "value": row["analysis_pipeline_version"],
                    "data_category": "directly observed" if row["analysis_pipeline_version"] != not_available() else "not available in current artifacts",
                    "source_file": rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_A" / audit.execution_id / "forensic_result_card.json"),
                    "source_field": "analysis_profile_id",
                    "case_id_or_level": audit.source_case_id,
                    "aggregation_needed": "false",
                    "aggregation_formula": "",
                    "notes": audit.source_scope,
                },
            ]
        )
    for row in tables["Table C"]:
        audit = level_b_by_case.get(str(row["case_id"]))
        if not audit:
            continue
        rows.append(
            {
                "table_name": "Table C",
                "row_id": row["rep_id"],
                "metric_name": "nested_level_a_campaign_id",
                "value": row["nested_level_a_campaign_id"],
                "data_category": "directly observed" if row["nested_level_a_campaign_id"] != not_available() else "not available in current artifacts",
                "source_file": rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "execution_manifest.json"),
                "source_field": "scientific_reports.level_a[].report_metadata_path and level_b_repetition_report nested_level_a",
                "case_id_or_level": audit.case_id,
                "aggregation_needed": "false",
                "aggregation_formula": "",
                "notes": "analysis over Level B case",
            }
        )
    for row in tables["Table H"]:
        audit = level_b_by_case.get(str(row["case_id"]))
        if not audit:
            continue
        rows.append(
            {
                "table_name": "Table H",
                "row_id": row["case_id"],
                "metric_name": "alert_to_memory_preserved_s",
                "value": row["alert_to_memory_preserved_s"],
                "data_category": "computed from existing artifacts" if isinstance(row["alert_to_memory_preserved_s"], (int, float)) else "not available in current artifacts",
                "source_file": rel(audit.bundle_root / "metadata" / "pipeline_events.jsonl") if audit.bundle_root else "",
                "source_field": "memory_preserved.ts_utc - alert.ts_utc",
                "case_id_or_level": audit.case_id,
                "aggregation_needed": "true",
                "aggregation_formula": "memory_preserved_utc - trigger_time_utc",
                "notes": "",
            }
        )
    for row in tables["Table K"]:
        rows.append(
            {
                "table_name": "Table K",
                "row_id": f"{row['case_id']}:{row['analysis_run_id']}",
                "metric_name": "CPR",
                "value": row["CPR"],
                "data_category": "computed from existing artifacts" if row["CPR"] != not_available() else "not available in current artifacts",
                "source_file": "",
                "source_field": "recovered_relations / expected_relations",
                "case_id_or_level": row["level"],
                "aggregation_needed": "true",
                "aggregation_formula": "CPR = recovered_relations_count / expected_causal_relations_count",
                "notes": "",
            }
        )
    return rows


def _build_availability_matrix(
    *,
    tables: dict[str, list[dict]],
    level_a_audits: list[LevelAExecutionAudit],
    level_b_audits: list[lb.ExecutionAudit],
    level_a_standalone_count: int,
    level_b_accepted_count: int,
    industrial_available: bool,
) -> list[dict]:
    rows: list[dict] = []

    def add(
        table_name: str,
        metric_name: str,
        available: bool,
        source_file: str,
        source_field: str,
        case_id_or_level: str,
        aggregation_needed: bool,
        aggregation_formula: str,
        data_category: str,
        can_be_computed_from_existing_artifacts: bool,
        requires_only_reporting_fix: bool,
        requires_analysis_code_change: bool,
        requires_acquisition_code_change: bool,
        requires_repeating_level_b: bool,
        notes: str,
    ) -> None:
        rows.append(
            {
                "table_name": table_name,
                "metric_name": metric_name,
                "available": "true" if available else "false",
                "source_file": source_file,
                "source_field": source_field,
                "case_id_or_level": case_id_or_level,
                "aggregation_needed": "true" if aggregation_needed else "false",
                "aggregation_formula": aggregation_formula,
                "data_category": data_category,
                "can_be_computed_from_existing_artifacts": "true" if can_be_computed_from_existing_artifacts else "false",
                "requires_only_reporting_fix": "true" if requires_only_reporting_fix else "false",
                "requires_analysis_code_change": "true" if requires_analysis_code_change else "false",
                "requires_acquisition_code_change": "true" if requires_acquisition_code_change else "false",
                "requires_repeating_level_b": "true" if requires_repeating_level_b else "false",
                "notes": notes,
            }
        )

    add(
        "Table A",
        "input_manifest_hash",
        True,
        "forensic_result_card.json",
        "preservation_summary.manifest_sha256",
        "Level A",
        False,
        "",
        "directly observed",
        True,
        False,
        False,
        False,
        False,
        "Available for current nested Level A executions.",
    )
    add(
        "Table A",
        "git_commit",
        False,
        "",
        "",
        "Level A",
        False,
        "",
        "not available in current artifacts",
        False,
        False,
        False,
        False,
        False,
        "Git commit is not persisted in current Level A artifacts.",
    )
    add(
        "Table B",
        "CPR",
        True,
        "analysis_repeatability_profile.json",
        "CPR",
        "Level A",
        True,
        "recovered_relations / expected_relations",
        "computed from existing artifacts",
        True,
        False,
        False,
        False,
        False,
        "Available for nested Level A executions over Level B cases.",
    )
    add(
        "Table C",
        "deployment_id",
        False,
        "",
        "",
        "Level B",
        False,
        "",
        "not available in current artifacts",
        False,
        False,
        False,
        False,
        False,
        "Deployment identifier is not persisted in current Level B artifacts.",
    )
    add(
        "Table D",
        "packet_confirmed_modbus_function",
        False,
        "network PCAPs",
        "Modbus packet fields",
        "Level B",
        False,
        "",
        "not computed by current pipeline",
        False,
        False,
        False,
        True,
        True,
        "The current accepted bundle does not preserve packet-level PCAP evidence for a defendible Modbus confirmation, so this field cannot be recovered from existing artifacts.",
    )
    add(
        "Table D",
        "declared_modbus_function",
        True,
        "attack_profile.json",
        "ot_function",
        "Level B",
        False,
        "",
        "declared but not packet-confirmed",
        True,
        False,
        False,
        False,
        False,
        "Declared in attack profile and ground truth.",
    )
    add(
        "Table F",
        "industrial_ot_evidence_preservation",
        industrial_available,
        "manifest.json / ot_findings.json",
        "industrial/* entries and OT findings",
        "Level B",
        False,
        "",
        "not available in current artifacts" if not industrial_available else "directly observed",
        industrial_available,
        False,
        False,
        not industrial_available,
        not industrial_available,
        "OT export is absent in current cases." if not industrial_available else "Observed in current artifacts.",
    )
    add(
        "Table G",
        "manifest_verification_mode",
        True,
        "integrity_custody_report.json",
        "findings.hash_validated_artifacts/hash_skipped_large_or_nohash",
        "Level B",
        False,
        "",
        "partial verification",
        True,
        False,
        True,
        False,
        False,
        "Current integrity report does not separately compute hash mismatch vs missing artifact counts.",
    )
    add(
        "Table H",
        "alert_to_memory_preserved_s",
        True,
        "pipeline_events.jsonl",
        "memory_preserved.ts_utc - alert.ts_utc",
        "Level B",
        True,
        "memory_preserved_utc - trigger_time_utc",
        "computed from existing artifacts",
        True,
        True,
        False,
        False,
        False,
        "",
    )
    add(
        "Table H",
        "industrial_export_preserved_utc",
        False,
        "",
        "",
        "Level B",
        False,
        "",
        "not available in current artifacts",
        False,
        False,
        False,
        True,
        True,
        "Current Level B cases do not preserve OT export artifacts.",
    )
    add(
        "Table J",
        "max_clock_offset_s",
        True,
        "metadata/time_sync.json",
        "max_clock_offset_seconds",
        "Level B",
        False,
        "",
        "directly observed",
        True,
        False,
        False,
        False,
        False,
        "",
    )
    add(
        "Table J",
        "mean_clock_offset_s",
        False,
        "",
        "",
        "Level B",
        False,
        "",
        "not computed by current pipeline",
        False,
        False,
        True,
        False,
        False,
        "Only max numeric offset is persisted now.",
    )
    add(
        "Table M",
        "Level A analysis stability over preserved source case",
        False,
        "",
        "",
        "Level A nested analysis",
        False,
        "",
        "preliminary only",
        False,
        False,
        False,
        False,
        False,
        "The package contains nested Level A runs over one preserved Level B source case, but interpretive-label drift and partial verification semantics still need explicit treatment.",
    )
    add(
        "Table M",
        "Level B final-paper usability",
        level_b_accepted_count >= 6 and industrial_available,
        "",
        "",
        "Level B",
        False,
        "",
        "not available in current artifacts" if level_b_accepted_count < 6 or not industrial_available else "directly observed",
        False,
        False,
        False,
        not industrial_available,
        level_b_accepted_count < 6 or not industrial_available,
        f"Current accepted Level B denominator is n={level_b_accepted_count}.",
    )
    return rows


def _gap_rows(
    level_a_standalone_count: int,
    level_b_accepted_count: int,
    industrial_available: bool,
    level_b_audits: list[lb.ExecutionAudit],
    accepted_level_b_ids: set[str],
) -> list[dict]:
    rows = [
        {
            "missing_data": "stable interpretation semantics for nested Level A",
            "affected_table_or_metric": "Table A, Table B, Table M and Level A stability claims",
            "table_can_be_generated_now": True,
            "data_can_be_recovered_from_existing_artifacts": True,
            "final_claim_defensible_now": False,
            "root_cause": "Structural metrics are stable across the 6 nested Level A runs, but interpretive labels change between EXEC-0001 and later iterations while integrity semantics remain partial.",
            "affected_pipeline_stage": "analysis interpretation / repeatability labeling",
            "existing_evidence_checked": "Table B nested Level A rows; Table K structural metrics; partial-verification semantics in Table G / Table F",
            "missing_evidence": "a stable explanation for the interpretive-label drift and final verification semantics that do not overstate the first run",
            "issue_class": "analysis-side",
            "exact_correction_needed": "Explain and stabilize the EXEC-0001 vs EXEC-0002..EXEC-0006 label drift, and keep verification wording aligned with partial large-artifact skip before turning this subset into a final stability claim.",
            "requires_only_reporting_fix": False,
            "requires_analysis_code_change": True,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
        }
    ]
    rows.extend(lb.build_gap_root_cause_rows(level_b_audits, accepted_level_b_ids))
    return rows


def _gap_option(level_a_standalone_count: int, level_b_accepted_count: int, industrial_available: bool) -> str:
    if level_a_standalone_count == 0 or level_b_accepted_count < 6 or not industrial_available:
        return "Option C: not enough; requires reporting/preservation fixes and a fresh Level B campaign before final paper use."
    return "Option A: enough for current paper tables"


def _rerun_readiness_plan(
    *,
    decision: str,
    decision_reasons: list[str],
    level_a_standalone_count: int,
    level_b_accepted_count: int,
    industrial_available: bool,
) -> str:
    section_a = [
        "A fresh standalone Level A campaign is optional and only needed if a separate final Level A stability denominator is required.",
        "Minimum acceptance criteria:",
        "- N_A = 6 accepted analysis repetitions",
        "- same sealed input case",
        "- same input manifest hash",
        "- same analysis pipeline version",
        "- same reconstruction criteria",
        "- same relation definitions",
        "- same weights",
        "- all output metrics recorded",
        "- all differences between repetitions explicitly reported",
    ]
    section_b = [
        "Fresh homogeneous Level B campaign required if final Level B claims are needed.",
        "Minimum acceptance criteria:",
        "- N_B = 6 accepted incident-to-case repetitions",
        "- same deployment",
        "- same scenario_id",
        "- same attack_profile_id and version",
        "- same acquisition_profile_id and version",
        "- same procedure_version",
        "- same analysis_pipeline_version",
        "- all case_ids recorded",
        "- all exclusions recorded",
        "- network, host, memory, disk, alert and OT/industrial preservation reported honestly",
        "- pipeline timings available",
        "- manifest/custody verification mode explicit",
        "- causal reconstruction generated per case",
        "- nested Level A analysis over each Level B case recorded",
    ]
    section_c = [
        "Can be resolved with reporting only:",
        "- clearer denominator labeling",
        "- declared vs observed wording",
        "- explicit preliminary-only labeling",
        "- optional reporting-only Modbus packet parser over preserved PCAPs only in campaigns where preserved PCAP evidence actually exists",
    ]
    section_d = [
        "Requires reanalysis over existing artifacts only:",
        "- packet-level Modbus confirmation from preserved PCAPs only when preserved PCAP evidence actually exists; this does not apply to the current accepted Level B case because preserved_segments=0 and pcap_artifact_count=0",
        "- stronger provenance joins across already preserved alert and network artifacts",
    ]
    section_e = [
        "Requires changing preservation/acquisition/analysis before a new final campaign:",
        "- OT/industrial export preservation",
        "- explicit persistence of deployment_id, attack_profile_version, procedure_version, analysis_pipeline_version, and git_commit",
        "- explicit Wazuh trigger-to-case binding if final trigger mapping is needed",
        "- integrity reporting that separates hash mismatch from missing artifact counts",
    ]
    section_f = [
        f"Obligates a fresh campaign rather than reusing current n={level_b_accepted_count} accepted Level B case(s):",
        "- any acquisition or preservation change that affects what evidence is captured",
        "- any analysis or reconstruction change that affects generated metrics or relation states",
        "- any metadata persistence change needed for final comparability",
        f"- any final Level B denominator increase from n={level_b_accepted_count} to N_B=6",
        "Current accepted Level B cases must remain preliminary audit only and must not be pooled with new post-change campaigns.",
    ]
    return "\n".join(
        [
            "# FORGE-VI Level A / Level B Rerun Readiness Plan",
            "",
            f"Current decision: **{decision}**",
            "",
            "Reasons:",
            *[f"- {reason}" for reason in decision_reasons],
            "",
            "## A) What is required for a final Level A campaign",
            *section_a,
            "",
            "## B) What is required for a final Level B campaign",
            *section_b,
            "",
            "## C) What can be resolved with reporting only",
            *section_c,
            "",
            "## D) What requires reanalysis over existing artifacts",
            *section_d,
            "",
            "## E) What requires changing preservation/acquisition/analysis",
            *section_e,
            "",
            "## F) What obligates a fresh campaign",
            *section_f,
            "",
            "Current denominators:",
            f"- `N_A_total = {level_a_standalone_count}` standalone Level A executions",
            f"- `N_B_accepted = {level_b_accepted_count}` accepted Level B cases",
            f"- `Industrial / OT evidence preserved = {industrial_available}`",
        ]
    )


def _render_evaluation_report(
    *,
    tables: dict[str, list[dict]],
    level_b_audits: list[lb.ExecutionAudit],
    level_a_audits: list[LevelAExecutionAudit],
    accepted_level_b_ids: set[str],
    decision: str,
    decision_reasons: list[str],
    level_a_total: int,
    level_a_accepted: int,
    level_a_excluded: int,
    level_a_over_level_b: int,
    level_b_total: int,
    level_b_accepted: int,
    level_b_excluded: int,
    level_a_breakdown_rows: list[dict],
    consistency_rows: list[dict],
    use_sections: dict[str, list[str]],
    output_dir: Path,
) -> str:
    accepted_level_b_rows = _accepted_level_b_case_rows(tables["Table C"])
    excluded_level_b_rows = _excluded_level_b_execution_rows(tables["Table C"])
    stability_rows = _level_a_stability_note_rows(tables["Table B"])
    case_alias_rows = _case_alias_rows(level_b_audits, accepted_level_b_ids)
    return "\n".join(
        [
            "# FORGE-VI Level A / Level B Truthful Evaluation Report",
            "",
            "## Scope",
            "",
            "This package audits only existing Level A and Level B artifacts. It does not modify acquisition, analysis, or reconstruction code, and it does not rerun campaigns.",
            "",
            "## Denominators",
            "",
            f"- `N_A_total = {level_a_total}` standalone Level A executions",
            f"- `N_A_accepted = {level_a_accepted}`",
            f"- `N_A_excluded = {level_a_excluded}`",
            f"- `N_A_over_Level_B_cases = {level_a_over_level_b}` Level A executions over Level B cases",
            f"- `N_B_total = {level_b_total}`",
            f"- `N_B_accepted = {level_b_accepted}`",
            f"- `N_B_excluded = {level_b_excluded}`",
            "",
            "`N_A_total = 0` means that no standalone Level A campaign exists in the current artifacts.",
            "",
            f"`N_A_over_Level_B_cases = {level_a_over_level_b}` means that the package contains nested Level A executions over Level B cases:",
            "",
            _markdown_table(
                level_a_breakdown_rows,
                [
                    "source_case_id",
                    "parent_level_b_campaign_id",
                    "parent_level_b_execution_id",
                    "level_a_campaign_id",
                    "analysis_run_id",
                    "analysis_iteration_id",
                    "status",
                    "denominator_scope",
                ],
            ),
            "",
            "Interpretation of the current Level A denominator:",
            f"- {level_b_total} Level B execution records are available in the registry.",
            f"- {level_b_accepted} Level B case(s) are accepted for scientific evidence aggregation.",
            f"- Therefore the current nested Level A total is {level_a_over_level_b} executions.",
            f"- These {level_a_over_level_b} executions must be reported only as `analysis over Level B case`.",
            "- They must not be used as a standalone Level A denominator.",
            "",
            f"`N_B_accepted = {level_b_accepted}` means that the current Level B dataset is preliminary only. It must not be presented as a final `N_B=6` evaluation.",
            "",
            "The additional API routes and UI controls added for this package are reporting and visualization only. They do not modify acquisition, preservation, or analysis code paths and they do not rerun campaigns.",
            "",
            "## Final Decision",
            "",
            f"**{decision}**",
            "",
            "Reasons:",
            *[f"- {reason}" for reason in decision_reasons],
            "",
            "Practical conclusion for the current package:",
            f"- Level A is potentially usable as a {level_a_over_level_b}-run analysis stability subset only after resolving the interpretive-label change and verification semantics.",
            f"- Level B is not usable as a final paper denominator because there are only {level_b_accepted} accepted case(s) and {level_b_excluded} excluded execution(s).",
            "- Industrial / OT evidence is not preserved.",
            "- Network evidence is not sufficiently preserved as packet-level Modbus evidence unless PCAP/Modbus observation can be proven.",
            "- Manifest/custody semantics remain partial verification, not full verification.",
            "",
            "## Package Consistency Validation",
            "",
            _markdown_table(
                consistency_rows,
                ["check_name", "status", "detail"],
            ),
            "",
            "## Accepted Level B Case Metrics",
            "",
            _markdown_table(
                accepted_level_b_rows,
                [
                    "rep_id",
                    "case_id",
                    "status",
                    "accepted_or_excluded",
                    "nested_level_a_campaign_id",
                    "case_directory_alias",
                    "case_directory_mapping_note",
                ],
            ),
            "",
            "## Failed / Excluded Level B Executions",
            "",
            _markdown_table(
                excluded_level_b_rows,
                [
                    "rep_id",
                    "case_id",
                    "status",
                    "accepted_or_excluded",
                    "exclusion_reason",
                    "case_directory_alias",
                    "case_directory_mapping_note",
                ],
            ),
            "",
            "## Case Directory Mapping",
            "",
            _markdown_table(
                case_alias_rows,
                [
                    "execution_id",
                    "case_id",
                    "preserved_case_directory",
                    "retained_bundle_path",
                    "mapping_note",
                ],
            ),
            "",
            "## Nested Level A Stability Interpretation",
            "",
            _markdown_table(
                stability_rows,
                [
                    "level_a_campaign_id",
                    "source_case_id",
                    "run_count",
                    "structural_metrics_stable",
                    "interpretive_labels_changed",
                    "interpretive_label_trace",
                    "interpretation",
                ],
            ),
            "",
            "## Table Inventory",
            "",
            f"- Table A rows: `{len(tables['Table A'])}`",
            f"- Table B rows: `{len(tables['Table B'])}`",
            f"- Table C rows: `{len(tables['Table C'])}`",
            f"- Table D rows: `{len(tables['Table D'])}`",
            f"- Table E rows: `{len(tables['Table E'])}`",
            f"- Table F rows: `{len(tables['Table F'])}`",
            f"- Table G rows: `{len(tables['Table G'])}`",
            f"- Table H rows: `{len(tables['Table H'])}`",
            f"- Table I rows: `{len(tables['Table I'])}`",
            f"- Table J rows: `{len(tables['Table J'])}`",
            f"- Table K rows: `{len(tables['Table K'])}`",
            f"- Table L rows: `{len(tables['Table L'])}`",
            f"- Table M rows: `{len(tables['Table M'])}`",
            "",
            *_truthful_case_specific_causal_sections(level_b_audits, level_a_audits),
            "",
            "## Scientific Usability of Current Level B and Level A Artifacts",
            "",
            _markdown_table(
                tables["Table M"],
                [
                    "metric_or_table",
                    "usable_for_final_paper",
                    "usable_only_as_preliminary_audit",
                    "main_limitation",
                    "requires_only_reporting_fix",
                    "requires_analysis_change",
                    "requires_acquisition_or_preservation_change",
                    "requires_fresh_level_a_campaign",
                    "requires_fresh_level_b_campaign",
                ],
            ),
            "",
            "## What Can Be Used Now",
            "",
            *[f"- {item}" for item in use_sections["What can be used now"]],
            "",
            "## What Is Preliminary Only",
            "",
            *[f"- {item}" for item in use_sections["What is preliminary only"]],
            "",
            "## What Cannot Be Used As Final Paper Claims",
            "",
            *[f"- {item}" for item in use_sections["What cannot be used as final paper claims"]],
            "",
            "## What Must Be Rerun",
            "",
            *[f"- {item}" for item in use_sections["What must be rerun"]],
            "",
            "## Output Directory",
            "",
            f"`{rel(output_dir)}`",
        ]
    )


def _render_gap_report(gap_rows: list[dict], preliminary_option: str, option: str, decision: str, use_sections: dict[str, list[str]]) -> str:
    return "\n".join(
        [
            "# FORGE-VI Level A / Level B Truthful Gap Report",
            "",
            "## Decision Mapping",
            f"- Preliminary audit-table status: **{preliminary_option}**",
            f"- Final-claim status: **{option}**",
            "",
            "Option B and Option C intentionally coexist in this package.",
            "- `Option B` means the current artifacts are sufficient to generate preliminary audit tables and explicit limitation statements.",
            "- `Option C` means the same package is still not scientifically sufficient for final paper claims.",
            "",
            f"Decision mapping: **{decision}**",
            "",
            _markdown_table(
                gap_rows,
                [
                    "missing_data",
                    "affected_table_or_metric",
                    "table_can_be_generated_now",
                    "data_can_be_recovered_from_existing_artifacts",
                    "final_claim_defensible_now",
                    "root_cause",
                    "affected_pipeline_stage",
                    "existing_evidence_checked",
                    "missing_evidence",
                    "issue_class",
                    "exact_correction_needed",
                    "requires_only_reporting_fix",
                    "requires_analysis_code_change",
                    "requires_acquisition_code_change",
                    "requires_repeating_level_b",
                ],
            ),
            "",
            "## What can be used now",
            *[f"- {item}" for item in use_sections["What can be used now"]],
            "",
            "## What is preliminary only",
            *[f"- {item}" for item in use_sections["What is preliminary only"]],
            "",
            "## What cannot be used as final paper claims",
            *[f"- {item}" for item in use_sections["What cannot be used as final paper claims"]],
            "",
            "## What must be rerun",
            *[f"- {item}" for item in use_sections["What must be rerun"]],
        ]
    )


def _render_paper_tables(tables: dict[str, list[dict]]) -> str:
    sections: list[str] = ["# FORGE-VI Level A / Level B Truthful Paper Tables", ""]
    table_columns = {
        "Table A": [
            "level_a_campaign_id",
            "source_case_id",
            "analysis_run_id",
            "analysis_iteration_id",
            "analysis_pipeline_version",
            "input_manifest_hash",
            "input_case_digest",
            "started_at_utc",
            "ended_at_utc",
            "status",
            "accepted_or_excluded",
            "exclusion_reason",
        ],
        "Table B": [
            "source_case_id",
            "analysis_run_id",
            "expected_relations",
            "recovered_relations",
            "degraded_relations",
            "ambiguous_relations",
            "missing_relations",
            "CPR",
            "WCPR",
            "recoverability_label",
            "scientific_confidence",
            "temporal_confidence",
            "integrity_completeness",
            "changed_from_previous_iteration",
            "change_reason",
        ],
        "Table C": [
            "rep_id",
            "case_id",
            "run_id",
            "campaign_id",
            "scenario_id",
            "deployment_id",
            "attack_profile_id",
            "attack_profile_version",
            "acquisition_profile_id",
            "procedure_version",
            "analysis_pipeline_version",
            "git_commit",
            "started_at_utc",
            "ended_at_utc",
            "status",
            "accepted_or_excluded",
            "exclusion_reason",
            "case_directory_alias",
            "case_directory_mapping_note",
            "nested_level_a_campaign_id",
            "nested_level_a_status",
        ],
        "Table D": [
            "rep_id",
            "case_id",
            "scenario_type",
            "incident_class",
            "MITRE ATT&CK for ICS technique",
            "source_role",
            "source_ip",
            "target_role",
            "target_ip",
            "protocol",
            "port",
            "declared_modbus_function",
            "packet_confirmed_modbus_function",
            "declared_register_or_address",
            "packet_confirmed_register_or_address",
            "declared_value",
            "packet_confirmed_value",
            "detection_path",
            "suricata_rule_id",
            "suricata_signature",
            "wazuh_rule_id",
            "wazuh_alert_id",
            "data_category",
        ],
        "Table E": [
            "case_id",
            "network_artifact_count",
            "network_total_size_bytes",
            "network_metadata_artifact_count",
            "pcap_artifact_count",
            "pcap_total_size_bytes",
            "network_context_manifest_present",
            "memory_artifact_count",
            "memory_total_size_bytes",
            "disk_artifact_count",
            "disk_total_size_bytes",
            "industrial_artifact_count",
            "industrial_total_size_bytes",
            "alerts_artifact_count",
            "metadata_artifact_count",
            "derived_artifact_count",
            "manifest_present",
            "custody_log_present",
            "pipeline_events_present",
        ],
        "Table F": [
            "case_id",
            "network_evidence_preservation",
            "trigger_alert_preservation",
            "industrial_ot_evidence_preservation",
            "host_evidence_preservation",
            "manifest_and_custody_verification",
            "main_limitation",
        ],
        "Table G": [
            "case_id",
            "manifest_verification_mode",
            "manifest_declared_artifacts",
            "manifest_deduped_artifacts",
            "manifest_verification_attempted_artifacts",
            "manifest_verified_artifacts",
            "manifest_skipped_artifacts",
            "manifest_failed_artifacts",
            "manifest_missing_artifacts",
            "custody_chain_valid",
            "custody_event_count",
            "hash_chain_errors",
            "primary_derived_separation_verified",
            "full_rehash_performed",
            "large_artifact_skip_enabled",
            "integrity_verification_ratio",
        ],
        "Table H": [
            "case_id",
            "trigger_time_utc",
            "memory_acquisition_start_utc",
            "memory_preserved_utc",
            "network_context_import_preserved_utc",
            "industrial_export_preserved_utc",
            "disk_snapshot_start_utc",
            "disk_snapshot_preserved_utc",
            "first_primary_artifact_sealed_utc",
            "full_case_sealed_utc",
            "alert_to_memory_start_s",
            "alert_to_memory_preserved_s",
            "alert_to_industrial_export_preserved_s",
            "alert_to_disk_snapshot_start_s",
            "alert_to_disk_snapshot_preserved_s",
            "T_first_sealed_s",
            "T_case_sealed_s",
        ],
        "Table I": [
            "level",
            "metric_name",
            "mean",
            "sample_standard_deviation",
            "minimum",
            "maximum",
            "denominator_n",
            "missing_cases",
            "data_category",
        ],
        "Table J": [
            "case_id",
            "time_sync_status",
            "nodes_measured",
            "nodes_failed",
            "max_clock_offset_s",
            "worst_node",
            "correction_applied",
        ],
        "Table K": [
            "level",
            "case_id",
            "analysis_run_id",
            "expected_relations",
            "recovered_relations",
            "degraded_relations",
            "ambiguous_relations",
            "missing_relations",
            "CPR",
            "WCPR",
            "recoverability_label",
            "scientific_confidence",
            "temporal_confidence",
            "integrity_completeness",
        ],
        "Table L": [
            "level",
            "case_id",
            "analysis_run_id",
            "relation_id",
            "relation_description",
            "relation_state",
            "relation_weight",
            "evidence_refs",
            "timestamp_available",
            "timestamp_resolvable",
            "integrity_verified",
            "degradation_reason",
            "missing_reason",
            "classification_rationale",
        ],
        "Table M": [
            "metric_or_table",
            "usable_for_final_paper",
            "usable_only_as_preliminary_audit",
            "main_limitation",
            "requires_only_reporting_fix",
            "requires_analysis_change",
            "requires_acquisition_or_preservation_change",
            "requires_fresh_level_a_campaign",
            "requires_fresh_level_b_campaign",
        ],
    }
    for name, columns in table_columns.items():
        sections.append(f"## {name}")
        sections.append("")
        sections.append(_markdown_table(tables[name], columns))
        sections.append("")
    return "\n".join(sections)


def generate_truthful_evaluation_bundle() -> dict[str, Any]:
    output_dir = _truthful_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    level_b_audits = lb.load_execution_audits()
    accepted_ids = lb.accepted_execution_ids(level_b_audits)
    accepted_level_b_audits = _accepted_level_b_audits(level_b_audits, accepted_ids)
    level_a_audits = load_level_a_audits(level_b_audits)

    level_a_standalone = [audit for audit in level_a_audits if audit.source_scope == "standalone Level A"]
    level_a_nested = [audit for audit in level_a_audits if audit.source_scope != "standalone Level A"]

    level_a_total = len(level_a_standalone)
    level_a_accepted = sum(1 for audit in level_a_standalone if _accepted_level_a(audit)[0] == "accepted")
    level_a_excluded = level_a_total - level_a_accepted
    level_b_total = len(level_b_audits)
    level_b_accepted = len(accepted_ids)
    level_b_excluded = level_b_total - level_b_accepted

    table_a = _level_a_table_a(level_a_audits)
    table_c = _augment_level_b_table_c(level_b_audits, accepted_ids)
    table_d = _augment_level_b_table_d(level_b_audits, accepted_ids)
    table_e = _level_b_table_e(accepted_level_b_audits)
    table_f = _level_b_table_f(accepted_level_b_audits)
    table_g = _level_b_table_g(accepted_level_b_audits)
    table_h = _level_b_table_h(accepted_level_b_audits)
    table_i = _level_b_table_i(table_e, table_h, accepted_level_b_audits, accepted_ids)
    table_j = _level_b_table_j(accepted_level_b_audits)
    table_k, table_l = _level_k_and_l(accepted_level_b_audits, level_a_audits)
    table_b = _level_a_table_b_from_table_k(level_a_audits, table_k)
    industrial_available = any(int(row.get("industrial_artifact_count") or 0) > 0 for row in table_e)
    table_m = _scientific_usability(
        level_a_standalone_count=level_a_total,
        level_b_accepted_count=level_b_accepted,
        industrial_available=industrial_available,
        level_a_nested_table_b=table_b,
    )

    tables = {
        "Table A": table_a,
        "Table B": table_b,
        "Table C": table_c,
        "Table D": table_d,
        "Table E": table_e,
        "Table F": table_f,
        "Table G": table_g,
        "Table H": table_h,
        "Table I": table_i,
        "Table J": table_j,
        "Table K": table_k,
        "Table L": table_l,
        "Table M": table_m,
    }

    decision, decision_reasons = _decision(level_a_total, level_b_accepted, industrial_available, table_b)
    option = _gap_option(level_a_total, level_b_accepted, industrial_available)
    level_a_breakdown_rows = _level_a_over_level_b_breakdown(level_a_audits)
    consistency_rows = _package_consistency_summary(
        tables=tables,
        decision=decision,
        option=option,
        level_a_total=level_a_total,
        level_a_accepted=level_a_accepted,
        level_a_excluded=level_a_excluded,
        level_a_over_level_b=len(level_a_nested),
        level_b_total=level_b_total,
        level_b_accepted=level_b_accepted,
        level_b_excluded=level_b_excluded,
    )
    use_sections = _what_can_be_used_sections(
        level_a_total=level_a_total,
        level_b_accepted=level_b_accepted,
        industrial_available=industrial_available,
        level_a_nested_table_b=table_b,
    )
    gap_rows = _gap_rows(level_a_total, level_b_accepted, industrial_available, level_b_audits, accepted_ids)
    preliminary_option = "Option B: enough for preliminary audit tables and explicit limitation reporting."
    provenance_rows = _build_provenance_rows(tables, level_a_audits, level_b_audits)
    availability_rows = _build_availability_matrix(
        tables=tables,
        level_a_audits=level_a_audits,
        level_b_audits=level_b_audits,
        level_a_standalone_count=level_a_total,
        level_b_accepted_count=level_b_accepted,
        industrial_available=industrial_available,
    )

    values_json = {
        "generated_at": lb.utc_now_iso(),
        "decision": decision,
        "option": option,
        "denominators": {
            "N_A_total": level_a_total,
            "N_A_accepted": level_a_accepted,
            "N_A_excluded": level_a_excluded,
            "N_A_over_Level_B_cases": len(level_a_nested),
            "N_B_total": level_b_total,
            "N_B_accepted": level_b_accepted,
            "N_B_excluded": level_b_excluded,
        },
        "level_a_over_level_b_breakdown": level_a_breakdown_rows,
        "package_consistency_checks": consistency_rows,
        "scientific_use_sections": use_sections,
        "tables": tables,
    }

    evaluation_report = _render_evaluation_report(
        tables=tables,
        level_b_audits=level_b_audits,
        level_a_audits=level_a_audits,
        accepted_level_b_ids=accepted_ids,
        decision=decision,
        decision_reasons=decision_reasons,
        level_a_total=level_a_total,
        level_a_accepted=level_a_accepted,
        level_a_excluded=level_a_excluded,
        level_a_over_level_b=len(level_a_nested),
        level_b_total=level_b_total,
        level_b_accepted=level_b_accepted,
        level_b_excluded=level_b_excluded,
        level_a_breakdown_rows=level_a_breakdown_rows,
        consistency_rows=consistency_rows,
        use_sections=use_sections,
        output_dir=output_dir,
    )
    gap_report = _render_gap_report(gap_rows, preliminary_option, option, decision, use_sections)
    paper_tables = _render_paper_tables(tables)
    rerun_plan = _rerun_readiness_plan(
        decision=decision,
        decision_reasons=decision_reasons,
        level_a_standalone_count=level_a_total,
        level_b_accepted_count=level_b_accepted,
        industrial_available=industrial_available,
    )

    (output_dir / OUTPUT_FILES["evaluation_report"]).write_text(evaluation_report, encoding="utf-8")
    (output_dir / OUTPUT_FILES["table_values"]).write_text(json.dumps(values_json, indent=2), encoding="utf-8")
    _write_csv(
        output_dir / OUTPUT_FILES["data_provenance"],
        provenance_rows,
        [
            "table_name",
            "row_id",
            "metric_name",
            "value",
            "data_category",
            "source_file",
            "source_field",
            "case_id_or_level",
            "aggregation_needed",
            "aggregation_formula",
            "notes",
        ],
    )
    _write_csv(
        output_dir / OUTPUT_FILES["availability_matrix"],
        availability_rows,
        [
            "table_name",
            "metric_name",
            "available",
            "source_file",
            "source_field",
            "case_id_or_level",
            "aggregation_needed",
            "aggregation_formula",
            "data_category",
            "can_be_computed_from_existing_artifacts",
            "requires_only_reporting_fix",
            "requires_analysis_code_change",
            "requires_acquisition_code_change",
            "requires_repeating_level_b",
            "notes",
        ],
    )
    (output_dir / OUTPUT_FILES["gap_report"]).write_text(gap_report, encoding="utf-8")
    (output_dir / OUTPUT_FILES["paper_tables"]).write_text(paper_tables, encoding="utf-8")
    (output_dir / OUTPUT_FILES["rerun_plan"]).write_text(rerun_plan, encoding="utf-8")

    report_id = output_dir.name
    metadata = {
        "report_id": report_id,
        "generated_at": lb.utc_now_iso(),
        "output_dir": rel(output_dir),
        "decision": decision,
        "option": option,
        "accepted_level_b_cases": level_b_accepted,
        "standalone_level_a_executions": level_a_total,
        "nested_level_a_executions": len(level_a_nested),
        "denominators": values_json["denominators"],
        "package_consistency_checks": consistency_rows,
        "files": {key: rel(output_dir / name) for key, name in OUTPUT_FILES.items() if key != "report_metadata"},
    }
    (output_dir / OUTPUT_FILES["report_metadata"]).write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return {
        "report_id": report_id,
        "generated_at": metadata["generated_at"],
        "output_dir": metadata["output_dir"],
        "decision": decision,
        "option": option,
        "accepted_level_b_cases": level_b_accepted,
        "standalone_level_a_executions": level_a_total,
        "nested_level_a_executions": len(level_a_nested),
    }


def list_generated_truthful_evaluation_reports() -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for path in sorted(VALIDATION_ROOT.glob("forge_vi_levela_levelb_truthful_evaluation_*/report_metadata.json"), reverse=True):
        payload = load_json(path)
        if not isinstance(payload, dict):
            continue
        reports.append(payload)
    return reports


def get_generated_truthful_evaluation_report(report_id: str) -> dict[str, Any] | None:
    report_dir = VALIDATION_ROOT / report_id
    metadata = load_json(report_dir / OUTPUT_FILES["report_metadata"])
    if not isinstance(metadata, dict):
        return None
    evaluation_report = (report_dir / OUTPUT_FILES["evaluation_report"]).read_text(encoding="utf-8") if (report_dir / OUTPUT_FILES["evaluation_report"]).is_file() else ""
    gap_report = (report_dir / OUTPUT_FILES["gap_report"]).read_text(encoding="utf-8") if (report_dir / OUTPUT_FILES["gap_report"]).is_file() else ""
    paper_tables = (report_dir / OUTPUT_FILES["paper_tables"]).read_text(encoding="utf-8") if (report_dir / OUTPUT_FILES["paper_tables"]).is_file() else ""
    rerun_plan = (report_dir / OUTPUT_FILES["rerun_plan"]).read_text(encoding="utf-8") if (report_dir / OUTPUT_FILES["rerun_plan"]).is_file() else ""
    values_json = load_json(report_dir / OUTPUT_FILES["table_values"]) or {}
    return {
        "report_id": report_id,
        "metadata": metadata,
        "output_dir": rel(report_dir),
        "evaluation_report_markdown": evaluation_report,
        "gap_report_markdown": gap_report,
        "paper_tables_markdown": paper_tables,
        "rerun_plan_markdown": rerun_plan,
        "values_json": values_json,
        "data_provenance_csv_path": rel(report_dir / OUTPUT_FILES["data_provenance"]),
        "availability_matrix_csv_path": rel(report_dir / OUTPUT_FILES["availability_matrix"]),
    }


def main() -> None:
    payload = generate_truthful_evaluation_bundle()
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
