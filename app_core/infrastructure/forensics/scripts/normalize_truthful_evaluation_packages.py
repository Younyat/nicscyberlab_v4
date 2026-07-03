#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
VALIDATION_ROOT = (
    REPO_ROOT
    / "app_core"
    / "infrastructure"
    / "forensics"
    / "evidence_store"
    / "validation_reports"
)

VALUES_NAME = "FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json"
REPORT_NAME = "FORGE-VI_LevelA_LevelB_Truthful_Evaluation_Report.md"
PROVENANCE_NAME = "FORGE-VI_LevelA_LevelB_Truthful_Data_Provenance.csv"
AVAILABILITY_NAME = "FORGE-VI_LevelA_LevelB_Truthful_Data_Availability_Matrix.csv"
GAP_NAME = "FORGE-VI_LevelA_LevelB_Truthful_Gap_Report.md"
PAPER_NAME = "FORGE-VI_LevelA_LevelB_Truthful_Paper_Tables.md"
RERUN_NAME = "FORGE-VI_LevelA_LevelB_Rerun_Readiness_Plan.md"
META_NAME = "report_metadata.json"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except Exception:
        return str(path)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def markdown_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", "<br>")


def markdown_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "_No rows available._"
    header = "| " + " | ".join(columns) + " |"
    sep = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(markdown_escape(row.get(col, "")) for col in columns) + " |")
    return "\n".join([header, sep, *body])


def is_na(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip().lower()
    return not text or text.startswith("not available") or text.startswith("not computed")


def bool_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return default


def _case_integrity_ratio_from_k(table_k: list[dict[str, Any]]) -> dict[str, float | str]:
    mapping: dict[str, float | str] = {}
    for row in table_k:
        if str(row.get("level")) != "Level B case":
            continue
        case_id = str(row.get("case_id") or "")
        mapping[case_id] = row.get("integrity_completeness", "not available in current artifacts")
    return mapping


def _normalize_table_g(tables: dict[str, list[dict[str, Any]]]) -> None:
    ratio_map = _case_integrity_ratio_from_k(tables.get("Table K", []))
    new_rows: list[dict[str, Any]] = []
    for row in tables["Table G"]:
        deduped = as_int(row.get("manifest_total_artifacts") or 0)
        attempted = row.get("manifest_verified_artifacts")
        skipped = as_int(row.get("manifest_skipped_artifacts") or 0)
        failed = row.get("manifest_failed_artifacts")
        missing = row.get("manifest_missing_artifacts")
        mode = str(row.get("manifest_verification_mode") or "not computed by current pipeline")
        case_id = str(row.get("case_id") or "")
        new_rows.append(
            {
                "case_id": case_id,
                "manifest_verification_mode": mode,
                "manifest_declared_artifacts": deduped,
                "manifest_deduped_artifacts": deduped,
                "manifest_verification_attempted_artifacts": attempted,
                "manifest_verified_artifacts": attempted,
                "manifest_skipped_artifacts": skipped,
                "manifest_failed_artifacts": failed,
                "manifest_missing_artifacts": missing,
                "custody_chain_valid": row.get("custody_chain_valid"),
                "custody_event_count": row.get("custody_event_count"),
                "hash_chain_errors": row.get("hash_chain_errors"),
                "primary_derived_separation_verified": row.get("primary_derived_separation_verified"),
                "full_rehash_performed": False if skipped else True,
                "large_artifact_skip_enabled": skipped > 0,
                "integrity_verification_ratio": ratio_map.get(case_id, "not computed by current pipeline"),
            }
        )
    tables["Table G"] = new_rows


def _integrity_by_case(table_g: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("case_id")): row for row in table_g}


def _normalize_table_f(tables: dict[str, list[dict[str, Any]]]) -> None:
    table_e_by_case = {str(row.get("case_id")): row for row in tables["Table E"]}
    table_d_by_case = {str(row.get("case_id")): row for row in tables["Table D"]}
    table_g_by_case = _integrity_by_case(tables["Table G"])
    new_rows: list[dict[str, Any]] = []
    for row in tables["Table F"]:
        case_id = str(row.get("case_id") or "")
        artifacts = table_e_by_case.get(case_id, {})
        incident = table_d_by_case.get(case_id, {})
        integrity = table_g_by_case.get(case_id, {})
        alerts_count = as_int(artifacts.get("alerts_artifact_count") or 0)
        industrial_count = as_int(artifacts.get("industrial_artifact_count") or 0)
        suricata_rule = incident.get("suricata_rule_id", "not available in current artifacts")
        suricata_sig = incident.get("suricata_signature", "not available in current artifacts")
        new_rows.append(
            {
                "case_id": case_id,
                "network_evidence_preservation": row.get("network_evidence_preservation"),
                "trigger_alert_preservation": "partial verification",
                "industrial_ot_evidence_preservation": (
                    "directly observed absence / failed preservation" if industrial_count == 0 else row.get("industrial_ot_evidence_preservation")
                ),
                "host_evidence_preservation": row.get("host_evidence_preservation"),
                "manifest_and_custody_verification": "partial verification",
                "trigger_event_recorded": "directly observed",
                "trigger_to_case_binding_present": "directly observed",
                "suricata_rule_observed": "directly observed" if not is_na(suricata_rule) else "not available in current artifacts",
                "suricata_signature_observed": "directly observed" if not is_na(suricata_sig) else "not available in current artifacts",
                "raw_suricata_alert_preserved": "not available in current artifacts" if alerts_count == 0 else "directly observed",
                "raw_wazuh_alert_preserved": "not available in current artifacts",
                "wazuh_trigger_mapping_status": "not computed by current pipeline",
                "alerts_directory_artifact_count": alerts_count,
                "manifest_verification_mode": integrity.get("manifest_verification_mode", "not computed by current pipeline"),
                "full_rehash_performed": integrity.get("full_rehash_performed", False),
                "large_artifact_skip_enabled": integrity.get("large_artifact_skip_enabled", True),
                "integrity_verification_ratio": integrity.get("integrity_verification_ratio", "not computed by current pipeline"),
                "main_limitation": "Industrial / OT export is not preserved in the current Level B artifacts.",
            }
        )
    tables["Table F"] = new_rows


def _normalize_table_a(tables: dict[str, list[dict[str, Any]]]) -> None:
    for row in tables["Table A"]:
        source_scope = str(row.get("source_scope") or "")
        if source_scope == "analysis over Level B case":
            row["analysis_execution_mode"] = "dry_run linked_existing_case"
            row["full_analysis_executed"] = False
            row["cached_or_linked_outputs_used"] = True
        else:
            row["analysis_execution_mode"] = "not available in current artifacts"
            row["full_analysis_executed"] = "not available in current artifacts"
            row["cached_or_linked_outputs_used"] = "not available in current artifacts"


def _normalize_relation_rows(tables: dict[str, list[dict[str, Any]]]) -> None:
    table_e_by_case = {str(row.get("case_id")): row for row in tables["Table E"]}
    for row in tables["Table L"]:
        row["independent_observation"] = str(row.get("level")) == "Level B case"
        case_id = str(row.get("case_id") or "")
        industrial_count = as_int(table_e_by_case.get(case_id, {}).get("industrial_artifact_count") or 0)
        if str(row.get("relation_id")) == "edge_ot_write_to_plc_state_observation" and industrial_count == 0:
            row["relation_state"] = "missing"
            row["degradation_reason"] = ""
            row["missing_reason"] = (
                "No preserved OT export or PLC/SCADA state entries were available for this case; "
                "this relation cannot be supported from current artifacts."
            )
            row["timestamp_resolvable"] = "no"
            row["classification_rationale"] = (
                "missing because preserved OT export is absent and no alternate preserved evidence explicitly supports "
                "the PLC state observation"
            )


def _rebuild_table_k_and_b(tables: dict[str, list[dict[str, Any]]]) -> None:
    integrity = _integrity_by_case(tables["Table G"])
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in tables["Table L"]:
        key = (str(row.get("level")), str(row.get("case_id")), str(row.get("analysis_run_id")))
        groups.setdefault(key, []).append(row)

    def weight_sum(rows: list[dict[str, Any]], recovered_only: bool = False) -> float | str:
        total = 0.0
        seen = False
        for item in rows:
            if recovered_only and str(item.get("relation_state")) != "recovered":
                continue
            try:
                total += float(item.get("relation_weight"))
                seen = True
            except Exception:
                continue
        return round(total, 6) if seen else "not computable because relation weights are not available"

    new_table_k: list[dict[str, Any]] = []
    for key, rows in groups.items():
        level, case_id, analysis_run_id = key
        expected = len(rows)
        recovered = sum(1 for item in rows if str(item.get("relation_state")) == "recovered")
        degraded = sum(1 for item in rows if str(item.get("relation_state")) == "degraded")
        ambiguous = sum(1 for item in rows if str(item.get("relation_state")) == "ambiguous")
        missing = sum(1 for item in rows if str(item.get("relation_state")) == "missing")
        total_weight = weight_sum(rows, recovered_only=False)
        recovered_weight = weight_sum(rows, recovered_only=True)
        if isinstance(total_weight, float) and total_weight > 0 and isinstance(recovered_weight, float):
            wcpr: float | str = round(recovered_weight / total_weight, 6)
        else:
            wcpr = "not computable because relation weights are not available"
        irow = integrity.get(case_id, {})
        new_table_k.append(
            {
                "level": level,
                "case_id": case_id,
                "analysis_run_id": analysis_run_id,
                "expected_relations": expected,
                "recovered_relations": recovered,
                "degraded_relations": degraded,
                "ambiguous_relations": ambiguous,
                "missing_relations": missing,
                "CPR": round(recovered / expected, 6) if expected else "not available in current artifacts",
                "WCPR": wcpr,
                "recoverability_label": "weak_recoverability",
                "hypothesis_support_level": "moderate_support",
                "scientific_confidence": "limited",
                "temporal_confidence": "limited",
                "integrity_verification_ratio": irow.get("integrity_verification_ratio", "not computed by current pipeline"),
                "manifest_verification_mode": irow.get("manifest_verification_mode", "not computed by current pipeline"),
                "integrity_completeness": irow.get("integrity_verification_ratio", "not computed by current pipeline"),
                "independent_observation": level == "Level B case",
            }
        )
    new_table_k.sort(key=lambda row: (row["case_id"], row["level"], row["analysis_run_id"]))
    tables["Table K"] = new_table_k

    old_table_a = {str(row.get("analysis_run_id")): row for row in tables["Table A"]}
    new_table_b: list[dict[str, Any]] = []
    previous_by_campaign: dict[str, dict[str, Any] | None] = {}
    for row in new_table_k:
        if str(row.get("level")) != "analysis over Level B case":
            continue
        analysis_run_id = str(row.get("analysis_run_id"))
        arow = old_table_a.get(analysis_run_id, {})
        campaign_id = str(arow.get("level_a_campaign_id") or "not available in current artifacts")
        current = {
            "expected_relations": row["expected_relations"],
            "recovered_relations": row["recovered_relations"],
            "degraded_relations": row["degraded_relations"],
            "ambiguous_relations": row["ambiguous_relations"],
            "missing_relations": row["missing_relations"],
            "CPR": row["CPR"],
            "WCPR": row["WCPR"],
            "recoverability_label": row["recoverability_label"],
            "hypothesis_support_level": row["hypothesis_support_level"],
            "scientific_confidence": row["scientific_confidence"],
            "temporal_confidence": row["temporal_confidence"],
            "integrity_verification_ratio": row["integrity_verification_ratio"],
            "manifest_verification_mode": row["manifest_verification_mode"],
            "integrity_completeness": row["integrity_completeness"],
        }
        previous = previous_by_campaign.get(campaign_id)
        diffs = [name for name, value in current.items() if previous and previous.get(name) != value]
        new_table_b.append(
            {
                "source_case_id": row["case_id"],
                "analysis_run_id": analysis_run_id,
                **current,
                "changed_from_previous_iteration": bool(diffs),
                "change_reason": ("metric_changed=" + ", ".join(diffs)) if diffs else ("not applicable" if previous is None else ""),
                "level_a_campaign_id": campaign_id,
                "source_scope": arow.get("source_scope", "analysis over Level B case"),
                "independent_observation": False,
            }
        )
        previous_by_campaign[campaign_id] = current
    tables["Table B"] = new_table_b


def _normalize_table_i(tables: dict[str, list[dict[str, Any]]], accepted_n: int, accepted_cases: list[str]) -> None:
    for row in tables["Table I"]:
        metric = str(row.get("metric_name"))
        if metric == "industrial_total_size_bytes":
            row["mean"] = 0.0
            row["sample_standard_deviation"] = 0.0 if accepted_n >= 2 else "not available in current artifacts"
            row["minimum"] = 0.0
            row["maximum"] = 0.0
            row["denominator_n"] = accepted_n
            row["missing_cases"] = ""
            row["data_category"] = "directly observed absence / failed preservation"
        if metric in {"alert_to_industrial_export_preserved_s", "alert_to_industrial_export_start_s"}:
            row["mean"] = "not available in current artifacts"
            row["sample_standard_deviation"] = "not available in current artifacts"
            row["minimum"] = "not available in current artifacts"
            row["maximum"] = "not available in current artifacts"
            row["denominator_n"] = 0
            row["missing_cases"] = ", ".join(accepted_cases)
            row["data_category"] = "not available in current artifacts"


def _build_provenance_rows(tables: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in tables["Table G"]:
        case_id = row["case_id"]
        rows.append(
            {
                "table_name": "Table G",
                "row_id": case_id,
                "metric_name": "manifest_verification_attempted_artifacts",
                "value": row["manifest_verification_attempted_artifacts"],
                "data_category": "computed from existing artifacts",
                "source_file": "FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json",
                "source_field": "Table G manifest verification counters",
                "case_id_or_level": case_id,
                "aggregation_needed": "false",
                "aggregation_formula": "",
                "notes": "Attempted/verified counters use a different verification denominator than deduped manifest artifacts.",
            }
        )
    for row in tables["Table F"]:
        case_id = row["case_id"]
        rows.append(
            {
                "table_name": "Table F",
                "row_id": case_id,
                "metric_name": "trigger_alert_preservation",
                "value": row["trigger_alert_preservation"],
                "data_category": "partial verification",
                "source_file": "FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json",
                "source_field": "Table F trigger alert preservation subfields",
                "case_id_or_level": case_id,
                "aggregation_needed": "false",
                "aggregation_formula": "",
                "notes": "Trigger metadata is observed, but raw alert preservation and Wazuh trigger mapping are incomplete.",
            }
        )
    for row in tables["Table L"]:
        if row["relation_id"] != "edge_ot_write_to_plc_state_observation":
            continue
        rows.append(
            {
                "table_name": "Table L",
                "row_id": f"{row['case_id']}:{row['analysis_run_id']}",
                "metric_name": "edge_ot_write_to_plc_state_observation",
                "value": row["relation_state"],
                "data_category": "not available in current artifacts",
                "source_file": "FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json",
                "source_field": "Table L relation_state/missing_reason",
                "case_id_or_level": row["case_id"],
                "aggregation_needed": "false",
                "aggregation_formula": "",
                "notes": "Reclassified to missing because no preserved OT export or PLC/SCADA state entries exist in the current artifacts.",
            }
        )
    return rows


def _build_availability_rows(values: dict[str, Any], tables: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    denoms = values.get("denominators", {})
    accepted_n = int(denoms.get("N_B_accepted") or 0)
    rows: list[dict[str, Any]] = []
    def add(table_name: str, metric_name: str, available: bool, category: str, case_id_or_level: str, notes: str, requires_reporting=False, requires_analysis=False, requires_acq=False, rerun=False, formula=""):
        rows.append(
            {
                "table_name": table_name,
                "metric_name": metric_name,
                "available": bool_text(available),
                "source_file": VALUES_NAME,
                "source_field": metric_name,
                "case_id_or_level": case_id_or_level,
                "aggregation_needed": bool_text(bool(formula)),
                "aggregation_formula": formula,
                "data_category": category,
                "can_be_computed_from_existing_artifacts": bool_text(available or category == "computed from existing artifacts"),
                "requires_only_reporting_fix": bool_text(requires_reporting),
                "requires_analysis_code_change": bool_text(requires_analysis),
                "requires_acquisition_code_change": bool_text(requires_acq),
                "requires_repeating_level_b": bool_text(rerun),
                "notes": notes,
            }
        )
    for row in tables["Table A"]:
        add("Table A", "analysis_execution_mode", True, "computed from existing artifacts", row["source_case_id"], "Derived from source_scope and campaign source_mode.")
    for row in tables["Table F"]:
        add("Table F", "trigger_alert_preservation", True, "partial verification", row["case_id"], "Trigger metadata is observed, but raw alert artifacts and Wazuh trigger mapping are incomplete.")
        add("Table F", "raw_suricata_alert_preserved", not is_na(row["raw_suricata_alert_preserved"]), str(row["raw_suricata_alert_preserved"]), row["case_id"], "Alert directory artifact count is used here.")
        add("Table F", "raw_wazuh_alert_preserved", False, "not available in current artifacts", row["case_id"], "No raw Wazuh alert artifact is preserved in the current package.")
        add("Table F", "wazuh_trigger_mapping_status", False, "not computed by current pipeline", row["case_id"], "A defensible per-trigger Wazuh binding is not computed.")
    for row in tables["Table G"]:
        add("Table G", "manifest_verification_attempted_artifacts", True, "computed from existing artifacts", row["case_id"], "Verification counters and deduped manifest counts use different denominators.")
        add("Table G", "integrity_verification_ratio", not is_na(row["integrity_verification_ratio"]), "computed from existing artifacts", row["case_id"], "Numeric ratio reused from the package reconstruction summary.")
    add("Table I", "industrial_total_size_bytes", True, "directly observed absence / failed preservation", "Level B cases", f"Observed over n={accepted_n} accepted Level B cases.")
    add("Table I", "alert_to_industrial_export_preserved_s", False, "not available in current artifacts", "Level B cases", "Industrial export timestamps are unavailable because OT export was not preserved.", requires_acq=True, rerun=True)
    for row in tables["Table L"]:
        if row["relation_id"] != "edge_ot_write_to_plc_state_observation":
            continue
        add("Table L", "edge_ot_write_to_plc_state_observation", False, "not available in current artifacts", row["case_id"], "The relation is missing because no preserved OT export or PLC/SCADA state entries exist.")
    return rows


def render_report(values: dict[str, Any], output_dir: Path) -> str:
    tables = values["tables"]
    denoms = values["denominators"]
    decision = values["decision"]
    use_sections = values.get("scientific_use_sections", {})
    breakdown = values.get("level_a_over_level_b_breakdown", [])
    consistency = values.get("package_consistency_checks", [])
    return "\n".join(
        [
            "# FORGE-VI Level A / Level B Truthful Evaluation Report",
            "",
            "## Scope",
            "",
            "This package audits only existing Level A and Level B artifacts. It does not modify acquisition, preservation, or analysis code paths.",
            "",
            "## Denominators",
            "",
            f"- `N_A_total = {denoms['N_A_total']}` standalone Level A executions",
            f"- `N_A_accepted = {denoms['N_A_accepted']}`",
            f"- `N_A_excluded = {denoms['N_A_excluded']}`",
            f"- `N_A_over_Level_B_cases = {denoms['N_A_over_Level_B_cases']}` Level A executions over Level B cases",
            f"- `N_B_total = {denoms['N_B_total']}`",
            f"- `N_B_accepted = {denoms['N_B_accepted']}`",
            f"- `N_B_excluded = {denoms['N_B_excluded']}`",
            "",
            "`N_A_total = 0` means that no standalone Level A campaign exists in the current artifacts.",
            "",
            "`N_A_over_Level_B_cases = 4` means that two Level B source cases each carry two nested dry-run Level A analytical iterations over the same preserved evidence.",
            "",
            markdown_table(
                breakdown,
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
            "`N_B_accepted = 2` means that the current Level B dataset remains preliminary only and must not be presented as a final `N_B=6` evaluation.",
            "",
            "The API and UI additions used for these reports are reporting and visualization only. They do not modify acquisition, preservation, or analysis code paths.",
            "",
            "## Final Decision",
            "",
            f"**{decision}**",
            "",
            "## Package Consistency Validation",
            "",
            markdown_table(consistency, ["check_name", "status", "detail"]),
            "",
            "## Scientific Usability of Current Level B and Level A Artifacts",
            "",
            markdown_table(
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
            *[f"- {item}" for item in use_sections.get("What can be used now", [])],
            "",
            "## What Is Preliminary Only",
            *[f"- {item}" for item in use_sections.get("What is preliminary only", [])],
            "",
            "## What Cannot Be Used In The Paper",
            *[f"- {item}" for item in use_sections.get("What cannot be used in the paper", [])],
            "",
            "## What Must Be Rerun",
            *[f"- {item}" for item in use_sections.get("What must be rerun", [])],
            "",
            "## Output Directory",
            "",
            f"`{rel(output_dir)}`",
        ]
    ) + "\n"


def render_gap_report(values: dict[str, Any]) -> str:
    tables = values["tables"]
    use_sections = values.get("scientific_use_sections", {})
    rows = [
        {
            "missing_data": "standalone Level A campaign",
            "affected_table_or_metric": "Table A, Table B, Table M",
            "why_it_matters": "Level A standalone stability cannot be claimed from the current artifacts.",
            "can_be_recovered_from_existing_artifacts": False,
            "requires_only_reporting_fix": False,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Run a fresh standalone Level A campaign with the final intended denominator.",
        },
        {
            "missing_data": "accepted Level B denominator beyond n=2",
            "affected_table_or_metric": "Table C through Table M",
            "why_it_matters": "Current Level B aggregates are preliminary only and must not be presented as final N_B=6.",
            "can_be_recovered_from_existing_artifacts": False,
            "requires_only_reporting_fix": False,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": True,
            "recommendation": "Run a fresh homogeneous Level B campaign with the final intended denominator.",
        },
        {
            "missing_data": "OT/industrial export and packet-confirmed PLC state observation",
            "affected_table_or_metric": "Table D, Table F, Table H, Table I, Table K, Table L, Table M",
            "why_it_matters": "Industrial preservation failed in the current Level B cases, and relations that require preserved OT export must remain missing.",
            "can_be_recovered_from_existing_artifacts": False,
            "requires_only_reporting_fix": False,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": True,
            "requires_repeating_level_b": True,
            "recommendation": "Preserve OT export during Level B acquisition before claiming industrial evidence coverage.",
        },
        {
            "missing_data": "defensible Wazuh trigger mapping",
            "affected_table_or_metric": "Table D, Table F",
            "why_it_matters": "Trigger identifiers must not be inferred without a raw-alert binding.",
            "can_be_recovered_from_existing_artifacts": False,
            "requires_only_reporting_fix": False,
            "requires_analysis_code_change": True,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": True,
            "recommendation": "Persist raw Wazuh trigger bindings and rerun Level B if final paper tables need them.",
        },
        {
            "missing_data": "manifest verification denominator split and explicit mismatch taxonomy",
            "affected_table_or_metric": "Table G, Table K, Table M",
            "why_it_matters": "Verification must not appear complete when large artifacts were skipped and denominators differ.",
            "can_be_recovered_from_existing_artifacts": True,
            "requires_only_reporting_fix": True,
            "requires_analysis_code_change": True,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Keep the current package honest with split denominators and partial-verification language; future integrity outputs should separate mismatch and missing counts explicitly.",
        },
    ]
    return "\n".join(
        [
            "# FORGE-VI Level A / Level B Truthful Gap Report",
            "",
            "Overall classification: **Option C: not enough; requires pipeline/reporting changes and rerunning Level A and/or Level B.**",
            "",
            f"Decision mapping: **{values['decision']}**",
            "",
            markdown_table(
                rows,
                [
                    "missing_data",
                    "affected_table_or_metric",
                    "why_it_matters",
                    "can_be_recovered_from_existing_artifacts",
                    "requires_only_reporting_fix",
                    "requires_analysis_code_change",
                    "requires_acquisition_code_change",
                    "requires_repeating_level_b",
                    "recommendation",
                ],
            ),
            "",
            "## What can be used now",
            *[f"- {item}" for item in use_sections.get("What can be used now", [])],
            "",
            "## What is preliminary only",
            *[f"- {item}" for item in use_sections.get("What is preliminary only", [])],
            "",
            "## What cannot be used in the paper",
            *[f"- {item}" for item in use_sections.get("What cannot be used in the paper", [])],
            "",
            "## What must be rerun",
            *[f"- {item}" for item in use_sections.get("What must be rerun", [])],
        ]
    ) + "\n"


def render_paper_tables(values: dict[str, Any]) -> str:
    tables = values["tables"]
    cols = {
        "Table A": [
            "level_a_campaign_id",
            "source_case_id",
            "analysis_run_id",
            "analysis_iteration_id",
            "analysis_pipeline_version",
            "analysis_execution_mode",
            "full_analysis_executed",
            "cached_or_linked_outputs_used",
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
            "hypothesis_support_level",
            "scientific_confidence",
            "temporal_confidence",
            "integrity_verification_ratio",
            "manifest_verification_mode",
            "changed_from_previous_iteration",
            "change_reason",
            "independent_observation",
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
            "trigger_event_recorded",
            "trigger_to_case_binding_present",
            "suricata_rule_observed",
            "suricata_signature_observed",
            "raw_suricata_alert_preserved",
            "raw_wazuh_alert_preserved",
            "wazuh_trigger_mapping_status",
            "alerts_directory_artifact_count",
            "industrial_ot_evidence_preservation",
            "host_evidence_preservation",
            "manifest_and_custody_verification",
            "manifest_verification_mode",
            "full_rehash_performed",
            "large_artifact_skip_enabled",
            "integrity_verification_ratio",
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
            "hypothesis_support_level",
            "scientific_confidence",
            "temporal_confidence",
            "integrity_verification_ratio",
            "manifest_verification_mode",
            "independent_observation",
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
            "independent_observation",
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
    sections = ["# FORGE-VI Level A / Level B Truthful Paper Tables", ""]
    for name, columns in cols.items():
        sections.append(f"## {name}")
        sections.append("")
        sections.append(markdown_table(tables[name], columns))
        sections.append("")
    return "\n".join(sections)


def render_rerun_plan(values: dict[str, Any]) -> str:
    denoms = values["denominators"]
    return "\n".join(
        [
            "# FORGE-VI Level A / Level B Rerun Readiness Plan",
            "",
            f"Current decision: **{values['decision']}**",
            "",
            "Reasons:",
            "- no standalone Level A campaign exists in current artifacts",
            f"- Level B accepted denominator is only n={denoms['N_B_accepted']}",
            "- OT/industrial export is not preserved in the current Level B artifacts",
            "- packet-level Modbus confirmation and Wazuh trigger mapping are not fully computed",
            "",
            "## A) What is required for a final Level A campaign",
            "Fresh standalone Level A campaign required if final Level A stability claims are needed.",
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
            "",
            "## B) What is required for a final Level B campaign",
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
            "",
            "## C) What can be resolved with reporting only",
            "Can be resolved with reporting only:",
            "- clearer denominator labeling",
            "- declared vs observed wording",
            "- explicit preliminary-only labeling",
            "- split manifest denominators so verification attempted artifacts are not confused with deduped manifest artifacts",
            "",
            "## D) What requires reanalysis over existing artifacts",
            "Requires reanalysis over existing artifacts only:",
            "- packet-level Modbus confirmation from preserved PCAPs, if the current captures are sufficient",
            "- stronger provenance joins across already preserved alert and network artifacts",
            "",
            "## E) What requires changing preservation/acquisition/analysis",
            "Requires changing preservation/acquisition/analysis before a new final campaign:",
            "- OT/industrial export preservation",
            "- explicit persistence of deployment_id, attack_profile_version, procedure_version, analysis_pipeline_version, and git_commit",
            "- explicit Wazuh trigger-to-case binding if final trigger mapping is needed",
            "- integrity reporting that separates hash mismatch from missing artifact counts",
            "",
            "## F) What obligates a fresh campaign",
            "Obligates a fresh campaign rather than reusing current preliminary cases:",
            "- any acquisition or preservation change that affects what evidence is captured",
            "- any analysis or reconstruction change that affects generated metrics or relation states",
            "- any metadata persistence change needed for final comparability",
            f"- any final Level B denominator increase from n={denoms['N_B_accepted']} to N_B=6",
            "- any future standalone Level A campaign, because none exists in current artifacts",
            "Current preliminary Level B cases must remain audit-only and must not be pooled with new post-change campaigns.",
            "",
            "Current denominators:",
            f"- `N_A_total = {denoms['N_A_total']}` standalone Level A executions",
            f"- `N_B_accepted = {denoms['N_B_accepted']}` accepted Level B cases",
            "- `Industrial / OT evidence preserved = False`",
        ]
    ) + "\n"


def normalize_package(report_dir: Path) -> None:
    values_path = report_dir / VALUES_NAME
    if not values_path.is_file():
        return
    values = load_json(values_path)
    tables = values["tables"]

    _normalize_table_g(tables)
    _normalize_table_f(tables)
    _normalize_table_a(tables)
    _normalize_relation_rows(tables)
    _rebuild_table_k_and_b(tables)

    accepted_cases = [str(row.get("case_id")) for row in tables["Table C"] if str(row.get("accepted_or_excluded")) == "accepted"]
    accepted_n = len(accepted_cases)
    _normalize_table_i(tables, accepted_n, accepted_cases)

    values["decision"] = "Decision E: both fresh Level A and fresh Level B campaigns are required."
    values["option"] = "Option C: not enough; requires pipeline/reporting changes and rerunning Level A and/or Level B."

    provenance_rows = _build_provenance_rows(tables)
    availability_rows = _build_availability_rows(values, tables)

    (report_dir / REPORT_NAME).write_text(render_report(values, report_dir), encoding="utf-8")
    (report_dir / GAP_NAME).write_text(render_gap_report(values), encoding="utf-8")
    (report_dir / PAPER_NAME).write_text(render_paper_tables(values), encoding="utf-8")
    (report_dir / RERUN_NAME).write_text(render_rerun_plan(values), encoding="utf-8")
    write_json(values_path, values)
    write_csv(
        report_dir / PROVENANCE_NAME,
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
    write_csv(
        report_dir / AVAILABILITY_NAME,
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
    meta_path = report_dir / META_NAME
    if meta_path.is_file():
        meta = load_json(meta_path)
        meta["decision"] = values["decision"]
        meta["option"] = values["option"]
        write_json(meta_path, meta)


def main() -> int:
    for report_dir in sorted(VALIDATION_ROOT.glob("forge_vi_levela_levelb_truthful_evaluation_*")):
        normalize_package(report_dir)
        print(rel(report_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
