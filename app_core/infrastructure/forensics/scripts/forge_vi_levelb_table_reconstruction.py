#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
EVIDENCE_ROOT = REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"
CAMPAIGNS_ROOT = EVIDENCE_ROOT / "repetition_campaigns"
VALIDATION_ROOT = EVIDENCE_ROOT / "validation_reports"


def utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path | str | None) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT.resolve()))
    except Exception:
        return str(path)


def load_json(path: Path | str | None) -> dict | list | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        with p.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def load_jsonl(path: Path | str | None) -> list[dict]:
    p = Path(path) if path else None
    if not p or not p.is_file():
        return []
    items: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def parse_ts(raw: str | None) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    for candidate in (
        text,
        text.replace("Z", "+00:00"),
    ):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            continue
    return None


def seconds_between(start: str | None, end: str | None) -> float | None:
    start_dt = parse_ts(start)
    end_dt = parse_ts(end)
    if not start_dt or not end_dt:
        return None
    return round((end_dt - start_dt).total_seconds(), 3)


def sha256_file(path: Path | str | None) -> str | None:
    p = Path(path) if path else None
    if not p or not p.is_file():
        return None
    digest = hashlib.sha256()
    with p.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def markdown_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br/>")


def csv_bool(value: bool | None) -> str:
    if value is None:
        return ""
    return "true" if value else "false"


def not_available(reason: str = "not available in current artifacts") -> str:
    return reason


def sample_std(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    return round(statistics.stdev(values), 6)


def mean_value(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 6)


def metric_display(value: Any) -> str:
    if value is None:
        return not_available()
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value)


def normalize_status(value: Any) -> str:
    return str(value or "").strip() or not_available()


def top_level_category(rel_path: str) -> str:
    rel_text = str(rel_path or "")
    if rel_text.startswith("network/"):
        return "network"
    if rel_text.startswith("memory/"):
        return "memory"
    if rel_text.startswith("disk/"):
        return "disk"
    if rel_text.startswith("industrial/"):
        return "industrial"
    if rel_text.startswith("alerts/"):
        return "alerts"
    if rel_text.startswith("metadata/"):
        return "metadata"
    if rel_text.startswith("derived/"):
        return "derived"
    return "other"


def dedupe_manifest_artifacts(manifest: dict | None) -> list[dict]:
    artifacts = list((manifest or {}).get("artifacts") or [])
    latest_by_rel: dict[str, dict] = {}
    ordered: list[str] = []
    for artifact in artifacts:
        rel_path = str(artifact.get("rel_path") or "")
        if not rel_path:
            continue
        if rel_path not in latest_by_rel:
            ordered.append(rel_path)
        latest_by_rel[rel_path] = artifact
    return [latest_by_rel[key] for key in ordered]


def find_first_event(events: list[dict], event_name: str) -> dict | None:
    for item in events:
        if str(item.get("event") or "") == event_name:
            return item
    return None


def find_last_event(events: list[dict], event_name: str) -> dict | None:
    found = None
    for item in events:
        if str(item.get("event") or "") == event_name:
            found = item
    return found


def distinct_run_ids(events: list[dict]) -> list[str]:
    seen: list[str] = []
    for item in events:
        run_id = str(item.get("run_id") or "").strip()
        if run_id and run_id not in seen:
            seen.append(run_id)
    return seen


@dataclass
class ExecutionAudit:
    campaign_id: str
    execution_id: str
    repetition_number: int
    case_id: str
    level_b_report: dict
    execution_manifest: dict
    execution_plan: dict
    campaign_manifest: dict
    campaign_config: dict
    attack_profile: dict
    ground_truth: dict
    detection_trigger_profile: dict
    forensic_result_card: dict
    forensic_comparison_profile: dict
    case_result_card: dict
    preservation_profile: dict
    level_b_acquisition_profile: dict
    retention_manifest: dict
    bundle_manifest: dict
    bundle_root: Path | None
    manifest: dict
    pipeline_events: list[dict]
    time_sync: dict
    evidence_inventory: dict
    integrity_report: dict
    alert_findings: dict
    ot_findings: dict
    network_context_manifest: dict
    reconstruction_metrics: dict
    causal_status: dict
    causal_graph: dict
    hypothesis_support_report: dict
    attack_result: dict
    nested_level_a: dict


def find_level_b_campaigns() -> list[Path]:
    manifests: list[Path] = []
    for path in sorted(CAMPAIGNS_ROOT.glob("CMP-*/campaign_manifest.json")):
        payload = load_json(path)
        if not isinstance(payload, dict):
            continue
        if str(payload.get("level") or "").upper() != "B":
            continue
        manifests.append(path)
    return manifests


def latest_level_b_validation_report(campaign_manifest: dict) -> dict:
    latest = (((campaign_manifest.get("validation_reports") or {}).get("latest_level_b")) or {})
    main = latest.get("main_report_path")
    payload = load_json(REPO_ROOT / str(main)) if main else None
    return payload if isinstance(payload, dict) else {}


def repetition_map(level_b_report: dict) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for item in list(level_b_report.get("per_repetition_results") or []):
        execution_id = str(item.get("execution_id") or "").strip()
        if execution_id:
            result[execution_id] = item
    return result


def bundle_root_from_execution(execution_manifest: dict, retention_manifest: dict, result_card: dict) -> Path | None:
    candidates = [
        execution_manifest.get("lightweight_case_bundle_path"),
        retention_manifest.get("preserved_lightweight_case_bundle_path"),
        result_card.get("lightweight_case_bundle_path"),
        execution_manifest.get("run_case_path"),
        execution_manifest.get("source_case_path"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = REPO_ROOT / str(candidate)
        if path.is_dir():
            return path
    return None


def load_execution_audits() -> list[ExecutionAudit]:
    audits: list[ExecutionAudit] = []
    for manifest_path in find_level_b_campaigns():
        campaign_manifest = load_json(manifest_path) or {}
        campaign_config = load_json(manifest_path.with_name("campaign_config.json")) or {}
        level_b_report = latest_level_b_validation_report(campaign_manifest)
        repetition_by_exec = repetition_map(level_b_report)
        for execution_manifest_path in sorted(manifest_path.parent.glob("level_B/EXEC-*/execution_manifest.json")):
            execution_manifest = load_json(execution_manifest_path) or {}
            execution_id = str(execution_manifest.get("execution_id") or execution_manifest_path.parent.name)
            exec_root = execution_manifest_path.parent
            execution_plan = load_json(exec_root / "execution_plan.json") or {}
            attack_profile = load_json(exec_root / "attack_profile.json") or {}
            ground_truth = load_json(exec_root / "ground_truth.json") or {}
            detection_trigger_profile = load_json(exec_root / "detection_trigger_profile.json") or {}
            forensic_result_card = load_json(exec_root / "forensic_result_card.json") or {}
            forensic_comparison_profile = load_json(exec_root / "forensic_comparison_profile.json") or {}
            preservation_profile = load_json(exec_root / "preservation_profile.json") or {}
            level_b_acquisition_profile = load_json(exec_root / "acquisition_profile.json") or {}
            retention_manifest = load_json(exec_root / "retention_manifest.json") or {}
            case_id = str(
                forensic_result_card.get("case_id")
                or execution_manifest.get("run_case_id")
                or execution_manifest.get("source_case_id")
                or ""
            )
            case_result_card = load_json(CAMPAIGNS_ROOT / "scientific_memory" / "case_registry" / case_id / "case_result_card.json") or {}
            bundle_root = bundle_root_from_execution(execution_manifest, retention_manifest, forensic_result_card)
            manifest = load_json(bundle_root / "manifest.json") if bundle_root else {}
            pipeline_events = load_jsonl(bundle_root / "metadata" / "pipeline_events.jsonl") if bundle_root else []
            time_sync = load_json(bundle_root / "metadata" / "time_sync.json") if bundle_root else {}
            evidence_inventory = load_json(bundle_root / "analysis" / "00_inventory" / "evidence_inventory.json") if bundle_root else {}
            integrity_report = load_json(bundle_root / "analysis" / "01_integrity_custody" / "integrity_custody_report.json") if bundle_root else {}
            alert_findings = load_json(bundle_root / "analysis" / "07_alerts" / "alert_findings.json") if bundle_root else {}
            ot_findings = load_json(bundle_root / "analysis" / "06_ot" / "ot_findings.json") if bundle_root else {}
            network_context_manifest = load_json(bundle_root / "network" / "traffic_preserved" / "network_context_manifest.json") if bundle_root else {}
            reconstruction_metrics = load_json(bundle_root / "derived" / "reconstruction" / "reconstruction_metrics.json") if bundle_root else {}
            causal_status = load_json(bundle_root / "derived" / "reconstruction" / "causal_status.json") if bundle_root else {}
            causal_graph = load_json(bundle_root / "derived" / "reconstruction" / "causal_graph.json") if bundle_root else {}
            hypothesis_support_report = load_json(bundle_root / "derived" / "evidence_support" / "hypothesis_support_report.json") if bundle_root else {}
            bundle_manifest = load_json(bundle_root / "lightweight_case_bundle_manifest.json") if bundle_root else {}
            attack_result_path = attack_profile.get("attack_script_reference")
            attack_result = load_json(REPO_ROOT / str(attack_result_path)) if attack_result_path else {}
            nested_level_a = (repetition_by_exec.get(execution_id) or {}).get("nested_level_a") or {}
            repetition_number = int((repetition_by_exec.get(execution_id) or {}).get("repetition_number") or len(audits) + 1)
            audits.append(
                ExecutionAudit(
                    campaign_id=str(campaign_manifest.get("campaign_id") or manifest_path.parent.name),
                    execution_id=execution_id,
                    repetition_number=repetition_number,
                    case_id=case_id,
                    level_b_report=repetition_by_exec.get(execution_id) or {},
                    execution_manifest=execution_manifest,
                    execution_plan=execution_plan,
                    campaign_manifest=campaign_manifest,
                    campaign_config=campaign_config,
                    attack_profile=attack_profile,
                    ground_truth=ground_truth,
                    detection_trigger_profile=detection_trigger_profile,
                    forensic_result_card=forensic_result_card,
                    forensic_comparison_profile=forensic_comparison_profile,
                    case_result_card=case_result_card,
                    preservation_profile=preservation_profile,
                    level_b_acquisition_profile=level_b_acquisition_profile,
                    retention_manifest=retention_manifest,
                    bundle_manifest=bundle_manifest,
                    bundle_root=bundle_root,
                    manifest=manifest if isinstance(manifest, dict) else {},
                    pipeline_events=pipeline_events,
                    time_sync=time_sync if isinstance(time_sync, dict) else {},
                    evidence_inventory=evidence_inventory if isinstance(evidence_inventory, dict) else {},
                    integrity_report=integrity_report if isinstance(integrity_report, dict) else {},
                    alert_findings=alert_findings if isinstance(alert_findings, dict) else {},
                    ot_findings=ot_findings if isinstance(ot_findings, dict) else {},
                    network_context_manifest=network_context_manifest if isinstance(network_context_manifest, dict) else {},
                    reconstruction_metrics=reconstruction_metrics if isinstance(reconstruction_metrics, dict) else {},
                    causal_status=causal_status if isinstance(causal_status, dict) else {},
                    causal_graph=causal_graph if isinstance(causal_graph, dict) else {},
                    hypothesis_support_report=hypothesis_support_report if isinstance(hypothesis_support_report, dict) else {},
                    attack_result=attack_result if isinstance(attack_result, dict) else {},
                    nested_level_a=nested_level_a if isinstance(nested_level_a, dict) else {},
                )
            )
    return audits


def accepted_execution_ids(audits: list[ExecutionAudit]) -> set[str]:
    accepted: set[str] = set()
    for audit in audits:
        if audit.level_b_report:
            accepted.add(audit.execution_id)
    return accepted


def latest_manifest_by_rel(audit: ExecutionAudit) -> list[dict]:
    return dedupe_manifest_artifacts(audit.manifest)


def manifest_counts_by_category(audit: ExecutionAudit) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {
        key: {"count": 0, "size": 0}
        for key in ["network", "memory", "disk", "industrial", "alerts", "metadata", "derived", "other"]
    }
    for artifact in latest_manifest_by_rel(audit):
        rel_path = str(artifact.get("rel_path") or "")
        category = top_level_category(rel_path)
        counts[category]["count"] += 1
        counts[category]["size"] += int(artifact.get("size") or 0)
    return counts


def event_time(audit: ExecutionAudit, event_name: str, *, first: bool) -> str | None:
    item = find_first_event(audit.pipeline_events, event_name) if first else find_last_event(audit.pipeline_events, event_name)
    return str((item or {}).get("ts_utc") or "").strip() or None


def case_level_times(audit: ExecutionAudit) -> dict[str, Any]:
    acquisition = audit.bundle_root / "metadata" / "acquisition_profile.json" if audit.bundle_root else None
    acquisition_profile = load_json(acquisition) or {}
    trigger_time = (
        event_time(audit, "alert", first=True)
        or str(acquisition_profile.get("trigger_time_utc") or "").strip()
        or str((audit.level_b_report.get("trigger_alert_timestamp") or "")).strip()
        or None
    )
    memory_start = event_time(audit, "memory_start", first=True) or str(acquisition_profile.get("memory_started_utc") or "").strip() or None
    memory_preserved = event_time(audit, "memory_preserved", first=False) or str(acquisition_profile.get("memory_completed_utc") or "").strip() or None
    industrial_start = event_time(audit, "industrial_start", first=True) or event_time(audit, "industrial_export_start", first=True)
    industrial_preserved = event_time(audit, "industrial_preserved", first=False) or event_time(audit, "industrial_export_preserved", first=False)
    disk_start = event_time(audit, "disk_start", first=True) or str(acquisition_profile.get("disk_started_utc") or "").strip() or None
    disk_preserved = event_time(audit, "disk_preserved", first=False) or str(acquisition_profile.get("disk_completed_utc") or "").strip() or None
    network_import_completed = event_time(audit, "network_context_import_completed", first=False) or str(acquisition_profile.get("network_context_import_completed_utc") or "").strip() or None

    primary_candidates = [value for value in [memory_preserved, industrial_preserved, disk_preserved, network_import_completed] if value]
    first_primary = None
    if primary_candidates:
        first_primary = min(primary_candidates, key=lambda item: parse_ts(item) or datetime.max.replace(tzinfo=timezone.utc))

    full_case_sealed = event_time(audit, "dfir_orchestration_done", first=False) or event_time(audit, "active_preservation_released", first=False)

    return {
        "trigger_time_utc": trigger_time or None,
        "memory_acquisition_start_utc": memory_start or None,
        "memory_preserved_utc": memory_preserved or None,
        "industrial_export_start_utc": industrial_start or None,
        "industrial_export_preserved_utc": industrial_preserved or None,
        "disk_snapshot_start_utc": disk_start or None,
        "disk_snapshot_preserved_utc": disk_preserved or None,
        "first_primary_artifact_sealed_utc": first_primary,
        "full_case_sealed_utc": full_case_sealed,
        "alert_to_memory_start_s": seconds_between(trigger_time, memory_start),
        "alert_to_memory_preserved_s": seconds_between(trigger_time, memory_preserved),
        "alert_to_industrial_export_preserved_s": seconds_between(trigger_time, industrial_preserved),
        "alert_to_disk_snapshot_start_s": seconds_between(trigger_time, disk_start),
        "alert_to_disk_snapshot_preserved_s": seconds_between(trigger_time, disk_preserved),
        "T_first_sealed_s": seconds_between(trigger_time, first_primary),
        "T_case_sealed_s": seconds_between(trigger_time, full_case_sealed),
    }


def rule_from_alert_findings(audit: ExecutionAudit) -> tuple[str | None, str | None]:
    findings = ((audit.alert_findings.get("findings") or {}))
    top_rules = findings.get("top_rules") or {}
    top_signatures = findings.get("top_signatures") or {}
    suricata_rule = None
    suricata_sig = None
    for signature, _count in top_signatures.items():
        if "Modbus write multiple registers" in signature:
            suricata_sig = signature
            break
    if suricata_sig:
        # The Modbus signature corresponds to the selected trigger rule in current artifacts.
        suricata_rule = str(audit.detection_trigger_profile.get("selected_trigger_rule") or "").strip() or None
    return suricata_rule, suricata_sig


def target_vm_id(audit: ExecutionAudit) -> str | None:
    event = find_first_event(audit.pipeline_events, "dfir_orchestration_start") or {}
    for target in list((event.get("meta") or {}).get("targets") or []):
        if str(target.get("role") or "").lower() == "plc":
            return str(target.get("vm_id") or "").strip() or None
    return None


def target_vm_ip(audit: ExecutionAudit) -> str | None:
    event = find_first_event(audit.pipeline_events, "dfir_orchestration_start") or {}
    for target in list((event.get("meta") or {}).get("targets") or []):
        if str(target.get("role") or "").lower() == "plc":
            return str(target.get("vm_ip") or "").strip() or None
    return None


def source_refs(paths: list[tuple[str, str]]) -> str:
    parts = []
    for path, field in paths:
        if not path and not field:
            continue
        parts.append(f"{path}:{field}" if field else path)
    return "; ".join(parts)


def bool_text(value: bool) -> str:
    return "yes" if value else "no"


def aggregate_metric(values: list[float], label: str, denominator_note: str) -> str:
    if not values:
        return not_available()
    mean = mean_value(values)
    std = sample_std(values)
    if std is None:
        return f"{metric_display(mean)} over n={len(values)} {denominator_note}"
    return f"{metric_display(mean)} ± {metric_display(std)} over n={len(values)} {denominator_note}"


def build_table1(audits: list[ExecutionAudit], accepted: set[str]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        report = audit.level_b_report
        run_ids = distinct_run_ids(audit.pipeline_events)
        scenario_selector = str(audit.campaign_config.get("scenario_id") or "").strip() or None
        validation_report_path = str(
            (
                ((audit.campaign_manifest.get("validation_reports") or {}).get("latest_level_b") or {}).get("main_report_path")
            )
            or ""
        ).strip()
        row = {
            "rep_id": audit.execution_id,
            "case_id": audit.case_id or not_available(),
            "run_id": ", ".join(run_ids) if run_ids else not_available(),
            "campaign_id": audit.campaign_id,
            "scenario_id": str(audit.forensic_result_card.get("scenario_id") or audit.ground_truth.get("scenario_id") or audit.execution_plan.get("scenario_id") or not_available()),
            "deployment_id": not_available(),
            "attack_profile_id": str(audit.forensic_result_card.get("attack_profile_id") or audit.campaign_config.get("attack_id") or not_available()),
            "attack_profile_version": not_available("not computed by current pipeline"),
            "acquisition_profile_id": str(audit.forensic_result_card.get("acquisition_profile_id") or audit.execution_plan.get("acquisition_profile_id") or not_available()),
            "procedure_version": not_available("not computed by current pipeline"),
            "started_at_utc": str(audit.attack_profile.get("attack_started_at") or audit.execution_manifest.get("created_at") or not_available()),
            "ended_at_utc": str((audit.nested_level_a.get("report") or {}).get("generated_at") or audit.execution_manifest.get("updated_at") or not_available()),
            "status": str(report.get("execution_status") or audit.execution_manifest.get("status") or not_available()),
            "excluded_or_accepted": "accepted" if audit.execution_id in accepted else "excluded",
            "exclusion_reason": "" if audit.execution_id in accepted else "not included in the higher-level comparison set",
            "provenance": source_refs(
                [
                    (rel(REPO_ROOT / audit.execution_manifest.get("job_path")) if audit.execution_manifest.get("job_path") else "", ""),
                    (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "execution_plan.json"), "scenario_id/acquisition_profile_id"),
                    (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "forensic_result_card.json"), "scenario_id/attack_profile_id"),
                    (rel(CAMPAIGNS_ROOT / audit.campaign_id / "campaign_config.json"), "scenario_id alias=" + (scenario_selector or "not_available")),
                    (validation_report_path, "per_repetition_results"),
                ]
            ),
        }
        rows.append(row)
    return rows


def build_table2(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        suricata_rule_id, suricata_signature = rule_from_alert_findings(audit)
        attack_log_rel = str(audit.attack_profile.get("attack_script_reference") or "")
        attack_log_path = REPO_ROOT / attack_log_rel if attack_log_rel else None
        row = {
            "rep_id": audit.execution_id,
            "case_id": audit.case_id,
            "scenario_type": str(audit.campaign_config.get("scenario_id") or not_available()),
            "incident_class": "controlled repeated incident execution",
            "MITRE ATT&CK for ICS technique": str(audit.forensic_result_card.get("mitre_technique_id") or audit.attack_profile.get("technique_id") or not_available()),
            "source_role": "attacker",
            "source_node_id": not_available(),
            "source_ip": str(audit.attack_result.get("attacker_ip") or not_available()),
            "target_role": str(audit.attack_result.get("effective_target_role") or audit.level_b_report.get("target_role") or not_available()),
            "target_node_id": target_vm_id(audit) or not_available(),
            "target_ip": str(audit.attack_result.get("effective_target_ip") or target_vm_ip(audit) or not_available()),
            "protocol": str(audit.attack_profile.get("protocol") or not_available()),
            "port": str(audit.level_b_report.get("destination_port") or 502),
            "declared_modbus_function": str(audit.attack_profile.get("ot_function") or not_available()),
            "declared_modbus_target_address": "declared but not packet-confirmed" if audit.attack_profile.get("register") is not None else not_available(),
            "declared_expected_value": "declared but not packet-confirmed" if audit.attack_profile.get("expected_value") is not None else not_available(),
            "expected_control_effect": "declared PLC/SCADA state change in ground truth",
            "detection_path": str(audit.attack_result.get("detection_engine") or audit.detection_trigger_profile.get("selected_trigger_source") or not_available()),
            "suricata_rule_id": suricata_rule_id or not_available(),
            "suricata_signature": suricata_signature or not_available(),
            "wazuh_rule_id": not_available("not available in current artifacts"),
            "wazuh_alert_id": not_available("not available in current artifacts"),
            "attack_log_path": rel(attack_log_path) if attack_log_path and attack_log_path.is_file() else not_available(),
            "attack_log_sha256": sha256_file(attack_log_path) or not_available(),
            "provenance": source_refs(
                [
                    (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "attack_profile.json"), "technique_id/protocol/ot_function/register/expected_value"),
                    (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "ground_truth.json"), "attack_expected/expected_edges"),
                    (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "detection_trigger_profile.json"), "selected_trigger*"),
                    (attack_log_rel, "result.json fields attacker_ip/effective_target_ip/detection_engine"),
                    (rel(audit.bundle_root / "analysis" / "07_alerts" / "alert_findings.json") if audit.bundle_root else "", "findings.top_signatures/top_rules"),
                ]
            ),
        }
        rows.append(row)
    return rows


def build_table3(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        counts = manifest_counts_by_category(audit)
        rows.append(
            {
                "case_id": audit.case_id,
                "network_artifact_count": counts["network"]["count"],
                "network_total_size_bytes": counts["network"]["size"],
                "memory_artifact_count": counts["memory"]["count"],
                "memory_total_size_bytes": counts["memory"]["size"],
                "disk_artifact_count": counts["disk"]["count"],
                "disk_total_size_bytes": counts["disk"]["size"],
                "industrial_artifact_count": counts["industrial"]["count"],
                "industrial_total_size_bytes": counts["industrial"]["size"],
                "alerts_artifact_count": counts["alerts"]["count"],
                "metadata_artifact_count": counts["metadata"]["count"],
                "derived_artifact_count": counts["derived"]["count"],
                "manifest_present": bool(audit.bundle_root and (audit.bundle_root / "manifest.json").is_file()),
                "custody_log_present": bool(audit.bundle_root and (audit.bundle_root / "chain_of_custody.log").is_file()),
                "pipeline_events_present": bool(audit.bundle_root and (audit.bundle_root / "metadata" / "pipeline_events.jsonl").is_file()),
                "provenance": source_refs(
                    [
                        (rel(audit.bundle_root / "manifest.json") if audit.bundle_root else "", "artifacts[*] deduped by rel_path"),
                        (rel(audit.bundle_root / "chain_of_custody.log") if audit.bundle_root else "", "presence"),
                        (rel(audit.bundle_root / "metadata" / "pipeline_events.jsonl") if audit.bundle_root else "", "presence"),
                    ]
                ),
            }
        )
    return rows


def manifest_verification_status(audit: ExecutionAudit) -> str:
    findings = (audit.integrity_report.get("findings") or {})
    missing = list(findings.get("missing_artifacts") or [])
    skipped = list(findings.get("hash_skipped_large_or_nohash") or [])
    if missing:
        return "failed_or_incomplete"
    if skipped:
        return "verified_with_large_artifact_skip"
    if findings.get("hash_validated_artifacts") is not None:
        return "verified"
    return not_available("not computed by current pipeline")


def build_table4(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        findings = (audit.integrity_report.get("findings") or {})
        missing = list(findings.get("missing_artifacts") or [])
        custody_valid = findings.get("custody_chain_valid")
        deduped_artifacts = latest_manifest_by_rel(audit)
        has_primary = any(not str(item.get("rel_path") or "").startswith("derived/") for item in deduped_artifacts)
        has_derived = any(str(item.get("rel_path") or "").startswith("derived/") for item in deduped_artifacts)
        rows.append(
            {
                "case_id": audit.case_id,
                "manifest_present": bool(audit.bundle_root and (audit.bundle_root / "manifest.json").is_file()),
                "manifest_verification_status": manifest_verification_status(audit),
                "manifest_verified_artifacts": findings.get("hash_validated_artifacts", not_available()),
                "manifest_failed_artifacts": not_available("not separately computed by current pipeline"),
                "manifest_missing_artifacts": len(missing),
                "custody_log_present": bool(audit.bundle_root and (audit.bundle_root / "chain_of_custody.log").is_file()),
                "custody_chain_verification_status": "valid" if custody_valid is True else ("failed" if custody_valid is False else not_available()),
                "custody_event_count": findings.get("custody_events", not_available()),
                "hash_chain_errors": not_available("not separately computed by current pipeline"),
                "primary_derived_separation_verified": has_primary and has_derived,
                "provenance": source_refs(
                    [
                        (rel(audit.bundle_root / "analysis" / "01_integrity_custody" / "integrity_custody_report.json") if audit.bundle_root else "", "findings.hash_validated_artifacts/missing_artifacts/custody_chain_valid/custody_events"),
                        (rel(audit.bundle_root / "manifest.json") if audit.bundle_root else "", "presence + rel_path top-level separation"),
                        (rel(audit.bundle_root / "chain_of_custody.log") if audit.bundle_root else "", "presence"),
                    ]
                ),
            }
        )
    return rows


def build_table5(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        times = case_level_times(audit)
        row = {"case_id": audit.case_id, **times}
        row["provenance"] = source_refs(
            [
                (rel(audit.bundle_root / "metadata" / "pipeline_events.jsonl") if audit.bundle_root else "", "alert/memory_start/memory_preserved/network_context_import_completed/disk_start/disk_preserved/dfir_orchestration_done"),
                (rel(audit.bundle_root / "metadata" / "acquisition_profile.json") if audit.bundle_root else "", "trigger_time_utc fallback and acquisition timestamps"),
            ]
        )
        rows.append(row)
    return rows


def build_table6(audits: list[ExecutionAudit], accepted: set[str]) -> list[dict]:
    accepted_audits = [audit for audit in audits if audit.execution_id in accepted]
    table3 = {row["case_id"]: row for row in build_table3(accepted_audits)}
    time_rows = {row["case_id"]: row for row in build_table5(accepted_audits)}

    metrics = [
        ("alert_to_memory_start_s", "Table 5 per-case values"),
        ("alert_to_memory_preserved_s", "Table 5 per-case values"),
        ("alert_to_industrial_export_preserved_s", "Table 5 per-case values"),
        ("alert_to_disk_snapshot_start_s", "Table 5 per-case values"),
        ("alert_to_disk_snapshot_preserved_s", "Table 5 per-case values"),
        ("T_first_sealed_s", "Table 5 per-case values"),
        ("T_case_sealed_s", "Table 5 per-case values"),
        ("network_total_size_bytes", "Table 3 deduped manifest counts"),
        ("memory_total_size_bytes", "Table 3 deduped manifest counts"),
        ("disk_total_size_bytes", "Table 3 deduped manifest counts"),
        ("industrial_total_size_bytes", "Table 3 deduped manifest counts"),
    ]

    rows: list[dict] = []
    for metric_name, note in metrics:
        values: list[float] = []
        for audit in accepted_audits:
            if metric_name in time_rows[audit.case_id]:
                value = time_rows[audit.case_id][metric_name]
            else:
                value = table3[audit.case_id].get(metric_name)
            if metric_name == "industrial_total_size_bytes" and int(table3[audit.case_id].get("industrial_artifact_count") or 0) == 0:
                continue
            if isinstance(value, (int, float)):
                values.append(float(value))
        rows.append(
            {
                "metric_name": metric_name,
                "mean": mean_value(values) if values else not_available(),
                "sample_standard_deviation": sample_std(values) if values else not_available(),
                "minimum": round(min(values), 6) if values else not_available(),
                "maximum": round(max(values), 6) if values else not_available(),
                "denominator_n": len(values),
                "provenance": note,
            }
        )

    retry_values: list[float] = []
    for audit in accepted_audits:
        failed_events = [event for event in audit.pipeline_events if str(event.get("event") or "").endswith("_failed")]
        retries = max(int(audit.level_b_report.get("trigger_attempts_total") or 1) - 1, 0)
        retry_values.append(float(len(failed_events) + retries))
    rows.append(
        {
            "metric_name": "retries_or_failures_count",
            "mean": mean_value(retry_values) if retry_values else not_available(),
            "sample_standard_deviation": sample_std(retry_values) if retry_values else not_available(),
            "minimum": round(min(retry_values), 6) if retry_values else not_available(),
            "maximum": round(max(retry_values), 6) if retry_values else not_available(),
            "denominator_n": len(retry_values),
            "provenance": "pipeline_events event names ending with _failed plus trigger_attempts_total-1 from level_b_repetition_report.json",
        }
    )
    return rows


def build_table7(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        rows.append(
            {
                "case_id": audit.case_id,
                "time_sync_status": str(audit.time_sync.get("temporal_sync_status") or not_available()),
                "nodes_measured": audit.time_sync.get("nodes_ok", not_available()),
                "nodes_failed": audit.time_sync.get("nodes_failed", not_available()),
                "max_clock_offset_s": audit.time_sync.get("max_clock_offset_seconds", not_available()),
                "worst_node": str(((audit.time_sync.get("worst_node") or {}).get("name")) or not_available()),
                "correction_applied": audit.time_sync.get("correction_applied", not_available()),
                "time_sync_report_path": rel(audit.bundle_root / "metadata" / "time_sync.json") if audit.bundle_root else not_available(),
                "provenance": source_refs(
                    [
                        (rel(audit.bundle_root / "metadata" / "time_sync.json") if audit.bundle_root else "", "temporal_sync_status/nodes_ok/nodes_failed/max_clock_offset_seconds/worst_node/correction_applied"),
                    ]
                ),
            }
        )
    return rows


def invariant_row(audit: ExecutionAudit) -> dict:
    counts = manifest_counts_by_category(audit)
    network_manifest = audit.network_context_manifest
    alert_findings_ok = str(audit.alert_findings.get("status") or "") == "completed"
    ot_status = str(audit.ot_findings.get("status") or "")
    integrity_status = manifest_verification_status(audit)
    custody_valid = bool(((audit.integrity_report.get("findings") or {}).get("custody_chain_valid")) is True)
    c1 = bool(network_manifest and ((network_manifest.get("summary") or {}).get("preserved_segments") or 0) > 0 and ((network_manifest.get("network_context_window") or {}).get("trigger_time_utc")))
    c2 = bool(find_first_event(audit.pipeline_events, "alert") and alert_findings_ok and audit.detection_trigger_profile)
    c3 = bool(ot_status not in {"", "skipped_no_ot_export"} and counts["industrial"]["count"] > 0)
    c4 = bool(counts["memory"]["count"] > 0 and counts["disk"]["count"] > 0)
    c5 = bool(audit.bundle_root and (audit.bundle_root / "manifest.json").is_file() and (audit.bundle_root / "chain_of_custody.log").is_file() and integrity_status != "failed_or_incomplete" and custody_valid)
    return {
        "case_id": audit.case_id,
        "network_evidence_preservation_status": "directly observed" if c1 else not_available(),
        "network_evidence_refs": source_refs([(rel(audit.bundle_root / "network" / "traffic_preserved" / "network_context_manifest.json") if audit.bundle_root else "", "summary.preserved_segments/network_context_window.trigger_time_utc")]),
        "trigger_alert_preservation_status": "directly observed" if c2 else not_available(),
        "trigger_alert_evidence_refs": source_refs([(rel(audit.bundle_root / "analysis" / "07_alerts" / "alert_findings.json") if audit.bundle_root else "", "status/findings"), (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "detection_trigger_profile.json"), "selected_trigger*"), (rel(audit.bundle_root / "metadata" / "pipeline_events.jsonl") if audit.bundle_root else "", "alert event")]),
        "industrial_ot_evidence_preservation_status": "not available in current artifacts" if not c3 else "directly observed",
        "industrial_ot_evidence_refs": source_refs([(rel(audit.bundle_root / "analysis" / "06_ot" / "ot_findings.json") if audit.bundle_root else "", "status/not_executed_reason"), (rel(audit.bundle_root / "manifest.json") if audit.bundle_root else "", "industrial/* entries")]),
        "host_evidence_preservation_status": "directly observed" if c4 else not_available(),
        "host_evidence_refs": source_refs([(rel(audit.bundle_root / "manifest.json") if audit.bundle_root else "", "memory/* and disk/* entries"), (rel(audit.bundle_root / "metadata" / "acquisition_profile.json") if audit.bundle_root else "", "memory_started_utc/disk_started_utc")]),
        "manifest_and_custody_verification_status": "directly observed" if c5 else not_available(),
        "manifest_and_custody_evidence_refs": source_refs([(rel(audit.bundle_root / "analysis" / "01_integrity_custody" / "integrity_custody_report.json") if audit.bundle_root else "", "custody_chain_valid/hash_validated_artifacts"), (rel(audit.bundle_root / "manifest.json") if audit.bundle_root else "", "presence"), (rel(audit.bundle_root / "chain_of_custody.log") if audit.bundle_root else "", "presence")]),
    }


def build_table8_case(audits: list[ExecutionAudit]) -> list[dict]:
    return [invariant_row(audit) for audit in audits]


def build_table8_aggregate(case_rows: list[dict], accepted: set[str]) -> list[dict]:
    invariants = [
        ("Network evidence preservation", "network_evidence_preservation_status"),
        ("Trigger alert preservation", "trigger_alert_preservation_status"),
        ("Industrial / OT evidence preservation", "industrial_ot_evidence_preservation_status"),
        ("Host evidence preservation", "host_evidence_preservation_status"),
        ("Manifest and custody verification", "manifest_and_custody_verification_status"),
    ]
    rows: list[dict] = []
    denominator = len(case_rows)
    for invariant_id, field in invariants:
        passed = [row["case_id"] for row in case_rows if str(row.get(field) or "") == "directly observed"]
        failed = [row["case_id"] for row in case_rows if str(row.get(field) or "") != "directly observed"]
        reason = ""
        if invariant_id == "Industrial / OT evidence preservation" and failed:
            reason = "No preserved OT export was found for the current Level B cases."
        elif failed:
            reason = "See per-case evidence refs."
        rows.append(
            {
                "technical_check": invariant_id,
                "passed_cases": ", ".join(passed) if passed else "",
                "denominator": denominator,
                "success_rate_percent": round((len(passed) / denominator) * 100, 2) if denominator else 0.0,
                "failure_cases": ", ".join(failed) if failed else "",
                "failure_reason": reason,
            }
        )
    return rows


def build_table9_case(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        metrics = audit.reconstruction_metrics
        hypothesis = audit.hypothesis_support_report
        rows.append(
            {
                "case_id": audit.case_id,
                "expected_causal_relations_count": metrics.get("expected_edges", not_available()),
                "recovered_relations_count": metrics.get("recovered_edges", not_available()),
                "degraded_relations_count": metrics.get("degraded_edges", not_available()),
                "ambiguous_relations_count": metrics.get("ambiguous_edges", not_available()),
                "missing_relations_count": metrics.get("missing_edges", not_available()),
                "CPR": metrics.get("causal_path_recoverability", not_available()),
                "WCPR": metrics.get("weighted_cpr", not_available()),
                "recoverability_label": metrics.get("recoverability_label", not_available()),
                "scientific_confidence": audit.causal_status.get("scientific_confidence", not_available()),
                "hypothesis_support_level": hypothesis.get("global_support_level", not_available()),
                "temporal_confidence": metrics.get("temporal_confidence_state", not_available()),
                "integrity_completeness": metrics.get("integrity_verification_ratio", not_available()),
                "provenance": source_refs(
                    [
                        (rel(audit.bundle_root / "derived" / "reconstruction" / "reconstruction_metrics.json") if audit.bundle_root else "", "expected_edges/recovered_edges/degraded_edges/ambiguous_edges/missing_edges/causal_path_recoverability/weighted_cpr/recoverability_label/temporal_confidence_state/integrity_verification_ratio"),
                        (rel(audit.bundle_root / "derived" / "reconstruction" / "causal_status.json") if audit.bundle_root else "", "scientific_confidence"),
                        (rel(audit.bundle_root / "derived" / "evidence_support" / "hypothesis_support_report.json") if audit.bundle_root else "", "global_support_level"),
                    ]
                ),
            }
        )
    return rows


def build_table9_relations(audits: list[ExecutionAudit]) -> list[dict]:
    rows: list[dict] = []
    for audit in audits:
        expected_edges = {str(item.get("edge_id") or ""): item for item in list(audit.ground_truth.get("expected_edges") or []) if str(item.get("edge_id") or "")}
        graph_edges = {str(item.get("edge_id") or ""): item for item in list(audit.causal_graph.get("edges") or []) if str(item.get("edge_id") or "")}
        hypo_edges = {str(item.get("edge_id") or ""): item for item in list(audit.hypothesis_support_report.get("relations") or []) if str(item.get("edge_id") or "")}
        for edge_id, edge in expected_edges.items():
            graph = graph_edges.get(edge_id) or {}
            hypo = hypo_edges.get(edge_id) or {}
            support_status = str(graph.get("support_status") or hypo.get("own_support_status") or not_available())
            temporal_status = str(graph.get("temporal_status") or "")
            has_timestamp_refs = bool(edge.get("source_timestamp_ref") or edge.get("target_timestamp_ref"))
            rows.append(
                {
                    "case_id": audit.case_id,
                    "relation_id": edge_id,
                    "relation_description": str(edge.get("meaning") or not_available()),
                    "relation_state": support_status,
                    "relation_weight": edge.get("weight", not_available()),
                    "evidence_refs": "; ".join(list(graph.get("evidence_refs") or [])) or "; ".join(list(graph.get("required_evidence") or [])) or not_available(),
                    "timestamp_available": "yes" if has_timestamp_refs else "not available in current artifacts",
                    "timestamp_resolvable": "yes" if temporal_status in {"supported", "not_required"} else ("no" if temporal_status else not_available()),
                    "integrity_verified": "yes" if str(graph.get("integrity_status") or "") == "verified" else ("no" if graph else not_available()),
                    "degradation_reason": "; ".join(list(graph.get("limitations") or [])) if support_status == "degraded" else "",
                    "missing_reason": str(graph.get("status_reason") or "") if support_status == "missing" else "",
                    "provenance": source_refs(
                        [
                            (rel(CAMPAIGNS_ROOT / audit.campaign_id / "level_B" / audit.execution_id / "ground_truth.json"), f"expected_edges[{edge_id}]"),
                            (rel(audit.bundle_root / "derived" / "reconstruction" / "causal_graph.json") if audit.bundle_root else "", f"edges[{edge_id}]"),
                            (rel(audit.bundle_root / "derived" / "evidence_support" / "hypothesis_support_report.json") if audit.bundle_root else "", f"relations[{edge_id}]"),
                        ]
                    ),
                }
            )
    return rows


def build_table10(audits: list[ExecutionAudit]) -> list[dict]:
    rows = [
        {
            "paper_table_or_metric": "Table 1: Level B repetition index",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "deployment_id, attack_profile_version, procedure_version",
            "requires_only_report_aggregation": False,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Generate now, but keep unavailable markers for metadata fields not preserved by the current pipeline.",
        },
        {
            "paper_table_or_metric": "Table 2: incident specification",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "source_node_id, explicit Wazuh alert/rule mapping, packet-confirmed Modbus register/value precision",
            "requires_only_report_aggregation": False,
            "requires_analysis_code_change": True,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": True,
            "recommendation": "The declared incident can be reported now, but packet-level Modbus precision and detector cross-mapping would need pipeline changes and a fresh rerun to become defensible.",
        },
        {
            "paper_table_or_metric": "Table 3: preserved artifacts summary",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Generate directly from deduped manifest artifacts.",
        },
        {
            "paper_table_or_metric": "Table 4: manifest and custody verification",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "explicit hash mismatch count separate from missing artifact count",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": True,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "The table is generable now, but a future integrity report should emit hash mismatch counts explicitly.",
        },
        {
            "paper_table_or_metric": "Table 5: temporal and pipeline metrics",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "industrial export timestamps for cases without preserved OT export",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": True,
            "requires_repeating_level_b": True,
            "recommendation": "Generate now with unavailable markers for OT-export timings; preserving OT exports in future runs would require acquisition changes and reruns.",
        },
        {
            "paper_table_or_metric": "Table 6: operational aggregates",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "industrial size/timing values remain unavailable because the underlying OT exports were not preserved",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": True,
            "requires_repeating_level_b": True,
            "recommendation": "Compute aggregates over available values and report the real denominator.",
        },
        {
            "paper_table_or_metric": "Table 7: time synchronization",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Generate directly from metadata/time_sync.json.",
        },
        {
            "paper_table_or_metric": "Table 8: technical evidence and preservation checks",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "Industrial / OT evidence preservation fails because no OT export was preserved in the current cases",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": True,
            "requires_repeating_level_b": True,
            "recommendation": "Generate the invariants now and make the OT-preservation gap explicit instead of forcing a pass.",
        },
        {
            "paper_table_or_metric": "Table 9: causal reconstruction and relation states",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Generate directly from reconstruction_metrics.json, causal_graph.json and hypothesis_support_report.json.",
        },
    ]
    rows.append(
        {
            "paper_table_or_metric": "Table 10: technical availability conclusion",
            "can_be_generated_from_current_artifacts": True,
            "missing_data": "This table is itself the availability synthesis.",
            "requires_only_report_aggregation": True,
            "requires_analysis_code_change": False,
            "requires_acquisition_code_change": False,
            "requires_repeating_level_b": False,
            "recommendation": "Generate directly from the audit output.",
        }
    )
    return rows


def build_scientific_usability(table10_rows: list[dict]) -> list[dict]:
    rows: list[dict] = []
    mapping = [
        ("repetition index", "Table 1: Level B repetition index"),
        ("incident specification", "Table 2: incident specification"),
        ("artifact summary", "Table 3: preserved artifacts summary"),
        ("manifest/custody verification", "Table 4: manifest and custody verification"),
        ("timing metrics", "Table 5: temporal and pipeline metrics"),
        ("Level B aggregate metrics", "Table 6: operational aggregates"),
        ("time sync", "Table 7: time synchronization"),
        ("network evidence preservation", "Table 8: technical evidence and preservation checks"),
        ("trigger alert preservation", "Table 8: technical evidence and preservation checks"),
        ("host evidence preservation", "Table 8: technical evidence and preservation checks"),
        ("industrial / OT evidence preservation", "Table 8: technical evidence and preservation checks"),
        ("causal reconstruction summary", "Table 9: causal reconstruction and relation states"),
        ("relation-level reconstruction table", "Table 9: causal reconstruction and relation states"),
        ("CPR", "Table 9: causal reconstruction and relation states"),
        ("WCPR", "Table 9: causal reconstruction and relation states"),
    ]
    index = {str(row.get("paper_table_or_metric") or ""): row for row in table10_rows}
    for metric_name, source_name in mapping:
        source = index.get(source_name) or {}
        missing = str(source.get("missing_data") or "").strip()
        requires_reporting_fix = bool(source.get("requires_only_report_aggregation"))
        requires_pipeline_change = bool(source.get("requires_analysis_code_change") or source.get("requires_acquisition_code_change"))
        requires_repeating = bool(source.get("requires_repeating_level_b"))
        if metric_name in {"network evidence preservation", "trigger alert preservation", "host evidence preservation", "manifest/custody verification"}:
            missing = ""
            requires_pipeline_change = False if metric_name != "manifest/custody verification" else requires_pipeline_change
            requires_repeating = False
        if metric_name == "industrial / OT evidence preservation":
            missing = "No OT/industrial export was preserved in the current Level B cases."
            requires_pipeline_change = True
            requires_repeating = True
        usable_now = bool(source.get("can_be_generated_from_current_artifacts")) and not requires_repeating and not missing
        preliminary = bool(source.get("can_be_generated_from_current_artifacts")) and not usable_now
        rows.append(
            {
                "metric_or_table": metric_name,
                "usable_for_paper_now": usable_now,
                "usable_only_as_preliminary_audit": preliminary,
                "main_limitation": missing or "",
                "requires_only_reporting_fix": requires_reporting_fix,
                "requires_pipeline_change": requires_pipeline_change,
                "requires_repeating_level_b": requires_repeating,
            }
        )
    return rows


def availability_row(*, table_name: str, metric_name: str, available: bool, source_file: str, source_field: str, case_id_or_level: str, aggregation_needed: bool, aggregation_formula: str, data_category: str, can_compute: bool, requires_only_reporting_fix: bool, requires_analysis_code_change: bool, requires_acquisition_code_change: bool, requires_repeating_level_b: bool, notes: str) -> dict:
    return {
        "table_name": table_name,
        "metric_name": metric_name,
        "available": csv_bool(available),
        "source_file": source_file,
        "source_field": source_field,
        "case_id_or_level": case_id_or_level,
        "aggregation_needed": csv_bool(aggregation_needed),
        "aggregation_formula": aggregation_formula,
        "data_category": data_category,
        "can_be_computed_from_existing_artifacts": csv_bool(can_compute),
        "requires_only_reporting_fix": csv_bool(requires_only_reporting_fix),
        "requires_analysis_code_change": csv_bool(requires_analysis_code_change),
        "requires_acquisition_code_change": csv_bool(requires_acquisition_code_change),
        "requires_repeating_level_b": csv_bool(requires_repeating_level_b),
        "notes": notes,
    }


def is_available_value(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    lowered = text.lower()
    return not (lowered.startswith("not available in current artifacts") or lowered.startswith("not computed by current pipeline"))


def matrix_overrides(table_name: str, metric_name: str, value: Any) -> tuple[str, bool, bool, bool, bool, str]:
    text = str(value).strip()
    unavailable = not is_available_value(value)
    default_note = text if unavailable else ""
    overrides: dict[str, tuple[str, bool, bool, bool, bool, str]] = {
        "deployment_id": ("not available in current artifacts", False, True, False, False, "The current campaign stores deployment_profile_id, not a concrete deployment_id for the run."),
        "attack_profile_version": ("not available in current artifacts", False, True, False, False, "Attack profile version is not persisted by the current pipeline."),
        "procedure_version": ("not available in current artifacts", False, True, False, False, "Procedure version is not persisted by the current pipeline."),
        "source_node_id": ("not available in current artifacts", False, False, True, False, "The current artifacts preserve source IP and role, but not a stable source node identifier."),
        "wazuh_rule_id": ("not computed by current pipeline", False, False, True, False, "Current artifacts preserve alert summaries but not a defensible per-trigger Wazuh rule mapping."),
        "wazuh_alert_id": ("not computed by current pipeline", False, False, True, False, "Current artifacts preserve alert summaries but not a defensible per-trigger Wazuh alert identifier."),
        "industrial_export_start_utc": ("not available in current artifacts", False, False, False, True, "The current Level B cases do not preserve OT export artifacts, so OT-export timing cannot be reconstructed."),
        "industrial_export_preserved_utc": ("not available in current artifacts", False, False, False, True, "The current Level B cases do not preserve OT export artifacts, so OT-export timing cannot be reconstructed."),
        "alert_to_industrial_export_preserved_s": ("not available in current artifacts", False, False, False, True, "The current Level B cases do not preserve OT export artifacts, so OT-export timing cannot be reconstructed."),
        "industrial_artifact_count": ("not available in current artifacts", False, False, False, True, "Current Level B cases preserved no OT export artifacts."),
        "industrial_total_size_bytes": ("not available in current artifacts", False, False, False, True, "Current Level B cases preserved no OT export artifacts."),
        "industrial_ot_evidence_preservation_status": ("not available in current artifacts", False, False, False, True, "Current Level B cases preserved no OT export artifacts."),
        "manifest_failed_artifacts": ("not computed by current pipeline", False, True, False, False, "Current integrity reports expose missing artifacts, but not an explicit separate hash-mismatch count."),
        "hash_chain_errors": ("not computed by current pipeline", False, True, False, False, "Current integrity reports expose custody validity, but not a richer custody hash-chain error taxonomy."),
    }
    if metric_name == "declared_modbus_target_address":
        return ("declared but not packet-confirmed", True, False, False, False, "Available as a declared value only; packet-confirmed precision is not preserved.")
    if metric_name == "declared_expected_value":
        return ("declared but not packet-confirmed", True, False, False, False, "Available as a declared value only; packet-confirmed precision is not preserved.")
    if table_name == "Table 3" and metric_name in {"industrial_artifact_count", "industrial_total_size_bytes"}:
        return ("directly observed", True, False, False, False, "Observed as zero preserved OT artifacts in the current retained manifest.")
    if metric_name in overrides:
        if unavailable or metric_name in {"industrial_artifact_count", "industrial_total_size_bytes", "industrial_ot_evidence_preservation_status"}:
            return overrides[metric_name]
    if unavailable:
        return ("not available in current artifacts", False, False, False, False, default_note or "The value is not available in current artifacts.")
    return ("directly observed", True, False, False, False, default_note)


def build_availability_matrix(audits: list[ExecutionAudit], tables: dict[str, list[dict]]) -> list[dict]:
    rows: list[dict] = []
    table_specs: list[tuple[str, str, list[str], bool, str]] = [
        ("Table 1", "table1", ["rep_id", "case_id", "run_id", "scenario_id", "deployment_id", "attack_profile_id", "attack_profile_version", "acquisition_profile_id", "procedure_version", "started_at_utc", "ended_at_utc", "status", "excluded_or_accepted", "exclusion_reason"], False, ""),
        ("Table 2", "table2", ["scenario_type", "incident_class", "MITRE ATT&CK for ICS technique", "source_role", "source_node_id", "source_ip", "target_role", "target_node_id", "target_ip", "protocol", "port", "declared_modbus_function", "declared_modbus_target_address", "declared_expected_value", "expected_control_effect", "detection_path", "suricata_rule_id", "suricata_signature", "wazuh_rule_id", "wazuh_alert_id", "attack_log_path", "attack_log_sha256"], False, ""),
        ("Table 3", "table3", ["network_artifact_count", "network_total_size_bytes", "memory_artifact_count", "memory_total_size_bytes", "disk_artifact_count", "disk_total_size_bytes", "industrial_artifact_count", "industrial_total_size_bytes", "alerts_artifact_count", "metadata_artifact_count", "derived_artifact_count", "manifest_present", "custody_log_present", "pipeline_events_present"], False, ""),
        ("Table 4", "table4", ["manifest_present", "manifest_verification_status", "manifest_verified_artifacts", "manifest_failed_artifacts", "manifest_missing_artifacts", "custody_log_present", "custody_chain_verification_status", "custody_event_count", "hash_chain_errors", "primary_derived_separation_verified"], False, ""),
        ("Table 5", "table5", ["trigger_time_utc", "memory_acquisition_start_utc", "memory_preserved_utc", "industrial_export_start_utc", "industrial_export_preserved_utc", "disk_snapshot_start_utc", "disk_snapshot_preserved_utc", "first_primary_artifact_sealed_utc", "full_case_sealed_utc", "alert_to_memory_start_s", "alert_to_memory_preserved_s", "alert_to_industrial_export_preserved_s", "alert_to_disk_snapshot_start_s", "alert_to_disk_snapshot_preserved_s", "T_first_sealed_s", "T_case_sealed_s"], False, ""),
        ("Table 6", "table6", ["mean", "sample_standard_deviation", "minimum", "maximum", "denominator_n"], True, "aggregate over accepted Level B cases with non-null values"),
        ("Table 7", "table7", ["time_sync_status", "nodes_measured", "nodes_failed", "max_clock_offset_s", "worst_node", "correction_applied", "time_sync_report_path"], False, ""),
        ("Table 8A", "table8_case", ["network_evidence_preservation_status", "trigger_alert_preservation_status", "industrial_ot_evidence_preservation_status", "host_evidence_preservation_status", "manifest_and_custody_verification_status"], False, ""),
        ("Table 8B", "table8_aggregate", ["passed_cases", "denominator", "success_rate_percent", "failure_cases", "failure_reason"], True, "aggregate over accepted Level B cases"),
        ("Table 9A", "table9_case", ["expected_causal_relations_count", "recovered_relations_count", "degraded_relations_count", "ambiguous_relations_count", "missing_relations_count", "CPR", "WCPR", "recoverability_label", "scientific_confidence", "hypothesis_support_level", "temporal_confidence", "integrity_completeness"], False, ""),
        ("Table 9B", "table9_relations", ["relation_description", "relation_state", "relation_weight", "evidence_refs", "timestamp_available", "timestamp_resolvable", "integrity_verified", "degradation_reason", "missing_reason"], False, ""),
        ("Table 10", "table10", ["can_be_generated_from_current_artifacts", "missing_data", "requires_only_report_aggregation", "requires_analysis_code_change", "requires_acquisition_code_change", "requires_repeating_level_b", "recommendation"], True, "availability synthesis over the current Level B artifact set"),
    ]

    for table_name, table_key, metrics, aggregation_needed, aggregation_formula in table_specs:
        for row in tables.get(table_key, []):
            provenance = str(row.get("provenance") or "").strip()
            if table_key == "table6":
                case_id_or_level = "Level B aggregate"
                metric_name_source = str(row.get("metric_name") or "aggregate_metric")
            elif table_key == "table8_aggregate":
                case_id_or_level = "Level B aggregate"
                metric_name_source = str(row.get("technical_check") or "technical_check")
            elif table_key == "table10":
                case_id_or_level = "Level B availability synthesis"
                metric_name_source = str(row.get("paper_table_or_metric") or "availability_item")
            elif table_key == "table9_relations":
                case_id_or_level = str(row.get("case_id") or not_available())
                metric_name_source = str(row.get("relation_id") or "relation")
            else:
                case_id_or_level = str(row.get("case_id") or row.get("rep_id") or not_available())
                metric_name_source = ""

            for metric in metrics:
                value = row.get(metric)
                available = is_available_value(value)
                data_category, can_compute, requires_only_reporting_fix, requires_analysis_code_change, requires_acquisition_code_change, note = matrix_overrides(table_name, metric, value)
                metric_name = metric if not metric_name_source else f"{metric_name_source}:{metric}"
                rows.append(
                    availability_row(
                        table_name=table_name,
                        metric_name=metric_name,
                        available=available,
                        source_file=provenance or "See report provenance",
                        source_field=metric,
                        case_id_or_level=case_id_or_level,
                        aggregation_needed=aggregation_needed,
                        aggregation_formula=aggregation_formula,
                        data_category=data_category,
                        can_compute=can_compute,
                        requires_only_reporting_fix=requires_only_reporting_fix,
                        requires_analysis_code_change=requires_analysis_code_change,
                        requires_acquisition_code_change=requires_acquisition_code_change,
                        requires_repeating_level_b=bool(requires_analysis_code_change or requires_acquisition_code_change),
                        notes=note,
                    )
                )
    return rows


def markdown_table(rows: list[dict], columns: list[str]) -> str:
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(markdown_escape(metric_display(row.get(col))) for col in columns) + " |")
    return "\n".join([header, divider, *body])


def overall_conclusion(table10_rows: list[dict]) -> str:
    can_all = all(bool(row.get("can_be_generated_from_current_artifacts")) for row in table10_rows)
    missing_any = any(str(row.get("missing_data") or "").strip() for row in table10_rows)
    if can_all and not missing_any:
        return "Option A: enough for current paper tables"
    if can_all:
        return "Option B: enough only for partial/preliminary tables"
    return "Option C: not enough; requires pipeline/reporting changes and rerunning Level B"


def build_gap_report(table10_rows: list[dict]) -> tuple[str, list[dict]]:
    rows: list[dict] = []
    for row in table10_rows:
        missing = str(row.get("missing_data") or "").strip()
        if not missing:
            continue
        rows.append(
            {
                "missing_data": missing,
                "affected_table_or_metric": row["paper_table_or_metric"],
                "why_it_matters": row["recommendation"],
                "can_be_recovered_from_existing_artifacts": bool(row.get("requires_only_report_aggregation")),
                "requires_only_reporting_fix": bool(row.get("requires_only_report_aggregation")),
                "requires_analysis_code_change": bool(row.get("requires_analysis_code_change")),
                "requires_acquisition_code_change": bool(row.get("requires_acquisition_code_change")),
                "requires_repeating_level_b": bool(row.get("requires_repeating_level_b")),
                "recommendation": row["recommendation"],
            }
        )
    return overall_conclusion(table10_rows), rows


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def render_report(audits: list[ExecutionAudit], tables: dict[str, list[dict]], output_dir: Path) -> str:
    accepted = accepted_execution_ids(audits)
    table10_rows = tables["table10"]
    conclusion = overall_conclusion(table10_rows)
    data_scope = [
        f"- Campaigns scanned: {', '.join(sorted({audit.campaign_id for audit in audits})) or 'none'}",
        f"- Level B executions found: {len(audits)}",
        f"- Accepted Level B executions for aggregate reporting: {len(accepted)}",
        f"- Current Level B artifacts contain n={len(accepted)} accepted cases.",
        "- These results must not be presented as the final N_B=6 evaluation.",
        "- Data sources were limited to existing campaign workspaces, retained lightweight case bundles, validation reports, paper evidence packages and attack output artifacts.",
    ]

    sections = [
        "# FORGE-VI Level B Table Reconstruction Report",
        "",
        f"Generated at: `{utc_now_iso()}`",
        "",
        "## Scope",
        *data_scope,
        "",
        "## Technical Conclusion",
        conclusion,
        "",
        "Current Level B artifacts are usable for preliminary reporting over n=2 accepted cases, but they are not sufficient to support a final N_B=6 evaluation.",
        "",
        "## Nested Level A Within Level B",
        *[
            f"- `{audit.execution_id}` -> case `{audit.case_id}` -> nested Level A `{audit.nested_level_a.get('campaign_id', 'not available')}` -> status `{audit.nested_level_a.get('status', 'not available')}` -> report `{audit.nested_level_a.get('report_markdown_path', not_available())}` -> note `analysis over Level B cases`"
            for audit in audits
        ],
        "",
        "## Table 1: Index of Level B Repetitions",
        markdown_table(
            tables["table1"],
            ["rep_id", "case_id", "run_id", "campaign_id", "scenario_id", "deployment_id", "attack_profile_id", "attack_profile_version", "acquisition_profile_id", "procedure_version", "started_at_utc", "ended_at_utc", "status", "excluded_or_accepted", "exclusion_reason", "provenance"],
        ),
        "",
        "## Table 2: Incident Specification Used in Level B",
        markdown_table(
            tables["table2"],
            ["rep_id", "case_id", "scenario_type", "incident_class", "MITRE ATT&CK for ICS technique", "source_role", "source_node_id", "source_ip", "target_role", "target_node_id", "target_ip", "protocol", "port", "declared_modbus_function", "declared_modbus_target_address", "declared_expected_value", "expected_control_effect", "detection_path", "suricata_rule_id", "suricata_signature", "wazuh_rule_id", "wazuh_alert_id", "attack_log_path", "attack_log_sha256", "provenance"],
        ),
        "",
        "## Table 3: Preserved Artifact Summary per Case",
        markdown_table(
            tables["table3"],
            ["case_id", "network_artifact_count", "network_total_size_bytes", "memory_artifact_count", "memory_total_size_bytes", "disk_artifact_count", "disk_total_size_bytes", "industrial_artifact_count", "industrial_total_size_bytes", "alerts_artifact_count", "metadata_artifact_count", "derived_artifact_count", "manifest_present", "custody_log_present", "pipeline_events_present", "provenance"],
        ),
        "",
        "## Table 4: Manifest and Chain of Custody Verification",
        markdown_table(
            tables["table4"],
            ["case_id", "manifest_present", "manifest_verification_status", "manifest_verified_artifacts", "manifest_failed_artifacts", "manifest_missing_artifacts", "custody_log_present", "custody_chain_verification_status", "custody_event_count", "hash_chain_errors", "primary_derived_separation_verified", "provenance"],
        ),
        "",
        "## Table 5: Temporal Metrics and Pipeline Events",
        markdown_table(
            tables["table5"],
            ["case_id", "trigger_time_utc", "memory_acquisition_start_utc", "memory_preserved_utc", "industrial_export_start_utc", "industrial_export_preserved_utc", "disk_snapshot_start_utc", "disk_snapshot_preserved_utc", "first_primary_artifact_sealed_utc", "full_case_sealed_utc", "alert_to_memory_start_s", "alert_to_memory_preserved_s", "alert_to_industrial_export_preserved_s", "alert_to_disk_snapshot_start_s", "alert_to_disk_snapshot_preserved_s", "T_first_sealed_s", "T_case_sealed_s", "provenance"],
        ),
        "",
        "## Table 6: Aggregated Operational Summary for Level B",
        markdown_table(
            tables["table6"],
            ["metric_name", "mean", "sample_standard_deviation", "minimum", "maximum", "denominator_n", "provenance"],
        ),
        "",
        "## Table 7: Time Synchronization",
        markdown_table(
            tables["table7"],
            ["case_id", "time_sync_status", "nodes_measured", "nodes_failed", "max_clock_offset_s", "worst_node", "correction_applied", "time_sync_report_path", "provenance"],
        ),
        "",
        "## Table 8A: Technical Evidence and Preservation Checks Per Case",
        markdown_table(
            tables["table8_case"],
            ["case_id", "network_evidence_preservation_status", "network_evidence_refs", "trigger_alert_preservation_status", "trigger_alert_evidence_refs", "industrial_ot_evidence_preservation_status", "industrial_ot_evidence_refs", "host_evidence_preservation_status", "host_evidence_refs", "manifest_and_custody_verification_status", "manifest_and_custody_evidence_refs"],
        ),
        "",
        "## Table 8B: Technical Check Aggregate Summary",
        markdown_table(
            tables["table8_aggregate"],
            ["technical_check", "passed_cases", "denominator", "success_rate_percent", "failure_cases", "failure_reason"],
        ),
        "",
        "## Table 9A: Causal Reconstruction Summary Per Case",
        markdown_table(
            tables["table9_case"],
            ["case_id", "expected_causal_relations_count", "recovered_relations_count", "degraded_relations_count", "ambiguous_relations_count", "missing_relations_count", "CPR", "WCPR", "recoverability_label", "scientific_confidence", "hypothesis_support_level", "temporal_confidence", "integrity_completeness", "provenance"],
        ),
        "",
        "## Table 9B: Relation-Level Reconstruction State",
        markdown_table(
            tables["table9_relations"],
            ["case_id", "relation_id", "relation_description", "relation_state", "relation_weight", "evidence_refs", "timestamp_available", "timestamp_resolvable", "integrity_verified", "degradation_reason", "missing_reason", "provenance"],
        ),
        "",
        "## Table 10: Technical Availability Conclusion",
        markdown_table(
            tables["table10"],
            ["paper_table_or_metric", "can_be_generated_from_current_artifacts", "missing_data", "requires_only_report_aggregation", "requires_analysis_code_change", "requires_acquisition_code_change", "requires_repeating_level_b", "recommendation"],
        ),
        "",
        "## Scientific Usability of Current Level B Artifacts",
        markdown_table(
            tables["scientific_usability"],
            ["metric_or_table", "usable_for_paper_now", "usable_only_as_preliminary_audit", "main_limitation", "requires_only_reporting_fix", "requires_pipeline_change", "requires_repeating_level_b"],
        ),
        "",
        "## Output Files",
        f"- `{rel(output_dir / 'FORGE-VI_LevelB_Table_Values.json')}`",
        f"- `{rel(output_dir / 'FORGE-VI_LevelB_Data_Availability_Matrix.csv')}`",
        f"- `{rel(output_dir / 'FORGE-VI_LevelB_Table_Gap_Report.md')}`",
    ]
    return "\n".join(sections) + "\n"


def generate_report_bundle() -> dict[str, Any]:
    audits = load_execution_audits()
    accepted = accepted_execution_ids(audits)

    output_dir = VALIDATION_ROOT / f"forge_vi_levelb_table_reconstruction_{utc_now_compact().replace(':', '').replace('.', '_')}"
    output_dir.mkdir(parents=True, exist_ok=True)

    tables = {
        "table1": build_table1(audits, accepted),
        "table2": build_table2(audits),
        "table3": build_table3(audits),
        "table4": build_table4(audits),
        "table5": build_table5(audits),
        "table6": build_table6(audits, accepted),
        "table7": build_table7(audits),
    }
    tables["table8_case"] = build_table8_case(audits)
    tables["table8_aggregate"] = build_table8_aggregate(tables["table8_case"], accepted)
    tables["table9_case"] = build_table9_case(audits)
    tables["table9_relations"] = build_table9_relations(audits)
    tables["table10"] = build_table10(audits)
    tables["scientific_usability"] = build_scientific_usability(tables["table10"])

    values_payload = {
        "generated_at": utc_now_iso(),
        "scope": {
            "campaign_ids": sorted({audit.campaign_id for audit in audits}),
            "case_ids": [audit.case_id for audit in audits],
            "execution_ids": [audit.execution_id for audit in audits],
            "accepted_execution_ids": sorted(accepted),
        },
        "tables": tables,
    }
    write_json(output_dir / "FORGE-VI_LevelB_Table_Values.json", values_payload)

    availability_matrix = build_availability_matrix(audits, tables)
    write_csv(output_dir / "FORGE-VI_LevelB_Data_Availability_Matrix.csv", availability_matrix)

    conclusion, gap_rows = build_gap_report(tables["table10"])
    gap_md = "\n".join(
        [
            "# FORGE-VI Level B Table Gap Report",
            "",
            f"Generated at: `{utc_now_iso()}`",
            "",
            "## Conclusion",
            conclusion,
            "",
            "## Gaps",
            markdown_table(
                gap_rows,
                ["missing_data", "affected_table_or_metric", "why_it_matters", "can_be_recovered_from_existing_artifacts", "requires_only_reporting_fix", "requires_analysis_code_change", "requires_acquisition_code_change", "requires_repeating_level_b", "recommendation"],
            ) if gap_rows else "- No gaps detected in the current audit scope.",
        ]
    ) + "\n"
    (output_dir / "FORGE-VI_LevelB_Table_Gap_Report.md").write_text(gap_md, encoding="utf-8")

    report_md = render_report(audits, tables, output_dir)
    (output_dir / "FORGE-VI_LevelB_Table_Reconstruction_Report.md").write_text(report_md, encoding="utf-8")

    payload = {
        "report_id": output_dir.name,
        "generated_at": utc_now_iso(),
        "output_dir": rel(output_dir),
        "report_markdown_path": rel(output_dir / "FORGE-VI_LevelB_Table_Reconstruction_Report.md"),
        "report_markdown": report_md,
        "gap_report_path": rel(output_dir / "FORGE-VI_LevelB_Table_Gap_Report.md"),
        "gap_report_markdown": gap_md,
        "values_json_path": rel(output_dir / "FORGE-VI_LevelB_Table_Values.json"),
        "availability_matrix_csv_path": rel(output_dir / "FORGE-VI_LevelB_Data_Availability_Matrix.csv"),
        "conclusion": conclusion,
        "accepted_level_b_cases": len(accepted),
        "campaign_ids": sorted({audit.campaign_id for audit in audits}),
    }
    write_json(output_dir / "report_metadata.json", payload)
    return payload


def list_generated_reports() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for report_dir in sorted(VALIDATION_ROOT.glob("forge_vi_levelb_table_reconstruction_*"), reverse=True):
        if not report_dir.is_dir():
            continue
        metadata = load_json(report_dir / "report_metadata.json") or {}
        items.append(
            {
                "report_id": report_dir.name,
                "output_dir": rel(report_dir),
                "generated_at": str(metadata.get("generated_at") or report_dir.name),
                "conclusion": metadata.get("conclusion"),
                "accepted_level_b_cases": metadata.get("accepted_level_b_cases"),
                "campaign_ids": metadata.get("campaign_ids") or [],
                "report_markdown_path": metadata.get("report_markdown_path") or rel(report_dir / "FORGE-VI_LevelB_Table_Reconstruction_Report.md"),
                "gap_report_path": metadata.get("gap_report_path") or rel(report_dir / "FORGE-VI_LevelB_Table_Gap_Report.md"),
                "values_json_path": metadata.get("values_json_path") or rel(report_dir / "FORGE-VI_LevelB_Table_Values.json"),
                "availability_matrix_csv_path": metadata.get("availability_matrix_csv_path") or rel(report_dir / "FORGE-VI_LevelB_Data_Availability_Matrix.csv"),
            }
        )
    return items


def get_generated_report(report_id: str) -> dict[str, Any] | None:
    report_dir = VALIDATION_ROOT / str(report_id)
    if not report_dir.is_dir():
        return None
    metadata = load_json(report_dir / "report_metadata.json") or {}
    report_md_path = report_dir / "FORGE-VI_LevelB_Table_Reconstruction_Report.md"
    gap_md_path = report_dir / "FORGE-VI_LevelB_Table_Gap_Report.md"
    values_json_path = report_dir / "FORGE-VI_LevelB_Table_Values.json"
    return {
        "report_id": report_dir.name,
        "output_dir": rel(report_dir),
        "metadata": metadata,
        "report_markdown_path": rel(report_md_path),
        "report_markdown": report_md_path.read_text(encoding="utf-8") if report_md_path.is_file() else "",
        "gap_report_path": rel(gap_md_path),
        "gap_report_markdown": gap_md_path.read_text(encoding="utf-8") if gap_md_path.is_file() else "",
        "values_json_path": rel(values_json_path),
        "values_json": load_json(values_json_path) or {},
        "availability_matrix_csv_path": rel(report_dir / "FORGE-VI_LevelB_Data_Availability_Matrix.csv"),
    }


def main() -> int:
    payload = generate_report_bundle()
    print(payload["output_dir"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
