import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .foc_paths import project_path, relative_path
from .foc_sources import read_json_file, utc_now

_MISSING_SENTINELS = {"", "unknown", "unresolved", "not_available", "not_started", "n/a", "none"}
_CASE_SAMPLE_LIMIT = 12
_ALERT_SAMPLE_LIMIT = 25


def _artifact_path(indexes: dict, artifact_type: str) -> str | None:
    for artifact in ((indexes.get("artifacts_index") or {}).get("artifacts") or []):
        if artifact.get("artifact_type") == artifact_type:
            return artifact.get("path")
    return None


def _binding_maps(scenario_bom: dict) -> tuple[dict, dict]:
    by_node = {}
    by_instance = {}
    for binding in (scenario_bom.get("node_instance_bindings") or []):
        if binding.get("node_id"):
            by_node[binding["node_id"]] = binding
        if binding.get("instance_id"):
            by_instance[binding["instance_id"]] = binding
    return by_node, by_instance


def _parse_mbpoll_command(command: str) -> dict:
    out = {
        "protocol": "modbus_tcp" if "mbpoll" in str(command or "") else "unknown",
        "target_ip": None,
        "target_port": 502 if "mbpoll" in str(command or "") else None,
        "slave_id": None,
        "register_reference": None,
        "value": None,
        "data_type": None,
        "operation": "write" if "mbpoll" in str(command or "") else "unknown",
        "modbus_function": None,
    }
    raw = str(command or "").strip()
    if not raw:
        return out
    slave = re.search(r"\s-a\s+(\d+)", raw)
    register = re.search(r"\s-r\s+(\d+)", raw)
    dtype = re.search(r"\s-t\s+([^\s]+)", raw)
    target = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+(-?\d+)\s*$", raw)
    if slave:
        out["slave_id"] = int(slave.group(1))
    if register:
        out["register_reference"] = int(register.group(1))
    if dtype:
        out["data_type"] = dtype.group(1)
    if target:
        out["target_ip"] = target.group(1)
        try:
            out["value"] = int(target.group(2))
        except Exception:
            out["value"] = target.group(2)
    if out["protocol"] == "modbus_tcp":
        # Conservative heuristic for mbpoll register writes. If the write value is present and
        # the command targets registers, Modbus/TCP commonly emits function 16 for multi-register writes.
        out["modbus_function"] = "16" if out["register_reference"] is not None else None
    return out


def _load_json_if_exists(path_str: str | None) -> dict:
    if not path_str:
        return {}
    path = project_path(*Path(path_str).parts)
    payload = read_json_file(path, [])
    return payload if isinstance(payload, dict) else {}


def _load_attack_sidecar(source_path: str | None, filename: str) -> dict:
    if not source_path:
        return {}
    sidecar_path = project_path(*Path(source_path).parent.joinpath(filename).parts)
    payload = read_json_file(sidecar_path, [])
    return payload if isinstance(payload, dict) else {}


def _parse_timestamp(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def _seconds_between(start: str | None, end: str | None) -> float | None:
    start_dt = _parse_timestamp(start)
    end_dt = _parse_timestamp(end)
    if not start_dt or not end_dt:
        return None
    return round((end_dt - start_dt).total_seconds(), 3)


def _safe_rel_path(path_str: str | None) -> str | None:
    if not path_str:
        return None
    try:
        return relative_path(project_path(*Path(path_str).parts))
    except Exception:
        return path_str


def _path_exists(path_str: str | None) -> bool:
    if not path_str:
        return False
    try:
        return project_path(*Path(path_str).parts).exists()
    except Exception:
        return False


def _get_value(obj: dict, dotted_path: str):
    current = obj
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _is_present(value) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return value.strip().lower() not in _MISSING_SENTINELS
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return bool(value)


def _record_identifier(item: dict) -> str:
    for key in (
        "attack_id",
        "alert_id",
        "case_id",
        "artifact_id",
        "rule_id",
        "timeline_event_id",
        "node_id",
    ):
        value = item.get(key)
        if _is_present(value):
            return str(value)
    return "unidentified"


def _validate_records(records: list[dict], field_specs: list[dict], minimum_count: int = 1) -> dict:
    results = {}
    problems = []
    statuses = []
    for spec in field_specs:
        name = spec["name"]
        path = spec["path"]
        applies = spec.get("applies")
        validator = spec.get("validator")
        applicable = 0
        present = 0
        missing_samples = []
        for record in records:
            if applies and not applies(record):
                continue
            applicable += 1
            value = _get_value(record, path)
            is_valid = validator(value, record) if callable(validator) else _is_present(value)
            if is_valid:
                present += 1
            elif len(missing_samples) < _CASE_SAMPLE_LIMIT:
                missing_samples.append(_record_identifier(record))
        if applicable == 0:
            status = "not_applicable"
        elif present == applicable:
            status = "ok"
        elif present == 0:
            status = "missing"
        else:
            status = "partial"
        results[name] = {
            "path": path,
            "status": status,
            "present_records": present,
            "applicable_records": applicable,
            "coverage_ratio": round((present / applicable), 4) if applicable else None,
            "missing_samples": missing_samples,
        }
        if status in {"partial", "missing"}:
            problems.append(name)
        if status != "not_applicable":
            statuses.append(status)

    if len(records) < minimum_count:
        overall_status = "missing"
    elif statuses and all(status == "ok" for status in statuses):
        overall_status = "ok"
    elif statuses:
        overall_status = "partial"
    else:
        overall_status = "missing"

    return {
        "record_count": len(records),
        "minimum_expected_records": minimum_count,
        "overall_status": overall_status,
        "fields": results,
        "problem_fields": problems,
    }


def _infer_detector(alert_or_signature, source_type: str | None = None) -> str:
    signature = str(alert_or_signature or "")
    source = str(source_type or "")
    raw = f"{signature} {source}".lower()
    if "suricata" in raw or "modbus write" in raw or "ping detectado" in raw:
        return "Suricata"
    if "wazuh" in raw or source == "alerts_jsonl":
        return "Wazuh"
    if "sysmon" in raw:
        return "Sysmon"
    return "Unknown"


def _infer_mitre_techniques(signature: str | None) -> list[str]:
    raw = str(signature or "").lower()
    techniques = []
    if "modbus write" in raw:
        techniques.extend(["T0836", "T1692.001"])
    if "holding register read" in raw:
        techniques.extend(["T0861", "T0802"])
    if "coil read" in raw or "input register read" in raw:
        techniques.append("T0877")
    if "ping" in raw:
        techniques.append("T0846.001")
    return sorted(set(techniques))


def _infer_rule_file(signature: str | None, rule_id=None) -> str | None:
    raw = str(signature or "").lower()
    if "modbus write" in raw:
        return "/var/lib/suricata/rules/nics-modbus-register-manipulation.rules"
    if "ping detectado" in raw or "icmp" in raw:
        return "/var/lib/suricata/rules/nics-icmp.rules"
    if str(rule_id or "") in {"86601", "550"}:
        return "/var/ossec/etc/rules/local_rules.xml"
    return None


def _normalize_severity(rule_level, triage_severity) -> str:
    if _is_present(triage_severity):
        return str(triage_severity).upper()
    try:
        level = int(rule_level)
    except Exception:
        return "UNKNOWN"
    if level >= 10:
        return "CRITICAL"
    if level >= 7:
        return "HIGH"
    if level >= 4:
        return "MEDIUM"
    return "LOW"


def _normalized_alert_message(signature: str | None, rule_id=None) -> str:
    if _is_present(signature):
        return str(signature)
    if _is_present(rule_id):
        return f"Rule {rule_id} triggered"
    return "Unlabeled alert"


def _summarize_top_counter(counter: Counter, limit: int = 10) -> list[dict]:
    return [{"label": label, "count": count} for label, count in counter.most_common(limit) if _is_present(label)]


def _bucket_from_correlation_status(item: dict) -> str:
    status = str(item.get("correlation_status") or "").lower()
    reason = str(item.get("correlation_reason") or "").lower()
    signature = str(item.get("signature") or "").lower()
    if status in {"confirmed", "correlated"}:
        return "correlated"
    if "false_positive" in reason:
        return "false_positive_candidate"
    if status in {"unresolved", "uncorrelated"} and "no_matching_detection_event" in reason:
        return "missing_expected_alert"
    if status in {"unresolved", "uncorrelated"} and "nics cyberlab ics" not in signature:
        return "noise"
    return "uncorrelated"


def _find_trigger_alert(case_created_event: dict, alerts_normalized: list[dict], binding_by_node: dict, binding_by_instance: dict) -> dict | None:
    case_ts = _parse_timestamp(case_created_event.get("timestamp"))
    if not case_ts:
        return None
    candidates = []
    for alert in alerts_normalized:
        alert_ts = _parse_timestamp(alert.get("timestamp"))
        if not alert_ts or alert_ts > case_ts:
            continue
        delta = (case_ts - alert_ts).total_seconds()
        if delta < 0:
            continue
        candidates.append((delta, alert))
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1] if candidates else None


def _attack_expected_edges(attack: dict) -> list[dict]:
    attack_id = attack.get("attack_id")
    operation = attack.get("operation") or {}
    protocol = operation.get("protocol")
    edges = [
        {
            "edge_id": f"{attack_id}:execution_to_target",
            "source": attack_id,
            "target": attack.get("target", {}).get("node_id"),
            "edge_type": "attack_targets_node",
            "semantic_rule": "The executed attack must map to a deployed scenario node and instance binding.",
            "temporal_rule": "Target binding must exist before or at attack start time.",
            "required_evidence": [
                attack.get("evidence_references", [None])[0],
                "foc-reconstruction/scenario_bom.json",
            ],
        }
    ]
    if protocol == "modbus_tcp":
        edges.append(
            {
                "edge_id": f"{attack_id}:modbus_write",
                "source": attack_id,
                "target": "expected_detection:modbus_write",
                "edge_type": "attack_should_emit_detection",
                "semantic_rule": "A Modbus register or coil write should map to a write-focused detection rule when the detection profile is active on the path.",
                "temporal_rule": "The detection alert should occur between attack start and rollback completion or shortly after the write.",
                "required_evidence": [
                    attack.get("evidence_references", [None])[0],
                    "foc-reconstruction/attestations/detection_attestation.json",
                    "foc-reconstruction/attestations/alerts_normalized.json",
                ],
            }
        )
        edges.append(
            {
                "edge_id": f"{attack_id}:state_change",
                "source": attack_id,
                "target": "expected_effect:plc_state_change",
                "edge_type": "attack_should_change_process_state",
                "semantic_rule": "The manipulated Modbus value should be observable in OT state before rollback.",
                "temporal_rule": "State-after evidence must be captured after the write and before or at rollback.",
                "required_evidence": [
                    attack.get("evidence_references", [None, None, None, None])[2],
                    attack.get("evidence_references", [None, None, None, None])[3],
                ],
            }
        )
    if operation.get("rollback_required"):
        edges.append(
            {
                "edge_id": f"{attack_id}:rollback",
                "source": attack_id,
                "target": "expected_effect:state_restoration",
                "edge_type": "attack_should_restore_state",
                "semantic_rule": "Rollback-required attacks should preserve a restoration trace and final state evidence.",
                "temporal_rule": "Rollback evidence must occur after the manipulation and before scenario teardown.",
                "required_evidence": [
                    attack.get("operation", {}).get("rollback_command"),
                    attack.get("evidence_references", [None, None, None, None, None])[4],
                ],
            }
        )
    return edges


def build_attestations(
    scenario_bom: dict,
    tools_bom: dict,
    timeline: dict,
    sources_bundle: dict,
    indexes: dict,
    id_mapping: dict | None = None,
) -> dict:
    generated_at = utc_now()
    scenario_id = scenario_bom.get("scenario_id", "unknown")
    scenario_name = scenario_bom.get("scenario_name", "unknown")
    node_binding_by_node, node_binding_by_instance = _binding_maps(scenario_bom)
    relationships = ((indexes.get("relationships_index") or {}).get("edges") or [])
    cases_index = ((indexes.get("cases_index") or {}).get("cases") or [])
    artifacts = ((indexes.get("artifacts_index") or {}).get("artifacts") or [])

    timeline_events = timeline.get("events") or []
    attack_events = [ev for ev in timeline_events if ev.get("event_type") == "attack_execution"]
    detection_events = [ev for ev in timeline_events if ev.get("event_type") == "detection_alert"]
    triage_events = {
        ev.get("related_alert_id"): ev
        for ev in timeline_events
        if ev.get("event_type") == "triage_result" and ev.get("related_alert_id")
    }
    intervention_events = [
        ev
        for ev in timeline_events
        if ev.get("event_type") in {
            "case_created",
            "case_opened",
            "case_attached",
            "dfir_orchestration_start",
            "dfir_orchestration_done",
            "acquire_preserved",
            "pcap_preserved",
            "memory_preserved",
            "disk_preserved",
            "ot_export_preserved",
        }
    ]
    analysis_events = [
        ev
        for ev in timeline_events
        if ev.get("event_type") in {"memory_analysis_done", "disk_analysis_done"}
    ]

    alerts_by_id = {ev.get("related_alert_id"): ev for ev in detection_events if ev.get("related_alert_id")}
    case_by_id = {case.get("case_id"): case for case in cases_index if case.get("case_id")}
    artifact_by_id = {artifact.get("artifact_id"): artifact for artifact in artifacts if artifact.get("artifact_id")}

    attack_attestations = []
    for attack in attack_events:
        details = attack.get("details") or {}
        source_path = details.get("source_path") or attack.get("source_path")
        result_payload = _load_json_if_exists(source_path)
        modbus_log = _load_attack_sidecar(source_path, "modbus_transaction_log.json")
        command_payload = (modbus_log.get("write_command") or {}) if isinstance(modbus_log, dict) else {}
        parsed_command = _parse_mbpoll_command(command_payload.get("command"))
        binding = node_binding_by_node.get(attack.get("related_node_id"), {})
        expected_alerts = details.get("expected_alerts") or result_payload.get("expected_alerts") or []
        attack_attestations.append(
            {
                "attack_event_id": attack.get("timeline_event_id"),
                "attack_id": attack.get("related_attack_id"),
                "scenario_id": scenario_id,
                "scenario_name": scenario_name,
                "display_name": details.get("display_name") or result_payload.get("display_name") or attack.get("description"),
                "mitre": {
                    "domain": details.get("mitre_domain") or result_payload.get("mitre_domain"),
                    "technique_id": details.get("mitre_id") or result_payload.get("mitre_id"),
                    "technique_name": details.get("mitre_technique") or result_payload.get("mitre_technique"),
                    "tactic": details.get("tactic") or result_payload.get("tactic"),
                },
                "execution": {
                    "started_at": details.get("started_at") or result_payload.get("started_at") or attack.get("timestamp"),
                    "completed_at": details.get("completed_at") or result_payload.get("completed_at"),
                    "success": details.get("success", result_payload.get("success")),
                    "exit_code": details.get("exit_code", result_payload.get("exit_code")),
                    "execution_mode": details.get("execution_mode") or result_payload.get("execution_mode"),
                    "detection_engine": details.get("detection_engine") or result_payload.get("detection_engine"),
                    "success_criteria": details.get("success_criteria")
                    or result_payload.get("success_criteria")
                    or ("state_changed_and_observed" if parsed_command.get("protocol") == "modbus_tcp" else "exit_code_zero"),
                },
                "attacker": {
                    "ip": details.get("attacker_ip") or result_payload.get("attacker_ip"),
                    "user": details.get("target_user") or result_payload.get("target_user"),
                },
                "target": {
                    "node_id": attack.get("related_node_id"),
                    "instance_id": attack.get("related_instance_id"),
                    "instance_name": binding.get("instance_name"),
                    "node_name": binding.get("node_name"),
                    "target_role": details.get("target_role") or result_payload.get("target_role"),
                    "target_ip": details.get("target_ip") or result_payload.get("target_ip") or parsed_command.get("target_ip"),
                    "target_image": details.get("target_image") or result_payload.get("target_image"),
                },
                "operation": {
                    "tool_used": details.get("tool_used") or result_payload.get("tool_used") or "attack_executor",
                    "tool_version": details.get("tool_version") or result_payload.get("tool_version"),
                    "protocol": parsed_command.get("protocol") or details.get("protocol") or result_payload.get("protocol"),
                    "target_port": parsed_command.get("target_port") or details.get("target_port") or result_payload.get("target_port"),
                    "modbus_function": parsed_command.get("modbus_function"),
                    "register_reference": parsed_command.get("register_reference"),
                    "value": parsed_command.get("value"),
                    "slave_id": parsed_command.get("slave_id"),
                    "data_type": parsed_command.get("data_type"),
                    "parameters": details.get("parameters") or result_payload.get("parameters") or {},
                    "expected_alerts": expected_alerts,
                    "rollback_required": details.get("rollback_required", result_payload.get("rollback_required")),
                    "rollback_command": (modbus_log.get("rollback_command") or {}).get("command"),
                },
                "evidence_references": [
                    source_path,
                    _safe_rel_path(Path(source_path).parent.joinpath("modbus_transaction_log.json").as_posix()) if source_path else None,
                    _safe_rel_path(Path(source_path).parent.joinpath("plc_state_before.json").as_posix()) if source_path else None,
                    _safe_rel_path(Path(source_path).parent.joinpath("plc_state_after.json").as_posix()) if source_path else None,
                    _safe_rel_path(Path(source_path).parent.joinpath("rollback_log.json").as_posix()) if source_path else None,
                ],
            }
        )

    alerts_normalized = []
    for alert in detection_events:
        details = alert.get("details") or {}
        triage = triage_events.get(alert.get("related_alert_id"), {})
        signature = details.get("signature")
        normalized = {
            "alert_id": alert.get("related_alert_id"),
            "timeline_event_id": alert.get("timeline_event_id"),
            "scenario_id": scenario_id,
            "timestamp": alert.get("timestamp"),
            "source_type": alert.get("source_type"),
            "source_path": alert.get("source_path"),
            "node_id": alert.get("related_node_id"),
            "instance_id": alert.get("related_instance_id"),
            "detector": _infer_detector(signature, alert.get("source_type")),
            "signature": signature,
            "normalized_message": _normalized_alert_message(signature, details.get("rule_id")),
            "rule_id": details.get("rule_id"),
            "rule_level": details.get("rule_level"),
            "severity": _normalize_severity(details.get("rule_level"), details.get("triage_severity") or (triage.get("details") or {}).get("severity")),
            "protocol": details.get("protocol"),
            "agent": details.get("agent"),
            "src": details.get("src"),
            "dst": details.get("dst"),
            "origin": {
                "ip": (details.get("src") or {}).get("ip"),
                "port": (details.get("src") or {}).get("port"),
            },
            "destination": {
                "ip": (details.get("dst") or {}).get("ip"),
                "port": (details.get("dst") or {}).get("port"),
            },
            "triage_severity": details.get("triage_severity") or (triage.get("details") or {}).get("severity"),
            "recommend_forensics": details.get("recommend_forensics"),
            "correlated_attack_id": alert.get("related_attack_id"),
            "correlation_status": details.get("correlation_status"),
            "correlation_confidence": details.get("correlation_confidence"),
            "correlation_reason": details.get("correlation_reason"),
        }
        alerts_normalized.append(normalized)

    observed_rule_map = {}
    for item in alerts_normalized:
        signature = item.get("signature")
        detector = item.get("detector")
        rule_id = item.get("rule_id")
        node_id = item.get("node_id")
        key = (str(rule_id), str(signature), str(node_id), str(detector))
        if key in observed_rule_map:
            continue
        binding = node_binding_by_node.get(node_id) or node_binding_by_instance.get(item.get("instance_id")) or {}
        observed_rule_map[key] = {
            "detector_engine": detector,
            "engine_version": None,
            "rule_active": True,
            "rule_id": rule_id,
            "severity": item.get("severity"),
            "signature": signature,
            "rule_file": _infer_rule_file(signature, rule_id),
            "rule_hash": None,
            "rule_hash_status": "unavailable",
            "mitre_techniques": _infer_mitre_techniques(signature),
            "node_id": node_id,
            "node_name": binding.get("node_name"),
            "instance_id": item.get("instance_id"),
            "instance_name": binding.get("instance_name"),
            "protocol": item.get("protocol"),
        }

    detection_attestation = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "active_detection_stack": [
            {
                "node_id": node.get("node_id"),
                "node_name": node.get("node_name"),
                "instance_id": node.get("instance_id"),
                "instance_name": node.get("instance_name"),
                "installed_tools": node.get("installed_tools") or [],
                "detection_profiles": [
                    tool
                    for tool in (node.get("installed_tools") or [])
                    if any(token in str(tool).lower() for token in ("suricata", "wazuh", "fim", "rollback_"))
                ],
                "active_detection_nodes": bool(
                    any(token in str(tool).lower() for tool in (node.get("installed_tools") or []) for token in ("suricata", "wazuh"))
                ),
            }
            for node in (tools_bom.get("nodes") or [])
        ],
        "observed_detection_rules": sorted(
            observed_rule_map.values(),
            key=lambda item: (
                str(item.get("rule_id")),
                str(item.get("signature")),
                str(item.get("node_id")),
            ),
        ),
        "summary": {
            "alerts_total": len(alerts_normalized),
            "suricata_visible_alerts": sum(1 for item in alerts_normalized if item.get("detector") == "Suricata"),
            "wazuh_visible_alerts": sum(1 for item in alerts_normalized if item.get("detector") == "Wazuh"),
            "observed_rule_count": len(observed_rule_map),
            "engines": _summarize_top_counter(Counter(item.get("detector_engine") for item in observed_rule_map.values())),
        },
    }

    full_correlations = []
    attack_correlations = defaultdict(list)
    for edge in relationships:
        if edge.get("relation") != "produced_alert":
            continue
        details = edge.get("details") or {}
        correlation_item = {
            "attack_id": edge.get("from_id"),
            "alert_id": edge.get("to_id"),
            "relation": edge.get("relation"),
            "relationship_status": edge.get("relationship_status"),
            "correlation_status": edge.get("correlation_status"),
            "correlation_confidence": edge.get("correlation_confidence"),
            "correlation_reason": edge.get("correlation_reason"),
            "signature": details.get("signature"),
            "rule_id": details.get("rule_id"),
            "detector": _infer_detector(details.get("signature")),
            "node_id": details.get("node_id"),
            "instance_id": details.get("instance_id"),
            "detection_rule_relation": {
                "rule_id": details.get("rule_id"),
                "signature": details.get("signature"),
            },
            "evidence": edge.get("evidence") or [],
        }
        correlation_item["correlation_bucket"] = _bucket_from_correlation_status(correlation_item)
        full_correlations.append(correlation_item)
        attack_correlations[correlation_item.get("attack_id")].append(correlation_item)

    missing_expected_alerts = []
    for attack in attack_attestations:
        attack_id = attack.get("attack_id")
        expected = attack.get("operation", {}).get("expected_alerts") or []
        corr_items = attack_correlations.get(attack_id, [])
        has_confirmed = any(item.get("correlation_bucket") == "correlated" for item in corr_items)
        if expected and not has_confirmed:
            missing_expected_alerts.append(
                {
                    "attack_id": attack_id,
                    "display_name": attack.get("display_name"),
                    "expected_alerts": expected,
                    "status": "missing_expected_alert",
                    "target_node_id": attack.get("target", {}).get("node_id"),
                    "target_instance_id": attack.get("target", {}).get("instance_id"),
                }
            )

    correlation_bucket_counter = Counter(item.get("correlation_bucket") for item in full_correlations)
    uncorrelated_alert_samples = []
    for alert in alerts_normalized:
        if _is_present(alert.get("correlated_attack_id")) and str(alert.get("correlation_status") or "").lower() == "confirmed":
            continue
        bucket = "false_positive_candidate" if alert.get("recommend_forensics") else "noise"
        uncorrelated_alert_samples.append(
            {
                "alert_id": alert.get("alert_id"),
                "signature": alert.get("signature"),
                "rule_id": alert.get("rule_id"),
                "severity": alert.get("severity"),
                "node_id": alert.get("node_id"),
                "instance_id": alert.get("instance_id"),
                "status": bucket,
            }
        )
        if len(uncorrelated_alert_samples) >= _ALERT_SAMPLE_LIMIT:
            break

    alert_correlation_summary = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "total_correlation_records": len(full_correlations),
        "bucket_counts": {
            "correlated": correlation_bucket_counter.get("correlated", 0),
            "uncorrelated": correlation_bucket_counter.get("uncorrelated", 0),
            "noise": correlation_bucket_counter.get("noise", 0),
            "false_positive_candidate": correlation_bucket_counter.get("false_positive_candidate", 0),
            "missing_expected_alert": max(
                correlation_bucket_counter.get("missing_expected_alert", 0),
                len(missing_expected_alerts),
            ),
        },
        "top_signatures": _summarize_top_counter(Counter(item.get("signature") for item in full_correlations if _is_present(item.get("signature")))),
        "top_rule_ids": _summarize_top_counter(Counter(str(item.get("rule_id")) for item in full_correlations if _is_present(item.get("rule_id")))),
        "top_nodes": _summarize_top_counter(Counter(item.get("node_id") for item in full_correlations if _is_present(item.get("node_id")))),
        "missing_expected_alerts": missing_expected_alerts[:_ALERT_SAMPLE_LIMIT],
        "uncorrelated_alert_samples": uncorrelated_alert_samples,
    }

    alert_correlation = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "correlations": full_correlations,
        "summary": alert_correlation_summary,
    }

    case_profiles = []
    for case in cases_index:
        case_id = case.get("case_id")
        case_path = case.get("path")
        case_events = [event for event in intervention_events if event.get("related_case_id") == case_id]
        case_artifacts = [artifact for artifact in artifacts if artifact.get("case_id") == case_id]
        case_created = next((event for event in case_events if event.get("event_type") == "case_created"), None)
        dfir_start = next((event for event in case_events if event.get("event_type") == "dfir_orchestration_start"), None)
        trigger_alert = _find_trigger_alert(case_created or {}, alerts_normalized, node_binding_by_node, node_binding_by_instance) if case_created else None
        artifact_types = sorted({artifact.get("artifact_type") for artifact in case_artifacts if _is_present(artifact.get("artifact_type"))})
        expected_artifacts = sorted(
            {
                "network_pcap" if any("pcap" in str(artifact.get("artifact_type") or "").lower() for artifact in case_artifacts) else None,
                "industrial_export" if any("industrial" in str(artifact.get("artifact_type") or "").lower() or "ot_export" in str(artifact.get("path") or "").lower() for artifact in case_artifacts) else None,
                "custody_log" if any("custody" in str(artifact.get("artifact_type") or "").lower() for artifact in case_artifacts) else None,
            }
            - {None}
        )
        target_nodes = sorted(
            {
                artifact.get("related_node_id")
                for artifact in case_artifacts
                if _is_present(artifact.get("related_node_id"))
            }
        )
        acquired_ts = [
            event.get("timestamp")
            for event in case_events
            if event.get("event_type") in {"acquire_preserved", "pcap_preserved", "memory_preserved", "disk_preserved", "ot_export_preserved"}
        ]
        sealed_ts = max(acquired_ts) if acquired_ts else None
        case_profiles.append(
            {
                "case_id": case_id,
                "case_path": case_path,
                "trigger_alert_id": trigger_alert.get("alert_id") if trigger_alert else None,
                "trigger_signature": trigger_alert.get("signature") if trigger_alert else None,
                "trigger_detector": trigger_alert.get("detector") if trigger_alert else None,
                "profile_used": "dfir_orchestration" if dfir_start else "preservation_only",
                "target_nodes": target_nodes,
                "expected_artifacts": expected_artifacts,
                "acquired_artifacts": artifact_types,
                "artifact_count": len(case_artifacts),
                "latency_alert_to_start_seconds": _seconds_between(trigger_alert.get("timestamp") if trigger_alert else None, dfir_start.get("timestamp") if dfir_start else None),
                "latency_start_to_sealed_seconds": _seconds_between(dfir_start.get("timestamp") if dfir_start else None, sealed_ts),
                "result": "completed" if case_artifacts else "not_started",
            }
        )

    acquisition_profile = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "case_count": len(cases_index),
        "cases": case_profiles,
        "primary_evidence": [
            {
                "artifact_id": artifact.get("artifact_id"),
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "case_id": artifact.get("case_id"),
                "related_node_id": artifact.get("related_node_id"),
                "related_instance_id": artifact.get("related_instance_id"),
                "sha256": artifact.get("sha256"),
                "is_primary_evidence": artifact.get("is_primary_evidence"),
            }
            for artifact in artifacts
            if artifact.get("is_primary_evidence")
        ],
        "preserved_evidence_summary": {
            "network": sum(1 for artifact in artifacts if "pcap" in str(artifact.get("artifact_type") or "").lower()),
            "disk": sum(1 for artifact in artifacts if "disk" in str(artifact.get("artifact_type") or "").lower()),
            "memory": sum(1 for artifact in artifacts if "memory" in str(artifact.get("artifact_type") or "").lower()),
            "logs": sum(1 for artifact in artifacts if "log" in str(artifact.get("artifact_type") or "").lower()),
            "ot_state": sum(1 for artifact in artifacts if "industrial" in str(artifact.get("artifact_type") or "").lower() or "ot_" in str(artifact.get("path") or "").lower()),
        },
    }

    intervention_by_case = defaultdict(list)
    for event in intervention_events:
        intervention_by_case[event.get("related_case_id")].append(event)

    forensic_intervention = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "interventions": [
            {
                "case_id": case_id,
                "trigger": next((case_profile.get("trigger_signature") for case_profile in case_profiles if case_profile.get("case_id") == case_id), None),
                "target_nodes": sorted(
                    {
                        artifact.get("related_node_id")
                        for artifact in artifacts
                        if artifact.get("case_id") == case_id and _is_present(artifact.get("related_node_id"))
                    }
                ),
                "tools_used": sorted(
                    {
                        "traffic_api" if "acquire_preserved" in str(event.get("event_type")) else
                        "industrial_exporter" if "ot_export_preserved" in str(event.get("event_type")) else
                        "dfir_orchestrator" if "dfir_orchestration" in str(event.get("event_type")) else
                        "forensics_api" if "case_" in str(event.get("event_type")) else
                        "unknown"
                        for event in events
                    }
                ),
                "commands_executed": [
                    (((event.get("details") or {}).get("command")) or ((event.get("details") or {}).get("details") or {}).get("command"))
                    for event in events
                    if _is_present((((event.get("details") or {}).get("command")) or ((event.get("details") or {}).get("details") or {}).get("command")))
                ],
                "collected_artifacts": [
                    artifact.get("artifact_id")
                    for artifact in artifacts
                    if artifact.get("case_id") == case_id
                ],
                "chain_of_custody_events": [
                    event.get("timeline_event_id")
                    for event in timeline_events
                    if event.get("related_case_id") == case_id and event.get("source_type") == "chain_of_custody"
                ],
            }
            for case_id, events in intervention_by_case.items()
            if _is_present(case_id)
        ],
        "raw_events": [
            {
                "timeline_event_id": event.get("timeline_event_id"),
                "event_type": event.get("event_type"),
                "timestamp": event.get("timestamp"),
                "status": event.get("status"),
                "related_case_id": event.get("related_case_id"),
                "related_node_id": event.get("related_node_id"),
                "related_instance_id": event.get("related_instance_id"),
                "description": event.get("description"),
                "details": event.get("details"),
            }
            for event in intervention_events
        ],
    }

    forensic_analysis_manifest = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "analysis_performed": bool(analysis_events),
        "analysis_events": [
            {
                "timeline_event_id": event.get("timeline_event_id"),
                "event_type": event.get("event_type"),
                "timestamp": event.get("timestamp"),
                "related_case_id": event.get("related_case_id"),
                "related_artifact_id": event.get("related_artifact_id"),
                "description": event.get("description"),
                "details": event.get("details"),
            }
            for event in analysis_events
        ],
        "analysis_artifacts": [
            {
                "artifact_id": artifact.get("artifact_id"),
                "artifact_type": artifact.get("artifact_type"),
                "path": artifact.get("path"),
                "case_id": artifact.get("case_id"),
                "sha256": artifact.get("sha256"),
            }
            for artifact in artifacts
            if artifact.get("artifact_class") == "analysis_outputs"
        ],
        "analysis_status_note": "No forensic analysis events were observed; preserved evidence and reconstruction outputs must not be treated as primary forensic analysis."
        if not analysis_events
        else "Analysis events were observed and linked below.",
    }

    expected_causal_edges = []
    for attack in attack_attestations:
        expected_causal_edges.extend(_attack_expected_edges(attack))

    scenario_ground_truth = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "scenario": {
            "nodes": scenario_bom.get("nodes") or [],
            "edges": scenario_bom.get("edges") or [],
            "node_instance_bindings": scenario_bom.get("node_instance_bindings") or [],
            "industrial_linkages": scenario_bom.get("industrial_linkages") or [],
            "scenario_state": scenario_bom.get("scenario_state") or {},
        },
        "executed_attacks": [
            {
                "attack_id": item.get("attack_id"),
                "display_name": item.get("display_name"),
                "target_node_id": item.get("target", {}).get("node_id"),
                "target_instance_id": item.get("target", {}).get("instance_id"),
                "target_ip": item.get("target", {}).get("target_ip"),
                "protocol": item.get("operation", {}).get("protocol"),
                "target_port": item.get("operation", {}).get("target_port"),
                "modbus_function": item.get("operation", {}).get("modbus_function"),
                "register_reference": item.get("operation", {}).get("register_reference"),
                "value": item.get("operation", {}).get("value"),
                "expected_alerts": item.get("operation", {}).get("expected_alerts") or [],
            }
            for item in attack_attestations
        ],
        "expected_causal_edges": expected_causal_edges,
        "required_evidence_by_edge": [
            {
                "edge_id": edge.get("edge_id"),
                "required_evidence": [e for e in (edge.get("required_evidence") or []) if _is_present(e)],
            }
            for edge in expected_causal_edges
        ],
        "semantic_rules": [
            "Ground truth is derived from scenario deployment state, attack execution parameters, and preservation context, not solely from observed alerts.",
            "Primary evidence remains external to FOC; this file only declares expected causal relationships and required corroboration.",
        ],
        "temporal_rules": [
            "Attack start must precede any detection or preservation event attributed to that attack.",
            "Preservation sealing must occur after acquisition start.",
            "Rollback-required OT attacks should preserve evidence of both manipulation and restoration.",
        ],
    }

    case_manifest_link = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "links": [],
    }
    for edge in relationships:
        if edge.get("relation") != "contains_artifact":
            continue
        artifact = artifact_by_id.get(edge.get("to_id")) or {}
        case = case_by_id.get(edge.get("from_id")) or {}
        manifest_path = case.get("manifest_path")
        manifest_payload = _load_json_if_exists(manifest_path)
        manifest_artifacts = manifest_payload.get("artifacts") or []
        rel_path = None
        artifact_path = artifact.get("path")
        if artifact_path and case.get("path"):
            try:
                rel_path = str(Path(artifact_path).relative_to(Path(case.get("path")))).replace("\\", "/")
            except Exception:
                rel_path = None
        case_manifest_link["links"].append(
            {
                "case_id": edge.get("from_id"),
                "artifact_id": edge.get("to_id"),
                "artifact_path": artifact_path,
                "case_path": case.get("path"),
                "manifest_path": manifest_path,
                "relation": edge.get("relation"),
                "relationship_status": edge.get("relationship_status"),
                "artifact_exists": _path_exists(artifact_path),
                "manifest_exists": _path_exists(manifest_path),
                "artifact_in_manifest": any(item.get("rel_path") == rel_path for item in manifest_artifacts if isinstance(item, dict)),
            }
        )

    attack_validation = _validate_records(
        attack_attestations,
        [
            {"name": "attack_executed", "path": "attack_id"},
            {"name": "tool", "path": "operation.tool_used"},
            {"name": "version", "path": "operation.tool_version"},
            {"name": "mitre_technique", "path": "mitre.technique_id"},
            {"name": "target_node", "path": "target.node_id"},
            {"name": "target_ip", "path": "target.target_ip"},
            {"name": "protocol", "path": "operation.protocol"},
            {"name": "port", "path": "operation.target_port"},
            {"name": "modbus_function", "path": "operation.modbus_function", "applies": lambda item: str(_get_value(item, 'operation.protocol') or '').startswith('modbus')},
            {"name": "register", "path": "operation.register_reference", "applies": lambda item: str(_get_value(item, 'operation.protocol') or '').startswith('modbus')},
            {"name": "expected_value", "path": "operation.value", "applies": lambda item: str(_get_value(item, 'operation.protocol') or '').startswith('modbus')},
            {"name": "started_at", "path": "execution.started_at"},
            {"name": "completed_at", "path": "execution.completed_at"},
            {"name": "success_criteria", "path": "execution.success_criteria"},
        ],
    )

    detection_validation = _validate_records(
        detection_attestation.get("observed_detection_rules") or [],
        [
            {"name": "detection_engine", "path": "detector_engine"},
            {"name": "engine_version", "path": "engine_version"},
            {"name": "rule_active", "path": "rule_active"},
            {"name": "rule_id", "path": "rule_id"},
            {"name": "severity", "path": "severity"},
            {"name": "rule_file", "path": "rule_file"},
            {"name": "rule_hash", "path": "rule_hash"},
            {"name": "mitre_technique", "path": "mitre_techniques"},
            {"name": "active_node", "path": "node_id"},
        ],
    )

    alerts_validation = _validate_records(
        alerts_normalized,
        [
            {"name": "timestamp", "path": "timestamp"},
            {"name": "detector", "path": "detector"},
            {"name": "rule_id", "path": "rule_id"},
            {"name": "severity", "path": "severity"},
            {"name": "origin", "path": "origin.ip"},
            {"name": "destination", "path": "destination.ip"},
            {"name": "protocol", "path": "protocol"},
            {"name": "normalized_message", "path": "normalized_message"},
        ],
    )

    correlation_records = full_correlations + missing_expected_alerts
    correlation_validation = _validate_records(
        correlation_records,
        [
            {"name": "attack_relation", "path": "attack_id"},
            {"name": "alert_relation", "path": "alert_id", "applies": lambda item: item.get("status") != "missing_expected_alert"},
            {"name": "detection_rule_relation", "path": "detection_rule_relation.rule_id", "applies": lambda item: item.get("status") != "missing_expected_alert"},
            {"name": "correlation_state", "path": "correlation_bucket", "applies": lambda item: item.get("status") != "missing_expected_alert"},
        ],
    )

    acquisition_validation = _validate_records(
        case_profiles,
        [
            {"name": "trigger_alert", "path": "trigger_alert_id"},
            {"name": "profile_used", "path": "profile_used"},
            {"name": "target_nodes", "path": "target_nodes"},
            {"name": "expected_artifacts", "path": "expected_artifacts"},
            {"name": "acquired_artifacts", "path": "acquired_artifacts"},
            {"name": "latency_alert_to_start", "path": "latency_alert_to_start_seconds"},
            {"name": "latency_start_to_sealed", "path": "latency_start_to_sealed_seconds"},
            {"name": "acquisition_result", "path": "result"},
        ],
    )

    intervention_validation = _validate_records(
        forensic_intervention.get("interventions") or [],
        [
            {"name": "associated_case", "path": "case_id"},
            {"name": "trigger", "path": "trigger"},
            {"name": "target_nodes", "path": "target_nodes"},
            {"name": "tools_used", "path": "tools_used"},
            {"name": "commands_executed", "path": "commands_executed"},
            {"name": "artifacts_collected", "path": "collected_artifacts"},
            {"name": "chain_of_custody_events", "path": "chain_of_custody_events"},
        ],
    )

    analysis_validation = _validate_records(
        [forensic_analysis_manifest],
        [
            {"name": "analysis_performed_flag", "path": "analysis_performed"},
            {"name": "analysis_status_note", "path": "analysis_status_note"},
        ],
    )

    ground_truth_validation = _validate_records(
        [scenario_ground_truth],
        [
            {"name": "expected_causal_edges", "path": "expected_causal_edges"},
            {"name": "required_evidence_by_edge", "path": "required_evidence_by_edge"},
            {"name": "semantic_rules", "path": "semantic_rules"},
            {"name": "temporal_rules", "path": "temporal_rules"},
        ],
    )

    case_link_validation = _validate_records(
        case_manifest_link.get("links") or [],
        [
            {"name": "case_id", "path": "case_id"},
            {"name": "manifest_path", "path": "manifest_path"},
            {"name": "artifact_exists", "path": "artifact_exists", "validator": lambda value, _: value is True},
            {"name": "artifact_in_manifest", "path": "artifact_in_manifest", "validator": lambda value, _: value is True},
        ],
    )

    critical_sections = {
        "attack_attestation": attack_validation,
        "detection_attestation": detection_validation,
        "alerts_normalized": alerts_validation,
        "alert_correlation": correlation_validation,
        "acquisition_profile": acquisition_validation,
        "forensic_intervention": intervention_validation,
        "forensic_analysis_manifest": analysis_validation,
        "scenario_ground_truth": ground_truth_validation,
        "case_manifest_link": case_link_validation,
    }
    not_ready_reasons = [
        name
        for name, section in critical_sections.items()
        if section.get("overall_status") != "ok"
    ]
    foc_readiness_report = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "causal_reconstruction_ready": len(not_ready_reasons) == 0,
        "readiness_state": "ready" if len(not_ready_reasons) == 0 else "partial",
        "missing_prerequisites": not_ready_reasons,
        "sections": critical_sections,
        "notes": [
            "Primary evidence remains outside this report; readiness only evaluates derived FOC semantic completeness.",
            "A section is marked non-ready whenever required traceability fields are missing, partial, or not yet observed.",
        ],
    }

    foc_context_summary = {
        "generated_at": generated_at,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "answers": {
            "scenario_deployed": {"value": scenario_name, "source": "scenario_bom.json"},
            "nodes_it_ot": {"value": len(scenario_bom.get("nodes") or []), "source": "scenario_bom.json"},
            "node_instance_bindings": {"value": len(scenario_bom.get("node_instance_bindings") or []), "source": "scenario_bom.json"},
            "installed_tools": {"value": sum(len(node.get("installed_tools") or []) for node in (tools_bom.get("nodes") or [])), "source": "tools_bom.json"},
            "attacks_executed": {"value": len(attack_attestations), "source": "attack_attestation.json"},
            "detection_rules_active": {"value": len(detection_attestation.get("observed_detection_rules") or []), "source": "detection_attestation.json"},
            "alerts_generated": {"value": len(alerts_normalized), "source": "alerts_normalized.json"},
            "attack_alert_correlations": {"value": len(full_correlations), "source": "alert_correlation_summary.json"},
            "forensic_interventions": {"value": len(forensic_intervention.get("interventions") or []), "source": "forensic_intervention.json"},
            "forensic_cases": {"value": len(cases_index), "source": "case_manifest_link.json"},
            "primary_evidence_items": {"value": len(acquisition_profile.get("primary_evidence") or []), "source": "acquisition_profile.json"},
            "analysis_outputs": {"value": len(forensic_analysis_manifest.get("analysis_artifacts") or []), "source": "forensic_analysis_manifest.json"},
            "causal_reconstruction_ready": {"value": foc_readiness_report.get("causal_reconstruction_ready"), "source": "foc_readiness_report.json"},
            "missing_prerequisites": {"value": foc_readiness_report.get("missing_prerequisites") or [], "source": "foc_readiness_report.json"},
        },
        "artifact_references": {
            "attack_attestation": "foc-reconstruction/attestations/attack_attestation.json",
            "detection_attestation": "foc-reconstruction/attestations/detection_attestation.json",
            "alerts_normalized": "foc-reconstruction/attestations/alerts_normalized.json",
            "alert_correlation": "foc-reconstruction/attestations/alert_correlation.json",
            "alert_correlation_summary": "foc-reconstruction/attestations/alert_correlation_summary.json",
            "acquisition_profile": "foc-reconstruction/attestations/acquisition_profile.json",
            "forensic_intervention": "foc-reconstruction/attestations/forensic_intervention.json",
            "forensic_analysis_manifest": "foc-reconstruction/attestations/forensic_analysis_manifest.json",
            "scenario_ground_truth": "foc-reconstruction/attestations/scenario_ground_truth.json",
            "case_manifest_link": "foc-reconstruction/attestations/case_manifest_link.json",
            "foc_readiness_report": "foc-reconstruction/validation/foc_readiness_report.json",
        },
        "readiness": {
            "state": foc_readiness_report.get("readiness_state"),
            "causal_reconstruction_ready": foc_readiness_report.get("causal_reconstruction_ready"),
            "missing_prerequisites": foc_readiness_report.get("missing_prerequisites") or [],
        },
    }

    return {
        "attack_attestation": {
            "generated_at": generated_at,
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "attacks": attack_attestations,
        },
        "detection_attestation": detection_attestation,
        "alerts_normalized": {
            "generated_at": generated_at,
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "alerts": alerts_normalized,
        },
        "alert_correlation": alert_correlation,
        "alert_correlation_summary": alert_correlation_summary,
        "acquisition_profile": acquisition_profile,
        "forensic_intervention": forensic_intervention,
        "forensic_analysis_manifest": forensic_analysis_manifest,
        "scenario_ground_truth": scenario_ground_truth,
        "case_manifest_link": case_manifest_link,
        "foc_context_summary": foc_context_summary,
        "foc_readiness_report": foc_readiness_report,
    }
