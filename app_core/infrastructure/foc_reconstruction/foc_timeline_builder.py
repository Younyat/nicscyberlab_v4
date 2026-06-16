import itertools
import re
from datetime import datetime, timezone
from pathlib import Path

from .foc_bootstrap import make_id, read_id_mapping
from .foc_paths import project_path, relative_path
from .foc_schema import clone, empty_timeline_event
from .foc_sources import read_json_file, read_jsonl_file, utc_now


def _add_event(events: list[dict], counter: itertools.count, **kwargs) -> None:
    event = clone(empty_timeline_event())
    event.update(kwargs)
    event["timeline_event_id"] = event.get("timeline_event_id") or make_id(
        "evt",
        str(event.get("timestamp") or ""),
        str(event.get("event_type") or ""),
        str(event.get("source_path") or ""),
        str(next(counter)),
    )
    events.append(event)


def _file_mtime_iso(path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        return utc_now()


def _timeline_sort_key(value: str) -> tuple[int, str]:
    raw = str(value or "").strip()
    if not raw:
        return (1, "")
    normalized = raw.replace("Z", "+00:00")
    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = normalized[:-2] + ":" + normalized[-2:]
    for candidate in (normalized, raw):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (0, dt.astimezone(timezone.utc).isoformat())
        except Exception:
            continue
    return (1, raw)


def _epoch_from_any(value: str) -> float:
    sort_key = _timeline_sort_key(value)
    if sort_key[0] != 0:
        return 0.0
    try:
        return datetime.fromisoformat(sort_key[1]).timestamp()
    except Exception:
        return 0.0


def _normalize_indicator(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _load_runtime_map(scenario_context: dict, warnings: list[dict]) -> dict:
    runtime = {"by_name": {}, "by_ip": {}}
    binding_by_name = {
        str(binding.get("instance_name") or "").lower(): binding
        for binding in scenario_context.get("node_instance_bindings", [])
        if binding.get("status") == "bound"
    }
    for path in sorted(project_path("tools-installer-tmp").glob("*.json")):
        data = read_json_file(path, warnings)
        if not isinstance(data, dict):
            continue
        instance_name = str(data.get("name") or "").strip()
        if not instance_name:
            continue
        binding = binding_by_name.get(instance_name.lower())
        if not binding:
            continue
        payload = {
            "node_id": binding.get("node_id", "unresolved"),
            "instance_id": binding.get("instance_id", "unresolved"),
            "instance_name": binding.get("instance_name", instance_name),
            "node_name": binding.get("node_name", instance_name),
        }
        runtime["by_name"][instance_name.lower()] = payload
        for key in ("ip", "ip_private", "ip_floating"):
            ip = str(data.get(key) or "").strip()
            if ip:
                runtime["by_ip"][ip] = payload
    return runtime


def _resolve_runtime(runtime_map: dict, *, name: str = "", ip: str = "") -> dict:
    if name:
        hit = runtime_map.get("by_name", {}).get(str(name).lower())
        if hit:
            return hit
    if ip:
        hit = runtime_map.get("by_ip", {}).get(str(ip).strip())
        if hit:
            return hit
    return {}


def _resolve_binding_by_vm_id(scenario_context: dict, vm_id: str | None) -> dict:
    raw = str(vm_id or "").strip()
    if not raw:
        return {}
    short = f"inst-{raw[:8]}"
    for binding in scenario_context.get("node_instance_bindings", []) or []:
        if binding.get("openstack_instance_id") == raw:
            return binding
        if binding.get("instance_id") == short:
            return binding
    return {}


def _infer_sensor_identity(alert: dict) -> tuple[str, str]:
    collector = str(alert.get("source") or "unknown").strip().lower() or "unknown"
    raw = alert.get("raw") or {}
    rule_groups = [str(group).lower() for group in (((raw.get("rule") or {}).get("groups")) or [])]
    location = str(raw.get("location") or "").lower()
    if "suricata" in rule_groups or "eve.json" in location:
        return collector, "suricata"
    if collector == "wazuh":
        return collector, "wazuh"
    return collector, collector


def _infer_rule_identity(alert: dict) -> dict:
    raw = alert.get("raw") or {}
    raw_data = raw.get("data") or {}
    raw_alert = raw_data.get("alert") or {}
    metadata = raw_alert.get("metadata") or {}
    signature_id = raw_alert.get("signature_id")
    mitre_ics = [str(item) for item in (metadata.get("mitre_ics") or [])]
    attack_stage = [str(item) for item in (metadata.get("attack_stage") or [])]
    confidence = [str(item) for item in (metadata.get("confidence") or [])]
    modbus_function = [str(item) for item in (metadata.get("modbus_function") or [])]
    return {
        "suricata_signature_id": str(signature_id) if signature_id is not None else None,
        "mitre_ics": mitre_ics,
        "attack_stage": attack_stage,
        "confidence": confidence,
        "modbus_function": modbus_function,
    }


def _expected_effect_match(attack: dict, alert_signature: str, rule_meta: dict) -> bool:
    raw = str(alert_signature or "").lower()
    protocol = str(attack.get("protocol") or "").lower()
    if protocol == "modbus_tcp":
        if "modbus write" in raw:
            return True
        if "control_manipulation" in {v.lower() for v in (rule_meta.get("attack_stage") or [])}:
            return True
    return False


def _mitre_match(attack: dict, rule_meta: dict) -> bool:
    attack_mitre = str(attack.get("mitre_id") or "").lower()
    mapped = {str(item).lower() for item in (rule_meta.get("mitre_ics") or [])}
    if not mapped or not attack_mitre:
        return False
    if attack_mitre in mapped:
        return True
    if attack_mitre == "t0831" and {"t0836", "t1692.001"} & mapped:
        return True
    return False


def _is_noise_alert(alert: dict, normalized_signature: str, original_sensor: str) -> bool:
    protocol = str(alert.get("protocol") or "").lower()
    signature = str(alert.get("signature") or "").lower()
    alert_type = str(alert.get("alert_type") or "").lower()
    if "ping detectado" in signature:
        return True
    if protocol in {"icmp", "ipv6-icmp"}:
        return True
    if original_sensor == "suricata" and "visibility tcp 502" in signature:
        return True
    if normalized_signature in {"etc_suricata_suricata_yaml", "etc_shadow_backup"} and alert_type.startswith("[fim"):
        return True
    return False


def _protocols_compatible(attack_protocol: str | None, alert_protocol: str | None) -> bool:
    attack = str(attack_protocol or "").strip().lower()
    alert = str(alert_protocol or "").strip().lower()
    if not attack or not alert:
        return False
    if attack == alert:
        return True
    if attack == "modbus_tcp" and alert == "tcp":
        return True
    return False


def _correlation_payload(
    *,
    same_target: bool,
    same_ip: bool,
    signature_match: bool,
    protocol_match: bool,
    mitre_match: bool,
    effect_match: bool,
    temporal_distance_seconds: float | None,
    original_sensor: str,
    is_noise: bool,
) -> tuple[str, str, str]:
    if is_noise:
        return "noise", "low", "noise_signature"
    reasons = []
    if same_target:
        reasons.append("same_target_node")
    if same_ip:
        reasons.append("same_target_ip")
    if protocol_match:
        reasons.append("protocol_match")
    if signature_match:
        reasons.append("expected_alert_match")
    if mitre_match:
        reasons.append("mitre_match")
    if effect_match:
        reasons.append("evidence_expectation_match")
    temporal_ok = temporal_distance_seconds is not None and temporal_distance_seconds <= 1800
    if temporal_ok:
        reasons.append("temporal_window_match")
    if temporal_ok and (same_target or same_ip) and protocol_match and (signature_match or mitre_match or effect_match):
        return "confirmed", "high", ",".join(reasons)
    if temporal_ok and (same_target or same_ip) and (protocol_match or signature_match or mitre_match):
        return "inferred_medium", "medium", ",".join(reasons) or "compatible_target_and_time"
    if same_target or same_ip:
        return "weak_candidate", "low", ",".join(reasons) or "same_target_only"
    if signature_match or mitre_match:
        return "inferred_low", "low", ",".join(reasons) or "signature_only_match"
    if original_sensor == "suricata":
        return "uncorrelated", "low", "sensor_visible_but_not_compatible"
    return "unresolved", "low", "no_strong_match"


def _correlation_rank(status: str, confidence: str, reason: str, attack: dict, alert_epoch: float) -> tuple[int, int, float]:
    status_rank = {
        "confirmed": 7,
        "inferred_medium": 5,
        "inferred_low": 4,
        "weak_candidate": 3,
        "uncorrelated": 2,
        "noise": 1,
        "unresolved": 0,
    }.get(str(status or "").lower(), 0)
    confidence_rank = {
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(str(confidence or "").lower(), 0)
    # Prefer same-target/same-ip explanations over a generic signature-only match.
    reason_rank = 0
    lowered_reason = str(reason or "").lower()
    if "same_target_node" in lowered_reason:
        reason_rank += 1
    if "same_target_ip" in lowered_reason:
        reason_rank += 2
    if "protocol_match" in lowered_reason:
        reason_rank += 2
    if "expected_alert_match" in lowered_reason:
        reason_rank += 2
    if "mitre_match" in lowered_reason:
        reason_rank += 2
    if "evidence_expectation_match" in lowered_reason:
        reason_rank += 2
    if "temporal_window_match" in lowered_reason:
        reason_rank += 2

    attack_end = float(attack.get("end_epoch") or attack.get("start_epoch") or 0.0)
    proximity = -abs(alert_epoch - attack_end) if alert_epoch and attack_end else float("-inf")
    return (status_rank, confidence_rank + reason_rank, proximity)


def _expected_alert_match(attack: dict, alert: dict, normalized_signature: str) -> bool:
    expected = {_normalize_indicator(item) for item in (attack.get("expected_alerts") or [])}
    if normalized_signature in expected:
        return True

    raw_alert = (((alert.get("raw") or {}).get("data") or {}).get("alert") or {})
    metadata = raw_alert.get("metadata") or {}
    attack_stages = {_normalize_indicator(item) for item in (metadata.get("attack_stage") or [])}
    mitre_ics = {_normalize_indicator(item) for item in (metadata.get("mitre_ics") or [])}

    if "control_manipulation" in expected and "control_manipulation" in attack_stages:
        return True
    if "modbus_write_register" in expected and "modbus_write" in normalized_signature:
        return True
    if "unauthorized_control_command" in expected and "modbus_write" in normalized_signature:
        return True
    if "t0836" in mitre_ics and ("modbus_write_register" in expected or "control_manipulation" in expected):
        return True
    if "t1692_001" in mitre_ics and "unauthorized_control_command" in expected:
        return True
    return False


def _load_attack_sidecar(source_path: str | None, filename: str) -> dict:
    if not source_path:
        return {}
    sidecar_path = project_path(*Path(source_path).parent.joinpath(filename).parts)
    payload = read_json_file(sidecar_path, [])
    return payload if isinstance(payload, dict) else {}


def build_timeline(scenario_context: dict, id_mapping: dict | None = None) -> dict:
    warnings: list[dict] = []
    events: list[dict] = []
    counter = itertools.count(1)
    id_mapping = id_mapping or read_id_mapping() or {}

    deployment_path = project_path("scenario", "deployment_status.json")
    destroy_path = project_path("scenario", "destroy_status.json")
    industrial_state_path = project_path("industrial-scenario", "state", "industrial_state.json")

    binding_by_instance = {
        binding.get("instance_id"): binding
        for binding in scenario_context.get("node_instance_bindings", [])
        if binding.get("instance_id") and binding.get("instance_id") != "unresolved"
    }
    runtime_map = _load_runtime_map(scenario_context, warnings)
    attack_windows: list[dict] = []

    for path, event_type, source_type in (
        (deployment_path, "scenario_deployment_status", "deployment_status"),
        (destroy_path, "scenario_destroy_status", "destroy_status"),
        (industrial_state_path, "industrial_state", "industrial_state"),
    ):
        data = read_json_file(path, warnings)
        if isinstance(data, dict):
            _add_event(
                events,
                counter,
                timestamp=_file_mtime_iso(path),
                event_type=event_type,
                phase="lifecycle",
                status="observed",
                source_type=source_type,
                source_path=relative_path(path),
                id_origin="derived_from_path",
                related_node_id="not_available",
                related_instance_id="not_available",
                related_attack_id="not_available",
                related_alert_id="not_available",
                related_case_id="not_available",
                related_artifact_id="not_available",
                description=str(data.get("message") or data.get("status") or event_type),
                details=data,
            )

    for path in sorted(project_path("tools-installer", "installed").glob("*.json")):
        data = read_json_file(path, warnings)
        if not isinstance(data, dict):
            continue
        instance_id = data.get("instance_id") or "unresolved"
        instance_name = data.get("instance_name") or "unknown"
        normalized_instance_id = f"inst-{instance_id[:8]}" if instance_id and instance_id != "unresolved" else "unresolved"
        binding = binding_by_instance.get(normalized_instance_id, {})
        for tool_name, ts in (data.get("installed_tools") or {}).items():
            _add_event(
                events,
                counter,
                timestamp=str(ts),
                event_type="tool_installed",
                phase="instrumentation",
                status="installed",
                source_type="tools_installed",
                source_path=relative_path(path),
                id_origin="derived_from_existing_id",
                related_node_id=binding.get("node_id", "unresolved"),
                related_instance_id=normalized_instance_id,
                related_attack_id="not_available",
                related_alert_id="not_available",
                related_case_id="not_available",
                related_artifact_id="not_available",
                description=f"{tool_name} installed on {instance_name}",
                details={
                    "tool_name": tool_name,
                    "instance_name": instance_name,
                    "installed_timestamp": ts,
                },
            )

    attack_mappings = {
        entry.get("source_path"): entry
        for entry in (id_mapping.get("mappings", {}).get("attacks", []) or [])
    }
    for path in sorted(project_path("app_core", "infrastructure", "attack", "outputs").glob("*/result.json")):
        data = read_json_file(path, warnings)
        if not isinstance(data, dict):
            continue
        source_rel = relative_path(path)
        modbus_log = _load_attack_sidecar(source_rel, "modbus_transaction_log.json")
        write_command = ((modbus_log.get("write_command") or {}).get("command")) if isinstance(modbus_log, dict) else None
        command_target_ip = None
        if write_command:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+(-?\d+)\s*$", str(write_command))
            if match:
                command_target_ip = match.group(1)
        target_ip = str(command_target_ip or data.get("target_ip") or "").strip()
        target_role = str(data.get("target_role") or "").lower()
        target_runtime = _resolve_runtime(runtime_map, ip=target_ip)
        related_node_id = target_runtime.get("node_id", "unresolved")
        related_instance_id = target_runtime.get("instance_id", "unresolved")
        if related_node_id == "unresolved":
            for binding in scenario_context.get("node_instance_bindings", []):
                if str(binding.get("node_name") or "").lower() == target_role:
                    related_node_id = binding.get("node_id", "unresolved")
                    related_instance_id = binding.get("instance_id", "unresolved")
                    break
        protocol = str(data.get("protocol") or "").strip().lower()
        if not protocol and write_command and "mbpoll" in str(write_command):
            protocol = "modbus_tcp"

        mapping_entry = attack_mappings.get(relative_path(path), {})
        attack_id = mapping_entry.get("attack_id", make_id("atk", data.get("attack_id") or relative_path(path)))
        started_at = str(data.get("started_at") or data.get("completed_at") or "")
        completed_at = str(data.get("completed_at") or data.get("started_at") or "")
        expected_alerts = [_normalize_indicator(v) for v in (data.get("expected_alerts") or [])]
        attack_windows.append(
            {
                "attack_id": attack_id,
                "display_name": data.get("display_name", "attack"),
                "mitre_id": data.get("mitre_id", "unknown"),
                "target_node_id": related_node_id,
                "target_instance_id": related_instance_id,
                "target_ip": target_ip,
                "target_role": target_role,
                "protocol": protocol or "unknown",
                "expected_alerts": expected_alerts,
                "start_epoch": _epoch_from_any(started_at),
                "end_epoch": _epoch_from_any(completed_at) or _epoch_from_any(started_at),
            }
        )
        _add_event(
            events,
            counter,
            timestamp=started_at,
            event_type="attack_execution",
            phase="offensive_execution",
            status="success" if data.get("success") else "failed",
            source_type="attack_output",
            source_path=relative_path(path),
            id_origin="derived_from_existing_id" if data.get("attack_id") else "derived_from_path",
            related_node_id=related_node_id,
            related_instance_id=related_instance_id,
            related_attack_id=attack_id,
            related_alert_id="unresolved",
            related_case_id=data.get("case_dir") or "not_available",
            related_artifact_id="not_available",
            description=f"{data.get('display_name', 'attack')} against {data.get('target_ip', 'unknown')}",
            details={
                "display_name": data.get("display_name", "unknown"),
                "mitre_id": data.get("mitre_id", "unknown"),
                "mitre_technique": data.get("mitre_technique", "unknown"),
                "detection_engine": data.get("detection_engine", "unknown"),
                "severity": data.get("severity", "unknown"),
                "target_ip": data.get("target_ip", "unknown"),
                "target_role": data.get("target_role", "unknown"),
                "protocol": protocol or "unknown",
                "attacker_ip": data.get("attacker_ip", "unknown"),
                "success": data.get("success", False),
                "exit_code": data.get("exit_code", "unknown"),
                "expected_alerts": data.get("expected_alerts", []),
                "expected_artifacts": data.get("expected_artifacts", []),
            },
        )

    alert_sessions = sorted(project_path("app_core", "infrastructure", "forensics", "alerts_store").glob("ALERTS-*"))
    for session_dir in alert_sessions:
        alerts_path = session_dir / "alerts.jsonl"
        triage_path = session_dir / "triage.jsonl"
        session_detection_lookup = {}
        triage_by_event = {
            str(item.get("event_id") or ""): item
            for item in read_jsonl_file(triage_path, warnings)
        }
        for alert in read_jsonl_file(alerts_path, warnings):
            normalized_alert_id = f"alr-{str(alert.get('event_id'))[:8]}" if alert.get("event_id") else make_id("alr", relative_path(alerts_path), str(alert.get("ts_utc") or ""))
            agent = alert.get("agent") or {}
            agent_name = str(agent.get("name") or "").strip()
            agent_ip = str(agent.get("ip") or "").strip()
            src_ip = str((alert.get("src") or {}).get("ip") or "").strip()
            dst_ip = str((alert.get("dst") or {}).get("ip") or "").strip()
            runtime = (
                _resolve_runtime(runtime_map, name=agent_name, ip=agent_ip)
                or _resolve_runtime(runtime_map, ip=dst_ip)
                or _resolve_runtime(runtime_map, ip=src_ip)
            )
            related_node_id = runtime.get("node_id", "unresolved")
            related_instance_id = runtime.get("instance_id", "unresolved")
            signature = str(alert.get("signature") or alert.get("alert_type") or "alert")
            normalized_signature = _normalize_indicator(signature)
            alert_epoch = float(alert.get("ts_epoch") or _epoch_from_any(alert.get("ts_utc") or ""))
            collector, original_sensor = _infer_sensor_identity(alert)
            rule_meta = _infer_rule_identity(alert)
            is_noise = _is_noise_alert(alert, normalized_signature, original_sensor)
            correlated_attack = None
            correlation_status = "unresolved"
            correlation_confidence = "low"
            correlation_reason = "no_strong_match"
            same_target = False
            same_ip = False
            protocol_match = False
            signature_match = False
            mitre_match = False
            effect_match = False
            temporal_distance_seconds = None
            best_rank = (0, 0, float("-inf"))
            for attack in reversed(sorted(attack_windows, key=lambda item: item.get("end_epoch", 0.0))):
                if alert_epoch and attack.get("start_epoch") and alert_epoch < attack["start_epoch"]:
                    continue
                if alert_epoch and attack.get("end_epoch") and alert_epoch - attack["end_epoch"] > 1800:
                    continue
                same_target = related_node_id != "unresolved" and attack.get("target_node_id") == related_node_id
                same_ip = bool(agent_ip and attack.get("target_ip") == agent_ip) or bool(dst_ip and attack.get("target_ip") == dst_ip)
                signature_match = _expected_alert_match(attack, alert, normalized_signature)
                protocol_match = _protocols_compatible(attack.get("protocol"), alert.get("protocol"))
                mitre_match = _mitre_match(attack, rule_meta)
                effect_match = _expected_effect_match(attack, signature, rule_meta)
                temporal_distance_seconds = abs(alert_epoch - float(attack.get("end_epoch") or attack.get("start_epoch") or 0.0)) if alert_epoch else None
                status, confidence, reason = _correlation_payload(
                    same_target=same_target,
                    same_ip=same_ip,
                    signature_match=signature_match,
                    protocol_match=protocol_match,
                    mitre_match=mitre_match,
                    effect_match=effect_match,
                    temporal_distance_seconds=temporal_distance_seconds,
                    original_sensor=original_sensor,
                    is_noise=is_noise,
                )
                rank = _correlation_rank(status, confidence, reason, attack, alert_epoch)
                if rank > best_rank:
                    best_rank = rank
                    correlated_attack = attack if status in {"confirmed", "inferred_medium", "inferred_low", "weak_candidate"} else None
                    correlation_status = status
                    correlation_confidence = confidence
                    correlation_reason = reason
            triage = triage_by_event.get(str(alert.get("event_id") or ""), {})
            _add_event(
                events,
                counter,
                timestamp=str(alert.get("ts_utc") or ""),
                event_type="detection_alert",
                phase="detection",
                status=str(triage.get("severity") or "observed").lower(),
                source_type="alerts_jsonl",
                source_path=relative_path(alerts_path),
                id_origin="derived_from_existing_id" if alert.get("event_id") else "derived_from_path",
                related_node_id=related_node_id,
                related_instance_id=related_instance_id,
                related_attack_id=(correlated_attack or {}).get("attack_id", "unresolved"),
                related_alert_id=normalized_alert_id,
                related_case_id="not_available",
                related_artifact_id="not_available",
                description=signature,
                details={
                    "session_id": session_dir.name,
                    "source": alert.get("source", "unknown"),
                    "collector": collector,
                    "original_sensor": original_sensor,
                    "alert_type": alert.get("alert_type", "unknown"),
                    "signature": signature,
                    "protocol": alert.get("protocol", "unknown"),
                    "rule_id": alert.get("rule_id", "unknown"),
                    "rule_level": alert.get("rule_level", "unknown"),
                    "suricata_signature_id": rule_meta.get("suricata_signature_id"),
                    "rule_groups": (((alert.get("raw") or {}).get("rule") or {}).get("groups") or []),
                    "ts_epoch": alert.get("ts_epoch", alert_epoch),
                    "src": alert.get("src", {}),
                    "dst": alert.get("dst", {}),
                    "agent": alert.get("agent", {}),
                    "triage_severity": triage.get("severity", "not_available"),
                    "recommend_forensics": triage.get("recommend_forensics", False),
                    "correlation_status": correlation_status,
                    "correlation_confidence": correlation_confidence,
                    "correlation_reason": correlation_reason,
                    "correlated_attack_display": (correlated_attack or {}).get("display_name", "unresolved"),
                    "correlated_attack_mitre_id": (correlated_attack or {}).get("mitre_id", "unresolved"),
                    "mitre_rule_ids": (((alert.get("raw") or {}).get("rule") or {}).get("mitre") or {}).get("id", []),
                    "mitre_rule_tactic": (((alert.get("raw") or {}).get("rule") or {}).get("mitre") or {}).get("tactic", []),
                    "mitre_rule_technique": (((alert.get("raw") or {}).get("rule") or {}).get("mitre") or {}).get("technique", []),
                    "mitre_ics": rule_meta.get("mitre_ics"),
                    "attack_stage": rule_meta.get("attack_stage"),
                    "confidence_tags": rule_meta.get("confidence"),
                    "modbus_function": rule_meta.get("modbus_function"),
                    "temporal_distance_seconds": temporal_distance_seconds,
                    "node_match": same_target if correlated_attack else False,
                    "ip_match": same_ip if correlated_attack else False,
                    "protocol_match": protocol_match if correlated_attack else False,
                    "rule_match": signature_match if correlated_attack else False,
                    "mitre_match": mitre_match if correlated_attack else False,
                    "evidence_expectation_match": effect_match if correlated_attack else False,
                    "normalization_status": "noise" if is_noise else ("normalized" if related_node_id != "unresolved" else "partial"),
                    "raw_reference": f"{relative_path(alerts_path)}#{alert.get('event_id') or normalized_alert_id}",
                },
            )
            session_detection_lookup[normalized_alert_id] = {
                "related_node_id": related_node_id,
                "related_instance_id": related_instance_id,
                "related_attack_id": (correlated_attack or {}).get("attack_id", "unresolved"),
                "original_sensor": original_sensor,
            }

        for triage in read_jsonl_file(triage_path, warnings):
            normalized_alert_id = (
                f"alr-{str(triage.get('event_id'))[:8]}"
                if triage.get("event_id")
                else make_id("alr", relative_path(triage_path), str(triage.get("ts_utc") or ""))
            )
            linked_alert = session_detection_lookup.get(normalized_alert_id, {})
            _add_event(
                events,
                counter,
                timestamp=str(triage.get("ts_utc") or ""),
                event_type="triage_result",
                phase="detection_triage",
                status=str(triage.get("severity") or "observed").lower(),
                source_type="triage_jsonl",
                source_path=relative_path(triage_path),
                id_origin="derived_from_existing_id" if triage.get("event_id") else "derived_from_path",
                related_node_id=linked_alert.get("related_node_id", "unresolved"),
                related_instance_id=linked_alert.get("related_instance_id", "unresolved"),
                related_attack_id=linked_alert.get("related_attack_id", "unresolved"),
                related_alert_id=normalized_alert_id,
                related_case_id="not_available",
                related_artifact_id="not_available",
                description=f"triage severity {triage.get('severity', 'unknown')}",
                details={
                    **triage,
                    "collector": "wazuh",
                    "original_sensor": linked_alert.get("original_sensor", "unknown"),
                },
            )

    for case_dir in sorted(project_path("app_core", "infrastructure", "forensics", "evidence_store").glob("CASE-*")):
        case_id = make_id("case", case_dir.name)
        pipeline_path = case_dir / "metadata" / "pipeline_events.jsonl"
        custody_path = case_dir / "chain_of_custody.log"
        for event in read_jsonl_file(pipeline_path, warnings):
            binding = _resolve_binding_by_vm_id(scenario_context, ((event.get("meta") or {}).get("vm_id")))
            _add_event(
                events,
                counter,
                timestamp=str(event.get("ts_utc") or event.get("ts") or ""),
                event_type=str(event.get("event") or event.get("event_type") or "pipeline_event"),
                phase="forensics_pipeline",
                status="observed",
                source_type="pipeline_events",
                source_path=relative_path(pipeline_path),
                id_origin="derived_from_hash",
                related_node_id=binding.get("node_id", "unresolved"),
                related_instance_id=binding.get("instance_id", (f"inst-{str((event.get('meta') or {}).get('vm_id'))[:8]}" if (event.get("meta") or {}).get("vm_id") else "unresolved")),
                related_attack_id="unresolved",
                related_alert_id="unresolved",
                related_case_id=case_id,
                related_artifact_id=(make_id("art", case_id, str((event.get("meta") or {}).get("rel") or "")) if (event.get("meta") or {}).get("rel") else "unresolved"),
                description=str(event.get("event") or event.get("event_type") or "pipeline event"),
                details=event,
            )
        for entry in read_jsonl_file(custody_path, warnings):
            artifact_rel = str(entry.get("artifact_rel") or "")
            binding = {}
            if "/per_vm/" in artifact_rel:
                vm_match = re.search(r"/per_vm/([0-9a-f-]{8,})/", artifact_rel)
                if vm_match:
                    binding = _resolve_binding_by_vm_id(scenario_context, vm_match.group(1))
            _add_event(
                events,
                counter,
                timestamp=str(entry.get("ts_utc") or ""),
                event_type=str(entry.get("action") or "custody_event"),
                phase="forensics_custody",
                status="recorded",
                source_type="chain_of_custody",
                source_path=relative_path(custody_path),
                id_origin="derived_from_hash",
                related_node_id=binding.get("node_id", "unresolved"),
                related_instance_id=binding.get("instance_id", "unresolved"),
                related_attack_id="unresolved",
                related_alert_id="unresolved",
                related_case_id=case_id,
                related_artifact_id=(make_id("art", case_id, str(entry.get("artifact_rel") or "")) if entry.get("artifact_rel") else "unresolved"),
                description=str(entry.get("action") or "custody event"),
                details=entry,
            )

    events.sort(key=lambda item: _timeline_sort_key(item.get("timestamp") or ""))
    return {
        "scenario_id": scenario_context.get("scenario_id", "unknown"),
        "generated_at": utc_now(),
        "events": events,
        "warnings": warnings,
    }
