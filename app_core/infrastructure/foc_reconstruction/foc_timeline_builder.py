import itertools
import re
from datetime import datetime, timezone

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


def _correlation_payload(*, same_target: bool, same_ip: bool, signature_match: bool) -> tuple[str, str, str]:
    reasons = []
    if same_target:
        reasons.append("same_target_node")
    if same_ip:
        reasons.append("same_target_ip")
    if signature_match:
        reasons.append("expected_alert_match")
    if len(reasons) >= 2:
        return "confirmed", "high", ",".join(reasons)
    if same_target or same_ip:
        return "inferred_high", "high", ",".join(reasons) or "target_proximity"
    if signature_match:
        return "inferred_medium", "medium", "expected_alert_match"
    return "unresolved", "low", "no_strong_match"


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
        target_ip = str(data.get("target_ip") or "").strip()
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
            correlated_attack = None
            correlation_status = "unresolved"
            correlation_confidence = "low"
            correlation_reason = "no_strong_match"
            for attack in reversed(sorted(attack_windows, key=lambda item: item.get("end_epoch", 0.0))):
                if alert_epoch and attack.get("start_epoch") and alert_epoch < attack["start_epoch"]:
                    continue
                if alert_epoch and attack.get("end_epoch") and alert_epoch - attack["end_epoch"] > 1800:
                    continue
                same_target = related_node_id != "unresolved" and attack.get("target_node_id") == related_node_id
                same_ip = bool(agent_ip and attack.get("target_ip") == agent_ip) or bool(dst_ip and attack.get("target_ip") == dst_ip)
                signature_match = normalized_signature in set(attack.get("expected_alerts") or [])
                status, confidence, reason = _correlation_payload(
                    same_target=same_target,
                    same_ip=same_ip,
                    signature_match=signature_match,
                )
                if status != "unresolved":
                    correlated_attack = attack
                    correlation_status = status
                    correlation_confidence = confidence
                    correlation_reason = reason
                    break
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
                    "alert_type": alert.get("alert_type", "unknown"),
                    "signature": signature,
                    "protocol": alert.get("protocol", "unknown"),
                    "rule_id": alert.get("rule_id", "unknown"),
                    "rule_level": alert.get("rule_level", "unknown"),
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
                },
            )

        for triage in read_jsonl_file(triage_path, warnings):
            normalized_alert_id = f"alr-{str(triage.get('event_id'))[:8]}" if triage.get("event_id") else make_id("alr", relative_path(triage_path), str(triage.get("ts_utc") or ""))
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
                related_node_id="unresolved",
                related_instance_id="unresolved",
                related_attack_id="unresolved",
                related_alert_id=normalized_alert_id,
                related_case_id="not_available",
                related_artifact_id="not_available",
                description=f"triage severity {triage.get('severity', 'unknown')}",
                details=triage,
            )

    for case_dir in sorted(project_path("app_core", "infrastructure", "forensics", "evidence_store").glob("CASE-*")):
        case_id = make_id("case", case_dir.name)
        pipeline_path = case_dir / "metadata" / "pipeline_events.jsonl"
        custody_path = case_dir / "chain_of_custody.log"
        for event in read_jsonl_file(pipeline_path, warnings):
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
                related_node_id="unresolved",
                related_instance_id=(f"inst-{str((event.get('meta') or {}).get('vm_id'))[:8]}" if (event.get("meta") or {}).get("vm_id") else "unresolved"),
                related_attack_id="unresolved",
                related_alert_id="unresolved",
                related_case_id=case_id,
                related_artifact_id=(make_id("art", case_id, str((event.get("meta") or {}).get("rel") or "")) if (event.get("meta") or {}).get("rel") else "unresolved"),
                description=str(event.get("event") or event.get("event_type") or "pipeline event"),
                details=event,
            )
        for entry in read_jsonl_file(custody_path, warnings):
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
                related_node_id="unresolved",
                related_instance_id="unresolved",
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
