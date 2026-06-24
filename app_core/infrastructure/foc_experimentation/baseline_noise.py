from __future__ import annotations

from .config import DEFAULT_BASELINE_NOISE_THRESHOLD, DEFAULT_EPSILON


def relative_difference(value_i, value_j, epsilon: float = DEFAULT_EPSILON) -> float:
    try:
        left = float(value_i or 0.0)
        right = float(value_j or 0.0)
    except Exception:
        return 0.0
    return abs(left - right) / max(abs(left), abs(right), epsilon)


def build_baseline_noise_profile(
    *,
    execution_id: str,
    enabled: bool,
    baseline_window_seconds: int | None,
    time_sync: dict | None,
    alerts_summary: dict | None,
    network_summary: dict | None,
    ot_summary: dict | None,
    threshold: float = DEFAULT_BASELINE_NOISE_THRESHOLD,
) -> dict:
    if not enabled:
        return {
            "execution_id": execution_id,
            "baseline_window_seconds": baseline_window_seconds or 0,
            "baseline_start_time": "not_applicable",
            "baseline_end_time": "not_applicable",
            "packets_per_second": None,
            "modbus_events_per_second": None,
            "alerts_per_second": None,
            "network_bytes_per_second": None,
            "hmi_polling_rate": None,
            "plc_initial_state": "not_applicable",
            "scada_hmi_initial_state": "not_applicable",
            "ot_variables_initial_state": "not_applicable",
            "ids_siem_rule_versions": [],
            "comparison_threshold": threshold,
            "baseline_noise_status": "not_applicable",
            "warning_reason": "baseline noise capture is not required for this execution level",
        }

    network = network_summary or {}
    alerts = alerts_summary or {}
    ot = ot_summary or {}
    time_sync = time_sync or {}
    packets = network.get("pcaps_analyzed") or network.get("packets") or 0
    alerts_count = alerts.get("alerts_summarized") or alerts.get("total_alerts_indexed") or 0
    modbus_hits = ot.get("modbus_events_per_second") or ot.get("protocol_hits") or 0
    bytes_ps = network.get("network_bytes_per_second") or 0
    warning_reason = None
    status = "ok"
    max_offset_ms = (time_sync.get("max_clock_offset_ms") or 0) if isinstance(time_sync, dict) else 0
    if max_offset_ms and float(max_offset_ms) > 5000:
        status = "comparability_warning"
        warning_reason = "baseline captured under large clock-offset uncertainty"

    return {
        "execution_id": execution_id,
        "baseline_window_seconds": baseline_window_seconds or 0,
        "baseline_start_time": time_sync.get("generated_at_utc") or "not_available",
        "baseline_end_time": time_sync.get("generated_at_utc") or "not_available",
        "packets_per_second": packets,
        "modbus_events_per_second": modbus_hits,
        "alerts_per_second": alerts_count,
        "network_bytes_per_second": bytes_ps,
        "hmi_polling_rate": ot.get("hmi_polling_rate") or "not_available",
        "plc_initial_state": ot.get("plc_initial_state") or "not_available",
        "scada_hmi_initial_state": ot.get("scada_hmi_initial_state") or "not_available",
        "ot_variables_initial_state": ot.get("ot_variables_initial_state") or "not_available",
        "ids_siem_rule_versions": ot.get("ids_siem_rule_versions") or [],
        "comparison_threshold": threshold,
        "baseline_noise_status": status,
        "warning_reason": warning_reason or "none",
    }
