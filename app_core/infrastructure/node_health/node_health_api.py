from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import openstack
from flask import Blueprint, Response, jsonify, send_from_directory, stream_with_context


node_health_bp = Blueprint("node_health", __name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
STATIC_DIR = REPO_ROOT / "app_core" / "static"
SSH_KEY_PATH = os.path.expanduser("~/.ssh/my_key")
PROBE_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "probe_node_health_inside_node.sh"
TOOLING_PROBE_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "probe_node_tooling_inside_node.sh"
CLEANUP_SCRIPT_PATH = REPO_ROOT / "pre_memory_cleanup_inside_node.sh"
TOOLS_INSTALLED_DIR = REPO_ROOT / "tools-installer" / "installed"
TOOLS_TMP_DIR = REPO_ROOT / "tools-installer-tmp"


def _connect():
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        region_name=os.environ.get("OS_REGION_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        compute_api_version="2",
        identity_interface="public",
    )


def _classify_role(server_name: str) -> str:
    name = (server_name or "").lower()
    if "fuxa" in name or "scada" in name:
        return "scada"
    if "plc" in name:
        return "plc"
    if "attack" in name:
        return "attacker"
    if "monitor" in name:
        return "monitor"
    if "victim" in name:
        return "victim"
    return "unknown"


def _map_user(image_name: str) -> str:
    n = (image_name or "").lower()
    if "ubuntu" in n:
        return "ubuntu"
    if "kali" in n:
        return "kali"
    return "debian"


def _detect_os(conn, server) -> tuple[str, str]:
    image_name = ""
    try:
        image_id = None
        img_prop = getattr(server, "image", None)
        if img_prop:
            if isinstance(img_prop, dict):
                image_id = img_prop.get("id")
            else:
                image_id = getattr(img_prop, "id", None)
        if image_id:
            image = conn.get_image(image_id)
            if image:
                image_name = image.get("os_distro") or image.get("display_name") or image.name or ""
        if not image_name:
            image_name = (getattr(server, "metadata", {}) or {}).get("os_distro", "Linux")
    except Exception:
        image_name = (getattr(server, "metadata", {}) or {}).get("os_distro", "Linux")

    low = (image_name or "").lower()
    if "ubuntu" in low:
        return "Ubuntu Linux", image_name
    if "debian" in low:
        return "Debian Linux", image_name
    if "kali" in low:
        return "Kali Linux", image_name
    if "windows" in low:
        return "Windows", image_name
    return image_name or "Linux", image_name or "Linux"


def _extract_ips_and_networks(server) -> tuple[str | None, str | None, list[dict]]:
    ip_private = None
    ip_floating = None
    networks: list[dict] = []
    addresses = getattr(server, "addresses", {}) or {}
    for net_name, addrs in addresses.items():
        for addr in addrs or []:
            ip = addr.get("addr")
            ip_type = addr.get("OS-EXT-IPS:type")
            mac = addr.get("OS-EXT-IPS-MAC:mac_addr") or addr.get("mac_addr")
            networks.append(
                {
                    "network": net_name,
                    "ip": ip,
                    "type": ip_type or "fixed",
                    "mac": mac,
                }
            )
            if ip_type == "floating":
                ip_floating = ip
            elif not ip_private:
                ip_private = ip
    return ip_private, ip_floating, networks


def _normalize_node(conn, server) -> dict:
    ip_private, ip_floating, networks = _extract_ips_and_networks(server)
    os_label, image_name = _detect_os(conn, server)
    ssh_user = _map_user(image_name or os_label)
    preferred_ip = ip_floating or ip_private or ""
    tool_inventory = _tool_inventory_for_instance(server.id, server.name)
    return {
        "id": server.id,
        "name": server.name,
        "status": getattr(server, "status", "UNKNOWN"),
        "role": _classify_role(server.name),
        "os": os_label,
        "image_name": image_name,
        "ssh_user": ssh_user,
        "ip_private": ip_private,
        "ip_floating": ip_floating,
        "ssh_target_ip": preferred_ip,
        "networks": networks,
        "availability_zone": getattr(server, "availability_zone", None),
        "flavor": getattr(getattr(server, "flavor", None), "get", lambda *_: None)("original_name") if getattr(server, "flavor", None) else None,
        "tool_inventory": tool_inventory,
    }


def _list_nodes() -> list[dict]:
    conn = _connect()
    try:
        servers = list(conn.compute.servers(details=True))
        return [_normalize_node(conn, server) for server in servers]
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _find_node(instance_id: str) -> dict | None:
    for node in _list_nodes():
        if node["id"] == instance_id:
            return node
    return None


def _run_local_text(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _local_host_summary(nodes: list[dict]) -> dict:
    root_df = _run_local_text(["df", "-P", "-B1", "/"]).splitlines()
    mem_lines = _run_local_text(["free", "-m"]).splitlines()

    root_total = root_used = root_avail = None
    root_use_pct = None
    if len(root_df) >= 2:
        cols = root_df[1].split()
        if len(cols) >= 6:
            try:
                root_total = int(cols[1])
                root_used = int(cols[2])
                root_avail = int(cols[3])
                root_use_pct = cols[4]
            except Exception:
                pass

    mem_total = mem_used = mem_avail = None
    if mem_lines:
        for line in mem_lines:
            if line.startswith("Mem:"):
                cols = line.split()
                if len(cols) >= 7:
                    try:
                        mem_total = int(cols[1])
                        mem_used = int(cols[2])
                        mem_avail = int(cols[6])
                    except Exception:
                        pass
                break

    role_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for node in nodes:
        role = node.get("role", "unknown")
        status = node.get("status", "UNKNOWN")
        role_counts[role] = role_counts.get(role, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "host": {
            "hostname": _run_local_text(["hostname"]) or "not_available",
            "date_utc": _run_local_text(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]) or "not_available",
            "loadavg": _run_local_text(["bash", "-lc", "cat /proc/loadavg | awk '{print $1\" \"$2\" \"$3}'"]) or "not_available",
            "root_total_bytes": root_total,
            "root_used_bytes": root_used,
            "root_avail_bytes": root_avail,
            "root_use_pct": root_use_pct,
            "mem_total_mb": mem_total,
            "mem_used_mb": mem_used,
            "mem_avail_mb": mem_avail,
        },
        "scenario": {
            "node_count": len(nodes),
            "role_counts": role_counts,
            "status_counts": status_counts,
            "network_count": len({net.get("network") for node in nodes for net in node.get("networks", []) if net.get("network")}),
        },
    }


def _network_graph(nodes: list[dict]) -> dict:
    graph_nodes = []
    graph_edges = []
    seen_networks: dict[str, dict] = {}
    for node in nodes:
        graph_nodes.append(
            {
                "data": {
                    "id": node["id"],
                    "label": node["name"],
                    "kind": "instance",
                    "role": node["role"],
                    "status": node["status"],
                    "os": node["os"],
                }
            }
        )
        for net in node.get("networks", []):
            if net.get("type") == "floating":
                continue
            net_name = net.get("network") or "unknown_net"
            net_id = f"net::{net_name}"
            if net_id not in seen_networks:
                seen_networks[net_id] = {
                    "data": {
                        "id": net_id,
                        "label": net_name,
                        "kind": "network",
                        "network": net_name,
                    }
                }
            graph_edges.append(
                {
                    "data": {
                        "id": f"edge::{node['id']}::{net_id}",
                        "source": node["id"],
                        "target": net_id,
                        "label": net_name,
                    }
                }
            )
    graph_nodes.extend(seen_networks.values())
    return {"nodes": graph_nodes, "edges": graph_edges}


def _run_remote_script_capture(node: dict, script_path: Path, *, remote_dump: str = "", timeout: int = 90) -> subprocess.CompletedProcess[str]:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")
    ssh_ip = node.get("ssh_target_ip") or node.get("ip_floating") or node.get("ip_private")
    if not ssh_ip:
        raise RuntimeError("No SSH target IP available for node")
    ssh_user = node.get("ssh_user") or "debian"
    remote_cmd = f"REMOTE_DUMP={shlex.quote(remote_dump)} bash -s"
    script_text = script_path.read_text(encoding="utf-8")
    return subprocess.run(
        [
            "ssh",
            "-i",
            SSH_KEY_PATH,
            "-o",
            "StrictHostKeyChecking=no",
            f"{ssh_user}@{ssh_ip}",
            remote_cmd,
        ],
        input=script_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _safe_instance_filename(instance_name: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", (instance_name or "").lower())
    return f"{safe_name}_tools.json"


def _read_json_file(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _tool_category(tool_name: str) -> str:
    name = (tool_name or "").lower()
    if name == "suricata":
        return "ids"
    if name == "wazuh":
        return "siem"
    if name in {"wazuh_agent", "caldera_agent"}:
        return "agent"
    if "integration" in name:
        return "integration"
    if "fim" in name:
        return "fim"
    if name.startswith("rollback_suricata_"):
        return "rule_pack"
    if name.startswith("rollback_wazuh_"):
        return "integration"
    if name.startswith("caldera"):
        return "orchestrator"
    return "other"


def _tool_display_name(tool_name: str) -> str:
    custom = {
        "suricata": "Suricata IDS",
        "wazuh": "Wazuh Manager",
        "wazuh_agent": "Wazuh Agent",
        "wazuh_fim_realtime": "Wazuh FIM Realtime",
        "rollback_suricata_ping_detection": "Suricata Ping Detection Rules",
        "rollback_suricata_modbus_register_detection": "Suricata Modbus Register Rules",
        "rollback_wazuh_suricata_integration": "Wazuh-Suricata Integration",
        "caldera": "MITRE Caldera",
        "caldera_agent": "Caldera Agent",
        "caldera_ot_plugins": "Caldera OT Plugins",
        "mbpoll": "mbpoll",
        "nmap": "Nmap",
    }
    if tool_name in custom:
        return custom[tool_name]
    return tool_name.replace("_", " ").strip().title()


def _runtime_probe_key(tool_name: str) -> str | None:
    mapping = {
        "suricata": "suricata",
        "wazuh": "wazuh-manager",
        "wazuh_agent": "wazuh-agent",
        "zeek": "zeek",
        "snort": "snort",
        "openplc": "openplc",
        "nmap": "nmap",
        "mbpoll": "mbpoll",
        "caldera": "caldera",
        "caldera_agent": "caldera-agent",
    }
    return mapping.get(tool_name)


def _expected_artifacts(tool_name: str) -> list[str]:
    mapping = {
        "rollback_suricata_ping_detection": ["nics-ping.rules"],
        "rollback_suricata_modbus_register_detection": ["nics-modbus-register-manipulation.rules"],
        "rollback_wazuh_suricata_integration": ["/var/ossec/etc/ossec.conf", "/var/ossec/logs/ossec.log"],
        "wazuh_fim_realtime": ["/var/ossec/etc/ossec.conf"],
    }
    return mapping.get(tool_name, [])


def _tool_inventory_for_instance(instance_id: str, instance_name: str) -> dict:
    records: dict[str, dict] = {}
    source_files: list[str] = []

    installed_path = TOOLS_INSTALLED_DIR / f"{instance_id}.json"
    installed_payload = _read_json_file(installed_path) if installed_path.exists() else None
    tmp_payload = None
    tmp_path = TOOLS_TMP_DIR / _safe_instance_filename(instance_name)
    if tmp_path.exists():
        tmp_payload = _read_json_file(tmp_path)
    if tmp_payload:
        source_files.append(str(tmp_path.relative_to(REPO_ROOT)))
    if installed_payload:
        source_files.append(str(installed_path.relative_to(REPO_ROOT)))

    tmp_tools = (tmp_payload or {}).get("tools") or {}
    installed_tools = (installed_payload or {}).get("installed_tools") or {}

    merged: dict[str, str] = {}
    for tool_name, status in tmp_tools.items():
        merged[tool_name] = status
    for tool_name, installed_at in installed_tools.items():
        if tool_name not in merged:
            merged[tool_name] = installed_at
        elif merged[tool_name] in ("error", "pending", "uninstalling"):
            continue
        else:
            merged[tool_name] = installed_at

    for tool_name, merged_status in merged.items():
        record = records.setdefault(
            tool_name,
            {
                "id": tool_name,
                "display_name": _tool_display_name(tool_name),
                "category": _tool_category(tool_name),
                "inventory_status": "unknown",
                "installed_at": None,
                "expected_artifacts": _expected_artifacts(tool_name),
            },
        )
        if tool_name in installed_tools:
            record["installed_at"] = installed_tools.get(tool_name)
        if tool_name in tmp_tools and tmp_tools.get(tool_name) in ("error", "pending", "uninstalling"):
            record["inventory_status"] = tmp_tools.get(tool_name)
        else:
            record["inventory_status"] = "installed" if tool_name in installed_tools or tmp_tools.get(tool_name) == "installed" else str(merged_status)

    tools = sorted(records.values(), key=lambda item: (item["category"], item["display_name"].lower()))
    counts: dict[str, int] = {}
    for tool in tools:
        counts[tool["category"]] = counts.get(tool["category"], 0) + 1
    return {
        "source_files": source_files,
        "tools": tools,
        "counts": counts,
        "total": len(tools),
    }


def _parse_probe_output(stdout: str) -> dict:
    values: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    current_section = None
    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("KV\t"):
            _, key, value = line.split("\t", 2)
            values[key] = value
            continue
        if line.startswith("SECTION\t"):
            _, name, marker = line.split("\t", 2)
            if marker == "BEGIN":
                current_section = name
                sections[current_section] = []
            elif marker == "END":
                current_section = None
            continue
        if current_section:
            sections[current_section].append(line)

    def as_int(key: str) -> int | None:
        value = values.get(key, "")
        try:
            return int(float(str(value).replace("%", "").strip()))
        except Exception:
            return None

    def as_float(key: str) -> float | None:
        value = values.get(key, "")
        try:
            return float(str(value).replace("%", "").strip())
        except Exception:
            return None

    mem_total = as_int("mem_total_mb") or 0
    mem_used = as_int("mem_used_mb") or 0
    mem_avail = as_int("mem_avail_mb") or 0
    mem_pct = round((mem_used / mem_total) * 100, 2) if mem_total else None
    swap_total = as_int("swap_total_mb") or 0
    swap_used = as_int("swap_used_mb") or 0
    swap_pct = round((swap_used / swap_total) * 100, 2) if swap_total else None
    root_total = as_int("root_total_bytes") or 0
    root_used = as_int("root_used_bytes") or 0
    root_avail = as_int("root_avail_bytes") or 0
    root_pct = as_int("root_use_pct")

    def severity(pct: float | int | None) -> str:
        if pct is None:
            return "unknown"
        if pct >= 95:
            return "critical"
        if pct >= 85:
            return "warning"
        return "ok"

    return {
        "raw_values": values,
        "sections": sections,
        "identity": {
            "hostname": values.get("hostname", "not_available"),
            "os": values.get("os_pretty", "not_available"),
            "kernel": values.get("kernel", "not_available"),
            "machine": values.get("machine", "not_available"),
            "date_utc": values.get("date_utc", "not_available"),
            "uptime": values.get("uptime_pretty", "not_available"),
            "loadavg": values.get("loadavg", "not_available"),
        },
        "cpu": {
            "cores": as_int("cpu_cores"),
            "usage_pct": as_float("cpu_usage_pct"),
            "severity": severity(as_float("cpu_usage_pct")),
        },
        "memory": {
            "total_mb": mem_total,
            "used_mb": mem_used,
            "available_mb": mem_avail,
            "usage_pct": mem_pct,
            "swap_total_mb": swap_total,
            "swap_used_mb": swap_used,
            "swap_free_mb": as_int("swap_free_mb"),
            "swap_usage_pct": swap_pct,
            "severity": severity(mem_pct),
        },
        "disk": {
            "root_total_bytes": root_total,
            "root_used_bytes": root_used,
            "root_avail_bytes": root_avail,
            "root_use_pct": root_pct,
            "root_inodes_use_pct": as_int("root_inodes_use_pct"),
            "var_log_size_bytes": as_int("var_log_size_bytes"),
            "suricata_log_size_bytes": as_int("suricata_log_size_bytes"),
            "tmp_size_bytes": as_int("tmp_size_bytes"),
            "var_tmp_size_bytes": as_int("var_tmp_size_bytes"),
            "apt_cache_size_bytes": as_int("apt_cache_size_bytes"),
            "severity": severity(root_pct),
        },
        "services": {
            (line.split("=", 1)[0] if "=" in line else line): (line.split("=", 1)[1] if "=" in line else "unknown")
            for line in sections.get("services", [])
        },
        "tables": {
            "filesystems": sections.get("filesystems", []),
            "top_cpu": sections.get("top_cpu", []),
            "top_mem": sections.get("top_mem", []),
            "largest_var": sections.get("largest_var", []),
        },
    }


def _parse_tooling_output(stdout: str) -> dict:
    values: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    current_section = None
    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("KV\t"):
            _, key, value = line.split("\t", 2)
            values[key] = value
            continue
        if line.startswith("SECTION\t"):
            _, name, marker = line.split("\t", 2)
            if marker == "BEGIN":
                current_section = name
                sections[current_section] = []
            elif marker == "END":
                current_section = None
            continue
        if current_section:
            sections[current_section].append(line)

    def _parse_pairs(lines: list[str]) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for line in lines:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()
        return parsed

    def _parse_file_sections(lines: list[str]) -> list[dict]:
        files: list[dict] = []
        current: dict | None = None
        for line in lines:
            if line.startswith("FILE\t"):
                if current:
                    files.append(current)
                current = {"path": line.split("\t", 1)[1].strip(), "content_lines": []}
                continue
            if line.startswith("FILE_END\t"):
                if current:
                    files.append(current)
                    current = None
                continue
            if current is not None:
                current["content_lines"].append(line)
        if current:
            files.append(current)
        return files

    def _interpret_suricata_rule(raw_rule: str) -> str:
        text = (raw_rule or "").strip()
        if not text:
            return "Empty rule line."
        proto = "traffic"
        direction = ""
        if text.startswith("alert "):
            parts = text.split("(", 1)[0].split()
            if len(parts) >= 7:
                proto = parts[1]
                direction = f"{parts[2]} {parts[3]} {parts[4]} {parts[5]} {parts[6]}"
        msg = "custom detection"
        sid = None
        if 'msg:"' in text:
            msg = text.split('msg:"', 1)[1].split('"', 1)[0]
        if "sid:" in text:
            sid = text.split("sid:", 1)[1].split(";", 1)[0].strip()
        hints: list[str] = []
        if "itype:8" in text:
            hints.append("ICMP echo request")
        if "byte_test:1,=,0x10,7" in text:
            hints.append("Modbus write multiple registers function 0x10")
        if "byte_test:1,=,0x06,7" in text:
            hints.append("Modbus write single register function 0x06")
        if "byte_test:1,=,0x05,7" in text:
            hints.append("Modbus write single coil function 0x05")
        if "byte_test:1,=,0x0f,7" in text:
            hints.append("Modbus write multiple coils function 0x0f")
        hint_text = "; ".join(hints) if hints else "see raw rule options"
        sid_text = f"sid {sid}" if sid else "no sid parsed"
        direction_text = direction or "custom flow expression"
        return f"{msg} | {sid_text} | alerts on {proto} {direction_text} | detects {hint_text}."

    def _extract_suricata_rules(files: list[dict]) -> list[dict]:
        parsed_rules: list[dict] = []
        for file_entry in files:
            path = file_entry.get("path", "unknown")
            for line in file_entry.get("content_lines", []):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or not stripped.startswith("alert "):
                    continue
                parsed_rules.append(
                    {
                        "path": path,
                        "raw": stripped,
                        "interpretation": _interpret_suricata_rule(stripped),
                    }
                )
        return parsed_rules

    suricata_rule_contents = _parse_file_sections(sections.get("suricata_rule_contents", []))
    wazuh_rule_contents = _parse_file_sections(sections.get("wazuh_rule_contents", []))

    return {
        "generated_at": values.get("date_utc", "not_available"),
        "tool_presence": _parse_pairs(sections.get("tool_presence", [])),
        "tool_status": _parse_pairs(sections.get("tool_status", [])),
        "tool_versions": _parse_pairs(sections.get("tool_versions", [])),
        "suricata": {
            "active_rule_files": sections.get("suricata_rule_files", []),
            "custom_signatures": sections.get("suricata_custom_signatures", []),
            "rule_inventory": sections.get("suricata_rule_inventory", []),
            "rule_contents": suricata_rule_contents,
            "parsed_rules": _extract_suricata_rules(suricata_rule_contents),
        },
        "wazuh": {
            "fim_paths": sections.get("wazuh_fim_paths", []),
            "local_rules": sections.get("wazuh_local_rules", []),
            "local_decoders": sections.get("wazuh_local_decoders", []),
            "rule_inventory": sections.get("wazuh_rule_inventory", []),
            "rule_contents": wazuh_rule_contents,
        },
        "raw_values": values,
    }


def _build_tooling_payload(node: dict) -> dict:
    inventory = _tool_inventory_for_instance(node["id"], node.get("name", ""))
    runtime = None
    runtime_error = None
    try:
        result = _run_remote_script_capture(node, TOOLING_PROBE_SCRIPT_PATH, timeout=120)
        if result.returncode == 0:
            runtime = _parse_tooling_output(result.stdout)
        else:
            runtime_error = {
                "message": "Remote tooling probe failed",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
    except Exception as exc:
        runtime_error = {"message": str(exc)}

    tools = []
    runtime_presence = (runtime or {}).get("tool_presence", {})
    runtime_status = (runtime or {}).get("tool_status", {})
    runtime_versions = (runtime or {}).get("tool_versions", {})
    for tool in inventory.get("tools", []):
        enriched = dict(tool)
        probe_key = _runtime_probe_key(tool["id"])
        enriched["runtime_probe_key"] = probe_key
        enriched["runtime_presence"] = runtime_presence.get(probe_key) if probe_key else None
        enriched["runtime_status"] = runtime_status.get(probe_key) if probe_key else None
        enriched["runtime_version"] = runtime_versions.get(probe_key) if probe_key else None
        tools.append(enriched)

    return {
        "node": node,
        "inventory": {
            **inventory,
            "tools": tools,
        },
        "runtime": runtime,
        "runtime_error": runtime_error,
    }


@node_health_bp.route("/node-health")
def node_health_view():
    return send_from_directory(STATIC_DIR, "node_health.html")


@node_health_bp.route("/api/node-health/nodes", methods=["GET"])
def node_health_nodes():
    nodes = _list_nodes()
    graph = _network_graph(nodes)
    summary = _local_host_summary(nodes)
    return jsonify(
        {
            "generated_at": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True).stdout.strip(),
            "nodes": nodes,
            "graph": graph,
            "summary": summary,
            "count": len(nodes),
        }
    )


@node_health_bp.route("/api/node-health/nodes/<instance_id>/probe", methods=["GET"])
def node_health_probe(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return jsonify({"error": f"Instance not found: {instance_id}"}), 404
    result = _run_remote_script_capture(node, PROBE_SCRIPT_PATH, timeout=120)
    if result.returncode != 0:
        return jsonify(
            {
                "error": "Remote probe failed",
                "node": node,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        ), 500
    return jsonify(
        {
            "node": node,
            "probe": _parse_probe_output(result.stdout),
            "stdout": result.stdout,
        }
    )


@node_health_bp.route("/api/node-health/nodes/<instance_id>/tooling", methods=["GET"])
def node_health_tooling(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return jsonify({"error": f"Instance not found: {instance_id}"}), 404
    return jsonify(_build_tooling_payload(node))


@node_health_bp.route("/api/node-health/nodes/<instance_id>/cleanup/stream", methods=["GET"])
def node_health_cleanup_stream(instance_id: str):
    node = _find_node(instance_id)
    if not node:
        return Response("data: [ERROR] Instance not found\n\n", mimetype="text/event-stream")

    ssh_ip = node.get("ssh_target_ip") or node.get("ip_floating") or node.get("ip_private")
    ssh_user = node.get("ssh_user") or "debian"
    remote_dump = ""

    def generate():
        yield f"data: [SYSTEM] node={node['name']} role={node['role']} os={node['os']}\n\n"
        yield f"data: [SYSTEM] ssh_user={ssh_user} ssh_target_ip={ssh_ip}\n\n"
        if not CLEANUP_SCRIPT_PATH.exists():
            yield "data: [ERROR] cleanup script not found\n\n"
            return
        remote_cmd = f"REMOTE_DUMP={shlex.quote(remote_dump)} bash -s"
        cmd = [
            "ssh",
            "-i",
            SSH_KEY_PATH,
            "-o",
            "StrictHostKeyChecking=no",
            f"{ssh_user}@{ssh_ip}",
            remote_cmd,
        ]
        script_text = CLEANUP_SCRIPT_PATH.read_text(encoding="utf-8")
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if proc.stdin:
                proc.stdin.write(script_text)
                proc.stdin.close()
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, ""):
                if line:
                    yield f"data: {line.rstrip()}\n\n"
            rc = proc.wait()
            yield f"data: [EXIT CODE] {rc}\n\n"
            yield "event: done\ndata: cleanup_finished\n\n"
        except Exception as exc:
            yield f"data: [ERROR] {str(exc)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
