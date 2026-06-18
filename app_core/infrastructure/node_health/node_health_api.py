from __future__ import annotations

import os
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
CLEANUP_SCRIPT_PATH = REPO_ROOT / "pre_memory_cleanup_inside_node.sh"


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


@node_health_bp.route("/node-health")
def node_health_view():
    return send_from_directory(STATIC_DIR, "node_health.html")


@node_health_bp.route("/api/node-health/nodes", methods=["GET"])
def node_health_nodes():
    nodes = _list_nodes()
    graph = _network_graph(nodes)
    return jsonify(
        {
            "generated_at": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True).stdout.strip(),
            "nodes": nodes,
            "graph": graph,
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

