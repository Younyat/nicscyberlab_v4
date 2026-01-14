#!/usr/bin/env python3
# ============================================================
# NICS CyberLab – Host Forensic Inventory API (FINAL ROBUST)
# OpenStack Instances + Tools Inventory + Live Traffic (SSE)
# ============================================================

import os
import time
import json
import re
import subprocess
from threading import Thread
from queue import Queue, Empty

from flask import Response, request, jsonify
from scapy.all import sniff, IP, TCP, UDP, wrpcap

# IMPORTA EL BLUEPRINT EXISTENTE (NO CREAR OTRO)
from app_core.presentation.api import api_bp

# ============================================================
# 1) PATHS / ENV
# ============================================================

def get_project_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def load_openstack_env():
    """
    Carga admin-openrc.sh de forma segura (sin source).
    """
    root = get_project_root()
    rc_path = os.path.join(root, "admin-openrc.sh")

    if not os.path.exists(rc_path):
        raise FileNotFoundError(f"admin-openrc.sh no encontrado en {rc_path}")

    env = os.environ.copy()

    with open(rc_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export ") and "=" in line:
                key, value = line.replace("export ", "", 1).split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")

    return env


def run_openstack_json(args):
    """
    Ejecuta OpenStack CLI y devuelve JSON.
    """
    env = load_openstack_env()
    cmd = ["openstack"] + args + ["-f", "json"]

    out = subprocess.check_output(
        cmd,
        env=env,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    if not out.strip():
        raise RuntimeError("OpenStack devolvió salida vacía")

    return json.loads(out)

# ============================================================
# 2) OPENSTACK – INSTANCIAS
# ============================================================

def parse_first_ipv4(s):
    if not s:
        return None
    m = re.search(r"[0-9]+(?:\.[0-9]+){3}", s)
    return m.group(0) if m else None


@api_bp.route("/api/openstack/instances/full", methods=["GET"])
def api_instances_full():
    try:
        servers = run_openstack_json(["server", "list", "--long"])
        fips = run_openstack_json(["floating", "ip", "list"])

        instances = []

        for s in servers:
            vm_id = s.get("ID") or s.get("Id")
            name = s.get("Name")
            status = s.get("Status", "UNKNOWN")

            networks = s.get("Networks", "")
            ip_private = parse_first_ipv4(networks)

            ip_floating = None
            for f in fips:
                if f.get("Fixed IP Address") == ip_private:
                    ip_floating = f.get("Floating IP Address")
                    break

            flavor = s.get("Flavor", "-")
            if isinstance(flavor, dict):
                flavor = flavor.get("original_name") or flavor.get("name") or "-"

            instances.append({
                "id": vm_id,
                "name": name,
                "status": status,
                "ip_private": ip_private,
                "ip_floating": ip_floating,
                "flavor": {"name": str(flavor)},
                "volumes": []
            })

        return jsonify({"instances": instances})

    except Exception as e:
        return jsonify({"instances": [], "error": str(e)}), 500

# ============================================================
# 3) HOST INVENTORY
# ============================================================

def is_installed(cmd):
    return subprocess.call(
        ["bash", "-lc", f"command -v {cmd} >/dev/null 2>&1"]
    ) == 0


@api_bp.route("/api/host/inventory", methods=["GET"])
def api_host_inventory():
    tools = [
        ("The Sleuth Kit (TSK)", "tsk_recover"),
        ("Tcpdump", "tcpdump"),
        ("Tshark", "tshark"),
        ("Termshark", "termshark"),
        ("Volatility 3", "volatility")
    ]

    out = []
    for name, binname in tools:
        out.append({
            "name": name,
            "status": "installed" if is_installed(binname) else "missing"
        })

    return jsonify({"tools": out})

# ============================================================
# 4) LIVE TRAFFIC – CORE LOGIC
# ============================================================

def get_vm_ips_live(vm_id):
    """
    Extrae IPs IPv4 del campo 'addresses' (TODOS los formatos).
    """
    try:
        data = run_openstack_json(["server", "show", vm_id])
        addresses = data.get("addresses")
        ips = []

        if isinstance(addresses, dict):
            for entries in addresses.values():
                if isinstance(entries, list):
                    for item in entries:
                        if isinstance(item, dict) and "addr" in item:
                            ips.append(item["addr"])
                        elif isinstance(item, str):
                            ips.extend(re.findall(r"[0-9]+(?:\.[0-9]+){3}", item))
                elif isinstance(entries, str):
                    ips.extend(re.findall(r"[0-9]+(?:\.[0-9]+){3}", entries))

        elif isinstance(addresses, str):
            ips.extend(re.findall(r"[0-9]+(?:\.[0-9]+){3}", addresses))

        return list(set(ips))

    except Exception as e:
        print(f"[ERROR] OpenStack IP discovery fallo: {e}")
        return []


def find_vm_sniff_iface(vm_ips):
    """
    Resuelve la interfaz qbr/tap asociada a una VM usando ARP.
    """
    try:
        neigh = subprocess.check_output(
            ["ip", "neigh", "show"],
            universal_newlines=True
        )
    except Exception:
        return None

    for line in neigh.splitlines():
        for ip in vm_ips:
            if ip in line and "dev" in line:
                parts = line.split()
                return parts[parts.index("dev") + 1]

    return None


def capture_packets(vm_id, selected_protos):
    packet_queue = Queue()

    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        yield "data: [ERROR] No se pudieron obtener IPs de la VM\n\n"
        return

    sniff_iface = find_vm_sniff_iface(vm_ips)
    if not sniff_iface:
        yield "data: [ERROR] No se pudo resolver la interfaz de red de la VM\n\n"
        return

    ip_filter = " or ".join(f"host {ip}" for ip in vm_ips)

    proto_bits = []
    if "modbus" in selected_protos:
        proto_bits.append("tcp port 502")
    if "profinet" in selected_protos:
        proto_bits.append("udp port 34964 or udp port 34962")
    if "tcp" in selected_protos:
        proto_bits.append("tcp")
    if "udp" in selected_protos:
        proto_bits.append("udp")

    proto_filter = " or ".join(proto_bits) if proto_bits else "ip"
    final_bpf = f"({ip_filter}) and ({proto_filter})"

    root = get_project_root()
    capture_dir = os.path.join(
        root, "app_core", "infrastructure", "ics_traffic", "captures"
    )
    os.makedirs(capture_dir, exist_ok=True)

    pcap_path = os.path.join(
        capture_dir, f"audit_{vm_id}_{int(time.time())}.pcap"
    )

    def packet_callback(pkt):
        if not pkt.haslayer(IP):
            return

        label = "IP"
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        sport = dport = ""

        if pkt.haslayer(TCP):
            sport, dport = str(pkt[TCP].sport), str(pkt[TCP].dport)
            label = "MODBUS TCP" if "502" in (sport, dport) else "TCP"

        elif pkt.haslayer(UDP):
            sport, dport = str(pkt[UDP].sport), str(pkt[UDP].dport)
            label = "PROFINET" if dport in ("34964", "34962") else "UDP"

        try:
            wrpcap(pcap_path, pkt, append=True)
        except Exception:
            pass

        ts = time.strftime("%H:%M:%S")
        src = f"{src_ip}:{sport}" if sport else src_ip
        dst = f"{dst_ip}:{dport}" if dport else dst_ip
        packet_queue.put(
            f"data: [{ts}] {label:<12} | {src:>22} -> {dst:<22}\n\n"
        )

    Thread(
        target=sniff,
        kwargs={
            "iface": sniff_iface,
            "filter": final_bpf,
            "prn": packet_callback,
            "store": 0,
            "promisc": True
        },
        daemon=True
    ).start()

    yield f"data: [SISTEMA] Interfaz: {sniff_iface}\n\n"
    yield f"data: [SISTEMA] IPs: {', '.join(vm_ips)}\n\n"
    yield f"data: [SISTEMA] BPF: {final_bpf}\n\n"

    try:
        while True:
            try:
                yield packet_queue.get(timeout=2)
            except Empty:
                yield ": keep-alive\n\n"
    except GeneratorExit:
        pass

# ============================================================
# 5) SSE ENDPOINT
# ============================================================

@api_bp.route("/api/openstack/traffic/<vm_id>", methods=["GET"])
def stream_traffic(vm_id):
    protos = [
        p.strip().lower()
        for p in request.args.get("protos", "").split(",")
        if p.strip()
    ]

    return Response(
        capture_packets(vm_id, protos),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )
