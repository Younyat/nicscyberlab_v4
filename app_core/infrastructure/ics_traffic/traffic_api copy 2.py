import os
import re
import time
import json
import subprocess
from threading import Thread
from queue import Queue, Empty
from flask import Blueprint, Response, request, send_from_directory
from scapy.all import sniff, IP, TCP, UDP, wrpcap

# Definición del Blueprint para esta infraestructura
traffic_bp = Blueprint('traffic_api', __name__)

def run_openstack_json(cmd):
    """Ejecuta comandos de OpenStack y retorna un diccionario."""
    try:
        # Forzar formato JSON
        full_cmd = ["openstack"] + cmd + ["-f", "json"]
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[TRAFFIC_API] Error OpenStack CLI: {e}")
        return {}

def get_vm_ips_live(vm_id):
    """Obtiene las IPs reales de la instancia mediante la API de OpenStack."""
    data = run_openstack_json(["server", "show", vm_id])
    if not data:
        return []

    ips = []
    # Intentar extraer del campo 'addresses'
    addresses = data.get("addresses", {})
    if isinstance(addresses, dict):
        for net in addresses.values():
            for entry in net:
                if isinstance(entry, dict) and 'addr' in entry:
                    ips.append(entry['addr'])
    
    # Fallback: Regex por si el formato JSON cambia entre versiones de CLI
    if not ips:
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", json.dumps(data))

    # Filtrar solo IPv4 y eliminar duplicados
    return list(set([ip for ip in ips if ":" not in ip]))

def find_vm_sniff_iface(vm_ips):
    """Busca la interfaz de red (tap/qbr) en el nodo local."""
    try:
        # Escaneamos la tabla de vecinos ARP
        neigh = subprocess.check_output(["ip", "neigh", "show"], universal_newlines=True)
        for line in neigh.splitlines():
            for ip in vm_ips:
                if ip in line and "dev" in line:
                    parts = line.split()
                    return parts[parts.index("dev") + 1]
    except Exception:
        pass
    
    # En entornos OVS, br-int suele ser el punto de agregación
    return "br-int"
def capture_packets_generator(vm_id, selected_protos):
    packet_queue = Queue()
    vm_ips = get_vm_ips_live(vm_id)
    
    if not vm_ips:
        yield "data: [ERROR] No se detectaron IPs.\n\n"
        return

    sniff_iface = find_vm_sniff_iface(vm_ips)
    
    # Limpiar la lista de protocolos (quitar espacios y vacíos)
    protos = [p.strip().lower() for p in selected_protos if p.strip()]
    
    # 1. Filtro de IP (Origen o Destino)
    ip_filter = " or ".join(f"host {ip}" for ip in vm_ips)
    
    # 2. Construcción de fragmentos BPF
    proto_bits = []
    
    # Si el usuario eligió Modbus
    if "modbus" in protos:
        proto_bits.append("tcp port 502")
    
    # Si el usuario eligió Profinet
    if "profinet" in protos:
        proto_bits.append("udp port 34964 or udp port 34962")
    
    # Si eligió TCP o UDP genérico
    if "tcp" in protos:
        proto_bits.append("tcp")
    if "udp" in protos:
        proto_bits.append("udp")

    # 3. Combinar filtros
    # Si no hay protocolos seleccionados, capturamos todo lo que sea IP de esa VM
    if not proto_bits:
        final_bpf = f"ip and ({ip_filter})"
    else:
        combined_protos = " or ".join(proto_bits)
        final_bpf = f"({ip_filter}) and ({combined_protos})"

    def packet_callback(pkt):
        if not pkt.haslayer(IP): return
        
        src, dst = pkt[IP].src, pkt[IP].dst
        sport = pkt.sport if hasattr(pkt, 'sport') else 0
        dport = pkt.dport if hasattr(pkt, 'dport') else 0
        
        # Clasificación para la UI
        label = "TCP" if pkt.haslayer(TCP) else "UDP"
        if 502 in (sport, dport): label = "MODBUS"
        elif dport in (34964, 34962): label = "PROFINET"

        ts = time.strftime("%H:%M:%S")
        msg = f"data: [{ts}] {label:<10} | {src}:{sport} -> {dst}:{dport}\n\n"
        packet_queue.put(msg)

    # Iniciar Sniffer (Asegurar que store=0 para no saturar memoria)
    sniff_thread = Thread(
        target=sniff,
        kwargs={"iface": sniff_iface, "filter": final_bpf, "prn": packet_callback, "store": 0},
        daemon=True
    )
    sniff_thread.start()

    yield f"data: [SISTEMA] Sniffer iniciado en {sniff_iface}\n\n"
    yield f"data: [SISTEMA] Filtro aplicado: {final_bpf}\n\n"

    try:
        while True:
            try:
                yield packet_queue.get(timeout=2.0)
            except Empty:
                yield ": keep-alive\n\n"
    except GeneratorExit:
        pass

# --- ENDPOINTS ---




@traffic_bp.route("/api/openstack/traffic/<vm_id>")
def stream_traffic(vm_id):
    # Captura los protocolos de la URL: ?protos=modbus,tcp
    protos_list = request.args.get("protos", "modbus").split(",")
    return Response(
        capture_packets_generator(vm_id, protos_list),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )



@traffic_bp.route("/api/openstack/traffic/download/<filename>")
def download_pcap(filename):
    """Permite descargar la captura forense una vez terminada."""
    capture_dir = os.path.join(os.getcwd(), "captures")
    return send_from_directory(capture_dir, filename, as_attachment=True)