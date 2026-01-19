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
    """Generador SSE que gestiona el sniffing de Scapy."""
    packet_queue = Queue()
    
    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        yield "data: [ERROR] No se pudieron obtener las IPs de la VM. Revise conexión con OpenStack.\n\n"
        return

    sniff_iface = find_vm_sniff_iface(vm_ips)
    
    # Configuración de Filtros BPF
    ip_filter = " or ".join(f"host {ip}" for ip in vm_ips)
    
    proto_bits = []
    if "modbus" in selected_protos: proto_bits.append("tcp port 502")
    if "profinet" in selected_protos: proto_bits.append("udp port 34964 or udp port 34962")
    if "tcp" in selected_protos: proto_bits.append("tcp")
    if "udp" in selected_protos: proto_bits.append("udp")
    
    proto_filter = " or ".join(proto_bits) if proto_bits else "ip"
    final_bpf = f"({ip_filter}) and ({proto_filter})"

    # Gestión de archivos PCAP
    capture_dir = os.path.join(os.getcwd(), "captures")
    os.makedirs(capture_dir, exist_ok=True)
    pcap_filename = f"audit_{vm_id}_{int(time.time())}.pcap"
    pcap_path = os.path.join(capture_dir, pcap_filename)

    def packet_callback(pkt):
        if not pkt.haslayer(IP): return
        
        src, dst = pkt[IP].src, pkt[IP].dst
        sport = pkt.sport if hasattr(pkt, 'sport') else ""
        dport = pkt.dport if hasattr(pkt, 'dport') else ""
        
        # Etiquetado ICS
        label = "IP"
        if pkt.haslayer(TCP): label = "MODBUS" if 502 in (sport, dport) else "TCP"
        elif pkt.haslayer(UDP): label = "PROFINET" if dport in (34964, 34962) else "UDP"

        # Guardar en disco
        try:
            wrpcap(pcap_path, pkt, append=True)
        except:
            pass

        # Formatear para el terminal de la UI
        ts = time.strftime("%H:%M:%S")
        msg = f"data: [{ts}] {label:<10} | {src}:{sport} -> {dst}:{dport}\n\n"
        packet_queue.put(msg)

    # Iniciar Sniffer en segundo plano
    sniff_thread = Thread(
        target=sniff,
        kwargs={
            "iface": sniff_iface,
            "filter": final_bpf,
            "prn": packet_callback,
            "store": 0,
            "promisc": True
        },
        daemon=True
    )
    sniff_thread.start()

    yield f"data: [INFO] Escuchando en {sniff_iface}\n\n"
    yield f"data: [INFO] Filtro BPF: {final_bpf}\n\n"
    yield f"data: [INFO] Archivo: {pcap_filename}\n\n"

    try:
        while True:
            try:
                # El timeout evita que el generador se bloquee si no hay tráfico
                yield packet_queue.get(timeout=1.5)
            except Empty:
                yield ": keep-alive\n\n"
    except GeneratorExit:
        print(f"[SISTEMA] Conexión cerrada. Captura {pcap_filename} finalizada.")

# --- ENDPOINTS ---

@traffic_bp.route("/api/openstack/traffic/<vm_id>")
def stream_traffic(vm_id):
    """Endpoint principal para el terminal de tráfico."""
    protos = request.args.get("protos", "tcp,udp").split(",")
    return Response(
        capture_packets_generator(vm_id, protos),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )

@traffic_bp.route("/api/openstack/traffic/download/<filename>")
def download_pcap(filename):
    """Permite descargar la captura forense una vez terminada."""
    capture_dir = os.path.join(os.getcwd(), "captures")
    return send_from_directory(capture_dir, filename, as_attachment=True)