import os
import re
import time
import json
import subprocess
from threading import Thread, Event
from queue import Queue, Empty
from flask import Blueprint, Response, request, send_from_directory
from scapy.all import sniff, IP, TCP, UDP, PcapWriter

# Definición del Blueprint
traffic_bp = Blueprint('traffic_api', __name__)

# Configuración de rutas absolutas para evitar problemas de directorios
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Ruta solicitada: app_core/infrastructure/ics_traffic/captures
CAPTURE_DIR = os.path.join(BASE_DIR, "captures", "captures")

if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR, mode=0o777, exist_ok=True)

def run_openstack_json(cmd):
    """Ejecuta comandos de OpenStack y retorna un diccionario."""
    try:
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
    addresses = data.get("addresses", {})
    if isinstance(addresses, dict):
        for net in addresses.values():
            for entry in net:
                if isinstance(entry, dict) and 'addr' in entry:
                    ips.append(entry['addr'])
    
    if not ips:
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", json.dumps(data))

    return list(set([ip for ip in ips if ":" not in ip]))

def find_vm_sniff_iface(vm_ips):
    """Busca la interfaz de red en el nodo local."""
    try:
        neigh = subprocess.check_output(["ip", "neigh", "show"], universal_newlines=True)
        for line in neigh.splitlines():
            for ip in vm_ips:
                if ip in line and "dev" in line:
                    parts = line.split()
                    return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "br-int"

def capture_packets_generator(vm_id, selected_protos):
    """Generador SSE con guardado en PCAP y control de parada."""
    packet_queue = Queue()
    stop_event = Event()  # Para detener el hilo de Scapy limpiamente
    
    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        yield "data: [ERROR] No se detectaron IPs en la VM.\n\n"
        return

    sniff_iface = find_vm_sniff_iface(vm_ips)
    
    # 1. Configuración de Filtros BPF
    protos = [p.strip().lower() for p in selected_protos if p.strip()]
    ip_filter = " or ".join(f"host {ip}" for ip in vm_ips)
    
    proto_bits = []
    if "modbus" in protos: proto_bits.append("tcp port 502")
    if "profinet" in protos: proto_bits.append("udp port 34964 or udp port 34962")
    if "tcp" in protos: proto_bits.append("tcp")
    if "udp" in protos: proto_bits.append("udp")

    final_bpf = f"({ip_filter})"
    if proto_bits:
        final_bpf += f" and ({' or '.join(proto_bits)})"

    # 2. Configuración del archivo PCAP
    pcap_filename = f"{vm_id}.pcap"
    pcap_path = os.path.join(CAPTURE_DIR, pcap_filename)
    
    # linktype=1 define Ethernet para evitar advertencias de Scapy
    pkts_writer = PcapWriter(pcap_path, append=False, sync=True, linktype=1)

    def packet_callback(pkt):
        if stop_event.is_set():
            return True # Detiene el sniffer
            
        if not pkt.haslayer(IP):
            return
        
        # Guardar en archivo
        try:
            pkts_writer.write(pkt)
        except:
            pass
        
        # Preparar datos para UI
        src, dst = pkt[IP].src, pkt[IP].dst
        sport = pkt.sport if hasattr(pkt, 'sport') else 0
        dport = pkt.dport if hasattr(pkt, 'dport') else 0
        
        label = "TCP" if pkt.haslayer(TCP) else "UDP"
        if 502 in (sport, dport): label = "MODBUS"
        elif dport in (34964, 34962): label = "PROFINET"

        ts = time.strftime("%H:%M:%S")
        msg = f"data: [{ts}] {label:<10} | {src}:{sport} -> {dst}:{dport}\n\n"
        packet_queue.put(msg)

    # 3. Iniciar Sniffer en hilo separado
    sniff_thread = Thread(
        target=sniff,
        kwargs={
            "iface": sniff_iface,
            "filter": final_bpf,
            "prn": packet_callback,
            "store": 0,
            "stop_filter": lambda x: stop_event.is_set()
        },
        daemon=True
    )
    sniff_thread.start()

    yield f"data: [SISTEMA] Sniffer iniciado en {sniff_iface}\n\n"
    yield f"data: [SISTEMA] Archivo: {pcap_filename}\n\n"

    try:
        while True:
            try:
                # Timeout para no bloquear el bucle y permitir detectar desconexión
                yield packet_queue.get(timeout=1.5)
            except Empty:
                yield ": keep-alive\n\n"
    except GeneratorExit:
        # 4. CIERRE LIMPIO
        stop_event.set()
        time.sleep(0.3) # Tiempo para que Scapy cierre el socket
        pkts_writer.close()
        print(f"[TRAFFIC] Captura finalizada y guardada para {vm_id}")

# --- ENDPOINTS ---

@traffic_bp.route("/api/openstack/traffic/<vm_id>")
def stream_traffic(vm_id):
    """Endpoint para el stream de datos en tiempo real (SSE)."""
    protos_list = request.args.get("protos", "modbus,tcp,udp").split(",")
    return Response(
        capture_packets_generator(vm_id, protos_list),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache", 
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )

@traffic_bp.route("/api/openstack/traffic/download/<filename>")
def download_pcap(filename):
    """Permite la descarga del archivo generado."""
    return send_from_directory(CAPTURE_DIR, filename, as_attachment=True)