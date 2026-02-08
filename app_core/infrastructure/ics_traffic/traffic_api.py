import os
import re
import time
import json
import subprocess
from threading import Thread, Event, Lock
from queue import Queue, Empty
from flask import Blueprint, Response, request, send_from_directory
from scapy.all import IP, TCP, UDP, PcapWriter, AsyncSniffer

# Definición del Blueprint
traffic_bp = Blueprint('traffic_api', __name__)

# Configuración de rutas absolutas para evitar problemas de directorios
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ruta solicitada: app_core/infrastructure/ics_traffic/captures
# OJO: tu código tenía "captures/captures". Mantengo la intención, pero lo normal es solo "captures".
# Si realmente quieres doble carpeta, deja esto como estaba.
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")

if not os.path.exists(CAPTURE_DIR):
    os.makedirs(CAPTURE_DIR, mode=0o777, exist_ok=True)

# Evitar capturas duplicadas por vm_id (causa del doble "Captura finalizada...")
_ACTIVE_CAPTURES = set()
_ACTIVE_LOCK = Lock()



def get_server_port_ids(vm_id):
    """Devuelve lista de Port IDs asociados a la instancia (Neutron ports)."""
    data = run_openstack_json(["port", "list", "--server", vm_id])

    # openstack -f json devuelve una LISTA de dicts
    if isinstance(data, list):
        ids = []
        for row in data:
            pid = row.get("ID") or row.get("Id") or row.get("id")
            if pid:
                ids.append(pid)
        return ids

    return []



def pick_tap_iface_for_vm(vm_id):
    """
    Devuelve (iface, port_id) usando port_id->tap{short} si existe en /sys/class/net.
    Prioridad: tap{short} existe localmente.
    Fallback: (None, primer port_id si existe).
    """
    port_ids = get_server_port_ids(vm_id)
    for pid in port_ids:
        short = pid[:11]
        tap = f"tap{short}"
        if os.path.exists(f"/sys/class/net/{tap}"):
            return tap, pid

    return None, (port_ids[0] if port_ids else None)







def run_openstack_json(cmd):
    """Ejecuta comandos de OpenStack y retorna JSON (dict o list)."""
    try:
        full_cmd = ["openstack"] + cmd + ["-f", "json"]
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[TRAFFIC_API] Error OpenStack CLI: {e}")
        return {}


def get_vm_ips_live(vm_id):
    """Obtiene las IPs (IPv4) de la instancia desde OpenStack (campo 'addresses')."""
    data = run_openstack_json(["server", "show", vm_id])
    if not data:
        return []

    addresses = data.get("addresses", {})
    ips = []

    if isinstance(addresses, dict):
        # Algunas clouds devuelven dict estructurado
        for net in addresses.values():
            for entry in net:
                if isinstance(entry, dict) and "addr" in entry:
                    ips.append(entry["addr"])
    else:
        # Lo habitual: string tipo "net=192.168.100.28, 10.0.2.9"
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", str(addresses))

    if not ips:
        # Fallback duro
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", json.dumps(data))

    # Solo IPv4 únicas
    return sorted(set(ip for ip in ips if ":" not in ip))


def find_vm_sniff_iface(vm_ips):
    """
    Busca interfaz local probable para esos IPs.
    PRIORIDAD:
      1) ip route get <ip>  (más fiable)
      2) ip neigh show
      3) fallback: env TRAFFIC_DEFAULT_IFACE o 'br-int'
    """
    # 1) route get
    for ip in vm_ips:
        try:
            out = subprocess.check_output(["ip", "route", "get", ip], universal_newlines=True).strip()
            m = re.search(r"\bdev\s+([^\s]+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass

    # 2) neigh
    try:
        neigh = subprocess.check_output(["ip", "neigh", "show"], universal_newlines=True)
        for line in neigh.splitlines():
            for ip in vm_ips:
                if ip in line and " dev " in line:
                    parts = line.split()
                    return parts[parts.index("dev") + 1]
    except Exception:
        pass

    return os.environ.get("TRAFFIC_DEFAULT_IFACE", "br-int")




def capture_packets_generator(vm_id, selected_protos):
    """Generador SSE: captura tráfico (Scapy) y escribe PCAP + metadata con cierre limpio."""
    packet_queue = Queue()
    stop_event = Event()

    # Bloqueo: una captura activa por vm_id
    with _ACTIVE_LOCK:
        if vm_id in _ACTIVE_CAPTURES:
            yield "data: [ERROR] Ya existe una captura activa para este vm_id.\n\n"
            return
        _ACTIVE_CAPTURES.add(vm_id)

    writer_lock = Lock()
    pkts_written = 0
    termination_reason = "unknown"
    start_ts = time.time()

    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield "data: [ERROR] No se detectaron IPs en la VM.\n\n"
        return

    # Selección de interfaz: preferir tap{short} si existe (captura real del port)
    tap_iface, port_id = pick_tap_iface_for_vm(vm_id)
    if tap_iface:
        sniff_iface = tap_iface
    else:
        sniff_iface = find_vm_sniff_iface(vm_ips)  # fallback

    # 1) Filtros BPF
    protos = [p.strip().lower() for p in selected_protos if p.strip()]
    ip_filter = " or ".join(f"host {ip}" for ip in vm_ips)

    proto_bits = []
    if "modbus" in protos:
        proto_bits.append("tcp port 502")
    if "profinet" in protos:
        proto_bits.append("udp port 34964 or udp port 34962")
    if "tcp" in protos:
        proto_bits.append("tcp")
    if "udp" in protos:
        proto_bits.append("udp")

    final_bpf = f"({ip_filter})"
    if proto_bits:
        final_bpf += f" and ({' or '.join(proto_bits)})"

    # DEBUG (colócalo aquí: ya tienes vm_id/port_id/iface/ips/bpf)
    print(f"[TRAFFIC_DEBUG] vm_id={vm_id} port_id={port_id} iface={sniff_iface} ips={vm_ips} bpf={final_bpf}")

    # 2) PCAP + metadata
    pcap_filename = f"{vm_id}.pcap"
    pcap_path = os.path.join(CAPTURE_DIR, pcap_filename)

    meta_filename = f"{vm_id}.metadata.json"
    meta_path = os.path.join(CAPTURE_DIR, meta_filename)

    pkts_writer = PcapWriter(pcap_path, append=False, sync=True, linktype=1)

    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "vm_id": vm_id,
                    "port_id": port_id,
                    "vm_ips": vm_ips,
                    "iface": sniff_iface,
                    "bpf": final_bpf,
                    "protos": protos,
                    "start_epoch": start_ts,
                    "start_local": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "pcap_file": pcap_filename,
                },
                f,
                indent=2,
            )
    except Exception:
        pass

    def packet_callback(pkt):
        nonlocal pkts_written
        if stop_event.is_set():
            return

        if not pkt.haslayer(IP):
            return

        # Escribir PCAP
        try:
            with writer_lock:
                pkts_writer.write(pkt)
                pkts_written += 1
        except Exception:
            pass

        # Mensaje SSE
        src, dst = pkt[IP].src, pkt[IP].dst
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0

        label = "TCP" if pkt.haslayer(TCP) else "UDP"
        if 502 in (sport, dport):
            label = "MODBUS"
        elif dport in (34964, 34962) or sport in (34964, 34962):
            label = "PROFINET"

        ts = time.strftime("%H:%M:%S")
        packet_queue.put(f"data: [{ts}] {label:<10} | {src}:{sport} -> {dst}:{dport}\n\n")

    # 3) Sniffer
    sniffer = AsyncSniffer(
        iface=sniff_iface,
        filter=final_bpf,
        prn=packet_callback,
        store=False,
    )

    try:
        sniffer.start()
    except Exception as e:
        termination_reason = f"sniffer_start_failed: {e}"
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield f"data: [ERROR] No se pudo iniciar sniffer en {sniff_iface}: {e}\n\n"
        return

    yield f"data: [SISTEMA] Sniffer iniciado en {sniff_iface}\n\n"
    yield f"data: [SISTEMA] BPF: {final_bpf}\n\n"
    yield f"data: [SISTEMA] Archivo: {pcap_filename}\n\n"

    try:
        while True:
            try:
                yield packet_queue.get(timeout=1.5)
            except Empty:
                yield ": keep-alive\n\n"

    except GeneratorExit:
        termination_reason = "client_disconnect"
        stop_event.set()

    except Exception as e:
        termination_reason = f"generator_exception: {e}"
        stop_event.set()

    finally:
        # 4) Cierre limpio
        try:
            sniffer.stop()
        except OSError as e:
            termination_reason = f"oserror: {e}"
        except Exception as e:
            termination_reason = f"sniffer_stop_exception: {e}"

        try:
            with writer_lock:
                pkts_writer.close()
        except Exception:
            pass

        end_ts = time.time()

        # Completar metadata
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update(
            {
                "end_epoch": end_ts,
                "end_local": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_s": round(end_ts - start_ts, 3),
                "packets_written": pkts_written,
                "termination_reason": termination_reason,
            }
        )

        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            pass

        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)

        print(f"[TRAFFIC] Captura finalizada y guardada para {vm_id} (reason={termination_reason}, pkts={pkts_written})")

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
