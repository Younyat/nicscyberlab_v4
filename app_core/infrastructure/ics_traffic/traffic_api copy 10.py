import os
import re
import time
import json
import subprocess
from threading import Event, Lock
from queue import Queue, Empty
from flask import Blueprint, Response, request, send_from_directory
from scapy.all import IP, TCP, UDP, PcapWriter, AsyncSniffer

import hashlib
from datetime import datetime

# ============================================================
# Blueprint
# ============================================================
traffic_bp = Blueprint("traffic_api", __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Repo root (igual criterio que forensics_api.py)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# Evidence root (debe coincidir con forensics_api.py)
EVIDENCE_ROOT = os.path.join(REPO_ROOT, "app_core", "infrastructure", "forensics", "evidence_store")
os.makedirs(EVIDENCE_ROOT, exist_ok=True)

# Fallback legacy cuando NO hay case_dir
CAPTURE_DIR_LEGACY = os.path.join(BASE_DIR, "captures")
os.makedirs(CAPTURE_DIR_LEGACY, mode=0o777, exist_ok=True)

# Evitar capturas duplicadas por vm_id
_ACTIVE_CAPTURES = set()
_ACTIVE_LOCK = Lock()


# ============================================================
# Helpers (manifest + events) compatibles con forensics_api.py
# ============================================================
def _is_safe_case_dir(case_dir: str) -> bool:
    if not case_dir:
        return False
    case_dir = os.path.normpath(case_dir)
    return case_dir.startswith(os.path.normpath(EVIDENCE_ROOT) + os.sep)

def _manifest_path(case_dir: str) -> str:
    return os.path.join(case_dir, "manifest.json")

def _read_manifest(case_dir: str) -> dict:
    mp = _manifest_path(case_dir)
    if not os.path.exists(mp):
        return {"case_dir": case_dir, "created_at": None, "artifacts": []}
    with open(mp, "r", encoding="utf-8") as f:
        return json.load(f)

def _write_manifest(case_dir: str, manifest: dict):
    mp = _manifest_path(case_dir)
    with open(mp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _events_path(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata", "pipeline_events.jsonl")





def _utc_now_iso() -> str:
    # Mantener compatibilidad (segundos)
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def _utc_now_iso_ms() -> str:
    # Nuevo: milisegundos
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _append_case_event(case_dir: str, event: str, run_id: str = "R1", meta: dict = None):
    os.makedirs(os.path.join(case_dir, "metadata"), exist_ok=True)
    now_epoch = time.time()
    rec = {
        "ts_utc": _utc_now_iso(),          # compat
        "ts_utc_ms": _utc_now_iso_ms(),    # nuevo
        "ts_epoch": now_epoch,             # nuevo (alta resolución, fácil de restar)
        "event": event,
        "run_id": (run_id or "R1"),
        "meta": (meta or {})
    }
    with open(_events_path(case_dir), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")





def _add_artifact_fast(case_dir: str, rel_path: str, a_type: str, sha256: str = None, size: int = None):
    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    if size is None:
        try:
            size = os.path.getsize(abs_path)
        except Exception:
            size = None

    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": a_type,
        "rel_path": rel_path,
        "sha256": sha256,
        "size": size,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)


# ============================================================
# OpenStack helpers
# ============================================================
def run_openstack_json(cmd):
    """Ejecuta comandos de OpenStack y retorna JSON (dict o list)."""
    try:
        full_cmd = ["openstack"] + cmd + ["-f", "json"]
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[TRAFFIC_API] Error OpenStack CLI: {e}")
        return {}

def get_server_port_ids(vm_id):
    """Devuelve lista de Port IDs asociados a la instancia (Neutron ports)."""
    data = run_openstack_json(["port", "list", "--server", vm_id])

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

def get_vm_ips_live(vm_id):
    """Obtiene las IPs (IPv4) de la instancia desde OpenStack (campo 'addresses')."""
    data = run_openstack_json(["server", "show", vm_id])
    if not data:
        return []

    addresses = data.get("addresses", {})
    ips = []

    if isinstance(addresses, dict):
        for net in addresses.values():
            for entry in net:
                if isinstance(entry, dict) and "addr" in entry:
                    ips.append(entry["addr"])
    else:
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", str(addresses))

    if not ips:
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", json.dumps(data))

    return sorted(set(ip for ip in ips if ":" not in ip))

def find_vm_sniff_iface(vm_ips):
    """
    Busca interfaz local probable para esos IPs.
    PRIORIDAD:
      1) ip route get <ip>
      2) ip neigh show
      3) TRAFFIC_DEFAULT_IFACE o 'br-int'
    """
    for ip in vm_ips:
        try:
            out = subprocess.check_output(["ip", "route", "get", ip], universal_newlines=True).strip()
            m = re.search(r"\bdev\s+([^\s]+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass

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


# ============================================================
# Capture generator (SSE)
# - Escribe PCAP + metadata
# - Registra manifest + pipeline_events.jsonl en el case
# ============================================================
def capture_packets_generator(vm_id, selected_protos, case_dir=None, run_id="R1"):
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

    # "Sesión" = desde que entra hasta que finaliza (incluye preparación + captura + teardown)
    session_start_epoch = time.time()

    # "Captura real" = desde sniffer.start() hasta sniffer.stop()
    capture_start_epoch = None
    capture_end_epoch = None

    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield "data: [ERROR] No se detectaron IPs en la VM.\n\n"
        return

    # Selección de interfaz: preferir tap{short} si existe
    tap_iface, port_id = pick_tap_iface_for_vm(vm_id)
    sniff_iface = tap_iface if tap_iface else find_vm_sniff_iface(vm_ips)

    # Filtros BPF
    protos = [p.strip().lower() for p in (selected_protos or []) if p.strip()]
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

    # OUTPUT DIR: case_dir/network/ o legacy captures/
    use_case = bool(case_dir) and _is_safe_case_dir(case_dir)
    if use_case:
        out_dir = os.path.join(case_dir, "network")
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(os.path.join(case_dir, "metadata"), exist_ok=True)
    else:
        out_dir = CAPTURE_DIR_LEGACY

    ts_tag = time.strftime("%Y%m%d_%H%M%SZ", time.gmtime())

    pcap_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.pcap"
    pcap_path = os.path.join(out_dir, pcap_filename)

    meta_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.metadata.json"
    meta_path = os.path.join(out_dir, meta_filename)

    # Rel paths para manifest (solo si use_case)
    pcap_rel = os.path.join("network", pcap_filename) if use_case else None
    meta_rel = os.path.join("network", meta_filename) if use_case else None

    # EVENT: traffic_start (inicio de sesión, NO inicio real de sniffer)
    if use_case:
        _append_case_event(case_dir, "traffic_start", run_id=run_id, meta={
            "vm_id": vm_id,
            "port_id": port_id,
            "iface": sniff_iface,
            "vm_ips": vm_ips,
            "protos": protos,
            "bpf": final_bpf,
            "pcap_rel": pcap_rel,
            "meta_rel": meta_rel
        })

    # Pcap writer
    pkts_writer = PcapWriter(pcap_path, append=False, sync=True, linktype=1)

    # Escribir metadata inicial (sesión)
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "vm_id": vm_id,
                    "run_id": run_id,
                    "port_id": port_id,
                    "vm_ips": vm_ips,
                    "iface": sniff_iface,
                    "bpf": final_bpf,
                    "protos": protos,

                    # compat: start_epoch (pero era sesión)
                    "start_epoch": session_start_epoch,
                    "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

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

    sniffer = AsyncSniffer(
        iface=sniff_iface,
        filter=final_bpf,
        prn=packet_callback,
        store=False,
    )

    try:
        sniffer.start()

        # Captura real empieza cuando el sniffer está arrancado
        capture_start_epoch = time.time()

        # NUEVO: evento explícito de inicio real de captura (defendible para latencias)
        if use_case:
            _append_case_event(case_dir, "traffic_capture_started", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "bpf": final_bpf,
                "pcap_rel": pcap_rel,
                "meta_rel": meta_rel,
                "capture_start_epoch": capture_start_epoch
            })

    except Exception as e:
        termination_reason = f"sniffer_start_failed: {e}"
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)

        if use_case:
            _append_case_event(case_dir, "traffic_failed", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "reason": str(e),
                "bpf": final_bpf
            })

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
        # Cierre limpio: capturar fin real justo al parar sniffer
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
            capture_end_epoch = time.time()
        except OSError as e:
            if termination_reason == "unknown":
                termination_reason = f"oserror: {e}"
            if capture_end_epoch is None:
                capture_end_epoch = time.time()
        except Exception as e:
            if termination_reason == "unknown":
                termination_reason = f"sniffer_stop_exception: {e}"
            if capture_end_epoch is None:
                capture_end_epoch = time.time()

        # NUEVO: evento explícito de parada real de captura
        if use_case and capture_end_epoch is not None:
            _append_case_event(case_dir, "traffic_capture_stopped", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "capture_end_epoch": capture_end_epoch,
                "termination_reason": termination_reason
            })

        try:
            with writer_lock:
                pkts_writer.close()
        except Exception:
            pass

        session_end_epoch = time.time()

        # Duraciones (sin romper compatibilidad)
        session_duration_s = round(session_end_epoch - session_start_epoch, 3)
        capture_duration_s = None
        if capture_start_epoch is not None and capture_end_epoch is not None:
            capture_duration_s = round(capture_end_epoch - capture_start_epoch, 3)

        # Completar metadata (final)
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update(
            {
                "end_epoch": session_end_epoch,
                "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

                # compat: duration_s = sesión
                "duration_s": session_duration_s,

                # nuevo: métricas profesionales
                "session_start_epoch": session_start_epoch,
                "session_end_epoch": session_end_epoch,
                "session_duration_s": session_duration_s,

                "capture_start_epoch": capture_start_epoch,
                "capture_end_epoch": capture_end_epoch,
                "capture_duration_s": capture_duration_s,

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

        # Registrar en manifest + pipeline event (solo si case)
        if use_case:
            pcap_size = None
            meta_size = None
            pcap_sha = None
            meta_sha = None

            try:
                try:
                    pcap_size = os.path.getsize(pcap_path)
                except Exception:
                    pcap_size = None
                try:
                    meta_size = os.path.getsize(meta_path)
                except Exception:
                    meta_size = None

                # PCAP normalmente no es gigante: hashear aquí es OK
                try:
                    pcap_sha = _sha256_file(pcap_path)
                except Exception:
                    pcap_sha = None
                try:
                    meta_sha = _sha256_file(meta_path)
                except Exception:
                    meta_sha = None

                if pcap_rel and os.path.exists(os.path.join(case_dir, pcap_rel)):
                    _add_artifact_fast(case_dir, pcap_rel, "pcap", sha256=pcap_sha, size=pcap_size)
                if meta_rel and os.path.exists(os.path.join(case_dir, meta_rel)):
                    _add_artifact_fast(case_dir, meta_rel, "pcap_metadata", sha256=meta_sha, size=meta_size)

            except Exception:
                pass

            _append_case_event(case_dir, "traffic_stopped", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "pcap_rel": pcap_rel,
                "pcap_sha256": pcap_sha,
                "pcap_size": pcap_size,
                "meta_rel": meta_rel,
                "meta_sha256": meta_sha,
                "meta_size": meta_size,
                "packets_written": pkts_written,

                # compat: duration_s = sesión
                "duration_s": session_duration_s,

                # nuevo: duración real de captura
                "capture_duration_s": capture_duration_s,

                "termination_reason": termination_reason
            })

        print(
            f"[TRAFFIC] Captura finalizada para {vm_id} "
            f"(run_id={run_id}, reason={termination_reason}, pkts={pkts_written}, "
            f"session_s={session_duration_s}, capture_s={capture_duration_s})"
        )

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

    # "Sesión" = desde que entra hasta que finaliza (incluye preparación + captura + teardown)
    session_start_epoch = time.time()

    # "Captura real" = desde sniffer.start() hasta sniffer.stop()
    capture_start_epoch = None
    capture_end_epoch = None

    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield "data: [ERROR] No se detectaron IPs en la VM.\n\n"
        return

    # Selección de interfaz: preferir tap{short} si existe
    tap_iface, port_id = pick_tap_iface_for_vm(vm_id)
    sniff_iface = tap_iface if tap_iface else find_vm_sniff_iface(vm_ips)

    # Filtros BPF
    protos = [p.strip().lower() for p in (selected_protos or []) if p.strip()]
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

    # OUTPUT DIR: case_dir/network/ o legacy captures/
    use_case = bool(case_dir) and _is_safe_case_dir(case_dir)
    if use_case:
        out_dir = os.path.join(case_dir, "network")
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(os.path.join(case_dir, "metadata"), exist_ok=True)
    else:
        out_dir = CAPTURE_DIR_LEGACY

    ts_tag = time.strftime("%Y%m%d_%H%M%SZ", time.gmtime())

    pcap_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.pcap"
    pcap_path = os.path.join(out_dir, pcap_filename)

    meta_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.metadata.json"
    meta_path = os.path.join(out_dir, meta_filename)

    # Rel paths para manifest (solo si use_case)
    pcap_rel = os.path.join("network", pcap_filename) if use_case else None
    meta_rel = os.path.join("network", meta_filename) if use_case else None

    # EVENT: traffic_start (solo si case) — (inicio de sesión de captura, no "captura real")
    if use_case:
        _append_case_event(case_dir, "traffic_start", run_id=run_id, meta={
            "vm_id": vm_id,
            "port_id": port_id,
            "iface": sniff_iface,
            "vm_ips": vm_ips,
            "protos": protos,
            "bpf": final_bpf,
            "pcap_rel": pcap_rel,
            "meta_rel": meta_rel
        })

    # Pcap writer
    pkts_writer = PcapWriter(pcap_path, append=False, sync=True, linktype=1)

    # Escribir metadata inicial (sesión)
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "vm_id": vm_id,
                    "run_id": run_id,
                    "port_id": port_id,
                    "vm_ips": vm_ips,
                    "iface": sniff_iface,
                    "bpf": final_bpf,
                    "protos": protos,

                    # compat: lo que antes llamabas start_epoch (pero era sesión)
                    "start_epoch": session_start_epoch,
                    "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

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

    sniffer = AsyncSniffer(
        iface=sniff_iface,
        filter=final_bpf,
        prn=packet_callback,
        store=False,
    )

    try:
        sniffer.start()
        # Captura real empieza cuando el sniffer está arrancado
        capture_start_epoch = time.time()
    except Exception as e:
        termination_reason = f"sniffer_start_failed: {e}"
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)

        if use_case:
            _append_case_event(case_dir, "traffic_failed", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "reason": str(e),
                "bpf": final_bpf
            })

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
        # Cierre limpio: capturar fin real justo al parar sniffer
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
            capture_end_epoch = time.time()
        except OSError as e:
            if termination_reason == "unknown":
                termination_reason = f"oserror: {e}"
            if capture_end_epoch is None:
                capture_end_epoch = time.time()
        except Exception as e:
            if termination_reason == "unknown":
                termination_reason = f"sniffer_stop_exception: {e}"
            if capture_end_epoch is None:
                capture_end_epoch = time.time()

        try:
            with writer_lock:
                pkts_writer.close()
        except Exception:
            pass

        session_end_epoch = time.time()

        # Duraciones (sin romper compatibilidad)
        session_duration_s = round(session_end_epoch - session_start_epoch, 3)
        capture_duration_s = None
        if capture_start_epoch is not None and capture_end_epoch is not None:
            # Si hubo arranque/parada real del sniffer
            capture_duration_s = round(capture_end_epoch - capture_start_epoch, 3)

        # Completar metadata (final)
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update(
            {
                "end_epoch": session_end_epoch,
                "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

                # compat: si tu UI/pipeline ya espera duration_s, lo mantenemos = sesión
                "duration_s": session_duration_s,

                # nuevo: métricas profesionales (no rompe nada)
                "session_start_epoch": session_start_epoch,
                "session_end_epoch": session_end_epoch,
                "session_duration_s": session_duration_s,

                "capture_start_epoch": capture_start_epoch,
                "capture_end_epoch": capture_end_epoch,
                "capture_duration_s": capture_duration_s,

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

        # Registrar en manifest + pipeline event (solo si case)
        if use_case:
            pcap_size = None
            meta_size = None
            pcap_sha = None
            meta_sha = None

            try:
                try:
                    pcap_size = os.path.getsize(pcap_path)
                except Exception:
                    pcap_size = None
                try:
                    meta_size = os.path.getsize(meta_path)
                except Exception:
                    meta_size = None

                # PCAP normalmente no es gigante: hashear aquí es OK
                try:
                    pcap_sha = _sha256_file(pcap_path)
                except Exception:
                    pcap_sha = None
                try:
                    meta_sha = _sha256_file(meta_path)
                except Exception:
                    meta_sha = None

                if pcap_rel and os.path.exists(os.path.join(case_dir, pcap_rel)):
                    _add_artifact_fast(case_dir, pcap_rel, "pcap", sha256=pcap_sha, size=pcap_size)
                if meta_rel and os.path.exists(os.path.join(case_dir, meta_rel)):
                    _add_artifact_fast(case_dir, meta_rel, "pcap_metadata", sha256=meta_sha, size=meta_size)

            except Exception:
                pass

            _append_case_event(case_dir, "traffic_stopped", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "pcap_rel": pcap_rel,
                "pcap_sha256": pcap_sha,
                "pcap_size": pcap_size,
                "meta_rel": meta_rel,
                "meta_sha256": meta_sha,
                "meta_size": meta_size,
                "packets_written": pkts_written,

                # compat: duration_s = sesión (igual que antes)
                "duration_s": session_duration_s,

                # nuevo: duración real de captura (sniffer start->stop)
                "capture_duration_s": capture_duration_s,

                "termination_reason": termination_reason
            })

        print(
            f"[TRAFFIC] Captura finalizada para {vm_id} "
            f"(run_id={run_id}, reason={termination_reason}, pkts={pkts_written}, "
            f"session_s={session_duration_s}, capture_s={capture_duration_s})"
        )

# ============================================================
# Endpoints
# ============================================================
@traffic_bp.route("/api/openstack/traffic/<vm_id>")
def stream_traffic(vm_id):
    protos_list = (request.args.get("protos", "modbus,tcp,udp") or "modbus,tcp,udp").split(",")
    case_dir = (request.args.get("case_dir", "").strip() or None)
    run_id = (request.args.get("run_id", "R1") or "R1").strip()

    return Response(
        capture_packets_generator(vm_id, protos_list, case_dir=case_dir, run_id=run_id),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

@traffic_bp.route("/api/openstack/traffic/download/<filename>")
def download_pcap(filename):
    """
    Descarga PCAP/metadata.
    - Si llega case_dir válido: busca en case_dir/network/
    - Si no: usa legacy captures/
    """
    case_dir = request.args.get("case_dir", "").strip() or None

    # anti-traversal básico
    if not filename or ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        return ("filename inválido", 400)

    if case_dir and _is_safe_case_dir(case_dir):
        directory = os.path.join(case_dir, "network")
    else:
        directory = CAPTURE_DIR_LEGACY

    return send_from_directory(directory, filename, as_attachment=True)


