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
CAPTURE_DIR_LEGACY = os.path.join(EVIDENCE_ROOT, "_legacy_captures", "victim-node-captures")
os.makedirs(CAPTURE_DIR_LEGACY, exist_ok=True)


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
# CHAIN OF CUSTODY (append-only + hash chaining) - traffic_api
# ============================================================

def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _read_last_custody_hash(case_dir: str) -> str:
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        return "0" * 64
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size <= 0:
                return "0" * 64
            back = min(8192, size)
            f.seek(-back, os.SEEK_END)
            tail = f.read().decode("utf-8", errors="ignore")
        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return "0" * 64
        last = json.loads(lines[-1])
        h = (last.get("entry_hash") or "").strip()
        return h if h else "0" * 64
    except Exception:
        return "0" * 64

def _ensure_custody_file(case_dir: str) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        try:
            from pathlib import Path
            Path(p).touch()
        except Exception:
            pass

def _append_custody_entry(
    case_dir: str,
    action: str,
    run_id: str,
    artifact_rel: str = None,
    outcome: str = "ok",
    details: dict = None
) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    _ensure_custody_file(case_dir)

    prev_hash = _read_last_custody_hash(case_dir)
    ts = _utc_now_iso()

    entry = {
        "ts_utc": ts,
        "ts_epoch": time.time(),
        "run_id": (run_id or "R1"),
        "actor": "traffic_api",
        "action": action,
        "artifact_rel": artifact_rel,
        "outcome": outcome,
        "details": (details or {}),
        "prev_hash": prev_hash,
    }

    payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    entry["entry_hash"] = _sha256_hex(payload)

    with open(_custody_path(case_dir), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def _register_custody_artifact(case_dir: str) -> None:
    rel = "chain_of_custody.log"
    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return
    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None
    _add_artifact_fast(case_dir, rel, "custody_log", sha256=sha, size=size)





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

def _preflight_capture_ready(iface: str, bpf: str = None):
    """
    Comprueba antes de arrancar la captura que:
      - la interfaz existe
      - tenemos permisos reales para abrir captura en esa interfaz

    Usa tcpdump -d para validar el filtro sin capturar y
    dumpcap/tcpdump -D o existencia de interfaz para comprobar entorno.
    """
    if not iface:
        return False, "No sniff interface resolved"

    if not os.path.exists(f"/sys/class/net/{iface}"):
        return False, f"Interface '{iface}' does not exist on this host"

    # Validar sintaxis BPF si existe tcpdump
    tcpdump_bin = subprocess.run(
        ["bash", "-lc", "command -v tcpdump || true"],
        capture_output=True,
        text=True
    ).stdout.strip()

    if tcpdump_bin and bpf:
        try:
            chk = subprocess.run(
                [tcpdump_bin, "-d", bpf],
                capture_output=True,
                text=True,
                timeout=10
            )
            if chk.returncode != 0:
                err = (chk.stderr or chk.stdout or "").strip()
                return False, f"Invalid BPF for tcpdump: {err}"
        except Exception as e:
            return False, f"BPF validation failed: {e}"

    # Prueba real de permisos de captura
    # Intentamos con dumpcap si existe, si no con tcpdump -i iface -c 1
    dumpcap_bin = subprocess.run(
        ["bash", "-lc", "command -v dumpcap || true"],
        capture_output=True,
        text=True
    ).stdout.strip()

    try:
        if dumpcap_bin:
            chk = subprocess.run(
                [dumpcap_bin, "-i", iface, "-f", bpf or "", "-a", "duration:1", "-w", "/dev/null"],
                capture_output=True,
                text=True,
                timeout=5
            )
        elif tcpdump_bin:
            cmd = [tcpdump_bin, "-i", iface, "-c", "1", "-nn"]
            if bpf:
                cmd.append(bpf)
            chk = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
        else:
            return False, "Neither dumpcap nor tcpdump is available for capture preflight"

        # rc 0 o timeout corto con arranque correcto es aceptable
        stderr_txt = (chk.stderr or "").strip().lower()
        stdout_txt = (chk.stdout or "").strip().lower()
        combined = f"{stdout_txt} {stderr_txt}"

        if "operation not permitted" in combined:
            return False, f"Capture permission denied on interface '{iface}'"
        if "you don't have permission" in combined:
            return False, f"Capture permission denied on interface '{iface}'"
        if "permission denied" in combined:
            return False, f"Capture permission denied on interface '{iface}'"
        if "no such device" in combined:
            return False, f"Interface '{iface}' not usable"
    except subprocess.TimeoutExpired:
        # timeout aquí significa que el backend arrancó y no falló de inmediato
        pass
    except Exception as e:
        return False, f"Capture preflight failed: {e}"

    return True, None




# ============================================================
# Capture generator (SSE)
# - Escribe PCAP + metadata
# - Registra manifest + pipeline_events.jsonl en el case
# ============================================================
def capture_packets_generator(vm_id, selected_protos, case_dir=None, run_id="R1"):
    """
    SSE generator:
      - Captura tráfico y escribe PCAP + metadata.
      - Si case_dir es válido:
          * registra pipeline_events.jsonl
          * registra manifest
          * exporta OT derivado a industrial/
    """
    from scapy.all import Raw

    packet_queue = Queue()
    stop_event = Event()

    with _ACTIVE_LOCK:
        if vm_id in _ACTIVE_CAPTURES:
            yield "data: [ERROR] Ya existe una captura activa para este vm_id.\n\n"
            return
        _ACTIVE_CAPTURES.add(vm_id)

    writer_lock = Lock()
    pkts_written = 0
    termination_reason = "unknown"

    session_start_epoch = time.time()
    capture_start_epoch = None
    capture_end_epoch = None

    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield "data: [ERROR] No se detectaron IPs en la VM.\n\n"
        return

    tap_iface, port_id = pick_tap_iface_for_vm(vm_id)
    sniff_iface = tap_iface if tap_iface else find_vm_sniff_iface(vm_ips)

    protos = [p.strip().lower() for p in (selected_protos or []) if p and p.strip()]
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

    use_case = bool(case_dir) and _is_safe_case_dir(case_dir)
    if use_case:
        per_vm_dir = os.path.join(case_dir, "network", "per_vm", vm_id)
        os.makedirs(per_vm_dir, exist_ok=True)
        out_dir = per_vm_dir

        meta_dir = os.path.join(case_dir, "metadata")
        os.makedirs(meta_dir, exist_ok=True)

        industrial_dir = os.path.join(case_dir, "industrial")
        os.makedirs(industrial_dir, exist_ok=True)
    else:
        out_dir = CAPTURE_DIR_LEGACY
        industrial_dir = None

    run_id = (run_id or "R1").strip() or "R1"
    ts_tag = time.strftime("%Y%m%d_%H%M%SZ", time.gmtime())

    pcap_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.pcap"
    pcap_path = os.path.join(out_dir, pcap_filename)

    meta_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.metadata.json"
    meta_path = os.path.join(out_dir, meta_filename)

    pcap_rel = os.path.join("network", "per_vm", vm_id, pcap_filename) if use_case else None
    meta_rel = os.path.join("network", "per_vm", vm_id, meta_filename) if use_case else None

    industrial_export_filename = f"ot_export_{vm_id}_{run_id}_{ts_tag}.json"
    industrial_export_path = os.path.join(industrial_dir, industrial_export_filename) if use_case else None
    industrial_export_rel = os.path.join("industrial", industrial_export_filename) if use_case else None

    if use_case:
        _append_case_event(
            case_dir,
            "traffic_start",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "vm_ips": vm_ips,
                "protos": protos,
                "bpf": final_bpf,
                "pcap_rel": pcap_rel,
                "meta_rel": meta_rel,
                "industrial_export_rel": industrial_export_rel,
            },
        )

    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield f"data: [ERROR] No puedo crear out_dir='{out_dir}': {e}\n\n"
        return

    try:
        pkts_writer = PcapWriter(pcap_path, append=False, sync=True, linktype=1)
    except Exception as e:
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)
        yield f"data: [ERROR] No puedo abrir PCAP en '{pcap_path}': {e}\n\n"
        return

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
                    "start_epoch": session_start_epoch,
                    "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "pcap_file": pcap_filename,
                    "industrial_export_file": industrial_export_filename if use_case else None,
                    "pcap_rel": pcap_rel if use_case else None,
                    "meta_rel": meta_rel if use_case else None,
                },
                f,
                indent=2,
            )
    except Exception:
        pass

    ot_ops = []
    ot_ops_max = 2000

    ot_seen_packets_502 = 0
    ot_seen_payload_packets = 0

    ot_first_epoch = None
    ot_last_epoch = None

    sniffer_failed = Event()
    sniffer_failure_reason = {"value": None}

    def _safe_int(x, default=None):
        try:
            return int(x)
        except Exception:
            return default

    def _iter_modbus_adus(payload: bytes):
        if not payload:
            return
        i = 0
        n = len(payload)
        while i + 8 <= n:
            pid = (payload[i + 2] << 8) | payload[i + 3]
            if pid != 0:
                i += 1
                continue

            length = (payload[i + 4] << 8) | payload[i + 5]
            adu_len = 6 + length
            if length <= 1 or i + adu_len > n:
                return

            yield payload[i : i + adu_len]
            i += adu_len

    def _decode_modbus_adu(adu: bytes):
        if not adu or len(adu) < 8:
            return None

        tid = (adu[0] << 8) | adu[1]
        pid = (adu[2] << 8) | adu[3]
        length = (adu[4] << 8) | adu[5]
        unit_id = adu[6]
        if pid != 0 or length <= 1:
            return None

        fc = adu[7]
        data = adu[8:]

        rec = {
            "tid": tid,
            "unit_id": unit_id,
            "fc": fc,
            "mbap_len": length,
            "is_write": fc in (0x05, 0x06, 0x0F, 0x10),
        }

        def u16(b0, b1):
            return (b0 << 8) | b1

        if fc == 0x05 and len(data) >= 4:
            addr = u16(data[0], data[1])
            val = u16(data[2], data[3])
            rec.update({"op": "write_single_coil", "address": addr, "value_raw": val,
                        "value": True if val == 0xFF00 else False if val == 0x0000 else None})
            return rec

        if fc == 0x06 and len(data) >= 4:
            addr = u16(data[0], data[1])
            val = u16(data[2], data[3])
            rec.update({"op": "write_single_register", "address": addr, "value": val})
            return rec

        if fc == 0x0F and len(data) >= 5:
            addr = u16(data[0], data[1])
            qty = u16(data[2], data[3])
            bytecount = data[4]
            values = data[5 : 5 + bytecount] if len(data) >= 5 + bytecount else b""
            rec.update({"op": "write_multiple_coils", "address": addr, "quantity": qty,
                        "bytecount": bytecount, "values_hex": values.hex() if values else None})
            return rec

        if fc == 0x10 and len(data) >= 5:
            addr = u16(data[0], data[1])
            qty = u16(data[2], data[3])
            bytecount = data[4]
            values = data[5 : 5 + bytecount] if len(data) >= 5 + bytecount else b""
            regs = None
            if values and len(values) % 2 == 0:
                regs = [u16(values[i], values[i + 1]) for i in range(0, len(values), 2)]
            rec.update({"op": "write_multiple_registers", "address": addr, "quantity": qty,
                        "bytecount": bytecount, "registers": regs, "values_hex": values.hex() if values else None})
            return rec

        rec.update({"op": "non_write_function", "data_len": len(data),
                    "data_hex_prefix": data[:16].hex() if data else None})
        return rec

    def packet_callback(pkt):
        nonlocal pkts_written, ot_seen_packets_502, ot_seen_payload_packets, ot_first_epoch, ot_last_epoch

        if stop_event.is_set():
            return
        if not pkt.haslayer(IP):
            return

        try:
            with writer_lock:
                pkts_writer.write(pkt)
                pkts_written += 1
        except Exception as e:
            sniffer_failure_reason["value"] = f"pcap_write_failed: {e}"
            sniffer_failed.set()
            return

        try:
            src, dst = pkt[IP].src, pkt[IP].dst
            sport = 0
            dport = 0
            label = "IP"

            if pkt.haslayer(TCP):
                sport = int(pkt[TCP].sport or 0)
                dport = int(pkt[TCP].dport or 0)
                label = "TCP"
            elif pkt.haslayer(UDP):
                sport = int(pkt[UDP].sport or 0)
                dport = int(pkt[UDP].dport or 0)
                label = "UDP"

            if 502 in (sport, dport):
                label = "MODBUS"
            elif (sport in (34964, 34962)) or (dport in (34964, 34962)):
                label = "PROFINET"

            ts = time.strftime("%H:%M:%S")
            packet_queue.put(f"data: [{ts}] {label:<10} | {src}:{sport} -> {dst}:{dport}\n\n")
        except Exception:
            pass

        if not use_case or "modbus" not in protos:
            return
        if not pkt.haslayer(TCP):
            return

        try:
            tcp = pkt[TCP]
            sport = _safe_int(getattr(tcp, "sport", None), 0)
            dport = _safe_int(getattr(tcp, "dport", None), 0)
            if 502 not in (sport, dport):
                return

            pkt_epoch = None
            try:
                pkt_epoch = float(getattr(pkt, "time", None))
            except Exception:
                pkt_epoch = None

            ot_seen_packets_502 += 1
            if pkt_epoch is not None:
                if ot_first_epoch is None:
                    ot_first_epoch = pkt_epoch
                ot_last_epoch = pkt_epoch

            if not pkt.haslayer(Raw):
                return

            raw_payload = bytes(pkt[Raw].load or b"")
            if not raw_payload:
                return

            ot_seen_payload_packets += 1

            for adu in _iter_modbus_adus(raw_payload):
                rec = _decode_modbus_adu(adu)
                if not rec:
                    continue

                rec.update(
                    {
                        "ts_epoch": pkt_epoch,
                        "ts_utc": _utc_now_iso(),
                        "ts_utc_ms": _utc_now_iso_ms(),
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst,
                        "src_port": sport,
                        "dst_port": dport,
                        "direction": "to_server" if dport == 502 else "from_server" if sport == 502 else None,
                    }
                )

                if len(ot_ops) < ot_ops_max:
                    ot_ops.append(rec)

        except Exception:
            return

    ok, preflight_err = _preflight_capture_ready(sniff_iface, final_bpf)
    if not ok:
        termination_reason = f"preflight_failed: {preflight_err}"

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update({
            "end_epoch": time.time(),
            "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "capture_start_epoch": None,
            "capture_end_epoch": None,
            "capture_duration_s": None,
            "packets_written": 0,
            "termination_reason": termination_reason,
        })

        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            pass

        if use_case:
            _append_case_event(
                case_dir,
                "traffic_failed",
                run_id=run_id,
                meta={
                    "vm_id": vm_id,
                    "port_id": port_id,
                    "iface": sniff_iface,
                    "reason": preflight_err,
                    "bpf": final_bpf,
                },
            )

        try:
            with writer_lock:
                pkts_writer.close()
        except Exception:
            pass

        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)

        yield f"data: [ERROR] Capture preflight failed on {sniff_iface}: {preflight_err}\n\n"
        return

    sniffer = AsyncSniffer(iface=sniff_iface, filter=final_bpf, prn=packet_callback, store=False)

    try:
        sniffer.start()
        capture_start_epoch = time.time()

        if use_case:
            _append_case_event(
                case_dir,
                "traffic_capture_started",
                run_id=run_id,
                meta={
                    "vm_id": vm_id,
                    "port_id": port_id,
                    "iface": sniff_iface,
                    "bpf": final_bpf,
                    "pcap_rel": pcap_rel,
                    "meta_rel": meta_rel,
                    "industrial_export_rel": industrial_export_rel,
                    "capture_start_epoch": capture_start_epoch,
                },
            )

    except Exception as e:
        termination_reason = f"sniffer_start_failed: {e}"
        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)

        if use_case:
            _append_case_event(
                case_dir,
                "traffic_failed",
                run_id=run_id,
                meta={"vm_id": vm_id, "port_id": port_id, "iface": sniff_iface, "reason": str(e), "bpf": final_bpf},
            )

        try:
            with writer_lock:
                pkts_writer.close()
        except Exception:
            pass

        yield f"data: [ERROR] No se pudo iniciar sniffer en {sniff_iface}: {e}\n\n"
        return

    yield f"data: [SISTEMA] Sniffer iniciado en {sniff_iface}\n\n"
    yield f"data: [SISTEMA] BPF: {final_bpf}\n\n"
    yield f"data: [SISTEMA] Archivo: {pcap_filename}\n\n"

    try:
        while True:
            if stop_event.is_set():
                if termination_reason == "unknown":
                    termination_reason = "stop_event_set"
                break

            if sniffer_failed.is_set():
                termination_reason = sniffer_failure_reason["value"] or "sniffer_runtime_failed"
                yield f"data: [ERROR] {termination_reason}\n\n"
                break

            if capture_start_epoch is not None and not getattr(sniffer, "running", False):
                try:
                    pending = packet_queue.get_nowait()
                    yield pending
                    continue
                except Empty:
                    if termination_reason == "unknown":
                        termination_reason = "sniffer_stopped_unexpectedly"
                    break

            try:
                yield packet_queue.get(timeout=1.5)
            except Empty:
                if capture_start_epoch is not None and not getattr(sniffer, "running", False):
                    if termination_reason == "unknown":
                        termination_reason = "sniffer_stopped_unexpectedly"
                    break
                yield ": keep-alive\n\n"

    except GeneratorExit:
        termination_reason = "client_disconnect"
        stop_event.set()

    except Exception as e:
        termination_reason = f"generator_exception: {e}"
        stop_event.set()

    finally:
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

        if use_case and capture_end_epoch is not None:
            _append_case_event(
                case_dir,
                "traffic_capture_stopped",
                run_id=run_id,
                meta={
                    "vm_id": vm_id,
                    "port_id": port_id,
                    "iface": sniff_iface,
                    "capture_end_epoch": capture_end_epoch,
                    "termination_reason": termination_reason,
                },
            )

        try:
            with writer_lock:
                pkts_writer.close()
        except Exception:
            pass

        session_end_epoch = time.time()
        session_duration_s = round(session_end_epoch - session_start_epoch, 3)

        capture_duration_s = None
        if capture_start_epoch is not None and capture_end_epoch is not None:
            capture_duration_s = round(capture_end_epoch - capture_start_epoch, 3)

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update(
            {
                "end_epoch": session_end_epoch,
                "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration_s": session_duration_s,
                "session_start_epoch": session_start_epoch,
                "session_end_epoch": session_end_epoch,
                "session_duration_s": session_duration_s,
                "capture_start_epoch": capture_start_epoch,
                "capture_end_epoch": capture_end_epoch,
                "capture_duration_s": capture_duration_s,
                "packets_written": pkts_written,
                "termination_reason": termination_reason,
                "ot_modbus_packets_502_seen": ot_seen_packets_502 if use_case and "modbus" in protos else 0,
                "ot_modbus_payload_packets_seen": ot_seen_payload_packets if use_case and "modbus" in protos else 0,
                "ot_modbus_records_exported": len(ot_ops) if use_case and "modbus" in protos else 0,
            }
        )

        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            pass

        with _ACTIVE_LOCK:
            _ACTIVE_CAPTURES.discard(vm_id)

        if use_case:
            pcap_size = meta_size = None
            pcap_sha = meta_sha = None

            try:
                pcap_size = os.path.getsize(pcap_path)
            except Exception:
                pass
            try:
                meta_size = os.path.getsize(meta_path)
            except Exception:
                pass

            try:
                pcap_sha = _sha256_file(pcap_path)
            except Exception:
                pass
            try:
                meta_sha = _sha256_file(meta_path)
            except Exception:
                pass

            try:
                if pcap_rel and os.path.exists(os.path.join(case_dir, pcap_rel)):
                    _add_artifact_fast(case_dir, pcap_rel, "pcap", sha256=pcap_sha, size=pcap_size)
                if meta_rel and os.path.exists(os.path.join(case_dir, meta_rel)):
                    _add_artifact_fast(case_dir, meta_rel, "pcap_metadata", sha256=meta_sha, size=meta_size)
            except Exception:
                pass

            if pcap_rel:
                _append_custody_entry(case_dir, "acquire_preserved", run_id, artifact_rel=pcap_rel,
                                      details={"kind": "pcap", "sha256": pcap_sha, "size": pcap_size})
            if meta_rel:
                _append_custody_entry(case_dir, "acquire_preserved", run_id, artifact_rel=meta_rel,
                                      details={"kind": "pcap_metadata", "sha256": meta_sha, "size": meta_size})
            _register_custody_artifact(case_dir)

            ind_sha = None
            ind_size = None
            ops_exported = 0

            if "modbus" in protos and industrial_export_path and industrial_export_rel:
                try:
                    _append_case_event(
                        case_dir,
                        "ot_export_start",
                        run_id=run_id,
                        meta={
                            "vm_id": vm_id,
                            "protocol": "modbus_tcp",
                            "industrial_export_rel": industrial_export_rel,
                            "records_buffered": len(ot_ops),
                        },
                    )

                    payload = {
                        "schema": "nics_ot_export_v1",
                        "case_dir": case_dir,
                        "run_id": run_id,
                        "vm_id": vm_id,
                        "protocol": "modbus_tcp",
                        "capture": {
                            "pcap_rel": pcap_rel,
                            "meta_rel": meta_rel,
                            "capture_start_epoch": capture_start_epoch,
                            "capture_end_epoch": capture_end_epoch,
                            "capture_duration_s": capture_duration_s,
                        },
                        "summary": {
                            "records_exported": len(ot_ops),
                            "packets_seen_502": ot_seen_packets_502,
                            "payload_packets_seen": ot_seen_payload_packets,
                            "first_epoch": ot_first_epoch,
                            "last_epoch": ot_last_epoch,
                            "max_records_cap": ot_ops_max,
                            "truncated": True if len(ot_ops) >= ot_ops_max else False,
                        },
                        "records": ot_ops,
                        "generated_at_utc": _utc_now_iso(),
                    }

                    with open(industrial_export_path, "w", encoding="utf-8") as f:
                        json.dump(payload, f, indent=2)

                    ind_size = os.path.getsize(industrial_export_path)
                    ind_sha = _sha256_file(industrial_export_path)
                    ops_exported = len(ot_ops)

                    _add_artifact_fast(
                        case_dir,
                        industrial_export_rel,
                        "industrial_ot_export_modbus_tcp",
                        sha256=ind_sha,
                        size=ind_size,
                    )
                    _append_custody_entry(case_dir, "acquire_preserved", run_id, artifact_rel=industrial_export_rel,
                                          details={"kind": "industrial_ot_export_modbus_tcp",
                                                   "sha256": ind_sha, "size": ind_size,
                                                   "records_exported": ops_exported})
                    _register_custody_artifact(case_dir)
                    _append_case_event(
                        case_dir,
                        "ot_export_preserved",
                        run_id=run_id,
                        meta={
                            "vm_id": vm_id,
                            "protocol": "modbus_tcp",
                            "industrial_export_rel": industrial_export_rel,
                            "industrial_export_sha256": ind_sha,
                            "industrial_export_size": ind_size,
                            "records_exported": ops_exported,
                        },
                    )
                except Exception as e:
                    _append_case_event(
                        case_dir,
                        "ot_export_failed",
                        run_id=run_id,
                        meta={
                            "vm_id": vm_id,
                            "protocol": "modbus_tcp",
                            "reason": str(e),
                            "industrial_export_rel": industrial_export_rel,
                        },
                    )
                    _append_custody_entry(case_dir, "acquire_failed", run_id, artifact_rel=industrial_export_rel,
                                          outcome="error",
                                          details={"kind": "industrial_ot_export_modbus_tcp", "reason": str(e)})
                    _register_custody_artifact(case_dir)

            _append_case_event(
                case_dir,
                "traffic_stopped",
                run_id=run_id,
                meta={
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
                    "duration_s": session_duration_s,
                    "capture_duration_s": capture_duration_s,
                    "termination_reason": termination_reason,
                    "industrial_export_rel": industrial_export_rel if ("modbus" in protos) else None,
                    "industrial_export_sha256": ind_sha if ("modbus" in protos) else None,
                    "industrial_export_size": ind_size if ("modbus" in protos) else None,
                    "records_exported": ops_exported if ("modbus" in protos) else 0,
                },
            )

        print(
            f"[TRAFFIC] Captura finalizada para {vm_id} "
            f"(run_id={run_id}, reason={termination_reason}, pkts={pkts_written}, "
            f"session_s={session_duration_s}, capture_s={capture_duration_s}, "
            f"modbus_502_pkts={ot_seen_packets_502 if use_case and 'modbus' in protos else 0}, "
            f"modbus_payload_pkts={ot_seen_payload_packets if use_case and 'modbus' in protos else 0}, "
            f"records={len(ot_ops) if use_case and 'modbus' in protos else 0})"
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







 # captura 20s no SSE


def capture_packets_fixed_duration(vm_id: str, selected_protos: list, duration_s: int, case_dir: str = None, run_id: str = "R1") -> dict:
    """
    Captura tráfico durante duration_s segundos y preserva PCAP + metadata.
    """
    from scapy.all import Raw

    duration_s = int(duration_s or 20)
    if duration_s <= 0:
        duration_s = 20

    run_id = (run_id or "R1").strip() or "R1"

    vm_ips = get_vm_ips_live(vm_id)
    if not vm_ips:
        return {"result": "error", "error": "No se detectaron IPs en la VM", "vm_id": vm_id}

    tap_iface, port_id = pick_tap_iface_for_vm(vm_id)
    sniff_iface = tap_iface if tap_iface else find_vm_sniff_iface(vm_ips)

    protos = [p.strip().lower() for p in (selected_protos or []) if p and p.strip()]
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

    use_case = bool(case_dir) and _is_safe_case_dir(case_dir)

    if use_case:
        per_vm_dir = os.path.join(case_dir, "network", "per_vm", vm_id)
        os.makedirs(per_vm_dir, exist_ok=True)
        out_dir = per_vm_dir

        meta_dir = os.path.join(case_dir, "metadata")
        os.makedirs(meta_dir, exist_ok=True)

        industrial_dir = os.path.join(case_dir, "industrial")
        os.makedirs(industrial_dir, exist_ok=True)
    else:
        out_dir = CAPTURE_DIR_LEGACY
        industrial_dir = None

    ts_tag = time.strftime("%Y%m%d_%H%M%SZ", time.gmtime())

    pcap_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.pcap"
    pcap_path = os.path.join(out_dir, pcap_filename)

    meta_filename = f"pcap_{vm_id}_{run_id}_{ts_tag}.metadata.json"
    meta_path = os.path.join(out_dir, meta_filename)

    pcap_rel = os.path.join("network", "per_vm", vm_id, pcap_filename) if use_case else None
    meta_rel = os.path.join("network", "per_vm", vm_id, meta_filename) if use_case else None

    industrial_export_filename = f"ot_export_{vm_id}_{run_id}_{ts_tag}.json"
    industrial_export_path = os.path.join(industrial_dir, industrial_export_filename) if use_case else None
    industrial_export_rel = os.path.join("industrial", industrial_export_filename) if use_case else None

    session_start_epoch = time.time()
    capture_start_epoch = None
    capture_end_epoch = None

    pkts_written = 0
    ot_ops = []
    ot_ops_max = 2000
    ot_seen_packets_502 = 0
    ot_seen_payload_packets = 0
    ot_first_epoch = None
    ot_last_epoch = None

    def _safe_int(x, default=None):
        try:
            return int(x)
        except Exception:
            return default

    def _iter_modbus_adus(payload: bytes):
        if not payload:
            return
        i = 0
        n = len(payload)
        while i + 8 <= n:
            pid = (payload[i + 2] << 8) | payload[i + 3]
            if pid != 0:
                i += 1
                continue
            length = (payload[i + 4] << 8) | payload[i + 5]
            adu_len = 6 + length
            if length <= 1 or i + adu_len > n:
                return
            yield payload[i : i + adu_len]
            i += adu_len

    def _decode_modbus_adu(adu: bytes):
        if not adu or len(adu) < 8:
            return None
        tid = (adu[0] << 8) | adu[1]
        pid = (adu[2] << 8) | adu[3]
        length = (adu[4] << 8) | adu[5]
        unit_id = adu[6]
        if pid != 0 or length <= 1:
            return None
        fc = adu[7]
        data = adu[8:]
        rec = {"tid": tid, "unit_id": unit_id, "fc": fc, "mbap_len": length, "is_write": fc in (0x05, 0x06, 0x0F, 0x10)}

        def u16(b0, b1):
            return (b0 << 8) | b1

        if fc == 0x05 and len(data) >= 4:
            addr = u16(data[0], data[1])
            val = u16(data[2], data[3])
            rec.update({"op": "write_single_coil", "address": addr, "value_raw": val,
                        "value": True if val == 0xFF00 else False if val == 0x0000 else None})
            return rec
        if fc == 0x06 and len(data) >= 4:
            addr = u16(data[0], data[1])
            val = u16(data[2], data[3])
            rec.update({"op": "write_single_register", "address": addr, "value": val})
            return rec
        if fc == 0x0F and len(data) >= 5:
            addr = u16(data[0], data[1])
            qty = u16(data[2], data[3])
            bytecount = data[4]
            values = data[5 : 5 + bytecount] if len(data) >= 5 + bytecount else b""
            rec.update({"op": "write_multiple_coils", "address": addr, "quantity": qty,
                        "bytecount": bytecount, "values_hex": values.hex() if values else None})
            return rec
        if fc == 0x10 and len(data) >= 5:
            addr = u16(data[0], data[1])
            qty = u16(data[2], data[3])
            bytecount = data[4]
            values = data[5 : 5 + bytecount] if len(data) >= 5 + bytecount else b""
            regs = None
            if values and len(values) % 2 == 0:
                regs = [u16(values[i], values[i + 1]) for i in range(0, len(values), 2)]
            rec.update({"op": "write_multiple_registers", "address": addr, "quantity": qty,
                        "bytecount": bytecount, "registers": regs, "values_hex": values.hex() if values else None})
            return rec

        rec.update({"op": "non_write_function", "data_len": len(data), "data_hex_prefix": data[:16].hex() if data else None})
        return rec

    if use_case:
        _append_case_event(case_dir, "traffic_start", run_id=run_id, meta={
            "vm_id": vm_id,
            "port_id": port_id,
            "iface": sniff_iface,
            "vm_ips": vm_ips,
            "protos": protos,
            "bpf": final_bpf,
            "pcap_rel": pcap_rel,
            "meta_rel": meta_rel,
            "industrial_export_rel": industrial_export_rel,
            "mode": "fixed_duration",
            "duration_s": duration_s,
        })

    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({
                "vm_id": vm_id,
                "run_id": run_id,
                "port_id": port_id,
                "vm_ips": vm_ips,
                "iface": sniff_iface,
                "bpf": final_bpf,
                "protos": protos,
                "start_epoch": session_start_epoch,
                "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pcap_file": pcap_filename,
                "industrial_export_file": industrial_export_filename if use_case else None,
                "pcap_rel": pcap_rel if use_case else None,
                "meta_rel": meta_rel if use_case else None,
                "duration_s_requested": duration_s,
            }, f, indent=2)
    except Exception:
        pass

    pkts_writer = None
    sniffer = None
    termination_reason = "unknown"

    ok, preflight_err = _preflight_capture_ready(sniff_iface, final_bpf)
    if not ok:
        termination_reason = f"preflight_failed: {preflight_err}"

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update({
            "end_epoch": time.time(),
            "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "capture_start_epoch": None,
            "capture_end_epoch": None,
            "capture_duration_s": None,
            "packets_written": 0,
            "termination_reason": termination_reason,
        })

        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            pass

        if use_case:
            _append_case_event(case_dir, "traffic_failed", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "reason": preflight_err,
                "bpf": final_bpf,
            })

        return {"result": "error", "error": preflight_err, "vm_id": vm_id}

    try:
        pkts_writer = PcapWriter(pcap_path, append=False, sync=True, linktype=1)

        def packet_callback(pkt):
            nonlocal pkts_written, ot_seen_packets_502, ot_seen_payload_packets, ot_first_epoch, ot_last_epoch
            if not pkt.haslayer(IP):
                return
            try:
                pkts_writer.write(pkt)
                pkts_written += 1
            except Exception:
                return

            if not use_case or "modbus" not in protos:
                return
            if not pkt.haslayer(TCP):
                return

            try:
                tcp = pkt[TCP]
                sport = _safe_int(getattr(tcp, "sport", None), 0)
                dport = _safe_int(getattr(tcp, "dport", None), 0)
                if 502 not in (sport, dport):
                    return

                pkt_epoch = None
                try:
                    pkt_epoch = float(getattr(pkt, "time", None))
                except Exception:
                    pkt_epoch = None

                ot_seen_packets_502 += 1
                if pkt_epoch is not None:
                    if ot_first_epoch is None:
                        ot_first_epoch = pkt_epoch
                    ot_last_epoch = pkt_epoch

                if not pkt.haslayer(Raw):
                    return

                raw_payload = bytes(pkt[Raw].load or b"")
                if not raw_payload:
                    return

                ot_seen_payload_packets += 1

                for adu in _iter_modbus_adus(raw_payload):
                    rec = _decode_modbus_adu(adu)
                    if not rec:
                        continue
                    rec.update({
                        "ts_epoch": pkt_epoch,
                        "ts_utc": _utc_now_iso(),
                        "ts_utc_ms": _utc_now_iso_ms(),
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst,
                        "src_port": sport,
                        "dst_port": dport,
                        "direction": "to_server" if dport == 502 else "from_server" if sport == 502 else None,
                    })
                    if len(ot_ops) < ot_ops_max:
                        ot_ops.append(rec)

            except Exception:
                return

        sniffer = AsyncSniffer(iface=sniff_iface, filter=final_bpf, prn=packet_callback, store=False)

        sniffer.start()
        capture_start_epoch = time.time()

        if use_case:
            _append_case_event(case_dir, "traffic_capture_started", run_id=run_id, meta={
                "vm_id": vm_id,
                "port_id": port_id,
                "iface": sniff_iface,
                "bpf": final_bpf,
                "pcap_rel": pcap_rel,
                "meta_rel": meta_rel,
                "industrial_export_rel": industrial_export_rel,
                "capture_start_epoch": capture_start_epoch,
                "duration_s": duration_s,
            })

        deadline = time.time() + duration_s
        while time.time() < deadline:
            if not getattr(sniffer, "running", False):
                termination_reason = "sniffer_stopped_unexpectedly"
                break
            time.sleep(0.2)
        else:
            termination_reason = "fixed_duration_elapsed"

    except Exception as e:
        termination_reason = f"traffic_exception: {e}"
        return {"result": "error", "error": str(e), "vm_id": vm_id}

    finally:
        try:
            if sniffer and getattr(sniffer, "running", False):
                sniffer.stop()
        except OSError as e:
            if termination_reason == "unknown":
                termination_reason = f"oserror: {e}"
        except Exception as e:
            if termination_reason == "unknown":
                termination_reason = f"sniffer_stop_exception: {e}"

        capture_end_epoch = time.time()

        try:
            if pkts_writer:
                pkts_writer.close()
        except Exception:
            pass

        session_end_epoch = time.time()
        session_duration_s = round(session_end_epoch - session_start_epoch, 3)
        capture_duration_s = round(capture_end_epoch - capture_start_epoch, 3) if capture_start_epoch else None

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        meta.update({
            "end_epoch": session_end_epoch,
            "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_start_epoch": session_start_epoch,
            "session_end_epoch": session_end_epoch,
            "session_duration_s": session_duration_s,
            "capture_start_epoch": capture_start_epoch,
            "capture_end_epoch": capture_end_epoch,
            "capture_duration_s": capture_duration_s,
            "packets_written": pkts_written,
            "termination_reason": termination_reason,
            "ot_modbus_packets_502_seen": ot_seen_packets_502 if use_case and "modbus" in protos else 0,
            "ot_modbus_payload_packets_seen": ot_seen_payload_packets if use_case and "modbus" in protos else 0,
            "ot_modbus_records_exported": len(ot_ops) if use_case and "modbus" in protos else 0,
        })

        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        except Exception:
            pass

        if use_case:
            pcap_sha = meta_sha = None
            pcap_size = meta_size = None

            try:
                pcap_size = os.path.getsize(pcap_path)
                pcap_sha = _sha256_file(pcap_path)
            except Exception:
                pass

            try:
                meta_size = os.path.getsize(meta_path)
                meta_sha = _sha256_file(meta_path)
            except Exception:
                pass

            if pcap_rel and os.path.exists(os.path.join(case_dir, pcap_rel)):
                _add_artifact_fast(case_dir, pcap_rel, "pcap", sha256=pcap_sha, size=pcap_size)
            if meta_rel and os.path.exists(os.path.join(case_dir, meta_rel)):
                _add_artifact_fast(case_dir, meta_rel, "pcap_metadata", sha256=meta_sha, size=meta_size)

            if pcap_rel:
                _append_custody_entry(case_dir, "acquire_preserved", run_id, artifact_rel=pcap_rel, details={
                    "kind": "pcap", "sha256": pcap_sha, "size": pcap_size, "duration_s": duration_s
                })
            if meta_rel:
                _append_custody_entry(case_dir, "acquire_preserved", run_id, artifact_rel=meta_rel, details={
                    "kind": "pcap_metadata", "sha256": meta_sha, "size": meta_size, "duration_s": duration_s
                })
            _register_custody_artifact(case_dir)

            ind_sha = None
            ind_size = None
            ops_exported = 0

            if "modbus" in protos and industrial_export_path and industrial_export_rel:
                try:
                    _append_case_event(case_dir, "ot_export_start", run_id=run_id, meta={
                        "vm_id": vm_id,
                        "protocol": "modbus_tcp",
                        "industrial_export_rel": industrial_export_rel,
                        "records_buffered": len(ot_ops),
                    })

                    payload = {
                        "schema": "nics_ot_export_v1",
                        "case_dir": case_dir,
                        "run_id": run_id,
                        "vm_id": vm_id,
                        "protocol": "modbus_tcp",
                        "capture": {
                            "pcap_rel": pcap_rel,
                            "meta_rel": meta_rel,
                            "capture_start_epoch": capture_start_epoch,
                            "capture_end_epoch": capture_end_epoch,
                            "capture_duration_s": capture_duration_s,
                        },
                        "summary": {
                            "records_exported": len(ot_ops),
                            "packets_seen_502": ot_seen_packets_502,
                            "payload_packets_seen": ot_seen_payload_packets,
                            "first_epoch": ot_first_epoch,
                            "last_epoch": ot_last_epoch,
                            "max_records_cap": ot_ops_max,
                            "truncated": True if len(ot_ops) >= ot_ops_max else False,
                        },
                        "records": ot_ops,
                        "generated_at_utc": _utc_now_iso(),
                    }

                    with open(industrial_export_path, "w", encoding="utf-8") as f:
                        json.dump(payload, f, indent=2)

                    ind_size = os.path.getsize(industrial_export_path)
                    ind_sha = _sha256_file(industrial_export_path)
                    ops_exported = len(ot_ops)

                    _add_artifact_fast(case_dir, industrial_export_rel, "industrial_ot_export_modbus_tcp", sha256=ind_sha, size=ind_size)
                    _append_custody_entry(case_dir, "acquire_preserved", run_id, artifact_rel=industrial_export_rel, details={
                        "kind": "industrial_ot_export_modbus_tcp",
                        "sha256": ind_sha,
                        "size": ind_size,
                        "records_exported": ops_exported
                    })
                    _register_custody_artifact(case_dir)

                    _append_case_event(case_dir, "ot_export_preserved", run_id=run_id, meta={
                        "vm_id": vm_id,
                        "protocol": "modbus_tcp",
                        "industrial_export_rel": industrial_export_rel,
                        "industrial_export_sha256": ind_sha,
                        "industrial_export_size": ind_size,
                        "records_exported": ops_exported,
                    })

                except Exception as e:
                    _append_case_event(case_dir, "ot_export_failed", run_id=run_id, meta={
                        "vm_id": vm_id,
                        "protocol": "modbus_tcp",
                        "reason": str(e),
                        "industrial_export_rel": industrial_export_rel,
                    })
                    _append_custody_entry(case_dir, "acquire_failed", run_id, artifact_rel=industrial_export_rel, outcome="error", details={
                        "kind": "industrial_ot_export_modbus_tcp", "reason": str(e)
                    })
                    _register_custody_artifact(case_dir)

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
                "duration_s": session_duration_s,
                "capture_duration_s": capture_duration_s,
                "termination_reason": termination_reason,
                "industrial_export_rel": industrial_export_rel if ("modbus" in protos) else None,
                "industrial_export_sha256": ind_sha if ("modbus" in protos) else None,
                "industrial_export_size": ind_size if ("modbus" in protos) else None,
                "records_exported": ops_exported if ("modbus" in protos) else 0,
            })

    return {
        "result": "ok",
        "vm_id": vm_id,
        "run_id": run_id,
        "pcap_rel": pcap_rel,
        "meta_rel": meta_rel,
        "duration_s": duration_s,
        "packets_written": pkts_written,
        "termination_reason": termination_reason,
        "industrial_export_rel": industrial_export_rel if (use_case and "modbus" in protos) else None
    }

@traffic_bp.route("/api/forensics/traffic/capture", methods=["POST"])
def api_forensics_traffic_capture_fixed():
    data = request.get_json(force=True, silent=True) or {}

    vm_id = (data.get("vm_id") or "").strip()
    case_dir = (data.get("case_dir") or "").strip()
    run_id = (data.get("run_id") or "R1").strip() or "R1"
    seconds = int(data.get("seconds") or 20)
    protos = data.get("protos") or ["modbus", "tcp", "udp"]

    if not vm_id:
        return {"error": "vm_id requerido"}, 400

    # case_dir puede ser vacío para legacy, pero en tu DFIR AUTO lo vas a pasar siempre
    if case_dir and not _is_safe_case_dir(case_dir):
        return {"error": "case_dir inválido"}, 400

    res = capture_packets_fixed_duration(vm_id, protos, seconds, case_dir=case_dir or None, run_id=run_id)
    if res.get("result") != "ok":
        return res, 500
    return res, 200