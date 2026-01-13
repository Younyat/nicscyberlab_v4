#!/usr/bin/env python3
# ============================================================
# MODBUS TCP FORENSIC SNIFFER – FULL AUTO-INSTALL
# ============================================================

import sys
import subprocess

# ------------------------------------------------------------
# AUTOINSTALACIÓN ROBUSTA DE DEPENDENCIAS
# ------------------------------------------------------------
def ensure_package(pkg):
    try:
        __import__(pkg)
    except ImportError:
        print(f"[!] Instalando dependencia faltante: {pkg}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "--quiet", pkg
        ])

# Dependencias necesarias
ensure_package("scapy")

# ------------------------------------------------------------
# IMPORTS (YA SEGUROS)
# ------------------------------------------------------------
import json
from scapy.all import sniff, Ether, IP, TCP, Raw
from datetime import datetime

# ------------------------------------------------------------
# MODBUS FUNCTION CODES
# ------------------------------------------------------------
MODBUS_FC = {
    1: "READ_COILS",
    3: "READ_HOLDING_REGISTERS",
    5: "WRITE_SINGLE_COIL",
    6: "WRITE_SINGLE_REGISTER",
    15: "WRITE_MULTIPLE_COILS",
    16: "WRITE_MULTIPLE_REGISTERS"
}

# ------------------------------------------------------------
# MODBUS MBAP PARSER
# ------------------------------------------------------------
def parse_mbap(payload):
    return {
        "transaction_id": int.from_bytes(payload[0:2], "big"),
        "protocol_id": int.from_bytes(payload[2:4], "big"),
        "length": int.from_bytes(payload[4:6], "big"),
        "unit_id": payload[6],
        "function_code": payload[7]
    }

# ------------------------------------------------------------
# PACKET HANDLER
# ------------------------------------------------------------
def dissect(packet):
    if not (packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    if not packet.haslayer(Raw):
        return

    payload = packet[Raw].load
    if len(payload) < 8:
        return

    try:
        mbap = parse_mbap(payload)

        forensic = {
            "timestamp": datetime.now().isoformat(),

            # Ethernet 802.3
            "eth_src": packet[Ether].src,
            "eth_dst": packet[Ether].dst,
            "eth_type": hex(packet[Ether].type),

            # IPv4
            "ip_src": packet[IP].src,
            "ip_dst": packet[IP].dst,
            "ttl": packet[IP].ttl,
            "ip_id": packet[IP].id,

            # TCP
            "tcp_sport": packet[TCP].sport,
            "tcp_dport": packet[TCP].dport,
            "tcp_flags": str(packet[TCP].flags),
            "tcp_seq": packet[TCP].seq,
            "tcp_ack": packet[TCP].ack,

            # Modbus MBAP
            "modbus_tid": mbap["transaction_id"],
            "modbus_protocol_id": mbap["protocol_id"],
            "modbus_length": mbap["length"],
            "unit_id": mbap["unit_id"],
            "function_code": mbap["function_code"],
            "function_name": MODBUS_FC.get(
                mbap["function_code"],
                f"FC_{mbap['function_code']}"
            ),

            # RAW
            "raw_hex": payload.hex(" ").upper()
        }

        print(json.dumps(forensic))

    except Exception:
        pass

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    print("[+] Sonda Forense Modbus TCP activa")
    print("[+] Autoinstalación de dependencias verificada")
    print("[+] Capturando tráfico en TCP/502")
    sniff(filter="tcp port 502", prn=dissect, store=0)
