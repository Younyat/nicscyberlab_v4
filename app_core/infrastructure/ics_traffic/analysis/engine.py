import subprocess
import os

def analyze_pcap(pcap_path: str) -> dict:
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(pcap_path)

    tcp = subprocess.run(
        ["tshark", "-r", pcap_path, "-Y", "tcp"],
        stdout=subprocess.PIPE,
        text=True
    ).stdout

    modbus = subprocess.run(
        ["tshark", "-r", pcap_path, "-Y", "tcp.port == 502"],
        stdout=subprocess.PIPE,
        text=True
    ).stdout

    return {
        "pcap": pcap_path,
        "tcp_packets": tcp.count("\n"),
        "modbus_packets": modbus.count("\n"),
        "has_modbus": bool(modbus.strip())
    }
