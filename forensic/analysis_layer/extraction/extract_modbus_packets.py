import pathlib
from datetime import datetime, timezone
from scapy.all import rdpcap
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

def extract_modbus_packets(case_path: pathlib.Path) -> list:
    """
    Extracts Modbus/TCP packets with semantic fields from PCAPs.
    Returns a list of packet-level forensic records.
    """
    records = []

    network_dir = case_path / "network"
    if not network_dir.exists():
        return records

    for pcap in network_dir.glob("*.pcap"):
        packets = rdpcap(str(pcap))

        for pkt in packets:
            if not pkt.haslayer(ModbusADURequest) and not pkt.haslayer(ModbusADUResponse):
                continue

            record = {
                "pcap": pcap.name,
                "timestamp_utc": datetime.fromtimestamp(
                    pkt.time, tz=timezone.utc
                ).isoformat(),
                "src_ip": pkt[0][1].src,
                "dst_ip": pkt[0][1].dst,
                "src_port": pkt.sport,
                "dst_port": pkt.dport,
                "direction": "request" if pkt.haslayer(ModbusADURequest) else "response",
                "unit_id": None,
                "function_code": None,
                "operation": None,
                "address": None,
                "count": None,
                "values": None,
                "exception": False,
            }

            modbus = pkt.getlayer(ModbusADURequest) or pkt.getlayer(ModbusADUResponse)

            record["unit_id"] = modbus.unit_id
            record["function_code"] = modbus.funcCode

            # Clasificación semántica
            if modbus.funcCode in {1, 2, 3, 4}:
                record["operation"] = "read"
            elif modbus.funcCode in {5, 6, 15, 16}:
                record["operation"] = "write"
            else:
                record["operation"] = "other"

            # Campos comunes
            if hasattr(modbus, "startingAddress"):
                record["address"] = modbus.startingAddress

            if hasattr(modbus, "quantity"):
                record["count"] = modbus.quantity

            if hasattr(modbus, "outputsValue"):
                record["values"] = modbus.outputsValue

            if hasattr(modbus, "registerValue"):
                record["values"] = modbus.registerValue

            if hasattr(modbus, "exceptionCode"):
                record["exception"] = True

            records.append(record)

    return records
