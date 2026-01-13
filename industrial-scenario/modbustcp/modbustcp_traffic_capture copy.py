import json
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime

# Diccionario de funciones Modbus
MODBUS_FC = {
    1: "READ_COILS", 3: "READ_HOLDING_REGS",
    5: "WRITE_COIL", 6: "WRITE_REGISTER",
    15: "WRITE_MULTIPLE_COILS", 16: "WRITE_MULTIPLE_REGS"
}

def dissect_modbus(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if len(payload) >= 8: # MBAP Header (7) + Function Code (1)
            try:
                # Extracción MBAP & PDU
                tid = int.from_bytes(payload[0:2], "big")
                fc = payload[7]
                addr = int.from_bytes(payload[8:10], "big")
                
                # Extracción de Valor Real
                value = "N/A"
                if fc == 5: # Coil
                    value = "TRUE" if payload[10] == 0xff else "FALSE"
                elif fc == 6: # Register
                    value = int.from_bytes(payload[10:12], "big")
                
                # Estructura Forense
                forensic_data = {
                    "timestamp": datetime.now().isoformat(),
                    "src": packet[IP].src,
                    "dst": packet[IP].dst,
                    "tid": tid,
                    "fc_name": MODBUS_FC.get(fc, f"FC_{fc}"),
                    "register": addr,
                    "value": value,
                    "hex": payload.hex(' ').upper()
                }
                
                # Enviamos el JSON (puedes redirigir esto a un archivo o websocket)
                print(json.dumps(forensic_data))
                
            except Exception:
                pass

if __name__ == "__main__":
    print("Sonda Industrial Activa... Filtrando Puerto 502")
    sniff(filter="tcp port 502", prn=dissect_modbus, store=0)