import socket
import json
import requests
import logging
from app_core.infrastructure.monitor.alerts_logger import AlertsLogger


BACKEND_URL = "http://127.0.0.1:5001/api/hud/events"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 9999

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("monitor_icmp")

def start_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    sock.listen(5)

    logger.info(f"[MONITOR] ICMP listener (TCP) active on {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        conn, addr = sock.accept()
        data = conn.recv(4096)
        conn.close()

        if not data:
            continue

        try:
            raw = data.decode().strip()
            logger.info(f"[MONITOR] RAW DATA: {raw}")

            event = json.loads(raw)
            logger.info(f"[MONITOR] EVENT RECEIVED {event}")

            r = requests.post(BACKEND_URL, json=event, timeout=2)
            logger.info(f"[MONITOR] Forwarded to backend ({r.status_code})")

        except Exception as e:
            logger.error(f"[MONITOR] ERROR {e}")

if __name__ == "__main__":
    start_listener()
