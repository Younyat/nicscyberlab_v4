import os
import time
import openstack
import paramiko
import logging
import subprocess

from flask import Blueprint, Response, request

from flask import Blueprint, Response, request

# ============================================================
# Configuración y Blueprint
# ============================================================
monitor_infra_bp = Blueprint("monitor_infra", __name__)
logger = logging.getLogger("app_logger")

# Rutas absolutas
SCRIPT_PATH = os.path.abspath("app_core/infrastructure/monitor/scripts/monitor_ataques.sh")
SSH_KEY_PATH = os.path.expanduser("~/.ssh/my_key")


@monitor_infra_bp.route("/live_wazuh_stream")
def live_wazuh_stream():
    monitor_ip = request.args.get("ip")

    if not monitor_ip:
        return Response(
            "data: [ERROR] IP ausente\n\n",
            mimetype="text/event-stream"
        )

    def generate():
        #  Heartbeat inmediato (obligatorio en SSE)
        yield "data: [SYSTEM] STREAM OPENED\n\n"
        yield f"data: [SYSTEM] Lanzando monitor Wazuh para {monitor_ip}\n\n"

        #  Script SH que YA gestiona SSH internamente
        cmd = [
            "bash",
            SCRIPT_PATH,
            monitor_ip,
            "ubuntu",
            SSH_KEY_PATH
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Stream continuo hacia el frontend
            for line in iter(process.stdout.readline, ""):
                if line:
                    # SSE requiere "data: ... \n\n"
                    yield f"data: {line.rstrip()}\n\n"

        except Exception as e:
            yield f"data: [ERROR] {str(e)}\n\n"

        #  NO cerrar proceso aquí
        #  NO terminate
        #  NO finally

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# ============================================================
# SSH + OpenStack Manager
# ============================================================
class SSHMonitorManager:
    def __init__(self, key_path: str):
        self.key_path = os.path.expanduser(key_path)

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.conn = openstack.connect()
            logger.info("[MONITOR] OpenStack connection established")
        except Exception as e:
            logger.error(f"[MONITOR] OpenStack connection error: {e}")
            self.conn = None

    # --------------------------------------------------------
    # Discover monitor instance by IP (REAL validation)
    # --------------------------------------------------------
    def discover_monitor_by_ip(self, monitor_ip: str):
        if not self.conn or not monitor_ip:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                if not server.name.lower().startswith("monitor"):
                    continue

                for net in (server.addresses or {}).values():
                    for addr in net:
                        if addr.get("addr") == monitor_ip:
                            image = self.conn.image.get_image(server.image.id)
                            user = self._map_user(image.name.lower())

                            logger.info(
                                f"[MONITOR] Found monitor instance "
                                f"name={server.name} id={server.id} "
                                f"ip={monitor_ip} image={image.name} "
                                f"user={user}"
                            )

                            return monitor_ip, user

            logger.warning(
                f"[MONITOR] No monitor instance found with IP {monitor_ip}"
            )
            return None, None

        except Exception as e:
            logger.error(f"[MONITOR] discover error: {e}")
            return None, None

    # --------------------------------------------------------
    # Map SSH user from image name
    # --------------------------------------------------------
    def _map_user(self, image_name: str) -> str:
        if "ubuntu" in image_name:
            return "ubuntu"
        if "kali" in image_name:
            return "kali"
        return "debian"

    # --------------------------------------------------------
    # SSH connect + functional verification
    # --------------------------------------------------------
    def connect_and_verify(self, ip: str, user: str):
        self.client.connect(
            hostname=ip,
            username=user,
            key_filename=self.key_path,
            timeout=15
        )

        stdin, stdout, stderr = self.client.exec_command("whoami")
        remote_user = stdout.read().decode().strip()

        if remote_user != user:
            raise RuntimeError(
                f"SSH user mismatch: expected={user} got={remote_user}"
            )

        logger.info(
            f"[MONITOR] SSH connection OK to {ip} as user '{remote_user}'"
        )

    # --------------------------------------------------------
    # Verify script presence
    # --------------------------------------------------------
    def verify_script_exists(self, script_name: str):
        stdin, stdout, stderr = self.client.exec_command(
            f"test -f {script_name} && echo EXISTS || echo MISSING"
        )
        result = stdout.read().decode().strip()

        if result != "EXISTS":
            raise RuntimeError(
                f"Script '{script_name}' not found on monitor node"
            )

        logger.info(
            f"[MONITOR] Script '{script_name}' exists on monitor node"
        )

    # --------------------------------------------------------
    # Start script and verify execution
    # --------------------------------------------------------
    def start_script(self, script_name: str):
        cmd = (
            f"nohup python3 {script_name} "
            f"> /tmp/{script_name}.log 2>&1 &"
        )
        self.client.exec_command(cmd)

        time.sleep(2)

        stdin, stdout, stderr = self.client.exec_command(
            f"pgrep -f {script_name} && echo RUNNING || echo NOT_RUNNING"
        )
        status = stdout.read().decode().strip()

        if status != "RUNNING":
            raise RuntimeError(
                f"Script '{script_name}' failed to start"
            )

        logger.info(
            f"[MONITOR] Script '{script_name}' is RUNNING"
        )

    # --------------------------------------------------------
    # Stop script
    # --------------------------------------------------------
    def stop_script(self, script_name: str):
        self.client.exec_command(f"pkill -f {script_name} || true")
        logger.info(
            f"[MONITOR] Script '{script_name}' stopped"
        )

    def close(self):
        self.client.close()


# ============================================================
# Manager instance
# ============================================================
manager = SSHMonitorManager(key_path="~/.ssh/my_key")

SCRIPT_NAME = "icmp_listener.py"

# ============================================================
# ▶ START ICMP LISTENER
# ============================================================
@monitor_infra_bp.route("/start_listener")
def start_monitor_listener():
    monitor_ip = request.args.get("ip")

    logger.info(f"[MONITOR] start listener request for ip={monitor_ip}")

    if not monitor_ip:
        return Response(
            "data: [ERROR] monitor_ip missing\n\n",
            mimetype="text/event-stream"
        )

    ip, user = manager.discover_monitor_by_ip(monitor_ip)

    if not ip or not user:
        return Response(
            "data: [ERROR] monitor instance not found\n\n",
            mimetype="text/event-stream"
        )

    try:
        manager.connect_and_verify(ip, user)
        manager.verify_script_exists(SCRIPT_NAME)
        manager.start_script(SCRIPT_NAME)
        manager.close()

        logger.info(
            f"[MONITOR] ICMP listener successfully started on {ip}"
        )

        return Response(
            "data: [MONITOR] ICMP listener started and verified\n\n",
            mimetype="text/event-stream"
        )

    except Exception as e:
        logger.error(f"[MONITOR] start listener error: {e}")
        manager.close()
        return Response(
            f"data: [ERROR] {e}\n\n",
            mimetype="text/event-stream"
        )


# ============================================================
# ⏹ STOP ICMP LISTENER
# ============================================================
@monitor_infra_bp.route("/stop_listener")
def stop_monitor_listener():
    monitor_ip = request.args.get("ip")

    logger.info(f"[MONITOR] stop listener request for ip={monitor_ip}")

    if not monitor_ip:
        return Response(
            "data: [ERROR] monitor_ip missing\n\n",
            mimetype="text/event-stream"
        )

    ip, user = manager.discover_monitor_by_ip(monitor_ip)

    if not ip or not user:
        return Response(
            "data: [ERROR] monitor instance not found\n\n",
            mimetype="text/event-stream"
        )

    try:
        manager.connect_and_verify(ip, user)
        manager.stop_script(SCRIPT_NAME)
        manager.close()

        return Response(
            "data: [MONITOR] ICMP listener stopped\n\n",
            mimetype="text/event-stream"
        )

    except Exception as e:
        logger.error(f"[MONITOR] stop listener error: {e}")
        manager.close()
        return Response(
            f"data: [ERROR] {e}\n\n",
            mimetype="text/event-stream"
        )


