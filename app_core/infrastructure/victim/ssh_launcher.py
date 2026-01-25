import os
import time
import openstack
import paramiko

from flask import Blueprint, Response, stream_with_context, request
import logging
logger = logging.getLogger("app_logger")



# ============================================================
# Blueprint
# ============================================================
victim_infra_bp = Blueprint("victim_infra", __name__)

# ============================================================
# Paths
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

# ============================================================
# SSH + OpenStack Manager
# ============================================================
class SSHTacticalManager:
    def __init__(self, key_path):
        self.key_path = os.path.expanduser(key_path)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.conn = openstack.connect()
        except Exception as e:
            print(f"[VICTIM] Error conexión OpenStack: {e}")
            self.conn = None

    # --------------------------------------------------------
    # Resolver instancia por IP (CLAVE)
    # --------------------------------------------------------
    def discover_instance_by_ip(self, target_ip):
        if not self.conn or not target_ip:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                for net in (server.addresses or {}).values():
                    for addr in net:
                        if addr.get("addr") == target_ip:
                            image = self.conn.image.get_image(server.image.id)
                            user = self._map_user(image.name.lower())
                            return target_ip, user
            return None, None
        except Exception as e:
            print(f"[VICTIM] discover_instance_by_ip error: {e}")
            return None, None

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------
    def _map_user(self, image_name):
        if "ubuntu" in image_name:
            return "ubuntu"
        if "kali" in image_name:
            return "kali"
        return "debian"

    # --------------------------------------------------------
    # SSH execution (stream)
    # --------------------------------------------------------
    def execute_remote_stream(self, host, user, local_script_path, args=[]):
        try:
            self.client.connect(
                host,
                username=user,
                key_filename=self.key_path,
                timeout=15
            )

            sftp = self.client.open_sftp()
            remote_path = f"/tmp/exec_{int(time.time())}.sh"
            sftp.put(local_script_path, remote_path)
            sftp.chmod(remote_path, 0o755)
            sftp.close()

            transport = self.client.get_transport()
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(f"{remote_path} {' '.join(args)}")

            while True:
                if channel.recv_ready():
                    data = channel.recv(1024).decode("utf-8", errors="ignore")
                    if data:
                        yield f"data: {data}\n\n"

                if channel.exit_status_ready():
                    break

            self.client.exec_command(f"rm -f {remote_path}")
            self.client.close()

        except Exception as e:
            yield f"data: [SSH ERROR] {str(e)}\n\n"
     
# ============================================================
# Manager instance
# ============================================================
manager = SSHTacticalManager(key_path="~/.ssh/my_key")

# ============================================================
# Endpoint: install detector on ANY node by IP
# ============================================================import os
import time
import openstack
import paramiko
from flask import Blueprint, Response, stream_with_context, request

# ============================================================
# Blueprint
# ============================================================
victim_infra_bp = Blueprint("victim_infra", __name__)

# ============================================================
# Paths
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

# ============================================================
# SSH + OpenStack Manager
# ============================================================
class SSHTacticalManager:
    def __init__(self, key_path):
        self.key_path = os.path.expanduser(key_path)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.conn = openstack.connect()
        except Exception as e:
            print(f"[VICTIM] Error conexión OpenStack: {e}")
            self.conn = None

    # --------------------------------------------------------
    # Resolver instancia por IP (CLAVE)
    # --------------------------------------------------------
    def discover_instance_by_ip(self, target_ip):
        if not self.conn or not target_ip:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                for net in (server.addresses or {}).values():
                    for addr in net:
                        if addr.get("addr") == target_ip:
                            image = self.conn.image.get_image(server.image.id)
                            user = self._map_user(image.name.lower())
                            return target_ip, user
            return None, None
        except Exception as e:
            print(f"[VICTIM] discover_instance_by_ip error: {e}")
            return None, None

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------
    def _map_user(self, image_name):
        if "ubuntu" in image_name:
            return "ubuntu"
        if "kali" in image_name:
            return "kali"
        return "debian"

    # --------------------------------------------------------
    # SSH execution (stream)
    # --------------------------------------------------------
    def execute_remote_stream(self, host, user, local_script_path, args=[]):
        try:
            self.client.connect(
                host,
                username=user,
                key_filename=self.key_path,
                timeout=15
            )

            sftp = self.client.open_sftp()
            remote_path = f"/tmp/exec_{int(time.time())}.sh"
            sftp.put(local_script_path, remote_path)
            sftp.chmod(remote_path, 0o755)
            sftp.close()

            transport = self.client.get_transport()
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(f"{remote_path} {' '.join(args)}")

            while True:
                if channel.recv_ready():
                    data = channel.recv(1024).decode("utf-8", errors="ignore")
                    if data:
                        yield f"data: {data}\n\n"

                if channel.exit_status_ready():
                    break

            self.client.exec_command(f"rm -f {remote_path}")
            self.client.close()

        except Exception as e:
            yield f"data: [SSH ERROR] {str(e)}\n\n"

# ============================================================
# Manager instance
# ============================================================
manager = SSHTacticalManager(key_path="~/.ssh/my_key")

# ============================================================
# Endpoint: install detector on ANY node by IP
# ============================================================
@victim_infra_bp.route("/install_detector")
def install_detector():
    script_name = request.args.get("script", "ping_target_detecter.sh")
    target_ip = request.args.get("ip")
    monitor_ip = request.args.get("monitor_ip")

    logger.info(f"[DETECTOR] request target={target_ip} monitor={monitor_ip}")

    if not target_ip or not monitor_ip:
        return Response(
            "data: [ERROR] target_ip or monitor_ip missing\n\n",
            mimetype="text/event-stream"
        )

    victim_ip, user = manager.discover_instance_by_ip(target_ip)

    if not victim_ip or not user:
        logger.error(f"[DETECTOR] No instance found for IP {target_ip}")
        return Response(
            f"data: [ERROR] No instance with IP {target_ip}\n\n",
            mimetype="text/event-stream"
        )

    logger.info(f"[DETECTOR] install on {victim_ip} as {user}")

    local_script = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(local_script):
        return Response(
            "data: [ERROR] Detector script not found\n\n",
            mimetype="text/event-stream"
        )

    return Response(
        stream_with_context(
            manager.execute_remote_stream(
                victim_ip,
                user,
                local_script,
                args=[monitor_ip]
            )
        ),
        mimetype="text/event-stream"
    )
