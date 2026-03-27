import os
import time
import openstack
import paramiko
from flask import Blueprint, Response, stream_with_context, request

attack_infra_bp = Blueprint('attack_infra', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")


class SSHTacticalManager:
    def __init__(self, key_path):
        self.key_path = os.path.expanduser(key_path)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Conexión a OpenStack
        try:
            self.conn = openstack.connect()
        except Exception as e:
            print(f"Error conexión OpenStack: {e}")
            self.conn = None

    def _map_user(self, image_name: str):
        n = (image_name or "").lower()
        if "ubuntu" in n:
            return "ubuntu"
        if "kali" in n:
            return "kali"
        # default
        return "debian"

    def _get_all_ips_from_addresses(self, addresses):
        """Devuelve todas las IPs (fixed + floating) de un server.addresses."""
        ips = []
        try:
            for net in (addresses or {}).values():
                for a in net or []:
                    ip = a.get("addr")
                    if ip:
                        ips.append(ip)
        except Exception:
            pass
        return ips

    def discover_attacker_instance(self):
        """Busca una instancia que empiece por 'attack', obtiene su Floating IP y su imagen."""
        if not self.conn:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                if server.name and server.name.lower().startswith("attack"):
                    f_ip = server.access_ipv4 or self._get_floating_ip_from_addresses(server.addresses)
                    if f_ip:
                        image = self.conn.image.get_image(server.image.id)
                        user = self._map_user(getattr(image, "name", "") or "")
                        return f_ip, user
            return None, None
        except Exception:
            return None, None

    def discover_instance_by_ip(self, target_ip: str):
        """
        Encuentra el server de OpenStack cuyo addresses contiene target_ip (fixed o floating).
        Devuelve (server, image_name) o (None, None).
        """
        if not self.conn or not target_ip:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                ips = self._get_all_ips_from_addresses(getattr(server, "addresses", None))
                # también considerar access_ipv4 si está poblado
                if getattr(server, "access_ipv4", None):
                    ips.append(server.access_ipv4)

                if target_ip in ips:
                    image = self.conn.image.get_image(server.image.id)
                    image_name = getattr(image, "name", "") or ""
                    return server, image_name
            return None, None
        except Exception:
            return None, None

    def _get_floating_ip_from_addresses(self, addresses):
        """Auxiliar para extraer la IP flotante del diccionario de direcciones."""
        for network in (addresses or {}).values():
            for addr in network or []:
                if addr.get('OS-EXT-IPS:type') == 'floating':
                    return addr.get('addr')
        return None

    def execute_remote_stream(self, host, user, local_script_path, args=None):
        if args is None:
            args = []

        try:
            self.client.connect(host, username=user, key_filename=self.key_path, timeout=15)

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
                    data = channel.recv(4096).decode('utf-8', errors='ignore')
                    if data:
                        # SSE correcto: cada línea con data:
                        for line in data.splitlines():
                            yield f"data: {line}\n\n"

                if channel.exit_status_ready():
                    break

                time.sleep(0.05)

            self.client.exec_command(f"rm -f {remote_path}")
            self.client.close()

        except Exception as e:
            yield f"data: [SSH ERROR] {str(e)}\n\n"


manager = SSHTacticalManager(key_path="~/.ssh/my_key")



def normalize_os_user(os_value: str) -> str:
    n = (os_value or "").strip().lower()

    if "ubuntu" in n:
        return "ubuntu"
    if "debian" in n:
        return "debian"
    if "kali" in n:
        return "kali"

    return "debian"




@attack_infra_bp.route('/launch')
def launch_attack():
    target_ip = request.args.get('target')  # IP de la víctima desde el front
    script_name = request.args.get('script', 'ping_target.sh')
  



    target_os = request.args.get('os', '')
    victim_user = normalize_os_user(target_os)
    print(f"[target_os_raw  : {target_os}]")
    print(f"[victim_user    : {victim_user}]")

    print(f"[ATTACK] Target IP recibida desde el frontend: {target_ip}")
    print(f"[script_name : {script_name}")

    # 1) localizar attacker dinámico
    attacker_ip, attacker_user = manager.discover_attacker_instance()
    print(f"[attacker_ip : {attacker_ip}")
    print(f"[attacker user : {attacker_user}")

    if not attacker_ip:
        return Response(
            "data: [ERROR] No se encontró ninguna instancia 'attack' con IP flotante\n\n",
            mimetype='text/event-stream'
        )

    # 2) localizar víctima por IP y mapear user por imagen
 
    server, image_name = manager.discover_instance_by_ip(target_ip)
    if server and image_name:
        victim_user = manager._map_user(image_name)
        print(f"[victim_server : {server.name}]")
        print(f"[victim_image  : {image_name}]")
        print(f"[victim_user   : {victim_user}]")
    else:
        print("[victim_lookup] No se pudo identificar la VM por IP; usando user fallback=debian")

    # 3) cargar script desde scripts/
    local_script = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(local_script):
        return Response(
            f"data: [ERROR] Script local no encontrado: {local_script}\n\n",
            mimetype='text/event-stream'
        )

    # 4) args al script: $1=target_ip, $2=victim_user
    return Response(
        stream_with_context(
            manager.execute_remote_stream(attacker_ip, attacker_user, local_script, [target_ip, victim_user])
        ),
        mimetype='text/event-stream'
    )