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
        
        # Conexión a OpenStack (usando variables de entorno o clouds.yaml)
        try:
            self.conn = openstack.connect()
        except Exception as e:
            print(f"Error conexión OpenStack: {e}")
            self.conn = None

    def discover_attacker_instance(self):
        """Busca una instancia que empiece por 'attack', obtiene su Floating IP y su imagen."""
        if not self.conn:
            return None, None

        try:
            # Listar servidores que empiecen con 'attack'
            for server in self.conn.compute.servers(all_projects=True):
                if server.name.lower().startswith("attack"):
                    # Extraer la Floating IP (usualmente en el campo access_ipv4 o buscando en addresses)
                    f_ip = server.access_ipv4 or self._get_floating_ip_from_addresses(server.addresses)
                    
                    if f_ip:
                        # Determinar usuario basado en la imagen
                        image = self.conn.image.get_image(server.image.id)
                        user = self._map_user(image.name.lower())
                        return f_ip, user
            return None, None
        except Exception:
            return None, None

    def _get_floating_ip_from_addresses(self, addresses):
        """Auxiliar para extraer la IP flotante del diccionario de direcciones."""
        for network in addresses.values():
            for addr in network:
                if addr.get('OS-EXT-IPS:type') == 'floating':
                    return addr.get('addr')
        return None

    def _map_user(self, image_name):
        if "ubuntu" in image_name: return "ubuntu"
        if "kali" in image_name: return "kali"
        return "debian"

    def execute_remote_stream(self, host, user, local_script_path, args=[]):
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
                    data = channel.recv(1024).decode('utf-8', errors='ignore')
                    if not data: break
                    yield f"data: {data}\n\n"
                if channel.exit_status_ready(): break

            self.client.exec_command(f"rm {remote_path}")
            self.client.close()
        except Exception as e:
            yield f"data: [SSH ERROR] {str(e)}\n\n"

manager = SSHTacticalManager(key_path="~/.ssh/my_key")

@attack_infra_bp.route('/launch')
def launch_attack():
    target_ip = request.args.get('target') # IP de la víctima desde el front
    script_name = request.args.get('script', 'ping_target.sh')
    print(f"[ATTACK] Target IP recibida desde el frontend: {target_ip}")
    print(f"[script_name : {script_name}")
    # BUSQUEDA DINÁMICA DE LA MÁQUINA ATACANTE EN OPENSTACK
    attacker_ip, user = manager.discover_attacker_instance()
    print(f"[attacker_ip : {attacker_ip}")
    print(f"[attacker user : {user}")
    if not attacker_ip:
        return Response("data: [ERROR] No se encontró ninguna instancia 'attack' con IP flotante\n\n", 
                        mimetype='text/event-stream')

    local_script = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(local_script):
        return Response("data: [ERROR] Script local no encontrado\n\n", mimetype='text/event-stream')

    return Response(
        stream_with_context(manager.execute_remote_stream(attacker_ip, user, local_script, [target_ip])),
        mimetype='text/event-stream'
    )