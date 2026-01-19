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
        
        # Conexión automática a OpenStack usando variables de entorno o clouds.yaml
        try:
            self.conn = openstack.connect()
        except Exception:
            self.conn = None

    def get_ssh_user_by_ip(self, ip):
        """Consulta OpenStack para determinar el usuario según la imagen."""
        if not self.conn:
            return "debian" # Fallback por defecto

        try:
            # Buscamos el servidor por su dirección IP
            server = next(self.conn.compute.servers(details=True, all_projects=True, access_ipv4=ip), None)
            if not server:
                return "debian"

            # Obtenemos el nombre de la imagen
            image_id = server.image.id
            image = self.conn.image.get_image(image_id)
            image_name = image.name.lower()

            # Mapeo lógico según tu requerimiento
            if "ubuntu" in image_name:
                return "ubuntu"
            elif "kali" in image_name:
                return "kali"
            elif "debian" in image_name:
                return "debian"
            
            return "debian" # Default
        except Exception:
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
                if channel.exit_status_ready():
                    break

            self.client.exec_command(f"rm {remote_path}")
            self.client.close()
        except Exception as e:
            yield f"data: [SSH ERROR] {str(e)}\n\n"

manager = SSHTacticalManager(key_path="~/.ssh/my_key")

@attack_infra_bp.route('/launch')
def launch_attack():
    attacker_ip = request.args.get('ip')
    target_ip = request.args.get('target')
    script_name = request.args.get('script')
    
    # 1. Determinamos el usuario dinámicamente consultando OpenStack
    user = manager.get_ssh_user_by_ip(attacker_ip)
    
    # 2. Ruta del script
    local_script = os.path.join(SCRIPTS_DIR, script_name)
    
    if not os.path.exists(local_script):
        return Response(f"data: [ERROR] Script no encontrado\n\n", mimetype='text/event-stream')

    return Response(
        stream_with_context(manager.execute_remote_stream(attacker_ip, user, local_script, [target_ip])),
        mimetype='text/event-stream'
    )