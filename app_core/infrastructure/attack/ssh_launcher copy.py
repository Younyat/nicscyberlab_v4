import os
import sys
import time
import subprocess
import paramiko
from flask import Blueprint, Response, stream_with_context, request

# Definición del Blueprint para esta infraestructura específica
attack_infra_bp = Blueprint('attack_infra', __name__)

class SSHTacticalManager:
    def __init__(self, key_path):
        self.key_path = os.path.expanduser(key_path)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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

            # Limpieza silenciosa
            self.client.exec_command(f"rm {remote_path}")
            self.client.close()
        except Exception as e:
            yield f"data: [INFRA ERROR] {str(e)}\n\n"

# Instancia del manager apuntando a tu clave privada SSH
# Nota: Asegúrate de que esta ruta sea a tu clave privada (.pem o id_rsa)
manager = SSHTacticalManager(key_path="~/.ssh/my_key")

@attack_infra_bp.route('/launch')
def launch_attack():
    attacker_ip = request.args.get('ip')
    target_ip = request.args.get('target')
    script_name = request.args.get('script')
    
    user = "debian"
    # Ruta absoluta a tus scripts
    local_script = f"/home/younes/nicscyberlab_v3/attack/scripts/{script_name}"

    if not os.path.exists(local_script):
        return Response("data: [ERROR] Script no encontrado\n\n", mimetype='text/event-stream')

    return Response(
        stream_with_context(manager.execute_remote_stream(attacker_ip, user, local_script, [target_ip])),
        mimetype='text/event-stream'
    )