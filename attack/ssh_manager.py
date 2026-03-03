import os
import sys
import time
import subprocess

try:
    import paramiko
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])
    import paramiko


class SSHTacticalManager:
    def __init__(self, key_path="~/.ssh/my_key"):
        self.key_path = os.path.expanduser(key_path)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def execute_remote_stream(self, host, user, local_script_path, args=None):
        if args is None:
            args = []

        def _emit_sse(text: str):
            # Convierte cualquier salida en SSE válido (data: ... \n\n)
            for line in (text or "").splitlines():
                yield f"data: {line}\n\n"

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

            # Ejecuta el script en el ATTACKER con args (p.ej. target_ip)
            cmd = f"{remote_path} {' '.join(args)}"
            channel.exec_command(cmd)

            while True:
                if channel.recv_ready():
                    data = channel.recv(4096).decode("utf-8", errors="ignore")
                    if data:
                        for chunk in _emit_sse(data):
                            yield chunk

                if channel.exit_status_ready():
                    break

                time.sleep(0.05)

            try:
                self.client.exec_command(f"rm -f {remote_path}")
            except Exception:
                pass

            self.client.close()

        except Exception as e:
            for chunk in _emit_sse(f"[MANAGER ERROR] {str(e)}"):
                yield chunk