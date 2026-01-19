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
                    yield data
                if channel.exit_status_ready():
                    break

            self.client.exec_command(f"rm {remote_path}")
            self.client.close()
        except Exception as e:
            yield f"\n[MANAGER ERROR] {str(e)}\n"








