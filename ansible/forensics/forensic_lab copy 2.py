import json
import subprocess
import time
import os

# --- CONFIGURACIÓN ---
MANAGER_IP = "10.0.2.160"
VICTIM_IP = "10.0.2.23"
SSH_KEY = os.path.expanduser("~/.ssh/my_key")
LOG_FILE = "/var/ossec/logs/archives/archives.json"

# Binarios ruidosos que vamos a IGNORAR completamente
IGNORAR = [
    "dash", "env", "run", "uname", "mkdir", "sftp", "python3", "locale", 
    "apt", "gpg", "sed", "chmod", "rm", "sleep", "df", "sort", "last", 
    "sshd", "grep", "test", "mktemp", "find", "base64", "cat" # Cat opcional
]

def run_ssh_cmd(ip, user, command, use_sudo=False):
    sudo_prefix = "sudo " if use_sudo else ""
    ssh_base = f"ssh -i {SSH_KEY} -o StrictHostKeyChecking=no {user}@{ip}"
    full_cmd = f"{ssh_base} \"{sudo_prefix}{command}\""
    return subprocess.run(full_cmd, shell=True, capture_output=True, text=True)

def analyze():
    print(f"\n--- 🕵️ REPORTE FORENSE DE ALTA PRECISIÓN ---")
    
    # Filtramos en el Manager antes de descargar los datos
    grep_cmd = f"grep 'forensic_' {LOG_FILE}"
    res = run_ssh_cmd(MANAGER_IP, "ubuntu", grep_cmd, use_sudo=True)
    
    if not res.stdout.strip():
        print("[!] No hay logs.")
        return

    print(f"{'HORA':<12} | {'USUARIO':<12} | {'EVENTO':<15} | {'COMANDO/BINARIO'}")
    print("-" * 75)

    lineas_vistas = set() # Para evitar duplicados

    for line in res.stdout.splitlines():
        try:
            data = json.loads(line)
            audit = data['data']['audit']
            ts = data.get('timestamp', 'N/A')[11:19]
            exe = audit.get('exe', '???')
            auid = audit.get('auid', '???')
            key = audit.get('key', '???')

            # Extraer solo el nombre del binario
            bin_name = exe.split('/')[-1]

            # FILTRO CRÍTICO:
            if bin_name in IGNORAR:
                continue
            
            # Crear una huella de la línea para evitar spam
            fingerprint = f"{ts}_{bin_name}"
            if fingerprint in lineas_vistas:
                continue
            lineas_vistas.add(fingerprint)

            user_type = "👤 HUMANO" if auid == "1000" else "🤖 SISTEMA"
            alerta = "🛑 ACCESO SHADOW" if "shadow" in key else "⚠️ EJECUCIÓN"

            print(f"{ts:<12} | {user_type:<12} | {alerta:<15} | {exe}")
        except:
            continue

if __name__ == "__main__":
    analyze()