# tools_uninstall_manager/tools_uninstall_manager.py

import os
import subprocess
import logging
import json
from datetime import datetime

from .json_tools_handler import remove_tool_from_json, load_tools

logger = logging.getLogger("tools_uninstall_manager")

# ============================================================
#  Rutas base
# ============================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(BASE_DIR, "tools_uninstall_manager")

SCRIPTS_DIR = os.path.join(TOOLS_DIR, "uninstall_scripts")
LOGS_DIR = os.path.join(TOOLS_DIR, "logs")   # 👈 AQUÍ LOS LOGS


# ============================================================
#  Detectar sistema operativo y usuario SSH
# ============================================================
def detect_instance_os_and_user(instance_name, ip):
    try:
        cmd = ["openstack", "server", "show", instance_name, "-f", "json"]
        output = subprocess.check_output(cmd, text=True)
        info = json.loads(output)

        raw_image = info.get("image")
        if isinstance(raw_image, dict):
            image_name = raw_image.get("name", "").lower()
        else:
            image_name = str(raw_image).lower()

        logger.info(f" Imagen detectada: {image_name}")

        if "ubuntu" in image_name:
            users = ["ubuntu", "debian"]
        elif "debian" in image_name:
            users = ["debian", "ubuntu"]
        elif "kali" in image_name:
            users = ["kali", "debian", "ubuntu"]
        elif "centos" in image_name or "rocky" in image_name:
            users = ["centos", "rocky", "ubuntu"]
        else:
            users = ["ubuntu", "debian"]

        ssh_key = os.path.expanduser("~/.ssh/my_key")

        for u in users:
            test = subprocess.run(
                [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-i", ssh_key,
                    f"{u}@{ip}",
                    "echo ok"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            )
            if test.returncode == 0:
                logger.info(f" Usuario SSH detectado: {u}")
                return u

        logger.warning(" No fue posible detectar usuario SSH válido. Fallback: ubuntu")
        return "ubuntu"

    except Exception as e:
        logger.error(f" Error detectando usuario OS: {e}")
        return "ubuntu"


# ============================================================
#  Desinstalar herramienta
# ============================================================
def uninstall_tool(instance: str, tool: str, ip_private: str, ip_floating: str):
    logger.info(f" Solicitada eliminación '{tool}' en instancia '{instance}'")

    os.makedirs(LOGS_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(
        LOGS_DIR,
        f"uninstall_{tool}_{instance}_{timestamp}.log"
    )

    logger.info(f" Logs de desinstalación en: {log_file}")

    script = os.path.join(SCRIPTS_DIR, f"uninstall_{tool}.sh")
    if not os.path.exists(script):
        logger.error(" Script de uninstall no existe")
        return {
            "status": "error",
            "msg": f"No existe script de uninstall para {tool}",
            "script_executed": False,
            "tools": None
        }

    os.chmod(script, 0o755)

    target_ip = ip_floating or ip_private
    ssh_user = detect_instance_os_and_user(instance, target_ip)

    logger.info(f" SSH User FINAL para desinstalación: {ssh_user}")

    ssh_key = os.path.expanduser("~/.ssh/my_key")
    remote_script = f"/tmp/uninstall_{tool}.sh"

    # ------------------------------------------------------------
    #  Copiar script a la VM
    # ------------------------------------------------------------
    scp = subprocess.run(
        [
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-i", ssh_key,
            script,
            f"{ssh_user}@{target_ip}:{remote_script}"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if scp.returncode != 0:
        with open(log_file, "w") as lf:
            lf.write(scp.stderr)

        logger.error(" Fallo SCP del script de uninstall")
        return {
            "status": "error",
            "msg": "Fallo SCP del script",
            "exit_code": scp.returncode,
            "script_executed": False,
            "log_file": log_file,
            "tools": None
        }

    # ------------------------------------------------------------
    #  Ejecutar script REMOTO como root (LOG + TIMEOUT)
    # ------------------------------------------------------------
    try:
        with open(log_file, "w") as lf:
            proc = subprocess.run(
                [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=10",
                    "-o", "ServerAliveInterval=5",
                    "-o", "ServerAliveCountMax=3",
                    "-i", ssh_key,
                    f"{ssh_user}@{target_ip}",
                    f"sudo -n bash {remote_script}"
                ],
                stdout=lf,
                stderr=lf,
                text=True,
                timeout=300   # ⏱️ 5 minutos
            )
        exit_code = proc.returncode

    except subprocess.TimeoutExpired:
        with open(log_file, "a") as lf:
            lf.write("\n[TIMEOUT] Ejecución excedió 300 segundos\n")
        exit_code = 124
        logger.error(" Timeout ejecutando uninstall remoto")

    # ------------------------------------------------------------
    #  Limpieza remota del script
    # ------------------------------------------------------------
    subprocess.run(
        [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-i", ssh_key,
            f"{ssh_user}@{target_ip}",
            f"rm -f {remote_script}"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    logger.info(f" UNINSTALL exit code: {exit_code}")
    logger.info(f" Logs completos en {log_file}")

    # ------------------------------------------------------------
    #  Actualización del JSON SOLO si OK
    # ------------------------------------------------------------
    if exit_code == 0:
        _, updated_tools = remove_tool_from_json(instance, tool)
        return {
            "status": "success",
            "msg": f" '{tool}' desinstalada COMPLETAMENTE de '{instance}'",
            "exit_code": exit_code,
            "script_executed": True,
            "log_file": log_file,
            "tools": updated_tools
        }
    else:
        current_tools, _ = load_tools(instance)
        return {
            "status": "warning",
            "msg": f" '{tool}' sigue instalada en '{instance}'. Ver logs.",
            "exit_code": exit_code,
            "script_executed": True,
            "log_file": log_file,
            "tools": current_tools
        }
