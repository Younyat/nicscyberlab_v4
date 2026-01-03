import os
import subprocess
import logging
import json
from datetime import datetime

# Importación de las funciones del manejador de JSON
from .json_tools_handler import (
    check_tool_status, 
    remove_tool_from_json, 
    load_tools
)

logger = logging.getLogger("tools_uninstall_manager")

# ============================================================
# Rutas base
# ============================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(BASE_DIR, "tools_uninstall_manager")

# Directorio donde se encuentran los scripts .sh (ej: uninstall_wazuh_agent.sh)
SCRIPTS_DIR = os.path.join(TOOLS_DIR, "uninstall_scripts")
LOGS_DIR = os.path.join(TOOLS_DIR, "logs")

# ============================================================
# Deteccion de sistema operativo y usuario SSH
# ============================================================
def detect_instance_os_and_user(instance_name, ip):
    """
    Utiliza OpenStack CLI para detectar la imagen y probar usuarios SSH validos.
    """
    try:
        cmd = ["openstack", "server", "show", instance_name, "-f", "json"]
        output = subprocess.check_output(cmd, text=True)
        info = json.loads(output)

        raw_image = info.get("image")
        if isinstance(raw_image, dict):
            image_name = raw_image.get("name", "").lower()
        else:
            image_name = str(raw_image).lower()

        logger.info(f"Imagen detectada: {image_name}")

        # Definicion de usuarios segun la distribucion
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

        # Prueba de conexion para confirmar el usuario activo
        for u in users:
            test = subprocess.run(
                [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=5",
                    "-i", ssh_key,
                    f"{u}@{ip}",
                    "echo ok"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            )
            if test.returncode == 0:
                logger.info(f"Usuario SSH confirmado: {u}")
                return u

        logger.warning("No se detecto usuario valido via SSH. Usando ubuntu por defecto.")
        return "ubuntu"

    except Exception as e:
        logger.error(f"Error en deteccion de OS/User: {e}")
        return "ubuntu"

# ============================================================
# Funcion Principal de Desinstalacion
# ============================================================
def uninstall_tool(instance: str, tool: str, ip_private: str, ip_floating: str):
    """
    Orquestador que valida el estado, detecta el entorno y ejecuta el script de Ansible.
    """
    logger.info(f"Solicitud de desinstalacion: tool='{tool}' en instancia='{instance}'")

    # 1. Validacion de estado en el archivo JSON
    # Solo procede si el estado es 'installed'
    can_proceed, msg, current_tools = check_tool_status(instance, tool)
    if not can_proceed:
        logger.warning(f"Abortado: {msg}")
        return {
            "status": "error",
            "msg": msg,
            "tools": current_tools
        }

    # 2. Preparacion de logs y rutas
    os.makedirs(LOGS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(LOGS_DIR, f"uninstall_{tool}_{instance}_{timestamp}.log")

    script_path = os.path.join(SCRIPTS_DIR, f"uninstall_{tool}.sh")
    if not os.path.exists(script_path):
        logger.error(f"Script no encontrado: {script_path}")
        return {
            "status": "error",
            "msg": f"No existe el script de desinstalacion para {tool}",
            "tools": current_tools
        }

    # Asegurar permisos de ejecucion para el script local
    os.chmod(script_path, 0o755)

    # 3. Deteccion de IP y Usuario
    target_ip = ip_floating or ip_private
    ssh_user = detect_instance_os_and_user(instance, target_ip)
    ssh_key = os.path.expanduser("~/.ssh/my_key")

    # 4. Ejecucion del Orquestador Bash (Ansible)
    # Se pasan los argumentos necesarios al script de Bash
    try:
        logger.info(f"Ejecutando orquestador: {script_path}")
        with open(log_file, "w") as lf:
            # Argumentos: $1=Nombre Instancia, $2=Ruta SSH Key, $3=IP, $4=Usuario
            process = subprocess.run(
                ["bash", script_path, instance, ssh_key, target_ip, ssh_user],
                stdout=lf,
                stderr=lf,
                text=True,
                timeout=600  # Limite de 10 minutos
            )
        
        exit_code = process.returncode

    except subprocess.TimeoutExpired:
        logger.error("Timeout: La desinstalacion excedio el tiempo limite.")
        exit_code = 124
    except Exception as e:
        logger.error(f"Error durante la ejecucion: {str(e)}")
        exit_code = 1

    # 5. Actualizacion del inventario JSON segun el resultado
    if exit_code == 0:
        logger.info(f"Desinstalacion exitosa de {tool}. Actualizando JSON.")
        success, updated_tools = remove_tool_from_json(instance, tool)
        return {
            "status": "success",
            "msg": f"'{tool}' desinstalada y purgada correctamente.",
            "exit_code": exit_code,
            "log_file": log_file,
            "tools": updated_tools
        }
    else:
        logger.error(f"Fallo en la desinstalacion de {tool}. Codigo: {exit_code}")
        # Recargamos las herramientas actuales para devolver el estado sin cambios
        current_tools_latest, _ = load_tools(instance)
        return {
            "status": "error",
            "msg": f"Fallo la desinstalacion tecnica de '{tool}'. Revise logs.",
            "exit_code": exit_code,
            "log_file": log_file,
            "tools": current_tools_latest
        }