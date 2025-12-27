# tools_uninstall_manager/tools_uninstall_manager.py

import os
import subprocess
import logging
import json

from .json_tools_handler import remove_tool_from_json, load_tools

logger = logging.getLogger("tools_uninstall_manager")


# ============================================================
#  Detectar sistema operativo y usuario SSH
# ============================================================
def detect_instance_os_and_user(instance_name, ip):
    """
    Detecta imagen de la VM desde OpenStack y 
    prueba usuarios SSH hasta encontrar uno válido.
    """
    try:
        # Obtener info de la instancia desde OpenStack
        cmd = ["openstack", "server", "show", instance_name, "-f", "json"]
        output = subprocess.check_output(cmd, text=True)
        info = json.loads(output)

        raw_image = info.get("image")
        if isinstance(raw_image, dict):
            image_name = raw_image.get("name", "").lower()
        else:
            image_name = str(raw_image).lower()

        logger.info(f" Imagen detectada: {image_name}")

        # Posibles usuarios según la imagen
        if "ubuntu" in image_name:
            users = ["ubuntu", "debian"]
        elif "debian" in image_name:
            users = ["debian", "ubuntu"]
        elif "kali" in image_name:
            users = ["kali", "debian", "ubuntu"]
        elif "centos" in image_name:
            users = ["centos", "rocky", "ubuntu"]
        else:
            users = ["ubuntu", "debian"]  # fallback

        ssh_key = os.path.expanduser("~/.ssh/id_rsa")

        # Probar usuarios
        for u in users:
            test = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-i", ssh_key, f"{u}@{ip}", "echo ok"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if test.returncode == 0:
                logger.info(f" Usuario SSH detectado: {u}")
                return u

        logger.warning(" No fue posible detectar un usuario SSH válido. Usando fallback: ubuntu")
        return "ubuntu"

    except Exception as e:
        logger.error(f" Error detectando usuario OS: {e}")
        return "ubuntu"


# ============================================================
#  Rutas principales
# ============================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "tools_uninstall_manager", "uninstall_scripts")


# ============================================================
#  Desinstalar herramienta
# ============================================================
def uninstall_tool(instance: str, tool: str, ip_private: str, ip_floating: str):
    logger.info(f" Solicitada eliminación '{tool}' en instancia '{instance}'")

    script = os.path.join(SCRIPTS_DIR, f"uninstall_{tool}.sh")
    if not os.path.exists(script):
        logger.warning(f" No existe script uninstall: {script}")
        return {
            "status": "error",
            "msg": f"No existe script de uninstall para {tool}",
            "script_executed": False,
            "tools": None
        }

    os.chmod(script, 0o755)

    #  Detectar usuario SSH correcto
    ssh_user = detect_instance_os_and_user(
        instance,
        ip_floating or ip_private
    )

    logger.info(f" SSH User FINAL para desinstalación: {ssh_user}")

    proc = subprocess.run(
        [script, instance, ip_private, ip_floating, ssh_user],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    exit_code = proc.returncode

    logger.info(f" UNINSTALL exit code: {exit_code}")
    logger.info(f" STDOUT:\n{proc.stdout}")
    logger.info(f" STDERR:\n{proc.stderr}")

    # ============================================================
    # SOLO si exit_code == 0 eliminamos del JSON
    # ============================================================
    if exit_code == 0:
        removed, updated_tools = remove_tool_from_json(instance, tool)
        return {
            "status": "success",
            "msg": f" '{tool}' desinstalada COMPLETAMENTE de '{instance}'",
            "exit_code": exit_code,
            "script_executed": True,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "tools": updated_tools
        }
    else:
        # No se borra del JSON
        current_tools, _ = load_tools(instance)
        return {
            "status": "warning",
            "msg": f" '{tool}' sigue instalada en '{instance}'. Validación falló.",
            "exit_code": exit_code,
            "script_executed": True,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "tools": current_tools
        }
