import os
import subprocess
import shutil
from flask import jsonify, Response
from datetime import datetime

# Cálculo de la raíz del proyecto (sube 3 niveles desde app_core/infrastructure/host_tools_installer/)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# 1. Definir las rutas base según tu estructura
INSTALL_SCRIPTS_DIR = os.path.join(REPO_ROOT, "tools-installer", "scripts-host")
UNINSTALL_SCRIPTS_DIR = os.path.join(REPO_ROOT, "tools_uninstall_manager", "uninstall_scripts-host")

LOG_DIR = os.path.join(REPO_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "host_manage.log")

# 2. Configuración del inventario con rutas separadas
TOOLS_INVENTORY = {
    "tsk": {
        "name": "The Sleuth Kit (TSK)", 
        "binary": "fls", 
        "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_tsk.sh"),
        "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_tsk.sh")
    },
    "tcpdump": {
        "name": "Tcpdump", 
        "binary": "tcpdump", 
        "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_tcpdump.sh"),
        "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_tcpdump.sh")
    },
    "tshark": {
        "name": "Tshark", 
        "binary": "tshark", 
        "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_tshark.sh"),
        "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_tshark.sh")
    },
    "termshark": {
        "name": "Termshark", 
        "binary": "termshark", 
        "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_termshark.sh"),
        "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_termshark.sh")
    },
    "volatility": {
        "name": "Volatility 3", 
        "binary": "vol", 
        "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_volatility.sh"),
        "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_volatility.sh")
    },
    "scapy": {
        "name": "Scapy", 
        "binary": "scapy", 
        "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_scapy.sh"),
        "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_scapy.sh")
    },
    "mbpoll": {
    "name": "mbpoll",
    "binary": "mbpoll",
    "script": os.path.join(INSTALL_SCRIPTS_DIR, "install_mbpoll.sh"),
    "uninstall": os.path.join(UNINSTALL_SCRIPTS_DIR, "uninstall_mbpoll.sh")
}

}

def write_to_log(message):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def get_inventory():
    inventory = []
    for key, info in TOOLS_INVENTORY.items():
        is_installed = shutil.which(info["binary"]) is not None
        inventory.append({
            "id": key,
            "name": info["name"],
            "status": "installed" if is_installed else "not_installed",
            "path": shutil.which(info["binary"]) or "N/A"
        })
    return jsonify({"tools": inventory})

def get_version(tool_id):
    tool = TOOLS_INVENTORY.get(tool_id)
    if not tool:
        return jsonify({"output": "Error: Herramienta no encontrada."}), 404

    binary = tool["binary"]

    cmd_map = {
        "tsk": ["fls", "-V"],
        "scapy": ["python3", "-c", "import scapy; print(scapy.__version__)"],
        "mbpoll": ["mbpoll", "-h"],  # mbpoll no soporta --version
    }

    cmd = cmd_map.get(tool_id, [binary, "--version"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout.strip() if result.stdout else result.stderr.strip()

        if not output:
            output = "No output returned"

        return jsonify({
            "output": f"$ {' '.join(cmd)}\n{output.splitlines()[0]}"
        })

    except FileNotFoundError:
        return jsonify({
            "output": f"Error: binario '{binary}' no encontrado en el sistema."
        }), 404

    except Exception as e:
        return jsonify({
            "output": f"Error ejecutando comando: {str(e)}"
        }), 500

def run_action_sse(tool_id, action="install"):
    tool = TOOLS_INVENTORY.get(tool_id)
    if not tool:
        return Response("Error: Herramienta no encontrada", status=404)
    
    # Selecciona la ruta del script según la acción (install o uninstall)
    script_path = tool["script"] if action == "install" else tool["uninstall"]

    def generate():
        write_to_log(f"INICIO_{action.upper()}: {tool_id}")
        
        # Validar si el script existe antes de intentar ejecutarlo
        if not os.path.exists(script_path):
            error_msg = f"Error: Script no encontrado en {script_path}"
            write_to_log(error_msg)
            yield f"data: {error_msg}\n\n"
            yield "data: [FIN]\n\n"
            return

        process = subprocess.Popen(
            ["bash", script_path], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )
        
        for line in process.stdout:
            clean_line = line.strip()
            write_to_log(f"[{tool_id}] {clean_line}")
            yield f"data: {clean_line}\n\n"
        
        process.wait()
        write_to_log(f"FIN_{action.upper()}: {tool_id} (Code: {process.returncode})")
        yield "data: [FIN]\n\n"

    return Response(generate(), mimetype='text/event-stream')