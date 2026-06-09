import json
import subprocess
import logging
import os
import re
import threading

from flask import Blueprint, request, jsonify, send_from_directory, Response
import openstack

logger = logging.getLogger("app_logger")

# Blueprint principal con todas las rutas migradas desde app.py
api_bp = Blueprint("api", __name__)




# Ruta base del repositorio (raíz del proyecto)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MOCK_SCENARIO_DATA = {}
SCENARIO_FILE = os.path.join(REPO_ROOT, "scenario", "scenario_file.json")

DEFAULT_SCENARIO = {
    "scenario_name": "Default Empty Scenario",
    "description": "Escenario por defecto: no se encontró 'scenario_file.json'",
    "nodes": [{"data": {"id": "n1", "name": "Nodo Inicial"}, "position": {"x": 100, "y": 100}}],
    "edges": []
}



INDUSTRIAL_ALLOWED_TOOLS = {
    "industrial_plc": ["openplc"],
    "industrial_scada": ["fuxa"]
}



try:
    with open(SCENARIO_FILE, 'r') as f:
        MOCK_SCENARIO_DATA["file"] = json.load(f)
except Exception:
    MOCK_SCENARIO_DATA["file"] = DEFAULT_SCENARIO


@api_bp.route('/api/console_url', methods=['POST'])
def get_console_url():
    try:
        data = request.get_json()
        instance_name = data.get('instance_name')
        logger.info(f"Consultar terminal del nodo {instance_name}")

        if not instance_name:
            return jsonify({'error': "Falta 'instance_name'"}), 400

        script_path = os.path.join(REPO_ROOT, "scenario", "get_console_url.sh")

        if not os.path.isfile(script_path):
            return jsonify({'error': f" Script no encontrado: {script_path}"}), 500

        if not os.access(script_path, os.X_OK):
            logger.warning(f" El script no es ejecutable: {script_path}. Corrigiendo permisos...")
            try:
                os.chmod(script_path, 0o755)
                logger.info(f" Permisos corregidos para {script_path}")
            except Exception as chmod_error:
                return jsonify({'error': f"No se pudo otorgar permiso de ejecución: {chmod_error}"}), 500

        proc = subprocess.run(
            [script_path, instance_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        logger.info(f" script stdout:\n{stdout}")
        logger.info(f" script stderr:\n{stderr}")

        text_to_search = stdout + "\n" + stderr
        m = re.search(r'https?://[^\s\'\"<>]+', text_to_search)

        if not m:
            logger.warning(f" No se encontró URL de consola en la salida del script '{instance_name}'")
            return jsonify({
                'error': 'No se encontró URL de la instancia',
                'stdout': stdout,
                'stderr': stderr
            }), 500

        url = m.group(0)
        logger.info(f" URL de consola encontrada para '{instance_name}': {url}")

        return jsonify({
            'message': f'Consola solicitada para {instance_name}',
            'output': url,
            'stdout': stdout,
            'stderr': stderr
        }), 200

    except subprocess.SubprocessError as suberr:
        logger.exception(f" Error al ejecutar el script para '{instance_name}': {suberr}")
        return jsonify({'error': 'Error al ejecutar el script', 'details': str(suberr)}), 500

    except Exception as e:
        logger.exception(f" Error inesperado al procesar la solicitud de consola para '{instance_name}'")
        return jsonify({'error': 'Error interno', 'details': str(e)}), 500


@api_bp.route('/api/get_scenario/<scenarioName>', methods=['GET'])
def get_scenario_by_name(scenarioName):
    try:
        scenario_dir = os.path.join(REPO_ROOT, "scenario")
        file_path = os.path.join(scenario_dir, f"scenario_{scenarioName}.json")

        if not os.path.exists(file_path):
            return jsonify({
                "status": "error",
                "message": f" Escenario '{scenarioName}' no encontrado en {scenario_dir}"
            }), 404

        with open(file_path, 'r') as f:
            scenario = json.load(f)
        return jsonify(scenario), 200

    except json.JSONDecodeError:
        return jsonify({
            "status": "error",
            "message": f" El archivo 'scenario_{scenarioName}.json' contiene JSON inválido"
        }), 500

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f" Error inesperado al leer el escenario: {str(e)}"
        }), 500


@api_bp.route('/api/destroy_scenario', methods=['POST'])
def destroy_scenario():
    try:
        SCENARIO_DIR = os.path.join(REPO_ROOT, "scenario")
        script_path = os.path.join(SCENARIO_DIR, "destroy_scenario_openstack_mejorado.sh")

        if not os.path.exists(script_path):
            return jsonify({"status": "error", "message": "Script no encontrado"}), 404

        process = subprocess.Popen(
            ["bash", script_path, "tf_out"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        status_file = os.path.join(SCENARIO_DIR, "destroy_status.json")
        with open(status_file, "w") as sf:
            json.dump({"status": "running"}, sf)

        def monitor():
            stdout, stderr = process.communicate()
            with open(status_file, "w") as sf:
                json.dump({
                    "status": "success" if process.returncode == 0 else "error",
                    "stdout": stdout,
                    "stderr": stderr
                }, sf)

        threading.Thread(target=monitor, daemon=True).start()

        return jsonify({
            "status": "running",
            "message": " Destrucción iniciada.",
            "pid": process.pid
        }), 202

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route('/api/destroy_status')
def destroy_status():
    status_file = os.path.join(REPO_ROOT, "scenario", "destroy_status.json")

    if not os.path.exists(status_file):
        return jsonify({"status": "unknown"}), 404

    with open(status_file) as f:
        return jsonify(json.load(f)), 200


@api_bp.route('/api/create_scenario', methods=['POST'])
def create_scenario():
    try:
        scenario_data = request.get_json()
        if not scenario_data:
            return jsonify({"status": "error", "message": "No se recibió JSON válido"}), 400

        scenario_name = scenario_data.get('scenario_name', 'Escenario_sin_nombre')
        safe_name = scenario_name.replace(' ', '_').replace(':', '').replace('/', '_').replace('\\', '_')

        SCENARIO_DIR = os.path.join(REPO_ROOT, "scenario")
        TF_OUT_DIR = os.path.join(REPO_ROOT, "tf_out")

        os.makedirs(SCENARIO_DIR, exist_ok=True)
        os.makedirs(TF_OUT_DIR, exist_ok=True)

        file_path = os.path.join(SCENARIO_DIR, f"scenario_{safe_name}.json")
        script_path = os.path.join(SCENARIO_DIR, "main_generator_inicial_openstack.sh")

        logger.info(f" Ruta base: {REPO_ROOT}")
        logger.info(f" Escenario: {file_path}")
        logger.info(f"  Script: {script_path}")

        with open(file_path, 'w') as f:
            json.dump(scenario_data, f, indent=4)
        logger.info(f" Escenario guardado en {file_path}")

        if not os.path.exists(script_path):
            return jsonify({
                "status": "error",
                "message": f" Script no encontrado: {script_path}"
            }), 500

        status_file = os.path.join(SCENARIO_DIR, "deployment_status.json")
        with open(status_file, "w") as sfile:
            json.dump({
                "status": "running",
                "message": f" Despliegue en curso para '{scenario_name}'...",
                "pid": None
            }, sfile, indent=4)

        process = subprocess.Popen(
            ["bash", script_path, file_path, TF_OUT_DIR],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        logger.info(f" Despliegue iniciado (PID={process.pid}) para {scenario_name}")

        with open(os.path.join(REPO_ROOT, "last_deployment.pid"), "w") as pidfile:
            pidfile.write(str(process.pid))

        def monitor_process():
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                logger.info(f" Despliegue completado correctamente para '{scenario_name}'")
                with open(status_file, "w") as sfile:
                    json.dump({
                        "status": "success",
                        "message": f" Despliegue completado correctamente para '{scenario_name}'.",
                        "stdout": stdout,
                        "stderr": stderr
                    }, sfile, indent=4)
            else:
                logger.error(f" Error en el despliegue de '{scenario_name}': {stderr}")
                with open(status_file, "w") as sfile:
                    json.dump({
                        "status": "error",
                        "message": f" Error al desplegar '{scenario_name}'",
                        "stdout": stdout,
                        "stderr": stderr
                    }, sfile, indent=4)

        threading.Thread(target=monitor_process, daemon=True).start()

        return jsonify({
            "status": "running",
            "message": f" Despliegue de '{scenario_name}' iniciado.",
            "pid": process.pid,
            "file": file_path,
            "output_dir": TF_OUT_DIR
        }), 202

    except Exception as e:
        logger.error(f" Error al procesar escenario: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Error interno: {str(e)}"}), 500


@api_bp.route('/api/deployment_status', methods=['GET'])
def deployment_status():
    status_file = os.path.join(REPO_ROOT, "scenario", "deployment_status.json")

    if not os.path.exists(status_file):
        return jsonify({
            "status": "unknown",
            "message": " No existe archivo de estado de despliegue."
        }), 404

    try:
        with open(status_file, "r") as sfile:
            data = json.load(sfile)
        return jsonify(data), 200
    except json.JSONDecodeError:
        return jsonify({
            "status": "error",
            "message": " Error al leer JSON de estado."
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f" Error interno: {str(e)}"
        }), 500


@api_bp.route('/api/destroy_initial_environment_setup', methods=['POST'])
def destroy_initial_environment_setup():
    try:
        logger.info("===============================================")
        logger.info(" API CALL: /api/run_initial_environment_setup")
        logger.info("===============================================")

        INITIAL_DIR = os.path.join(REPO_ROOT, "initial")
        script_path = os.path.join(INITIAL_DIR, "limpiar_inicial.sh")

        if not os.path.exists(script_path):
            return jsonify({
                "status": "error",
                "message": f" Script no encontrado: {script_path}"
            }), 404

        if not os.access(script_path, os.X_OK):
            os.chmod(script_path, 0o755)

        logger.info(" Ejecutando script (modo BLOQUEANTE)...")

        result = subprocess.run(
            ["bash", script_path],
            cwd=INITIAL_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        logger.info(" STDOUT:")
        logger.info(result.stdout)
        logger.info(" STDERR:")
        logger.info(result.stderr)

        if result.returncode == 0:
            return jsonify({
                "status": "success",
                "message": " Entorno inicial desplegado correctamente.",
                "stdout": result.stdout,
                "stderr": result.stderr
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": " Error durante el despliegue inicial.",
                "stdout": result.stdout,
                "stderr": result.stderr
            }), 500

    except Exception as e:
        logger.exception(" Error inesperado")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@api_bp.route('/api/run_initial_environment_setup', methods=['POST'])
def run_initial_environment_setup():
    try:
        logger.info("===============================================")
        logger.info(" API CALL: /api/run_initial_environment_setup")
        logger.info("===============================================")

        INITIAL_DIR = os.path.join(REPO_ROOT, "initial")
        CONFIG_DIR = os.path.join(INITIAL_DIR, "configs")

        os.makedirs(CONFIG_DIR, exist_ok=True)

        json_path = os.path.join(CONFIG_DIR, "scenario_config.json")

        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": " No se recibió JSON válido"
            }), 400

        with open(json_path, "w") as f:
            json.dump(data, f, indent=4)

        script_path = os.path.join(INITIAL_DIR, "run_scenario_from_json.sh")

        if not os.path.exists(script_path):
            return jsonify({
                "status": "error",
                "message": f" Script no encontrado: {script_path}"
            }), 404

        if not os.access(script_path, os.X_OK):
            os.chmod(script_path, 0o755)

        logger.info(" Ejecutando script (modo BLOQUEANTE)...")

        result = subprocess.run(
            ["bash", script_path, json_path],
            cwd=INITIAL_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        logger.info(" STDOUT:")
        logger.info(result.stdout)
        logger.info(" STDERR:")
        logger.info(result.stderr)

        if result.returncode == 0:
            return jsonify({
                "status": "success",
                "message": " Entorno inicial desplegado correctamente.",
                "stdout": result.stdout,
                "stderr": result.stderr
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": " Error durante el despliegue inicial.",
                "stdout": result.stdout,
                "stderr": result.stderr
            }), 500

    except Exception as e:
        logger.exception(" Error inesperado")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@api_bp.route('/api/run_initial_generator_stream')
def stream_logs():
    def generate():
        yield "data: iniciando...\n\n"
        with open(os.path.join(REPO_ROOT, "app.log"), "r") as f:
            for line in f:
                yield f"data: {line}\n\n"
    return Response(generate(), mimetype='text/event-stream')


# =========================
# OpenStack Connection
# =========================


def get_openstack_connection():
    """Devuelve una conexión OpenStack usando las variables cargadas desde admin-openrc.sh"""
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        region_name=os.environ.get("OS_REGION_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        compute_api_version="2",
        identity_interface="public"
    )







@api_bp.route("/api/openstack/instances", methods=["GET"])
def api_get_openstack_instances():
    try:
        conn = get_openstack_connection()
        instances = []

        # Listar todos los servidores de OpenStack
        for server in conn.compute.servers():
            ip_private = None
            ip_floating = None

            # Extraer direcciones IP
            for net_name, addresses in server.addresses.items():
                for addr in addresses:
                    ip = addr.get("addr")
                    if addr.get("OS-EXT-IPS:type") == "floating":
                        ip_floating = ip
                    else:
                        ip_private = ip

            # --- NUEVA LÓGICA DE PERSISTENCIA ---
            # Buscamos si existe un registro de herramientas para este ID de instancia
            installed_path = os.path.join(INSTALLED_DIR, f"{server.id}.json")
            installed_tools = {}

            if os.path.exists(installed_path):
                try:
                    with open(installed_path, "r") as f:
                        tool_data = json.load(f)
                        # Obtenemos el diccionario de herramientas (ej: {"wazuh": "2024-05-20..."})
                        installed_tools = tool_data.get("installed_tools", {})
                except Exception as e:
                    logger.error(f"Error leyendo registro de herramientas para {server.id}: {e}")

            # Construir el objeto de la instancia para el frontend
            instances.append({
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "ip_private": ip_private,
                "ip_floating": ip_floating,
                "ip": ip_floating or ip_private or "N/A",
                "image": server.image["id"] if server.image else None,
                "flavor": server.flavor["id"] if server.flavor else None,
                # Enviamos las herramientas instaladas para que el frontend las muestre
                "installed_tools": installed_tools 
            })

        return jsonify({"instances": instances}), 200

    except Exception as e:
        logger.error(f"Error al consultar instancias OpenStack: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@api_bp.route('/api/add_tool_to_instance', methods=['POST'])
def add_tool_to_instance():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "msg": "JSON vacío"}), 400

        instance = data.get("instance") or data.get("name")
        # Capturamos las tools. Si vienen como lista, las convertiremos a objeto abajo.
        tools_data = data.get("tools", {})

        DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")
        os.makedirs(DIR, exist_ok=True)

        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', instance.lower())
        path = os.path.join(DIR, f"{safe}_tools.json")

        # Mantenemos la estructura original pero aseguramos que 'tools' sea un objeto
        # Si recibimos ['wazuh'], lo convertimos a {'wazuh': 'pending'}
        if isinstance(tools_data, list):
            new_tools_obj = {}
            for t in tools_data:
                new_tools_obj[t] = "pending" # Estado por defecto para nuevos
            data["tools"] = new_tools_obj

        with open(path, "w") as f:
            json.dump(data, f, indent=4)

        return jsonify({"status": "success", "saved": path, "current_tools": data["tools"]})

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@api_bp.route('/api/read_tools_configs', methods=['GET'])
def read_tools_configs():
    print(" Leyendo archivos tools-installer/ ...")

    DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")

    if not os.path.exists(DIR):
        return jsonify({"files": []})

    result = []

    for filename in os.listdir(DIR):
        if filename.endswith("_tools.json"):
            path = os.path.join(DIR, filename)

            with open(path, "r") as f:
                data = json.load(f)

            result.append({
                "file": filename,
                "instance": data.get("instance"),
                "tools": data.get("tools", [])
            })

            print(f" {filename}: {data}")

    return jsonify({"files": result})


@api_bp.route('/api/install_tools', methods=['POST'])
def install_tools():
    # Obtenemos los datos para saber a quién registrar al final
    data = request.get_json()
    instance_id = data.get("instance_id")
    instance_name = data.get("instance")
    tools_to_install = data.get("tools", []) # Lista de nombres de tools

    SCRIPT = os.path.join(REPO_ROOT, "tools-installer", "tools_install_master.sh")

    if not os.path.exists(SCRIPT):
        return jsonify({"status": "error", "msg": "Script maestro no encontrado"}), 404

    os.chmod(SCRIPT, 0o755)

    def generate():
        process = subprocess.Popen(
            ["bash", SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            yield f"data: {line.strip()}\n\n"

        process.wait()
        
        # MOMENTO CLAVE: Si el proceso terminó bien (código 0)
        if process.returncode == 0:
            # Registramos cada herramienta instalada en el JSON persistente
            for t_name in tools_to_install:
                save_as_installed(instance_id, instance_name, t_name)
            yield f"data: [SUCCESS] Registro actualizado en el sistema.\n\n"
        
        yield f"data: [FIN] Exit Code: {process.returncode}\n\n"

    return Response(generate(), mimetype='text/event-stream')

import re

@api_bp.route('/api/get_tools_for_instance', methods=['GET'])
def get_tools_for_instance():
    instance_name = request.args.get("instance")

    if not instance_name:
        # Importante: devolver un objeto {} no un array []
        return jsonify({"tools": {}})

    DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")
    
    # NORMALIZACIÓN: "attack 2" -> "attack_2"
    # Esto coincide con como se guardan físicamente los archivos
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', instance_name.lower())
    filename = f"{safe_name}_tools.json"
    path = os.path.join(DIR, filename)

    print(f" Buscando archivo: {path} para instancia: {instance_name}")

    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
                
            print(f" JSON encontrado y cargado: {filename}")
            return jsonify({
                "instance": instance_name,
                "tools": data.get("tools", {}) # Retorna el objeto de herramientas
            })
        except Exception as e:
            print(f" Error al leer el archivo: {e}")
            return jsonify({"tools": {}}), 500

    print(f" JSON NO encontrado: {path}")
    return jsonify({"instance": instance_name, "tools": {}})

from tools_uninstall_manager.tools_uninstall_manager import uninstall_tool
#----------------------------------------------------------------------------------------------------------------------------------------uninstaller

@api_bp.route('/api/uninstall_tool_from_instance', methods=['POST'])
def api_uninstall_tool():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "msg": "JSON vacío"}), 400

        instance_name = data.get("instance")
        instance_id = data.get("instance_id") # Importante: enviar ID desde el front
        ip_private = data.get("ip_private", "")
        ip_floating = data.get("ip_floating", "")
        tool = data.get("tool")

        if not instance_name or not tool or not instance_id:
            return jsonify({
                "status": "error", 
                "msg": "Faltan campos: instance, instance_id y tool son obligatorios"
            }), 400

        # 1. Ejecutar la desinstalación física en el servidor
        result = uninstall_tool(
            instance_name,
            tool,
            ip_private,
            ip_floating
        )

        # 2. Si el script tuvo éxito, actualizamos nuestro registro local JSON
        if result.get("status") == "success" or result.get("exit_code") == 0:
            remove_from_installed(instance_id, tool)
            logger.info(f"Registro actualizado: {tool} eliminado de {instance_name}")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f" Error API uninstall: {e}", exc_info=True)
        return jsonify({"status": "error", "msg": str(e)}), 500

@api_bp.route("/api/instance_roles", methods=["GET"])
def api_instance_roles():
    conn = None

    try:
        conn = get_openstack_connection()
        servers = conn.compute.servers()

        result = {
            "attacker": None,
            "monitor": None,
            "victim": None,
            "unknown": []
        }

        for server in servers:

            ip_private = None
            ip_floating = None

            for net, addrs in server.addresses.items():
                for addr in addrs:
                    if addr.get("OS-EXT-IPS:type") == "floating":
                        ip_floating = addr["addr"]
                    else:
                        ip_private = addr["addr"]

            ip_final = ip_floating or ip_private or "N/A"

            name = server.name.lower()

            if any(x in name for x in ["attack", "attacker", "redteam", "pentest"]):
                result["attacker"] = {
                    "name": server.name,
                    "ip": ip_final,
                    "status": server.status
                }
                continue

            if any(x in name for x in ["monitor", "wazuh", "log", "siem"]):
                result["monitor"] = {
                    "name": server.name,
                    "ip": ip_final,
                    "status": server.status
                }
                continue

            if any(x in name for x in ["victim", "target", "blue", "server", "web"]):
                result["victim"] = {
                    "name": server.name,
                    "ip": ip_final,
                    "status": server.status
                }
                continue

            result["unknown"].append({
                "name": server.name,
                "ip": ip_final,
                "status": server.status
            })

        return jsonify(result), 200

    except Exception as e:
        logger.error(f" Error en /api/instance_roles: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@api_bp.route('/api/check_wazuh', methods=['POST'])
def api_check_wazuh():
    try:
        data = request.get_json()

        instance = data.get("instance")
        ip = data.get("ip")

        if not instance or not ip:
            return jsonify({"status": "error", "msg": "Faltan campos instance/ip"}), 400

        SSH_DIR = os.path.expanduser("~/.ssh")
        SSH_KEY = ""

        for fname in os.listdir(SSH_DIR):
            full = os.path.join(SSH_DIR, fname)

            if fname.endswith(".pub"):
                continue

            if os.path.isfile(full):
                with open(full, "r", errors="ignore") as f:
                    content = f.read()
                    if "PRIVATE KEY" in content:
                        SSH_KEY = full
                        break

        if not SSH_KEY:
            return jsonify({"status": "error", "msg": "No se encontró clave privada"}), 500

        user = detect_remote_user(ip, SSH_KEY)

        command = """
            (systemctl status wazuh-dashboard.service 2>/dev/null ||
             systemctl status wazuh-indexer.service 2>/dev/null ||
             echo ' Wazuh NO está instalado')
        """

        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-i", SSH_KEY,
            f"{user}@{ip}",
            command
        ]

        proc = subprocess.run(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return jsonify({
            "status": "success",
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode
        })

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500


@api_bp.route("/api/change_password", methods=["POST"])
def api_change_password():
    try:
        data = request.get_json()

        instance = data.get("instance")
        ip = data.get("ip")
        new_pass = data.get("new_password")

        if not instance or not ip or not new_pass:
            return jsonify({"error": "Faltan parámetros"}), 400

        SSH_DIR = os.path.expanduser("~/.ssh")
        SSH_KEY = ""

        for fname in os.listdir(SSH_DIR):
            full = os.path.join(SSH_DIR, fname)
            if fname.endswith(".pub"):
                continue
            if os.path.isfile(full):
                if "PRIVATE KEY" in open(full, "r", errors="ignore").read():
                    SSH_KEY = full
                    break

        if not SSH_KEY:
            return jsonify({"error": "Clave privada no encontrada"}), 500

        user = detect_remote_user(ip, SSH_KEY)

        cmd_change = f"echo '{user}:{new_pass}' | sudo chpasswd"

        proc_change = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, f"{user}@{ip}", cmd_change],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        return jsonify({
            "instance": instance,
            "ip": ip,
            "user": user,
            "stdout": proc_change.stdout,
            "stderr": proc_change.stderr,
            "exitcode": proc_change.returncode
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/change_keyboard_layout", methods=["POST"])
def api_change_keyboard_layout():
    try:
        data = request.get_json()

        instance = data.get("instance")
        ip = data.get("ip")
        layout = data.get("layout", "es")

        if not instance or not ip:
            return jsonify({"error": "Faltan parámetros"}), 400

        SSH_DIR = os.path.expanduser("~/.ssh")
        SSH_KEY = ""

        for fname in os.listdir(SSH_DIR):
            full = os.path.join(SSH_DIR, fname)
            if fname.endswith(".pub"):
                continue
            if os.path.isfile(full):
                with open(full, "r", errors="ignore") as f:
                    if "PRIVATE KEY" in f.read():
                        SSH_KEY = full
                        break

        if not SSH_KEY:
            return jsonify({"error": "Clave privada no encontrada"}), 500

        user = detect_remote_user(ip, SSH_KEY)

        cmd = f"sudo loadkeys {layout}"

        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-i", SSH_KEY, f"{user}@{ip}", cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        return jsonify({
            "instance": instance,
            "ip": ip,
            "user": user,
            "layout": layout,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def detect_remote_user(ip, ssh_key):
    """
    Detecta usuario SSH válido y SO sin bloquear.
    Compatible con Ubuntu / Debian / Kali / Root.
    """

    candidates = ["ubuntu", "debian", "kali", "root"]

    for user in candidates:
        try:
            proc = subprocess.run(
                [
                    "ssh",
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=5",
                    "-i", ssh_key,
                    f"{user}@{ip}",
                    "cat /etc/os-release"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            output = (proc.stdout + proc.stderr).lower()

            if proc.returncode == 0:
                if "ubuntu" in output:
                    return "ubuntu"
                if "debian" in output:
                    return "debian"
                if "kali" in output:
                    return "kali"

                return user

        except Exception:
            continue

    raise RuntimeError(" No se pudo detectar usuario SSH válido")


@api_bp.route("/api/run_tool_version", methods=["POST"])
def api_run_tool_version():
    try:
        data = request.get_json()
        tool = data.get("tool")
        instance = data.get("instance")
        ip = data.get("ip")

        if tool not in ["snort", "suricata"]:
            return jsonify({"error": "Tool no soportada"}), 400

        if not instance or not ip:
            return jsonify({"error": "Faltan parámetros"}), 400

        SSH_DIR = os.path.expanduser("~/.ssh")
        SSH_KEY = None

        for f in os.listdir(SSH_DIR):
            p = os.path.join(SSH_DIR, f)
            if f.endswith(".pub"):
                continue
            if os.path.isfile(p):
                with open(p, "r", errors="ignore") as fd:
                    if "PRIVATE KEY" in fd.read():
                        SSH_KEY = p
                        break

        if not SSH_KEY:
            return jsonify({"error": "No se encontró clave SSH"}), 500

        user = detect_remote_user(ip, SSH_KEY)
        cmd = f"{tool} --version"

        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-i", SSH_KEY,
            f"{user}@{ip}",
            cmd
        ]

        proc = subprocess.run(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return jsonify({
            "status": "success",
            "tool": tool,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "exit_code": proc.returncode
        })

    except Exception as e:
        logger.exception(" Error ejecutando tool --version")
        return jsonify({"error": str(e)}), 500


@api_bp.route('/api/save_industrial_scenario', methods=['POST'])
def save_industrial_scenario():
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "error",
                "message": "No se recibió JSON válido"
            }), 400

        scenario = data.get("scenario")
        if not scenario:
            return jsonify({
                "status": "error",
                "message": "Falta campo 'scenario'"
            }), 400

        scenario_name = scenario.get("scenario_name", "industrial_scenario")

        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', scenario_name.lower())

        INDUSTRIAL_DIR = os.path.join(REPO_ROOT, "industrial-scenario", "scenarios")

        os.makedirs(INDUSTRIAL_DIR, exist_ok=True)

        file_path = os.path.join(
            INDUSTRIAL_DIR,
            f"industrial_{safe_name}.json"
        )

        with open(file_path, "w") as f:
            json.dump(scenario, f, indent=4)

        logger.info(f"Escenario industrial guardado en {file_path}")

        return jsonify({
            "status": "success",
            "message": "Escenario industrial guardado correctamente",
            "file": file_path
        }), 200

    except Exception as e:
        logger.error(
            f"Error guardando escenario industrial: {e}",
            exc_info=True
        )
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

import os
import json
from datetime import datetime

INSTALLED_DIR = os.path.join(REPO_ROOT, "tools-installer", "installed")
os.makedirs(INSTALLED_DIR, exist_ok=True)

def is_tool_installed(instance_id, tool_name):
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            return tool_name in data.get("installed_tools", {})
    return False

def mark_tool_as_installed(instance_id, instance_name, tool_name):
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    data = {"instance_id": instance_id, "instance_name": instance_name, "installed_tools": {}}
    
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
    
    data["installed_tools"][tool_name] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(path, "w") as f:
        json.dump(data, f, indent=4)



def remove_from_installed(instance_id, tool_name):
    """Borra una herramienta del registro persistente de la instancia"""
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            
            if tool_name in data.get("installed_tools", {}):
                del data["installed_tools"][tool_name]
                with open(path, "w") as f:
                    json.dump(data, f, indent=4)
                return True
        except Exception as e:
            logger.error(f"Error al actualizar JSON en desinstalación: {e}")
    return False



# Definir la ruta permanente
INSTALLED_DIR = os.path.join(REPO_ROOT, "tools-installer", "installed")

def save_as_installed(instance_id, instance_name, tool_name):
    """Crea el archivo de registro permanente para la instancia"""
    if not os.path.exists(INSTALLED_DIR):
        os.makedirs(INSTALLED_DIR, exist_ok=True)

    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    
    # Cargar datos existentes o crear nuevos
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
    else:
        data = {
            "instance_id": instance_id,
            "instance_name": instance_name,
            "installed_tools": {}
        }

    # Registrar la herramienta con la fecha actual
    data["installed_tools"][tool_name] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Registro permanente creado en: {path}")







@api_bp.route("/api/get_active_scenario", methods=["GET"])
def get_active_scenario():
    industrial = os.path.join(
        REPO_ROOT, "industrial-scenario", "scenarios", "industrial_industrial_file.json"
    )
    base = os.path.join(REPO_ROOT, "scenario", "scenario_file.json")

    if os.path.exists(industrial):
        with open(industrial) as f:
            return jsonify(json.load(f)), 200

    if os.path.exists(base):
        with open(base) as f:
            return jsonify(json.load(f)), 200

    return jsonify({
        "status": "empty",
        "message": "No hay escenario creado todavía"
    }), 404


@api_bp.route("/api/delete_industrial_scenario", methods=["DELETE"])
def delete_industrial_scenario():
    path = os.path.join(
        REPO_ROOT, "industrial-scenario", "scenarios", "industrial_industrial_file.json"
    )

    if not os.path.exists(path):
        return jsonify({"status": "error"}), 404

    with open(path) as f:
        scenario = json.load(f)

    dep = scenario.get("deployment", {})

    if dep.get("plc_instance", {}).get("state") == "created" or \
       dep.get("scada_instance", {}).get("state") == "created":
        return jsonify({"status": "error"}), 409

    os.remove(path)
    return jsonify({"status": "success"}), 200

@api_bp.route('/api/add_industrial_tool', methods=['POST'])
def add_industrial_tool():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "msg": "JSON vacío"}), 400

        instance = data.get("instance")
        node_type = data.get("node_type")
        tool = data.get("tool")

        if not instance or not node_type or not tool:
            return jsonify({
                "status": "error",
                "msg": "Faltan campos: instance, node_type, tool"
            }), 400

        # Validación estricta PLC / SCADA
        allowed = {
            "industrial_plc": ["openplc"],
            "industrial_scada": ["fuxa"]
        }

        if tool not in allowed.get(node_type, []):
            return jsonify({
                "status": "error",
                "msg": f"Tool '{tool}' no permitida para {node_type}"
            }), 400

        DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")
        os.makedirs(DIR, exist_ok=True)

        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', instance.lower())
        path = os.path.join(DIR, f"{safe}_tools.json")

        payload = {
            "instance": instance,
            "tools": {
                tool: "pending"
            }
        }

        with open(path, "w") as f:
            json.dump(payload, f, indent=4)

        return jsonify({
            "status": "success",
            "instance": instance,
            "tool": tool,
            "file": path
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "msg": str(e)
        }), 500


@api_bp.route("/api/industrial/tools_for_node", methods=["GET"])
def get_tools_for_industrial_node():
    node_type = request.args.get("type")
    tools = INDUSTRIAL_ALLOWED_TOOLS.get(node_type, [])
    return jsonify({"tools": tools})






INDUSTRIAL_STATE_FILE = os.path.join(
    REPO_ROOT,
    "industrial-scenario",
    "state",
    "industrial_state.json"
)

def load_industrial_state():
    if not os.path.exists(INDUSTRIAL_STATE_FILE):
        os.makedirs(os.path.dirname(INDUSTRIAL_STATE_FILE), exist_ok=True)
        with open(INDUSTRIAL_STATE_FILE, "w") as f:
            json.dump({}, f, indent=4)
    with open(INDUSTRIAL_STATE_FILE) as f:
        return json.load(f)

def save_industrial_state(state):
    with open(INDUSTRIAL_STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)



@api_bp.route("/api/industrial/deploy", methods=["POST"])
def deploy_industrial_component():
    data = request.get_json(force=True)
    component = data.get("component")  # plc | scada

    if component not in ["plc", "scada"]:
        return jsonify({"status": "error", "msg": "Componente inválido"}), 400

    scripts = {
        "plc": "industrial-scenario/PLC/deploy_plc_scenario.sh",
        "scada": "industrial-scenario/FUXA/deploy_fuxa_vm.sh"
    }

    script_path = os.path.join(REPO_ROOT, scripts[component])
    log_path = get_log_path(component)

    state = load_industrial_state()
    comp = state.setdefault(component, {})

    # Bloqueo si está OK
    if comp.get("instance", {}).get("status") == "created" and \
       comp.get("tool", {}).get("status") == "installed":
        return jsonify({
            "status": "blocked",
            "msg": "Componente ya instalado correctamente"
        }), 409

    # Estado inicial
    comp["instance"] = {"status": "creating", "last_error": None}
    comp["tool"] = {
        "name": "openplc" if component == "plc" else "fuxa",
        "status": "installing",
        "last_error": None
    }
    save_industrial_state(state)

    def generate():
        yield f"[INFO] Ejecutando {script_path}\n"

        with open(log_path, "w") as logfile:
            process = subprocess.Popen(
                ["bash", script_path],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in process.stdout:
                logfile.write(line)
                logfile.flush()
                yield line

            process.wait()

            if process.returncode == 0:
                comp["instance"]["status"] = "created"
                comp["tool"]["status"] = "installed"
                save_industrial_state(state)

                yield "\n[SUCCESS] Instalación completada correctamente\n"
            else:
                comp["instance"]["status"] = "error"
                comp["tool"]["status"] = "error"
                comp["instance"]["last_error"] = "Error en instalación"
                comp["tool"]["last_error"] = "Error en instalación"
                save_industrial_state(state)

                yield "\n[ERROR] Fallo durante la instalación\n"

    return Response(generate(), mimetype="text/plain")



def get_log_path(component):
    base = os.path.join(REPO_ROOT, "industrial-scenario", "logs", component)
    os.makedirs(base, exist_ok=True)

    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(base, f"deploy_{ts}.log")


@api_bp.route("/api/industrial/state", methods=["GET"])
def get_industrial_state():
    try:
        with open(INDUSTRIAL_STATE_FILE) as f:
            state = json.load(f)
        return jsonify(state)
    except Exception as e:
        return jsonify({"error": str(e)}), 500







# Directorios existentes (los tuyos)
TOOLS_TMP_DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")
INSTALLED_DIR = os.path.join(REPO_ROOT, "tools-installer", "installed")

os.makedirs(TOOLS_TMP_DIR, exist_ok=True)
os.makedirs(INSTALLED_DIR, exist_ok=True)

# =========================
# OpenStack Connection
# =========================
def get_openstack_connection():
    """Devuelve una conexión OpenStack usando las variables cargadas desde admin-openrc.sh"""
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        region_name=os.environ.get("OS_REGION_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        compute_api_version="2",
        identity_interface="public",
    )

def safe_instance_filename(instance_name: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", (instance_name or "").lower())
    return f"{safe_name}_tools.json"

def load_tools_tmp(instance_name: str) -> dict:
    """Lee tools-installer-tmp/<instance>_tools.json (pending/error/...)"""
    path = os.path.join(TOOLS_TMP_DIR, safe_instance_filename(instance_name))
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("tools", {})
        if isinstance(tools, list):
            # Si por algún motivo alguien guardó lista antigua, la convertimos
            tools = {t: "pending" for t in tools}
        if not isinstance(tools, dict):
            return {}
        return tools
    except Exception as e:
        logger.error(f"Error leyendo tools tmp de {instance_name}: {e}")
        return {}

def load_tools_installed(instance_id: str) -> dict:
    """Lee tools-installer/installed/<instance_id>.json (fecha instalada)"""
    if not instance_id:
        return {}
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("installed_tools", {})
        if not isinstance(tools, dict):
            return {}
        return tools
    except Exception as e:
        logger.error(f"Error leyendo installed tools de {instance_id}: {e}")
        return {}

def merge_tools_state(instance_id: str, instance_name: str) -> dict:
    """
    Devuelve el estado FINAL por herramienta.

    Prioridad CORRECTA (forense):
      1) Estado ACTUAL (tools-installer-tmp): error / pending / uninstalling
      2) Estado HISTÓRICO (installed): fecha de instalación

    Regla de oro:
      - Un ERROR actual invalida cualquier instalación pasada
      - Installed es historia, TMP es el presente
    """

    tmp = load_tools_tmp(instance_name) or {}
    installed = load_tools_installed(instance_id) or {}

    merged = {}

    # 1. Primero, el estado ACTUAL manda (TMP)
    for tool, status in tmp.items():
        merged[tool] = status

    # 2. Solo añadimos installed SI NO hay estado negativo en TMP
    for tool, date in installed.items():
        if tool not in merged:
            merged[tool] = date
        else:
            # Si el estado actual es negativo, NO se pisa
            if merged[tool] in ("error", "pending", "uninstalling"):
                continue
            merged[tool] = date

    return merged

def extract_subnet_cidr(conn, network_id: str):
    """Obtiene CIDRs de subredes de una network (si existen)."""
    cidrs = []
    try:
        net = conn.network.get_network(network_id)
        subnet_ids = getattr(net, "subnet_ids", []) or []
        for sid in subnet_ids:
            try:
                sub = conn.network.get_subnet(sid)
                if getattr(sub, "cidr", None):
                    cidrs.append(sub.cidr)
            except Exception:
                continue
    except Exception:
        return []
    return cidrs

# =========================
# Endpoint: Full Forensic Snapshot (instancias)
# =========================
@api_bp.route("/api/openstack/instances/full", methods=["GET"])
def api_openstack_instances_full():
    conn = None
    try:
        conn = get_openstack_connection()
        out = []

        # details=True para más campos
        for server in conn.compute.servers(details=True):
            ip_private = None
            ip_floating = None
            networks = []

            addresses = server.addresses or {}
            for net_name, addrs in addresses.items():
                for a in addrs:
                    addr = a.get("addr")
                    ip_type = a.get("OS-EXT-IPS:type")
                    mac = a.get("OS-EXT-IPS-MAC:mac_addr") or a.get("mac_addr")
                    networks.append({
                        "network": net_name,
                        "ip": addr,
                        "type": ip_type,
                        "mac": mac
                    })
                    if ip_type == "floating":
                        ip_floating = addr
                    else:
                        ip_private = addr

            # =========================
            # FLAVOR (UUID o NOMBRE)
            # =========================
            flavor_obj = None
            try:
                flavor_ref = server.flavor["id"] if server.flavor else None

                if flavor_ref:
                    f = None

                    # 1) Intentar como UUID
                    try:
                        f = conn.compute.get_flavor(flavor_ref)
                    except Exception:
                        # 2) Fallback: buscar por NOMBRE
                        for fl in conn.compute.flavors():
                            if fl.name == flavor_ref:
                                f = fl
                                break

                    if f:
                        flavor_obj = {
                            "id": f.id,
                            "name": f.name,
                            "vcpus": f.vcpus,
                            "ram_mb": f.ram,
                            "disk_gb": f.disk,
                            "ephemeral_gb": getattr(f, "ephemeral", 0),
                            "swap_mb": getattr(f, "swap", 0),
                        }

            except Exception as e:
                logger.warning(f"No se pudo leer flavor para {server.name}: {e}")

            # =========================
            # VOLUMES ATTACHED
            # =========================
            volumes = []
            try:
                attached = getattr(server, "attached_volumes", []) or []
                for v in attached:
                    vid = v.get("id")
                    if not vid:
                        continue
                    try:
                        vol = conn.block_storage.get_volume(vid)
                        volumes.append({
                            "id": vol.id,
                            "name": vol.name,
                            "size_gb": vol.size,
                            "status": vol.status,
                            "bootable": vol.bootable,
                            "volume_type": getattr(vol, "volume_type", None),
                        })
                    except Exception:
                        volumes.append({
                            "id": vid,
                            "name": None,
                            "size_gb": None,
                            "status": "unknown",
                            "bootable": None
                        })
            except Exception as e:
                logger.warning(f"No se pudo leer volúmenes para {server.name}: {e}")

            # =========================
            # SECURITY GROUPS
            # =========================
            try:
                sgs = [
                    sg.get("name")
                    for sg in (server.security_groups or [])
                    if sg.get("name")
                ]
            except Exception:
                sgs = []

            # =========================
            # TOOLS STATE (CORREGIDO)
            # =========================
            tools_state = merge_tools_state(server.id, server.name)

            # =========================
            # RESPONSE OBJECT
            # =========================
            out.append({
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "image": server.image["id"] if server.image else None,
                "created_at": getattr(server, "created_at", None),
                "updated_at": getattr(server, "updated_at", None),

                "flavor": flavor_obj,
                "ip_private": ip_private,
                "ip_floating": ip_floating,
                "networks": networks,
                "security_groups": sgs,
                "volumes": volumes,

                "tools": tools_state,

                # Forensic evidence flags (guía)
                "evidence": {
                    "memory": (server.status == "ACTIVE"),
                    "disk": True,
                    "network": len(networks) > 0
                }
            })

        return jsonify({"instances": out}), 200

    except Exception as e:
        logger.error(
            f"Error /api/openstack/instances/full: {e}",
            exc_info=True
        )
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

# =========================
# Endpoint: Flavors
# =========================
@api_bp.route("/api/openstack/flavors", methods=["GET"])
def api_openstack_flavors():
    conn = None
    try:
        conn = get_openstack_connection()
        flavors = []
        for f in conn.compute.flavors(details=True):
            flavors.append({
                "id": f.id,
                "name": f.name,
                "vcpus": f.vcpus,
                "ram_mb": f.ram,
                "disk_gb": f.disk,
                "ephemeral_gb": getattr(f, "ephemeral", 0),
                "swap_mb": getattr(f, "swap", 0),
                "is_public": getattr(f, "is_public", None),
            })
        flavors.sort(key=lambda x: (x["vcpus"], x["ram_mb"], x["disk_gb"]))
        return jsonify({"flavors": flavors}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/flavors: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try: conn.close()
            except Exception: pass

# =========================
# Endpoint: Networks (+ CIDRs via subnets)
# =========================
@api_bp.route("/api/openstack/networks", methods=["GET"])
def api_openstack_networks():
    conn = None
    try:
        conn = get_openstack_connection()
        networks = []
        for n in conn.network.networks():
            cidrs = extract_subnet_cidr(conn, n.id)
            networks.append({
                "id": n.id,
                "name": n.name,
                "status": getattr(n, "status", None),
                "is_router_external": getattr(n, "is_router_external", None),
                "provider_network_type": getattr(n, "provider_network_type", None),
                "provider_segmentation_id": getattr(n, "provider_segmentation_id", None),
                "cidrs": cidrs
            })
        networks.sort(key=lambda x: x["name"] or "")
        return jsonify({"networks": networks}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/networks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try: conn.close()
            except Exception: pass

# =========================
# Endpoint: Security Groups (+ rules count)
# =========================
@api_bp.route("/api/openstack/security-groups", methods=["GET"])
def api_openstack_security_groups():
    conn = None
    try:
        conn = get_openstack_connection()
        sgs = []
        for sg in conn.network.security_groups():
            rules = getattr(sg, "security_group_rules", []) or []
            sgs.append({
                "id": sg.id,
                "name": sg.name,
                "description": getattr(sg, "description", ""),
                "rules_count": len(rules),
            })
        sgs.sort(key=lambda x: x["name"] or "")
        return jsonify({"security_groups": sgs}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/security-groups: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try: conn.close()
            except Exception: pass

# =========================
# Endpoint: Keypairs
# =========================
@api_bp.route("/api/openstack/keypairs", methods=["GET"])
def api_openstack_keypairs():
    conn = None
    try:
        conn = get_openstack_connection()
        keys = []
        for k in conn.compute.keypairs():
            keys.append({
                "name": k.name,
                "fingerprint": getattr(k, "fingerprint", None),
                "type": getattr(k, "type", None),
            })
        keys.sort(key=lambda x: x["name"] or "")
        return jsonify({"keypairs": keys}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/keypairs: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try: conn.close()
            except Exception: pass

# =========================
# Forensic Host Tools (instalar en el host)
# =========================
FORENSIC_HOST_TOOLS = {
    # tool_name: { "check_cmd": [...], "install_script": "relative/path.sh" }
    "volatility3": {"check_cmd": ["bash", "-lc", "vol --info >/dev/null 2>&1"], "install_script": "forensic-host/install_volatility3.sh"},
    "autopsy":     {"check_cmd": ["bash", "-lc", "autopsy --help >/dev/null 2>&1"], "install_script": "forensic-host/install_autopsy.sh"},
    "tsk":         {"check_cmd": ["bash", "-lc", "tsk_recover -V >/dev/null 2>&1"], "install_script": "forensic-host/install_tsk.sh"},
    "tcpdump":     {"check_cmd": ["bash", "-lc", "tcpdump --version >/dev/null 2>&1"], "install_script": "forensic-host/install_tcpdump.sh"},
    "tshark":      {"check_cmd": ["bash", "-lc", "tshark --version >/dev/null 2>&1"], "install_script": "forensic-host/install_tshark.sh"},
    "termshark":   {"check_cmd": ["bash", "-lc", "termshark --version >/dev/null 2>&1"], "install_script": "forensic-host/install_termshark.sh"},
}

def host_tool_status(tool_name: str) -> dict:
    spec = FORENSIC_HOST_TOOLS.get(tool_name)
    if not spec:
        return {"name": tool_name, "status": "unknown"}

    try:
        r = subprocess.run(spec["check_cmd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode == 0:
            return {"name": tool_name, "status": "installed"}
        return {"name": tool_name, "status": "not_installed"}
    except Exception as e:
        return {"name": tool_name, "status": "error", "error": str(e)}

@api_bp.route("/api/host/forensic/tools", methods=["GET"])
def api_host_forensic_tools():
    out = []
    for t in FORENSIC_HOST_TOOLS.keys():
        out.append(host_tool_status(t))
    return jsonify({"tools": out}), 200

@api_bp.route("/api/host/forensic/install", methods=["POST"])
def api_host_forensic_install():
    data = request.get_json(force=True, silent=True) or {}
    tool = data.get("tool")

    if tool not in FORENSIC_HOST_TOOLS:
        return jsonify({"status": "error", "msg": "Tool no permitida"}), 400

    script_rel = FORENSIC_HOST_TOOLS[tool]["install_script"]
    script_path = os.path.join(REPO_ROOT, script_rel)

    if not os.path.exists(script_path):
        return jsonify({"status": "error", "msg": f"Script no encontrado: {script_rel}"}), 404

    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["bash", script_path],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Re-check status
        status = host_tool_status(tool)

        return jsonify({
            "status": "success" if proc.returncode == 0 else "error",
            "tool": tool,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "after": status
        }), 200 if proc.returncode == 0 else 500

    except Exception as e:
        logger.error(f"Error instalando {tool} en host: {e}", exc_info=True)
        return jsonify({"status": "error", "msg": str(e)}), 500


#-------------------------------------------------------------------------------AI module-----------------------------

# ============================================================
# AI MODULE BACKEND
# ============================================================

import os
import json
import time
import threading
import subprocess

from flask import jsonify, Response

# ------------------------------------------------------------
# PATHS (FIJOS)
# ------------------------------------------------------------
AI_BASE_DIR = os.path.join(REPO_ROOT, "ai_bootstrap_bundle", "ai")
AI_LOG_DIR = os.path.join(AI_BASE_DIR, "logs")

AI_STATE_FILE = os.path.join(AI_BASE_DIR, "ai_module_state.json")
AI_LOG_FILE = os.path.join(AI_LOG_DIR, "deploy_ai.log")

AI_VM_NAME = "AI_Server_Qwen2_5_7B"

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------
def read_ai_state():
    if not os.path.exists(AI_STATE_FILE):
        return None
    with open(AI_STATE_FILE, "r") as f:
        return json.load(f)

# ------------------------------------------------------------
# STATUS
# ------------------------------------------------------------
@api_bp.route("/api/ai/status", methods=["GET"])
def api_ai_status():

    base = {
        "installed": False,
        "deploying": False,
        "progress": 0,
        "phase": "not_installed",
        "message": "The AI ​​module does not exist. It requires deployment.",
        "status": {
            "module": "ai",
            "instance": {
                "exists": False,
                "id": None,
                "name": AI_VM_NAME,
                "status": None
            },
            "network": {
                "ip_floating": None,
                "ip_private": None
            },
            "gui": {
                "installed": False,
                "port": 3000,
                "status": "not_installed",
                "url": None
            },
            "api": {
                "port": 8000,
                "url": None
            }
        }
    }

    if not os.path.exists(AI_STATE_FILE):
        return jsonify(base), 200

    try:
        data = read_ai_state()
        deployment = data.get("deployment", {})
        gui = data.get("gui", {})

        progress = int(deployment.get("progress", 0))
        deploying = 0 < progress < 100
        installed = gui.get("installed", False) and progress == 100

        return jsonify({
            "installed": installed,
            "deploying": deploying,
            "progress": progress,
            "phase": deployment.get("phase", "unknown"),
            "message": deployment.get("message", ""),
            "status": data
        }), 200

    except Exception as e:
        return jsonify({
            **base,
            "message": f"Error leyendo estado IA: {str(e)}"
        }), 200

# ------------------------------------------------------------
# DEPLOY
# ------------------------------------------------------------
@api_bp.route("/api/ai/deploy", methods=["POST"])
def api_ai_deploy():

    script = os.path.join(
        REPO_ROOT,
        "ai_bootstrap_bundle",
        "deploy_ai_server.sh"
    )

    if not os.path.exists(script):
        return jsonify({
            "status": "error",
            "message": "Script de despliegue IA no encontrado",
            "path": script
        }), 404

    os.makedirs(AI_BASE_DIR, exist_ok=True)
    os.makedirs(AI_LOG_DIR, exist_ok=True)

    def run():
        with open(AI_LOG_FILE, "w") as log:
            subprocess.run(
                ["bash", script],
                cwd=os.path.join(REPO_ROOT, "ai_bootstrap_bundle"),
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True
            )

    threading.Thread(target=run, daemon=True).start()

    return jsonify({
        "status": "deploying",
        "message": "Despliegue del módulo IA iniciado"
    }), 202

# ------------------------------------------------------------
# LOG STREAM (SSE)
# ------------------------------------------------------------
@api_bp.route("/api/ai/logs")
def api_ai_logs():

    def generate():
        while not os.path.exists(AI_LOG_FILE):
            yield "data: [INFO] Esperando logs...\n\n"
            time.sleep(0.5)

        with open(AI_LOG_FILE, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    yield f"data: {line.rstrip()}\n\n"
                else:
                    time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")

@api_bp.route('/api/openstack/hypervisor-stats')
def get_hypervisor_stats():
    try:
        # Ejecutamos el comando directamente para obtener el snapshot de recursos
        cmd = ["openstack", "hypervisor", "stats", "show", "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return jsonify({"error": result.stderr}), 500
            
        return jsonify(json.loads(result.stdout))
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@api_bp.route("/api/ai/ask", methods=["POST"])
def ask_ai():
    user_prompt = request.json.get("prompt", "").strip()

    if not user_prompt:
        return jsonify({
            "status": "error",
            "response": "Prompt vacío"
        }), 200

    script_path = os.path.join(
        os.getcwd(),
        "ai_bootstrap_bundle",
        "preguntarLLM.sh"
    )

    try:
        process = subprocess.run(
            ["/usr/bin/bash", script_path, user_prompt],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,   # ⬅️ NUNCA mostrar errores
            text=True,
            timeout=70
        )

        # ================================
        # LIMPIEZA TOTAL DE STDOUT
        # ================================
        raw_output = process.stdout.strip()

        # Nos quedamos SOLO con la última línea no vacía
        lines = [l.strip() for l in raw_output.splitlines() if l.strip()]
        clean_output = lines[-1] if lines else ""

        
        



        if clean_output == "IA_OCUPADA":
            return jsonify({
                "status": "busy",
                "response": "La IA está pensando. Inténtalo de nuevo en unos segundos."
            }), 200




        return jsonify({
            "status": "success",
            "response": clean_output
        }), 200

    except Exception:
        return jsonify({
            "status": "unavailable",
            "response": "Fallo controlado del backend"
        }), 200





#---------------------------------------------------------------------------------------------------------------------------------------------------------- analizar terafico begin------


# Carga endpoints de tráfico ICS (registra rutas en api_bp)
#import app_core.infrastructure.ics_traffic.traffic_api













# ===========================================-------------------------------------------------------host_tools_installer begin--------------------------------------------------------------------------------------------------- =================






# Importación del blueprint
from app_core.infrastructure.host_tools_installer.host_tools_endpoints import host_tools_bp
# REGISTRO: Esto crea las rutas /api/host/inventory, /api/host/install, etc.
api_bp.register_blueprint(host_tools_bp, url_prefix='/api/host')




# ===========================================-------------------------------------------------------host_tools_installer begin--------------------------------------------------------------------------------------------------- =================



# ===========================================-------------------------------------------------------TRAFFIC begin--------------------------------------------------------------------------------------------------- =================
# 4) LIVE TRAFFIC – CORE LOGIC
# ============================================================






from app_core.infrastructure.ics_traffic.traffic_api import traffic_bp

# ... (otras configuraciones de tu app) ...

# Registramos el blueprint de tráfico
api_bp.register_blueprint(traffic_bp)

# ===========================================-------------------------------------------------------TRAFFIC end--------------------------------------------------------------------------------------------------- =================



#---------------------------------------------------------------------------------------------------------------------------------------------------------- analizar terafico end-------
#-------------------------------------Dashboard f35 begin------------------------------------------------------





from app_core.infrastructure.dashboard.dashboard_F35 import hud_bp
api_bp.register_blueprint(hud_bp, url_prefix='/api/hud')



from app_core.infrastructure.attack.ssh_launcher import attack_infra_bp

api_bp.register_blueprint(attack_infra_bp, url_prefix='/api/hud/attack')



from app_core.infrastructure.victim.ssh_launcher import victim_infra_bp

api_bp.register_blueprint(victim_infra_bp, url_prefix='/api/hud/victim')



from app_core.infrastructure.monitor.ssh_launcher import monitor_infra_bp
api_bp.register_blueprint(monitor_infra_bp, url_prefix="/api/hud/monitor")


#-------------------------------------------Dashboard f35 end----------------------------------------------------



#-------------------------------------------Forensics new one begin----------------------------------------------------

from app_core.infrastructure.forensics.forensics_api import forensics_bp
api_bp.register_blueprint(forensics_bp)





from app_core.infrastructure.forensics.alerts_api import ALERTS_API_BP
api_bp.register_blueprint(ALERTS_API_BP)

#------------------------------------------- Forensic report


from app_core.infrastructure.forensics.forensics_report_api import forensics_report_bp
api_bp.register_blueprint(forensics_report_bp)


#-------------------------------------------Forensics new one  end----------------------------------------------------

        


#-------------------------------------------honeyv windows_lab_exchange_bp----------------------------------------------------



from honeyv_app_core.presentation.api.routes.windows_lab_exchange_routes import windows_lab_exchange_bp


api_bp.register_blueprint(windows_lab_exchange_bp)

#------------------------------------------- honeyv windows_lab_exchange_bp end----------------------------------------------------



#-------------------------------------------packet-level-etc---------------------------------------------------



from etc_lab.routes.etc_lab_routes import etc_lab_bp

api_bp.register_blueprint(etc_lab_bp, url_prefix="/api")

#------------------------------------------- packet-level-etc end----------------------------------------------------



#------------------------------------------- ciberia_bp



from ciberia_lab.routes import bp as ciberia_bp

api_bp.register_blueprint(ciberia_bp)

#------------------------------------------- ciberia_bp end----------------------------------------------------

#------------------------------------------- adv_detection

from adv_detection.routes import adv_detection_bp

api_bp.register_blueprint(adv_detection_bp)
#------------------------------------------- adv_detection end----------------------------------------------------




@api_bp.route("/")
def index():
    return send_from_directory(os.path.join(REPO_ROOT, "app_core", "static"), "index.html")
    #return send_from_directory(os.path.join(REPO_ROOT, 'static'), 'index.html')

@api_bp.route("/<path:path>")
def static_files(path):
    return send_from_directory(os.path.join(REPO_ROOT, "app_core", "static"), path)
    #return send_from_directory(os.path.join(REPO_ROOT, 'static'), path)





