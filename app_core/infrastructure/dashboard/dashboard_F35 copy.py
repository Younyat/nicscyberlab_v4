import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from flask import Blueprint, request, jsonify
import openstack
import json

# Configuración de Logging
logger = logging.getLogger("app_logger")

# Definición del Blueprint
hud_bp = Blueprint("hud", __name__)

# Alias para compatibilidad con el cargador de la aplicación
dashboard_f35 = hud_bp

# Definición de la ruta raíz para encontrar archivos JSON
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# Conexión a OpenStack
# ============================================================
def get_openstack_connection():
    """Establece conexión con el SDK de OpenStack usando variables de entorno."""
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

# ============================================================
# Helpers: IPs y Clasificación
# ============================================================
def extract_ips_and_networks(server) -> Tuple[Optional[str], Optional[str], List[Dict[str, Any]]]:
    ip_private, ip_floating, networks = None, None, []
    addresses = getattr(server, "addresses", {}) or {}
    
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

            # Priorizamos la red 192.168.100.x como IP principal para el HUD
            if addr.startswith("192.168.100.") or ip_type == "floating":
                ip_floating = addr
            else:
                ip_private = addr

    return ip_private, ip_floating, networks

def classify_role(server_name: str) -> str:
    """Asigna el rol del HUD basado en el nombre real de tu instancia."""
    name = (server_name or "").lower()
    if "fuxa" in name: return "scada"
    if "plc" in name: return "plc"
    if "attack" in name: return "attacker"
    if "monitor" in name: return "monitor"
    if "victim" in name: return "victim"
    return "unknown"

def strategies_for(role: str) -> Dict[str, List[Dict[str, Any]]]:
    """Define las acciones disponibles en el menú circular del HUD."""
    base = {"attack": [], "defense": [], "prevention": [], "forensics": []}
    role_clean = role.replace("industrial_", "").lower()
    
    if role_clean == "plc":
        base["attack"] = [{"action_id": "ot.modbus.scan", "label": "Modbus Recon (502)"}]
        base["forensics"] = [{"action_id": "forensic.net.capture", "label": "Capture OT Traffic"}]
    elif role_clean == "attacker":
        base["attack"] = [{"action_id": "c2.caldera.open", "label": "Open Caldera C2"}]
    elif role_clean == "scada":
        base["forensics"] = [{"action_id": "forensic.logs.collect", "label": "Collect SCADA Logs"}]
    elif role_clean == "monitor":
        base["defense"] = [{"action_id": "def.ids.reload", "label": "Reload IDS Rules"}]
    
    return base

# ============================================================
# Endpoints de la API
# ============================================================

@hud_bp.route("/instances", methods=["GET"])
def hud_instances():
    """Endpoint consolidado: Combina OpenStack con el escenario JSON."""
    conn = None
    try:
        # 1. Intentar leer el Escenario Industrial (JSON) para obtener posiciones y nodos predefinidos
        scenario_path = os.path.join(REPO_ROOT, "industrial-scenario", "scenarios", "industrial_industrial_file.json")
        scenario_data = {"nodes": [], "edges": []}
        if os.path.exists(scenario_path):
            with open(scenario_path, 'r') as f:
                scenario_data = json.load(f)

        # 2. Conexión a OpenStack
        conn = get_openstack_connection()
        os_servers = {s.name: s for s in conn.compute.servers(details=True)}

        items = []
        
        # 3. Mapear nodos del JSON con datos reales de OpenStack
        if scenario_data.get("nodes"):
            for node in scenario_data["nodes"]:
                server = os_servers.get(node["name"])
                ip_p, ip_f, nets = None, None, []
                status = "OFFLINE"
                
                if server:
                    ip_p, ip_f, nets = extract_ips_and_networks(server)
                    status = server.status

                items.append({
                    "id": node["id"],
                    "name": node["name"],
                    "status": status,
                    "role": node["type"].replace("industrial_", ""),
                    "os": "Linux/Ubuntu",
                    "ip": ip_f or ip_p or "N/A",
                    "position": node.get("position"),
                    "networks": nets,
                    "strategies": strategies_for(node["type"])
                })
        else:
            # Si el JSON está vacío, caer de vuelta a solo OpenStack (Lógica original)
            for server in os_servers.values():
                ip_p, ip_f, nets = extract_ips_and_networks(server)
                role = classify_role(server.name)
                items.append({
                    "id": server.id,
                    "name": server.name,
                    "status": server.status,
                    "role": role,
                    "os": "Linux/Ubuntu",
                    "ip": ip_f or ip_p or "N/A",
                    "networks": nets,
                    "strategies": strategies_for(role)
                })

        return jsonify({
            "instances": items,
            "edges": scenario_data.get("edges", [])
        }), 200

    except Exception as e:
        logger.error(f"HUD instances error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@hud_bp.route("/action", methods=["POST"])
def hud_action():
    """Maneja las acciones ejecutadas desde el menú circular."""
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id")
    action_id = data.get("action_id")

    if not instance_id or not action_id:
        return jsonify({"status": "error", "msg": "Missing fields"}), 400

    logger.info(f"[HUD ACTION] Executing {action_id} on {instance_id}")

    return jsonify({
        "status": "accepted",
        "instance_id": instance_id,
        "action_id": action_id
    }), 202

@hud_bp.route('/get-scenario', methods=['GET'])
def get_scenario():
    file_path = os.path.join(REPO_ROOT, 'industrial-scenario/scenarios/industrial_industrial_file.json')
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500








