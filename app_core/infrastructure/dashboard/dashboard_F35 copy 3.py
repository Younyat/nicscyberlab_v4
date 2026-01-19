# el front/back ahora es capaz de detectar el sistema operativo, los puertos que el grupo de seguridad permite abrir




import os
import logging
import json
from typing import Dict, Any, List, Optional, Tuple
from flask import Blueprint, request, jsonify
import openstack

# Configuración de Logging
logger = logging.getLogger("app_logger")

# Definición del Blueprint
hud_bp = Blueprint("hud", __name__)
dashboard_f35 = hud_bp

# Definición de la ruta raíz
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# Conexión a OpenStack
# ============================================================
def get_openstack_connection():
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
# Helpers
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

            if addr.startswith("192.168.100.") or ip_type == "floating":
                ip_floating = addr
            else:
                ip_private = addr
    return ip_private, ip_floating, networks

def classify_role(server_name: str) -> str:
    name = (server_name or "").lower()
    if "fuxa" in name: return "scada"
    if "plc" in name: return "plc"
    if "attack" in name: return "attacker"
    if "monitor" in name: return "monitor"
    if "victim" in name: return "victim"
    return "unknown"

def strategies_for(role: str) -> Dict[str, List[Dict[str, Any]]]:
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

def get_os_from_server(conn, server) -> str:
    try:
        image_id = server.image.id if server.image else None
        if not image_id:
            return server.metadata.get('os_distro', 'Linux/Unknown').capitalize()

        image = conn.get_image(image_id)
        if image:
            os_name = image.get('os_distro') or image.get('display_name') or image.name
            low_os = os_name.lower()
            if "ubuntu" in low_os: return "Ubuntu Linux"
            if "centos" in low_os: return "CentOS"
            if "windows" in low_os: return "Windows Server"
            if "debian" in low_os: return "Debian"
            return os_name
    except:
        pass
    return "Linux/Generic"

def get_allowed_ports(conn, server) -> List[str]:
    """Analiza los Security Groups para listar puertos de entrada permitidos."""
    allowed_rules = []
    try:
        sec_groups = getattr(server, "security_groups", [])
        for sg_info in sec_groups:
            sg = conn.network.find_security_group(sg_info['name'])
            if not sg: continue
            for rule in sg.security_group_rules:
                if rule['direction'] == 'ingress' and rule['ethertype'] == 'IPv4':
                    proto = (rule['protocol'] or 'all').upper()
                    p_min = rule['port_range_min']
                    p_max = rule['port_range_max']
                    if p_min is None: rule_str = f"{proto}: ALL"
                    elif p_min == p_max: rule_str = f"{proto}: {p_min}"
                    else: rule_str = f"{proto}: {p_min}-{p_max}"
                    if rule_str not in allowed_rules: allowed_rules.append(rule_str)
    except:
        return ["Unknown"]
    return allowed_rules if allowed_rules else ["No ingress rules"]

# ============================================================
# Endpoints
# ============================================================

@hud_bp.route("/instances", methods=["GET"])
def hud_instances():
    conn = None
    try:
        # 1. CARGAR DATOS DEL ESCENARIO
        file_path = os.path.join(REPO_ROOT, 'industrial-scenario/scenarios/industrial_industrial_file.json')
        scenario_data = {"nodes": [], "edges": []}
        
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                scenario_data = json.load(f)
        
        # 2. CONEXIÓN A OPENSTACK
        conn = get_openstack_connection()
        os_servers = {s.name: s for s in conn.compute.servers(details=True)}

        items = []
        if scenario_data.get("nodes"):
            for node in scenario_data["nodes"]:
                server = os_servers.get(node["name"])
                
                os_system = "Unknown"
                status = "OFFLINE"
                ip_p, ip_f, nets = None, None, []
                allowed_ports = []
                
                if server:
                    ip_p, ip_f, nets = extract_ips_and_networks(server)
                    status = server.status
                    os_system = get_os_from_server(conn, server)
                    allowed_ports = get_allowed_ports(conn, server)

                items.append({
                    "id": node["id"],
                    "name": node["name"],
                    "status": status,
                    "role": node["type"].replace("industrial_", ""),
                    "os": os_system,
                    "ip": ip_f or ip_p or "N/A",
                    "position": node.get("position"),
                    "networks": nets,
                    "allowed_ports": allowed_ports,
                    "strategies": strategies_for(node["type"])
                })
        else:
            # Fallback si no hay nodos en el JSON
            for server in os_servers.values():
                ip_p, ip_f, nets = extract_ips_and_networks(server)
                role = classify_role(server.name)
                items.append({
                    "id": server.id,
                    "name": server.name,
                    "status": server.status,
                    "role": role,
                    "os": get_os_from_server(conn, server),
                    "ip": ip_f or ip_p or "N/A",
                    "networks": nets,
                    "allowed_ports": get_allowed_ports(conn, server),
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
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id")
    action_id = data.get("action_id")
    if not instance_id or not action_id:
        return jsonify({"status": "error", "msg": "Missing fields"}), 400
    return jsonify({"status": "accepted", "instance_id": instance_id, "action_id": action_id}), 202

@hud_bp.route('/get-scenario', methods=['GET'])
def get_scenario():
    file_path = os.path.join(REPO_ROOT, 'industrial-scenario/scenarios/industrial_industrial_file.json')
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500