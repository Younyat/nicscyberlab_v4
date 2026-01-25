import os
import logging
import json
from typing import Dict, Any, List, Optional, Tuple

from flask import Blueprint, request, jsonify
from flask_cors import CORS
import openstack

# ============================================================
# Logging
# ============================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app_logger")

# ============================================================
# Blueprint
# ============================================================
hud_bp = Blueprint("hud", __name__)
CORS(hud_bp)

# ============================================================
# Ruta raíz del proyecto
# ============================================================
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

            if ip_type == "floating":
                ip_floating = addr
            elif not ip_private:
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

def strategies_for(role: str) -> Dict[str, List[str]]:
    base = {"attack": [], "defense": [], "prevention": []}
    role_clean = role.replace("industrial_", "").lower()

    if role_clean == "plc":
        base["attack"] = ["ot.modbus.scan", "ot.modbus.fuzz"]
        base["defense"] = ["ot.packet.inspect"]
    elif role_clean == "attacker":
        base["attack"] = ["c2.caldera.open", "net.nmap.scan"]
    elif role_clean == "scada":
        base["defense"] = ["sys.logs.collect"]
        base["prevention"] = ["sys.firewall.harden"]
    elif role_clean == "monitor":
        base["defense"] = ["ids.snort.reload", "siem.wazuh.check"]

    return base

def get_os_from_server(conn, server) -> str:
    try:
        # 1. Extracción segura del ID (Maneja si 'image' es dict, objeto o None)
        image_id = None
        img_prop = getattr(server, "image", None)
        
        if img_prop:
            if isinstance(img_prop, dict):
                image_id = img_prop.get("id")
            else:
                image_id = getattr(img_prop, "id", None)

        # 2. Si no hay ID de imagen, mirar metadata
        if not image_id:
            return server.metadata.get("os_distro", "Linux").capitalize()

        # 3. Buscar la imagen en Glance
        image = conn.get_image(image_id)
        if image:
            # Obtener nombre de varias fuentes
            os_name = image.get("os_distro") or image.get("display_name") or image.name
            
            if not os_name:
                return "Linux"

            low = os_name.lower()
            
            # --- REGLAS DE DETECCIÓN ---
            if "kali" in low: return "Kali Linux"      # <--- NUEVA LÍNEA
            if "ubuntu" in low: return "Ubuntu Linux"
            if "windows" in low: return "Windows Server"
            if "debian" in low: return "Debian Linux"
            if "centos" in low: return "CentOS Linux"
            
            return os_name
            
    except Exception as e:
        logger.debug(f"OS detection failed: {e}")

    return "Linux"

def get_allowed_ports(conn, server) -> List[str]:
    allowed_rules = []
    try:
        for sg_info in getattr(server, "security_groups", []):
            sg = conn.network.find_security_group(sg_info["name"])
            if not sg:
                continue

            for rule in sg.security_group_rules:
                if rule["direction"] != "ingress":
                    continue

                proto = (rule["protocol"] or "ALL").upper()
                p_min = rule["port_range_min"]
                p_max = rule["port_range_max"]

                if p_min is None:
                    rule_str = f"{proto}: ANY"
                elif p_min == p_max:
                    rule_str = f"{proto}: {p_min}"
                else:
                    rule_str = f"{proto}: {p_min}-{p_max}"

                if rule_str not in allowed_rules:
                    allowed_rules.append(rule_str)

    except Exception as e:
        logger.debug(f"Port extraction failed: {e}")
        return ["Unknown"]

    return allowed_rules if allowed_rules else ["No ingress"]





def load_base_scenario():
    path = os.path.join(REPO_ROOT, "scenario", "scenario_file.json")
    if not os.path.exists(path):
        return {"nodes": [], "edges": []}

    with open(path, "r") as f:
        return json.load(f)



def load_industrial_scenario():
    path = os.path.join(
        REPO_ROOT,
        "industrial-scenario",
        "scenarios",
        "industrial_industrial_file.json"
    )
    if not os.path.exists(path):
        return {"nodes": [], "edges": []}

    with open(path, "r") as f:
        return json.load(f)



# ============================================================
# Endpoints
# ============================================================
# ============================================================
# Endpoints
# ============================================================
@hud_bp.route("/instances", methods=["GET"])
def hud_instances():
    conn = None
    try:
        # ============================================================
        # OpenStack
        # ============================================================
        conn = get_openstack_connection()
        os_servers = {s.name: s for s in conn.compute.servers(details=True)}

        # ============================================================
        # NODOS CANÓNICOS (ID lógico -> instancia OpenStack real)
        # ============================================================
        # IDs lógicos estables para Cytoscape + escenarios
        CANON = [
            {"id": "node1", "name": "monitor 1",    "role": "monitor"},
            {"id": "node2", "name": "attack 2",     "role": "attacker"},
            {"id": "node3", "name": "victim 3",     "role": "victim"},
            {"id": "plc1",  "name": "PLC_Instance", "role": "plc"},
            {"id": "scada1","name": "FUXA_Instance","role": "scada"},
        ]

        # Posiciones (si no quieres, quítalas y Cytoscape las pone con layout)
        POS = {
            "node1": {"x": 720, "y": 120},
            "node2": {"x": 1030, "y": 310},
            "node3": {"x": 960, "y": 150},
            "plc1":  {"x": 1120, "y": 280},
            "scada1":{"x": 1120, "y": 170},
        }

        items = []
        id_index = {}

        for n in CANON:
            node_id = n["id"]
            instance_name = n["name"]   # nombre REAL OpenStack
            role = n["role"]

            server = os_servers.get(instance_name)

            status = "OFFLINE"
            ip = "N/A"
            os_sys = "Unknown"
            nets = []
            ports = []

            if server:
                ip_p, ip_f, nets = extract_ips_and_networks(server)
                status = server.status.upper()
                ip = ip_f or ip_p or "N/A"
                os_sys = get_os_from_server(conn, server)
                ports = get_allowed_ports(conn, server)

            info = {
                "id": node_id,                
                "name": instance_name,         
                "role": role,                  
                "status": status,
                "ip": ip,
                "os": os_sys,
                "networks": nets,
                "allowed_ports": ports,
                "strategies": strategies_for(role),
                "position": POS.get(node_id),
            }

            items.append(info)
            id_index[node_id] = info

        # ============================================================
        # EDGES FORZADOS (según tus reglas + OT)
        # ============================================================
        edges = []

        def add_edge(src, tgt, edge_type, eid):
            if src in id_index and tgt in id_index:
                edges.append({
                    "id": eid,
                    "source": src,
                    "target": tgt,
                    "type": edge_type
                })

        # Reglas IT:
        # node3 conectado con todo (node1,node2) + OT (plc1,scada1)
        add_edge("node3", "node1", "network", "edge_node3_node1")
        add_edge("node3", "node2", "network", "edge_node3_node2")
        add_edge("node3", "plc1",  "network", "edge_node3_plc1")
        add_edge("node3", "scada1","network", "edge_node3_scada1")

        # attacker (node2) conectado con monitor y victim + OT si quieres
       
        add_edge("node2", "node3", "attack",  "edge_node2_node3")
        add_edge("node2", "plc1",  "attack",  "edge_node2_plc1")
        add_edge("node2", "scada1","attack",  "edge_node2_scada1")

        # monitor (node1) conectado con todo
        add_edge("node1", "node2", "monitor", "edge_node1_node2")
        add_edge("node1", "node3", "monitor", "edge_node1_node3")
        add_edge("node1", "plc1",  "monitor", "edge_node1_plc1")
        add_edge("node1", "scada1","monitor", "edge_node1_scada1")

        # OT: PLC -> SCADA (modbus)
        add_edge("plc1", "scada1", "modbus", "edge_plc1_scada1")
         
      

        return jsonify({"instances": items, "edges": edges}), 200

    except Exception as e:
        logger.error(f"HUD instances error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


@hud_bp.route("/action", methods=["POST"])
def hud_action():
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id") or data.get("target_id")
    action_id = data.get("action_id") or data.get("action")

    if not instance_id or not action_id:
        return jsonify({
            "status": "error",
            "message": "Missing instance_id/target_id or action_id/action"
        }), 400

    logger.info(f"HUD ACTION | target={instance_id} | action={action_id}")

    return jsonify({
        "status": "accepted",
        "message": f"Acción {action_id} enviada a {instance_id}"
    }), 202

    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id") or data.get("target_id")
    action_id = data.get("action_id") or data.get("action")
    if not instance_id or not action_id:
        return jsonify({
            "status": "error",
            "message": "Missing instance_id/target_id or action_id/action"
        }), 400
    
    logger.info(f"HUD ACTION | target={instance_id} | action={action_id}")
    return jsonify({
        "status": "accepted",
        "message": f"Acción {action_id} enviada a {instance_id}"
    }), 202


