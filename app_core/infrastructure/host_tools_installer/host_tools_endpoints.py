from flask import Blueprint
from . import host_tools_installer_manager as manager
import logging


import json
import subprocess
import logging
import os
import re
import threading

from flask import Blueprint, request, jsonify, send_from_directory, Response
import openstack



# Definimos el blueprint
host_tools_bp = Blueprint('host_tools', __name__)
logger = logging.getLogger("app_logger")
@host_tools_bp.route('/inventory', methods=['GET'])
def inventory():
    return manager.get_inventory()

@host_tools_bp.route('/version/<tool_id>', methods=['GET'])
def version(tool_id):
    return manager.get_version(tool_id)

@host_tools_bp.route('/install/<tool_id>', methods=['GET'])
def install(tool_id):
    return manager.run_action_sse(tool_id, "install")

@host_tools_bp.route('/uninstall/<tool_id>', methods=['GET'])
def uninstall(tool_id):
    return manager.run_action_sse(tool_id, "uninstall")


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



@host_tools_bp.route("/instance_roles", methods=["GET"])
def api_instance_roles():
    conn = None

    try:
        conn = get_openstack_connection()
        servers = conn.compute.servers()

        # Estructura con las 5 categorías detectadas en tu lista
        result = {
            "attacker": None,
            "monitor": None,
            "victim": None,
            "scada": None,       # Para FUXA
            "plc": None,         # Para PLC_Instance
            "unknown": []
        }

        for server in servers:
            # Recolectar todas las IPs disponibles
            all_ips = []
            for net, addrs in server.addresses.items():
                for addr in addrs:
                    all_ips.append(addr["addr"])
            
            ip_display = ", ".join(all_ips) if all_ips else "N/A"
            name = server.name.lower()

            instance_info = {
                "name": server.name,
                "ip": ip_display,
                "status": server.status
            }

            # Lógica de clasificación basada en tus nombres reales
            if any(x in name for x in ["attack", "redteam", "kali"]):
                result["attacker"] = instance_info

            elif any(x in name for x in ["monitor", "wazuh", "siem"]):
                result["monitor"] = instance_info

            elif "fuxa" in name:
                result["scada"] = instance_info

            elif "plc" in name:
                result["plc"] = instance_info

            elif any(x in name for x in ["victim", "target", "blue"]):
                result["victim"] = instance_info

            else:
                result["unknown"].append(instance_info)

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