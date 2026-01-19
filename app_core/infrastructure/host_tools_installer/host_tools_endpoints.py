from flask import Blueprint
from . import host_tools_installer_manager as manager

# Definimos el blueprint
host_tools_bp = Blueprint('host_tools', __name__)

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