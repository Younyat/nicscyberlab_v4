from flask import Blueprint, request, Response, stream_with_context
from app_core.infrastructure.attack.ssh_manager import SSHTacticalManager
import os

attack_bp = Blueprint('attack', __name__)
manager = SSHTacticalManager()

# Ruta base de los scripts .sh
SCRIPTS_DIR = os.path.abspath(os.path.join(os.getcwd(), "attack", "scripts"))

@attack_bp.route('/launch', methods=['GET'])
def launch_attack():
    attacker_ip = request.args.get('ip')
    user = request.args.get('user', 'debian')
    script_name = request.args.get('script')
    target_ip = request.args.get('target', '')

    if not attacker_ip or not script_name:
        return {"error": "Missing parameters"}, 400

    local_script = os.path.join(SCRIPTS_DIR, script_name)
    
    if not os.path.exists(local_script):
        return {"error": f"Script {script_name} not found"}, 404

    return Response(
        stream_with_context(manager.execute_remote_stream(attacker_ip, user, local_script, [target_ip])),
        mimetype='text/event-stream'
    )





