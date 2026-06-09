import os
import time

import openstack
import paramiko
from flask import Blueprint, Response, jsonify, request, stream_with_context

from app_core.infrastructure.attack.catalog import (
    find_attack_by_id,
    get_attack_catalog,
    resolve_script_name,
)
from app_core.infrastructure.attack.executor import (
    resolve_requested_attack,
    stream_attack_execution,
)

attack_infra_bp = Blueprint("attack_infra", __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")


class SSHTacticalManager:
    def __init__(self, key_path):
        self.key_path = os.path.expanduser(key_path)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.conn = openstack.connect()
        except Exception as exc:
            print(f"OpenStack connection error: {exc}")
            self.conn = None

    def _map_user(self, image_name: str):
        n = (image_name or "").lower()
        if "ubuntu" in n:
            return "ubuntu"
        if "kali" in n:
            return "kali"
        return "debian"

    def _get_all_ips_from_addresses(self, addresses):
        ips = []
        try:
            for net in (addresses or {}).values():
                for addr in net or []:
                    ip = addr.get("addr")
                    if ip:
                        ips.append(ip)
        except Exception:
            pass
        return ips

    def discover_attacker_instance(self):
        if not self.conn:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                if server.name and server.name.lower().startswith("attack"):
                    floating_ip = server.access_ipv4 or self._get_floating_ip_from_addresses(server.addresses)
                    if floating_ip:
                        image = self.conn.image.get_image(server.image.id)
                        user = self._map_user(getattr(image, "name", "") or "")
                        return floating_ip, user
            return None, None
        except Exception:
            return None, None

    def discover_instance_by_ip(self, target_ip: str):
        if not self.conn or not target_ip:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                ips = self._get_all_ips_from_addresses(getattr(server, "addresses", None))
                if getattr(server, "access_ipv4", None):
                    ips.append(server.access_ipv4)

                if target_ip in ips:
                    image = self.conn.image.get_image(server.image.id)
                    image_name = getattr(image, "name", "") or ""
                    return server, image_name
            return None, None
        except Exception:
            return None, None

    def _get_floating_ip_from_addresses(self, addresses):
        for network in (addresses or {}).values():
            for addr in network or []:
                if addr.get("OS-EXT-IPS:type") == "floating":
                    return addr.get("addr")
        return None

    def execute_remote_stream(self, host, user, local_script_path, args=None):
        if args is None:
            args = []

        try:
            self.client.connect(host, username=user, key_filename=self.key_path, timeout=15)

            sftp = self.client.open_sftp()
            remote_path = f"/tmp/exec_{int(time.time())}.sh"
            sftp.put(local_script_path, remote_path)
            sftp.chmod(remote_path, 0o755)
            sftp.close()

            transport = self.client.get_transport()
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(f"{remote_path} {' '.join(args)}")

            while True:
                if channel.recv_ready():
                    data = channel.recv(4096).decode("utf-8", errors="ignore")
                    if data:
                        for line in data.splitlines():
                            yield f"data: {line}\n\n"

                if channel.exit_status_ready():
                    break

                time.sleep(0.05)

            exit_code = channel.recv_exit_status()
            yield f"data: [EXIT CODE] {exit_code}\n\n"

            self.client.exec_command(f"rm -f {remote_path}")
            self.client.close()

        except Exception as exc:
            yield f"data: [SSH ERROR] {str(exc)}\n\n"


manager = SSHTacticalManager(key_path="~/.ssh/my_key")


def normalize_os_user(os_value: str) -> str:
    n = (os_value or "").strip().lower()
    if "ubuntu" in n:
        return "ubuntu"
    if "debian" in n:
        return "debian"
    if "kali" in n:
        return "kali"
    return "debian"


def _resolve_target_context(target_ip: str, target_os: str):
    victim_user = normalize_os_user(target_os)
    server, image_name = manager.discover_instance_by_ip(target_ip)
    if server and image_name:
        victim_user = manager._map_user(image_name)
        return server, image_name, victim_user
    return None, "", victim_user


def _resolve_attacker_context(attacker_ip: str = ""):
    if attacker_ip:
        server, image_name = manager.discover_instance_by_ip(attacker_ip)
        if server and image_name:
            attacker_user = manager._map_user(image_name)
            return attacker_ip, attacker_user
    return manager.discover_attacker_instance()


@attack_infra_bp.route("/launch")
def launch_attack():
    target_ip = request.args.get("target")
    attack_id = request.args.get("attack_id", "").strip()
    script_name = resolve_script_name(
        script_name=request.args.get("script", "").strip(),
        attack_id=attack_id,
    ) or "ping_target.sh"

    target_os = request.args.get("os", "")
    print(f"[target_os_raw  : {target_os}]")
    print(f"[ATTACK] Target IP received from frontend: {target_ip}")
    print(f"[attack_id   : {attack_id or '(legacy-script-mode)'}")
    print(f"[script_name : {script_name}]")

    attacker_ip, attacker_user = _resolve_attacker_context()
    print(f"[attacker_ip   : {attacker_ip}]")
    print(f"[attacker_user : {attacker_user}]")

    if not attacker_ip:
        return Response(
            "data: [ERROR] No attacker instance with floating IP was found\n\n",
            mimetype="text/event-stream",
        )

    server, image_name, victim_user = _resolve_target_context(target_ip, target_os)
    print(f"[victim_user   : {victim_user}]")
    if server and image_name:
        print(f"[victim_server : {server.name}]")
        print(f"[victim_image  : {image_name}]")
    else:
        print("[victim_lookup] Could not identify the VM by IP; using OS-based fallback user")

    local_script = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(local_script):
        return Response(
            f"data: [ERROR] Local script not found: {local_script}\n\n",
            mimetype="text/event-stream",
        )

    return Response(
        stream_with_context(
            manager.execute_remote_stream(attacker_ip, attacker_user, local_script, [target_ip, victim_user])
        ),
        mimetype="text/event-stream",
    )


@attack_infra_bp.route("/catalog", methods=["GET"])
def attack_catalog():
    section = request.args.get("section", "")
    detection_engine = request.args.get("detection_engine", "")
    target_role = request.args.get("target_role", "")
    attacks = get_attack_catalog(
        section=section,
        detection_engine=detection_engine,
        target_role=target_role,
    )
    return jsonify({"attacks": attacks, "count": len(attacks)})


@attack_infra_bp.route("/describe", methods=["GET"])
def describe_attack():
    attack_id = request.args.get("attack_id", "").strip()
    attack = find_attack_by_id(attack_id)
    if not attack:
        return jsonify({"error": f"attack_id not found: {attack_id}"}), 404
    return jsonify(attack)


@attack_infra_bp.route("/execute", methods=["POST"])
def execute_attack():
    payload = request.get_json(silent=True) or {}
    attack = resolve_requested_attack(payload)
    if not attack:
        return jsonify({"error": "Unknown attack_id"}), 404

    target_ip = (payload.get("target_ip") or "").strip()
    target_role = (payload.get("target_role") or "").strip().lower()
    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400
    if target_role and target_role not in attack.get("target_roles", []):
        return jsonify(
            {
                "error": "target_role not allowed for this attack",
                "allowed_roles": attack.get("target_roles", []),
            }
        ), 400

    attacker_ip = (payload.get("attacker_ip") or "").strip()
    attacker_ip, attacker_user = _resolve_attacker_context(attacker_ip)
    if not attacker_ip:
        return jsonify({"error": "No attacker instance with floating IP was found"}), 503

    target_os = (payload.get("target_os") or payload.get("os") or "").strip()
    server, image_name, victim_user = _resolve_target_context(target_ip, target_os)
    local_script = os.path.join(SCRIPTS_DIR, attack["script"])
    if not os.path.exists(local_script):
        return jsonify({"error": f"Backend script not found: {attack['script']}"}), 500

    if server and image_name:
        print(f"[victim_server : {server.name}]")
        print(f"[victim_image  : {image_name}]")

    stream_payload = {
        "attack_id": attack["attack_id"],
        "target_ip": target_ip,
        "target_role": target_role,
        "attacker_ip": attacker_ip,
        "case_dir": payload.get("case_dir", ""),
        "parameters": payload.get("parameters", {}) or {},
    }

    return Response(
        stream_with_context(
            stream_attack_execution(
                manager=manager,
                attack=attack,
                local_script=local_script,
                attacker_ip=attacker_ip,
                attacker_user=attacker_user,
                target_user=victim_user,
                target_image=image_name,
                payload=stream_payload,
            )
        ),
        mimetype="text/event-stream",
    )
