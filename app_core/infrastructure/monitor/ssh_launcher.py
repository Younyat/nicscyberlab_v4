import os
import time
import openstack
import paramiko
import logging
import subprocess

from flask import Blueprint, Response, request




import json


from app_core.infrastructure.monitor.alerts_logger import AlertsLogger, attach_alert_to_case, _read_active_case_dir
ALERTS_LOGGER = AlertsLogger()


# ============================================================
# Configuración y Blueprint
# ============================================================
monitor_infra_bp = Blueprint("monitor_infra", __name__)
logger = logging.getLogger("app_logger")

# Rutas absolutas
SCRIPT_PATH = os.path.abspath("app_core/infrastructure/monitor/scripts/monitor_ataques.sh")
SSH_KEY_PATH = os.path.expanduser("~/.ssh/my_key")


@monitor_infra_bp.route("/live_wazuh_stream")
def live_wazuh_stream():
    monitor_ip = request.args.get("ip")

    # NUEVO: permitir pasar el case_dir desde el frontend
    # Ejemplo:
    #   /api/hud/monitor/live_wazuh_stream?ip=192.168.X.X&case_dir=/home/younes/.../CASE-20260221-180532
    case_dir = (request.args.get("case_dir") or "").strip()

    # Normaliza a ruta absoluta (si viene)
    if case_dir:
        case_dir = os.path.abspath(case_dir)

    if not monitor_ip:
        return Response("data: [ERROR] IP ausente\n\n", mimetype="text/event-stream")

    def generate():
        yield "data: [SYSTEM] STREAM OPENED\n\n"
        yield f"data: [SYSTEM] Lanzando monitor Wazuh para {monitor_ip}\n\n"

        # INFO útil para depurar desde el frontend sin tocar nada más
        if case_dir:
            yield f"data: [SYSTEM] case_dir={case_dir}\n\n"
        else:
            yield "data: [SYSTEM] case_dir=(none)\n\n"

        cmd = ["bash", SCRIPT_PATH, monitor_ip, "ubuntu", SSH_KEY_PATH]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in iter(process.stdout.readline, ""):
                if not line:
                    continue

                raw_line = line.rstrip()

                # 1) Si el SH emite JSON-tag -> registrar en forensics
                if raw_line.startswith("{") and "\"__tag\":\"NICS_ALERT_JSON\"" in raw_line:
                    try:
                        ev = json.loads(raw_line)
                        if ev.get("__tag") == "NICS_ALERT_JSON":
                            normalized = {
                                "event_id": ev.get("event_id"),
                                "ts_utc": ev.get("ts_utc"),
                                "source": ev.get("source", "wazuh"),
                                "alert_type": ev.get("alert_type", "unknown"),
                                "protocol": ev.get("protocol", "unknown"),
                                "rule_id": ev.get("rule_id"),
                                "rule_level": ev.get("rule_level"),
                                "description": ev.get("description"),
                                "signature": ev.get("signature"),
                                "src": ev.get("src", {}),
                                "dst": ev.get("dst", {}),
                                "agent": ev.get("agent"),
                                "raw": ev.get("raw", ev),
                            }

                            # NUEVO: Inyectar case_dir si se proporcionó
                            # Si el CASE no existe todavía, tu AlertsLogger lo ignorará (case_rel=None) sin fallar.
                            if case_dir:
                                normalized["case_dir"] = case_dir

                            out = ALERTS_LOGGER.log_event(normalized)

                            # NUEVO (blindaje): si por cualquier motivo no se pudo escribir en CASE en log_event,
                            # forzamos el attach por event_id usando alerts_store como fuente.
                            if case_dir and not out.get("case_rel"):
                                try:
                                    ev_id = (out.get("primary") or {}).get("event_id") or normalized.get("event_id")
                                    if ev_id:
                                        rel = attach_alert_to_case(case_dir, ev_id)
                                        if rel:
                                            out["case_rel"] = rel
                                except Exception:
                                    pass

                            # Log backend (útil para depurar)
                            try:
                                # Si el front no pasa case_dir, intenta resolverlo desde el puntero activo (si existe)
                                resolved_case_dir = case_dir or _read_active_case_dir() or "(none)"
                                logger.info(
                                    f"[MONITOR] log_event case_dir={resolved_case_dir} "
                                    f"case_rel={out.get('case_rel')}"
                                )
                            except Exception:
                                pass

                           
                            tri = out.get("triage", {})
                            sev = tri.get("severity", "UNKNOWN")
                            score = tri.get("native_score")
                            scale = tri.get("native_scale", "unknown")
                            rec = tri.get("recommend_forensics", False)

                            
                            case_rel = out.get("case_rel")
                            case_info = f"case_saved={case_rel}" if case_rel else "case_saved=NO"

                            human = (
                                f"[DETECTED] severity={sev} native_score={score} "
                                f"scale={scale} "
                                f"forensics={'YES' if rec else 'NO'} "
                                f"{case_info} "
                                f"sig={normalized.get('signature') or 'N/A'} "
                                f"src={normalized.get('src', {}).get('ip','?')}:{normalized.get('src', {}).get('port','?')} "
                                f"dst={normalized.get('dst', {}).get('ip','?')}:{normalized.get('dst', {}).get('port','?')}"
                            )
                            yield f"data: {human}\n\n"
                            continue
                    except Exception:
                        
                        pass

                # 3) Todo lo demás se stream-ea tal cual al frontend
                yield f"data: {raw_line}\n\n"

        except Exception as e:
            yield f"data: [ERROR] {str(e)}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
# ============================================================
# SSH + OpenStack Manager
# ============================================================
class SSHMonitorManager:
    def __init__(self, key_path: str):
        self.key_path = os.path.expanduser(key_path)

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.conn = openstack.connect()
            logger.info("[MONITOR] OpenStack connection established")
        except Exception as e:
            logger.error(f"[MONITOR] OpenStack connection error: {e}")
            self.conn = None

    # --------------------------------------------------------
    # Discover monitor instance by IP (REAL validation)
    # --------------------------------------------------------
    def discover_monitor_by_ip(self, monitor_ip: str):
        if not self.conn or not monitor_ip:
            return None, None

        try:
            for server in self.conn.compute.servers(all_projects=True):
                if not server.name.lower().startswith("monitor"):
                    continue

                for net in (server.addresses or {}).values():
                    for addr in net:
                        if addr.get("addr") == monitor_ip:
                            image = self.conn.image.get_image(server.image.id)
                            user = self._map_user(image.name.lower())

                            logger.info(
                                f"[MONITOR] Found monitor instance "
                                f"name={server.name} id={server.id} "
                                f"ip={monitor_ip} image={image.name} "
                                f"user={user}"
                            )

                            return monitor_ip, user

            logger.warning(
                f"[MONITOR] No monitor instance found with IP {monitor_ip}"
            )
            return None, None

        except Exception as e:
            logger.error(f"[MONITOR] discover error: {e}")
            return None, None

    # --------------------------------------------------------
    # Map SSH user from image name
    # --------------------------------------------------------
    def _map_user(self, image_name: str) -> str:
        if "ubuntu" in image_name:
            return "ubuntu"
        if "kali" in image_name:
            return "kali"
        return "debian"

    # --------------------------------------------------------
    # SSH connect + functional verification
    # --------------------------------------------------------
    def connect_and_verify(self, ip: str, user: str):
        self.client.connect(
            hostname=ip,
            username=user,
            key_filename=self.key_path,
            timeout=15
        )

        stdin, stdout, stderr = self.client.exec_command("whoami")
        remote_user = stdout.read().decode().strip()

        if remote_user != user:
            raise RuntimeError(
                f"SSH user mismatch: expected={user} got={remote_user}"
            )

        logger.info(
            f"[MONITOR] SSH connection OK to {ip} as user '{remote_user}'"
        )

    # --------------------------------------------------------
    # Verify script presence
    # --------------------------------------------------------
    def verify_script_exists(self, script_name: str):
        stdin, stdout, stderr = self.client.exec_command(
            f"test -f {script_name} && echo EXISTS || echo MISSING"
        )
        result = stdout.read().decode().strip()

        if result != "EXISTS":
            raise RuntimeError(
                f"Script '{script_name}' not found on monitor node"
            )

        logger.info(
            f"[MONITOR] Script '{script_name}' exists on monitor node"
        )

    # --------------------------------------------------------
    # Start script and verify execution
    # --------------------------------------------------------
    def start_script(self, script_name: str):
        cmd = (
            f"nohup python3 {script_name} "
            f"> /tmp/{script_name}.log 2>&1 &"
        )
        self.client.exec_command(cmd)

        time.sleep(2)

        stdin, stdout, stderr = self.client.exec_command(
            f"pgrep -f {script_name} && echo RUNNING || echo NOT_RUNNING"
        )
        status = stdout.read().decode().strip()

        if status != "RUNNING":
            raise RuntimeError(
                f"Script '{script_name}' failed to start"
            )

        logger.info(
            f"[MONITOR] Script '{script_name}' is RUNNING"
        )

    # --------------------------------------------------------
    # Stop script
    # --------------------------------------------------------
    def stop_script(self, script_name: str):
        self.client.exec_command(f"pkill -f {script_name} || true")
        logger.info(
            f"[MONITOR] Script '{script_name}' stopped"
        )

    def close(self):
        self.client.close()



# Manager instance
# ============================================================
manager = SSHMonitorManager(key_path="~/.ssh/my_key")

SCRIPT_NAME = "icmp_listener.py"


#  START ICMP LISTENER
# ============================================================
@monitor_infra_bp.route("/start_listener")
def start_monitor_listener():
    monitor_ip = request.args.get("ip")

    logger.info(f"[MONITOR] start listener request for ip={monitor_ip}")

    if not monitor_ip:
        return Response(
            "data: [ERROR] monitor_ip missing\n\n",
            mimetype="text/event-stream"
        )

    ip, user = manager.discover_monitor_by_ip(monitor_ip)

    if not ip or not user:
        return Response(
            "data: [ERROR] monitor instance not found\n\n",
            mimetype="text/event-stream"
        )

    try:
        manager.connect_and_verify(ip, user)
        manager.verify_script_exists(SCRIPT_NAME)
        manager.start_script(SCRIPT_NAME)
        manager.close()

        logger.info(
            f"[MONITOR] ICMP listener successfully started on {ip}"
        )

        return Response(
            "data: [MONITOR] ICMP listener started and verified\n\n",
            mimetype="text/event-stream"
        )

    except Exception as e:
        logger.error(f"[MONITOR] start listener error: {e}")
        manager.close()
        return Response(
            f"data: [ERROR] {e}\n\n",
            mimetype="text/event-stream"
        )


# ============================================================
# ⏹ STOP ICMP LISTENER
# ============================================================
@monitor_infra_bp.route("/stop_listener")
def stop_monitor_listener():
    monitor_ip = request.args.get("ip")

    logger.info(f"[MONITOR] stop listener request for ip={monitor_ip}")

    if not monitor_ip:
        return Response(
            "data: [ERROR] monitor_ip missing\n\n",
            mimetype="text/event-stream"
        )

    ip, user = manager.discover_monitor_by_ip(monitor_ip)

    if not ip or not user:
        return Response(
            "data: [ERROR] monitor instance not found\n\n",
            mimetype="text/event-stream"
        )

    try:
        manager.connect_and_verify(ip, user)
        manager.stop_script(SCRIPT_NAME)
        manager.close()

        return Response(
            "data: [MONITOR] ICMP listener stopped\n\n",
            mimetype="text/event-stream"
        )

    except Exception as e:
        logger.error(f"[MONITOR] stop listener error: {e}")
        manager.close()
        return Response(
            f"data: [ERROR] {e}\n\n",
            mimetype="text/event-stream"
        )





#---------------------------------------------------------- open_nmap_terminal



@monitor_infra_bp.route('/tools/open_nmap_terminal', methods=['POST'])
def open_nmap_terminal():
    try:
        env = os.environ.copy()
        data = request.get_json(silent=True) or {}

        target_ip = (data.get("ip") or "").strip()
        target_os = (data.get("os") or "").strip().lower()

        ssh_user = None

        if "ubuntu" in target_os:
            ssh_user = "ubuntu"
        elif "kali" in target_os:
            ssh_user = "kali"
        elif "debian" in target_os:
            ssh_user = "debian"

        if target_ip and ssh_user:
            command = (
                f"echo 'Opening SSH session to {ssh_user}@{target_ip}'; "
                f"ssh -o StrictHostKeyChecking=no {ssh_user}@{target_ip}; "
                f"exec bash"
            )

            subprocess.Popen([
                "gnome-terminal",
                "--",
                "bash",
                "-c",
                command
            ], env=env)

            return jsonify({
                "message": f"SSH terminal launched for {ssh_user}@{target_ip}"
            }), 200

        subprocess.Popen([
            "gnome-terminal",
            "--",
            "bash",
            "-c",
            "if command -v nmap >/dev/null 2>&1; then nmap --version; else echo 'nmap is not installed'; fi; exec bash"
        ], env=env)

        return jsonify({
            "message": "Local Nmap terminal launched"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500