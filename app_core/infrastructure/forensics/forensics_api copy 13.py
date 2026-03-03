import os
import re
import json
import time
import hashlib
import logging
import threading
import subprocess
from datetime import datetime, timezone


from flask import Blueprint, request, jsonify, Response, send_from_directory
import openstack



from pathlib import Path

# plotting (fig_forensic_cost_stacked.pdf)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt



logger = logging.getLogger("app_logger")

forensics_bp = Blueprint("forensics", __name__)



# ============================================================
# PATHS
# ============================================================

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))





FORENSICS_SCRIPTS_DIR = os.path.join(REPO_ROOT, "app_core", "infrastructure", "forensics", "scripts")





SCENARIO_DIR = os.path.join(REPO_ROOT, "scenario")
SCENARIO_FILE = os.path.join(SCENARIO_DIR, "scenario_file.json")

TOOLS_TMP_DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")
INSTALLED_DIR = os.path.join(REPO_ROOT, "tools-installer", "installed")

EVIDENCE_ROOT = os.path.join(REPO_ROOT, "app_core", "infrastructure", "forensics", "evidence_store")


os.makedirs(EVIDENCE_ROOT, exist_ok=True)


# ============================================================
# ACTIVE CASE POINTER (evidence_store/_active_case.txt)
# ============================================================

ACTIVE_CASE_PTR = os.path.join(EVIDENCE_ROOT, "_active_case.txt")

def set_active_case_dir(case_dir: str) -> None:
    """
    Guarda el puntero al CASE activo en:
      app_core/infrastructure/forensics/evidence_store/_active_case.txt

    - Escribe una ruta absoluta (1 línea).
    - No lanza excepciones (fail-safe).
    """
    try:
        case_dir = os.path.abspath((case_dir or "").strip())
        if not case_dir:
            return

        # Asegura que el case existe (si no existe, no escribimos puntero)
        if not os.path.isdir(case_dir):
            return

        os.makedirs(os.path.dirname(ACTIVE_CASE_PTR), exist_ok=True)

        with open(ACTIVE_CASE_PTR, "w", encoding="utf-8") as f:
            f.write(case_dir + "\n")
    except Exception:
        # Fail-safe: nunca romper el flujo de creación del caso
        pass


os.makedirs(TOOLS_TMP_DIR, exist_ok=True)
os.makedirs(INSTALLED_DIR, exist_ok=True)

DEFAULT_SCENARIO = {
    "scenario_name": "Default Empty Scenario",
    "description": "Escenario por defecto: no se encontró 'scenario_file.json'",
    "nodes": [{"data": {"id": "n1", "name": "Nodo Inicial"}, "position": {"x": 100, "y": 100}}],
    "edges": []
}

MOCK_SCENARIO_DATA = {}
try:
    with open(SCENARIO_FILE, "r") as f:
        MOCK_SCENARIO_DATA["file"] = json.load(f)
except Exception:
    MOCK_SCENARIO_DATA["file"] = DEFAULT_SCENARIO

# ============================================================
# OpenStack Connection
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
# TOOLS: tmp + installed merge (lo que tu UI necesita)
# ============================================================
def safe_instance_filename(instance_name: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", (instance_name or "").lower())
    return f"{safe_name}_tools.json"

def load_tools_tmp(instance_name: str) -> dict:
    path = os.path.join(TOOLS_TMP_DIR, safe_instance_filename(instance_name))
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("tools", {})
        if isinstance(tools, list):
            tools = {t: "pending" for t in tools}
        return tools if isinstance(tools, dict) else {}
    except Exception as e:
        logger.error(f"Error leyendo tools tmp de {instance_name}: {e}")
        return {}

def load_tools_installed(instance_id: str) -> dict:
    if not instance_id:
        return {}
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("installed_tools", {})
        return tools if isinstance(tools, dict) else {}
    except Exception as e:
        logger.error(f"Error leyendo installed tools de {instance_id}: {e}")
        return {}

def merge_tools_state(instance_id: str, instance_name: str) -> dict:
    tmp = load_tools_tmp(instance_name) or {}
    installed = load_tools_installed(instance_id) or {}

    merged = {}
    for tool, status in tmp.items():
        merged[tool] = status

    for tool, date in installed.items():
        if tool not in merged:
            merged[tool] = date
        else:
            if merged[tool] in ("error", "pending", "uninstalling"):
                continue
            merged[tool] = date

    return merged

# ============================================================
# OpenStack inventory endpoints
# ============================================================
def extract_subnet_cidr(conn, network_id: str):
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

@forensics_bp.route("/api/openstack/instances/full", methods=["GET"])
def api_openstack_instances_full():
    conn = None
    try:
        conn = get_openstack_connection()
        out = []

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
                    networks.append({"network": net_name, "ip": addr, "type": ip_type, "mac": mac})
                    if ip_type == "floating":
                        ip_floating = addr
                    else:
                        ip_private = addr

            flavor_obj = None
            try:
                flavor_ref = server.flavor["id"] if server.flavor else None
                if flavor_ref:
                    f = None
                    try:
                        f = conn.compute.get_flavor(flavor_ref)
                    except Exception:
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
                        volumes.append({"id": vid, "name": None, "size_gb": None, "status": "unknown", "bootable": None})
            except Exception as e:
                logger.warning(f"No se pudo leer volúmenes para {server.name}: {e}")

            try:
                sgs = [sg.get("name") for sg in (server.security_groups or []) if sg.get("name")]
            except Exception:
                sgs = []

            tools_state = merge_tools_state(server.id, server.name)

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
                "evidence": {"memory": (server.status == "ACTIVE"), "disk": True, "network": len(networks) > 0}
            })

        return jsonify({"instances": out}), 200

    except Exception as e:
        logger.error(f"Error /api/openstack/instances/full: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/flavors", methods=["GET"])
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
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/networks", methods=["GET"])
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
                "cidrs": cidrs,
            })
        networks.sort(key=lambda x: x["name"] or "")
        return jsonify({"networks": networks}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/networks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/security-groups", methods=["GET"])
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
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/keypairs", methods=["GET"])
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
            try:
                conn.close()
            except Exception:
                pass

# ============================================================
# Tools tmp endpoints (para tu instalador actual)
# ============================================================
def save_as_installed(instance_id, instance_name, tool_name):
    os.makedirs(INSTALLED_DIR, exist_ok=True)
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")

    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
    else:
        data = {"instance_id": instance_id, "instance_name": instance_name, "installed_tools": {}}

    data["installed_tools"][tool_name] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def remove_from_installed(instance_id, tool_name):
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if not os.path.exists(path):
        return False
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

@forensics_bp.route("/api/add_tool_to_instance", methods=["POST"])
def add_tool_to_instance():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "msg": "JSON vacío"}), 400

        instance = data.get("instance") or data.get("name")
        tools_data = data.get("tools", {})

        os.makedirs(TOOLS_TMP_DIR, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", instance.lower())
        path = os.path.join(TOOLS_TMP_DIR, f"{safe}_tools.json")

        if isinstance(tools_data, list):
            data["tools"] = {t: "pending" for t in tools_data}

        if not isinstance(data.get("tools"), dict):
            data["tools"] = {}

        with open(path, "w") as f:
            json.dump(data, f, indent=4)

        return jsonify({"status": "success", "saved": path, "current_tools": data["tools"]}), 200

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@forensics_bp.route("/api/get_tools_for_instance", methods=["GET"])
def get_tools_for_instance():
    instance_name = request.args.get("instance")
    if not instance_name:
        return jsonify({"tools": {}}), 200

    filename = safe_instance_filename(instance_name)
    path = os.path.join(TOOLS_TMP_DIR, filename)

    if not os.path.exists(path):
        return jsonify({"instance": instance_name, "tools": {}}), 200

    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("tools", {})
        if isinstance(tools, list):
            tools = {t: "pending" for t in tools}
        return jsonify({"instance": instance_name, "tools": tools}), 200
    except Exception as e:
        logger.error(f"Error leyendo tools tmp {path}: {e}")
        return jsonify({"instance": instance_name, "tools": {}}), 500

@forensics_bp.route("/api/read_tools_configs", methods=["GET"])
def read_tools_configs():
    if not os.path.exists(TOOLS_TMP_DIR):
        return jsonify({"files": []}), 200

    result = []
    for filename in os.listdir(TOOLS_TMP_DIR):
        if filename.endswith("_tools.json"):
            path = os.path.join(TOOLS_TMP_DIR, filename)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                result.append({"file": filename, "instance": data.get("instance"), "tools": data.get("tools", {})})
            except Exception:
                continue
    return jsonify({"files": result}), 200

@forensics_bp.route("/api/install_tools", methods=["POST"])
def install_tools():
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id")
    instance_name = data.get("instance")
    tools_to_install = data.get("tools", [])

    script = os.path.join(REPO_ROOT, "tools-installer", "tools_install_master.sh")
    if not os.path.exists(script):
        return jsonify({"status": "error", "msg": "Script maestro no encontrado"}), 404

    try:
        os.chmod(script, 0o755)
    except Exception:
        pass

    def generate():
        process = subprocess.Popen(
            ["bash", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            yield f"data: {line.strip()}\n\n"

        process.wait()

        if process.returncode == 0 and instance_id and instance_name:
            for t_name in tools_to_install:
                save_as_installed(instance_id, instance_name, t_name)
            yield "data: [SUCCESS] Registro actualizado en el sistema.\n\n"

        yield f"data: [FIN] Exit Code: {process.returncode}\n\n"

    return Response(generate(), mimetype="text/event-stream")

# ============================================================
# Forensic Host Tools (instalar en el host)
# ============================================================
FORENSIC_HOST_TOOLS = {
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

@forensics_bp.route("/api/host/forensic/tools", methods=["GET"])
def api_host_forensic_tools():
    out = [host_tool_status(t) for t in FORENSIC_HOST_TOOLS.keys()]
    return jsonify({"tools": out}), 200

@forensics_bp.route("/api/host/forensic/install", methods=["POST"])
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
        proc = subprocess.run(["bash", script_path], cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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

# ============================================================
# DFIR / FORENSICS (lo que tu UI llama)
# ============================================================
def _is_safe_case_dir(case_dir: str) -> bool:
    if not case_dir:
        return False
    case_dir = os.path.normpath(case_dir)
    return case_dir.startswith(os.path.normpath(EVIDENCE_ROOT) + os.sep)

def _manifest_path(case_dir: str) -> str:
    return os.path.join(case_dir, "manifest.json")

def _read_manifest(case_dir: str) -> dict:
    mp = _manifest_path(case_dir)
    if not os.path.exists(mp):
        return {"case_dir": case_dir, "created_at": None, "artifacts": []}
    with open(mp, "r") as f:
        return json.load(f)

def _write_manifest(case_dir: str, manifest: dict):
    mp = _manifest_path(case_dir)
    with open(mp, "w") as f:
        json.dump(manifest, f, indent=2)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()







def _add_artifact_fast(case_dir: str, rel_path: str, a_type: str, sha256: str = None, size: int = None):
    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    if size is None:
        try:
            size = os.path.getsize(abs_path)
        except Exception:
            size = None

    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": a_type,
        "rel_path": rel_path,
        "sha256": sha256,
        "size": size,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)






# ============================================================
# CHAIN OF CUSTODY (append-only + hash chaining) + TIME SYNC
# ============================================================

def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _read_last_custody_hash(case_dir: str) -> str:
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        return "0" * 64
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size <= 0:
                return "0" * 64
            back = min(8192, size)
            f.seek(-back, os.SEEK_END)
            tail = f.read().decode("utf-8", errors="ignore")
        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return "0" * 64
        last = json.loads(lines[-1])
        h = (last.get("entry_hash") or "").strip()
        return h if h else "0" * 64
    except Exception:
        return "0" * 64

def _ensure_custody_file(case_dir: str) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        try:
            Path(p).touch()
        except Exception:
            pass

def _append_custody_entry(
    case_dir: str,
    action: str,
    actor: str,
    run_id: str = "R1",
    artifact_rel: str = None,
    outcome: str = "ok",
    details: dict = None
) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    _ensure_custody_file(case_dir)

    prev_hash = _read_last_custody_hash(case_dir)
    ts = _utc_now_iso()

    entry = {
        "ts_utc": ts,
        "ts_epoch": time.time(),
        "run_id": (run_id or "R1"),
        "actor": (actor or "unknown"),
        "action": action,
        "artifact_rel": artifact_rel,
        "outcome": outcome,
        "details": (details or {}),
        "prev_hash": prev_hash,
    }

    payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    entry["entry_hash"] = _sha256_hex(payload)

    with open(_custody_path(case_dir), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def _register_custody_artifact(case_dir: str) -> None:
    rel = "chain_of_custody.log"
    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return
    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None
    _add_artifact_fast(case_dir, rel, "custody_log", sha256=sha, size=size)


def _parse_chrony_tracking_max_offset_ms(text: str):
    if not text:
        return None

    def to_ms(val: float, unit: str):
        u = (unit or "").strip().lower()
        if u in ("s", "sec", "secs", "second", "seconds"):
            return val * 1000.0
        if u in ("ms", "msec", "msecs", "millisecond", "milliseconds"):
            return val
        if u in ("us", "usec", "usecs", "microsecond", "microseconds"):
            return val / 1000.0
        if u in ("ns", "nsec", "nsecs", "nanosecond", "nanoseconds"):
            return val / 1_000_000.0
        return None

    max_ms = None

    # 1) Captura líneas típicas de chronyc tracking:
    #    "Last offset     : -0.000123456 seconds"
    #    "RMS offset      : 0.000456789 seconds"
    #    "System time     : 0.000001234 seconds slow of NTP time"
    patterns = [
        r"(?:Last|RMS)\s+offset\s*:\s*([+-]?\d+(?:\.\d+)?)\s*([a-zA-Z]+)",
        r"System\s+time\s*:\s*([+-]?\d+(?:\.\d+)?)\s*([a-zA-Z]+)",
        # fallback genérico
        r"offset\s*[:=]\s*([+-]?\d+(?:\.\d+)?)\s*([a-zA-Z]+)",
    ]

    for pat in patterns:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            try:
                v = abs(float(m.group(1)))
            except Exception:
                continue
            ms = to_ms(v, m.group(2))
            if ms is None:
                continue
            max_ms = ms if max_ms is None else max(max_ms, ms)

    return round(max_ms, 3) if max_ms is not None else None

def _export_time_sync(case_dir: str, run_id: str = "R1") -> dict:
    if not _is_safe_case_dir(case_dir):
        return {}

    ensure_case_layout(case_dir)

    rel = os.path.join("metadata", "time_sync.json")
    abs_path = os.path.join(case_dir, rel)

    chrony_tracking = ""
    chrony_sources = ""
    ntpq = ""
    timedatectl = ""

    try:
        r = subprocess.run(["bash", "-lc", "chronyc tracking 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        chrony_tracking = r.stdout or ""
    except Exception:
        pass

    try:
        r = subprocess.run(["bash", "-lc", "chronyc sources -v 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        chrony_sources = r.stdout or ""
    except Exception:
        pass

    try:
        r = subprocess.run(["bash", "-lc", "ntpq -pn 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ntpq = r.stdout or ""
    except Exception:
        pass

    try:
        r = subprocess.run(["bash", "-lc", "timedatectl 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        timedatectl = r.stdout or ""
    except Exception:
        pass

    max_offset_ms = _parse_chrony_tracking_max_offset_ms(chrony_tracking)

    payload = {
        "schema": "nics_time_sync_v1",
        "generated_at_utc": _utc_now_iso(),
        "run_id": (run_id or "R1"),
        "max_offset_ms": max_offset_ms,
        "raw": {
            "chronyc_tracking": chrony_tracking,
            "chronyc_sources_v": chrony_sources,
            "ntpq_pn": ntpq,
            "timedatectl": timedatectl,
        },
    }

    try:
        _atomic_write_json(abs_path, payload)
    except Exception:
        return {}

    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None

    try:
        _add_artifact_fast(case_dir, rel, "time_sync", sha256=sha, size=size)
    except Exception:
        pass

    try:
        _append_case_event(case_dir, "time_sync_exported", run_id=run_id, meta={
            "rel": rel, "sha256": sha, "size": size, "max_offset_ms": max_offset_ms
        })
    except Exception:
        pass

    return {"rel": rel, "sha256": sha, "size": size, "max_offset_ms": max_offset_ms}


def _write_case_digest(case_dir: str, run_id: str = "R1") -> dict:
    if not _is_safe_case_dir(case_dir):
        return {}

    ensure_case_layout(case_dir)

    rel = os.path.join("metadata", "case_digest.json")
    abs_path = os.path.join(case_dir, rel)

    def safe_sha(relp: str):
        ap = os.path.join(case_dir, relp)
        if not os.path.exists(ap):
            return None
        try:
            return _sha256_file(ap)
        except Exception:
            return None

    payload = {
        "schema": "nics_case_digest_v1",
        "generated_at_utc": _utc_now_iso(),
        "run_id": (run_id or "R1"),
        "digests": {
            "manifest_json_sha256": safe_sha("manifest.json"),
            "pipeline_events_jsonl_sha256": safe_sha(os.path.join("metadata", "pipeline_events.jsonl")),
            "chain_of_custody_log_sha256": safe_sha("chain_of_custody.log"),
            "time_sync_json_sha256": safe_sha(os.path.join("metadata", "time_sync.json")),
        }
    }

    try:
        _atomic_write_json(abs_path, payload)
    except Exception:
        return {}

    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None

    try:
        _add_artifact_fast(case_dir, rel, "case_digest", sha256=sha, size=size)
    except Exception:
        pass

    try:
        _append_case_event(case_dir, "case_digest_written", run_id=run_id, meta={"rel": rel, "sha256": sha, "size": size})
    except Exception:
        pass

    return {"rel": rel, "sha256": sha, "size": size}




def iso_to_epoch(iso_utc: str) -> float:
    s = (iso_utc or "").strip()
    if not s:
        return 0.0

    # Soporta:
    # - 2026-02-19T15:22:57Z
    # - 2026-02-19T15:22:57.367+0000
    # - 2026-02-19T15:22:57.367+00:00
    if s.endswith("Z"):
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    else:
        # normaliza +0000 -> +00:00
        if len(s) >= 5 and (s[-5] in ["+", "-"]) and s[-3] != ":":
            s = s[:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s)

    return dt.astimezone(timezone.utc).timestamp()


def _utc_now_iso() -> str:
    # ISO UTC real (timezone-aware)
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_case_event(case_dir: str, event: str, run_id: str = "R1", meta: dict = None, ts_utc: str = None):
    """
    Append-only event log.
    Si ts_utc se proporciona, se usa ese timestamp (y su ts_epoch coherente).
    Si no, se usa 'now' en UTC.
    """
    os.makedirs(_case_meta_dir(case_dir), exist_ok=True)

    ts = (ts_utc or "").strip() or _utc_now_iso()
    rec = {
        "ts_utc": ts,
        "ts_epoch": iso_to_epoch(ts),
        "event": event,
        "run_id": (run_id or "R1"),
        "meta": meta or {}
    }
    with open(_events_path(case_dir), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _get_or_set_alert_ts(case_dir: str, run_id: str = "R1", provided_alert_ts_utc: str = None) -> str:
    run_id = (run_id or "R1").strip() or "R1"
    alert_ts = (provided_alert_ts_utc or "").strip() or _utc_now_iso()

    ep = _events_path(case_dir)

    if os.path.exists(ep):
        try:
            with open(ep, "r", encoding="utf-8") as f:
                for line in f:
                    line = (line or "").strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    if r.get("event") == "alert" and r.get("run_id") == run_id:
                        return (r.get("ts_utc") or alert_ts).strip() or alert_ts
        except Exception:
            pass

    _append_case_event(
        case_dir,
        "alert",
        run_id=run_id,
        meta={"source": "pipeline"},
        ts_utc=alert_ts
    )

    _export_time_sync(case_dir, run_id=run_id)
    _append_custody_entry(case_dir, "alert", "forensics_api", run_id=run_id, details={"source": "pipeline"})
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    return alert_ts







def _case_meta_dir(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata")

def _events_path(case_dir: str) -> str:
    return os.path.join(_case_meta_dir(case_dir), "pipeline_events.jsonl")



def ensure_case_layout(case_dir: str) -> None:
    """
    Asegura que la estructura del caso existe y que dirs críticos (ej. derived/)
    NO son ficheros. Si algún dir existe como fichero, lo elimina y crea el directorio.
    """
    if not case_dir or not os.path.isdir(case_dir):
        return

    required_dirs = ["metadata", "network", "disk", "memory", "industrial", "analysis", "derived"]

    for d in required_dirs:
        p = os.path.join(case_dir, d)

        # Si existe como fichero -> rompería todo (caso actual de derived)
        if os.path.exists(p) and not os.path.isdir(p):
            try:
                os.remove(p)
            except Exception:
                # si no se puede borrar, no seguimos para no romper nada silenciosamente
                raise

        # Crear dir si no existe
        os.makedirs(p, exist_ok=True)

    # Asegurar pipeline_events.jsonl existe
    evp = _events_path(case_dir)
    if not os.path.exists(evp):
        try:
            Path(evp).touch()
        except Exception:
            pass





def register_derived(
    case_dir: str,
    rel_path: str,
    derived_type: str,
    run_id: str = "R1",
    source_rel: str = None,
    extra_meta: dict = None,
    compute_sha: bool = False,
) -> None:
    """
    Registra un artefacto DERIVADO (dentro de derived/ o analysis/ si lo decides así)
    en el manifest, y deja un evento append-only en pipeline_events.jsonl.

    - NO inventa nada: solo indexa lo que ya exista en disco.
    - Por defecto NO recalcula SHA (compute_sha=False) para no costear dumps grandes.
    """
    if not _is_safe_case_dir(case_dir):
        return
    if not rel_path:
        return

    ensure_case_layout(case_dir)

    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    sha = None
    size = None

    try:
        if os.path.isfile(abs_path):
            size = os.path.getsize(abs_path)
            if compute_sha:
                sha = _sha256_file(abs_path)
        else:
            # directorio: sin sha/size
            size = None
            sha = None
    except Exception:
        pass

    # Manifest
    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": derived_type,
        "rel_path": rel_path,
        "sha256": sha,
        "size": size,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)

    # Evento pipeline (append-only)
    meta = {"rel": rel_path, "type": derived_type}
    if source_rel:
        meta["source_rel"] = source_rel
    if extra_meta and isinstance(extra_meta, dict):
        meta.update(extra_meta)

    try:
        _append_case_event(case_dir, "derived_registered", run_id=run_id, meta=meta)
    except Exception:
        pass








def _atomic_write_json(path: str, obj: dict):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)









def _add_artifact(case_dir: str, rel_path: str, a_type: str):
    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    manifest = _read_manifest(case_dir)
    artifacts = manifest.setdefault("artifacts", [])

    try:
        sha = _sha256_file(abs_path)
        size = os.path.getsize(abs_path)
    except Exception:
        sha = None
        size = None

    artifacts.append({
        "type": a_type,
        "rel_path": rel_path,
        "sha256": sha,
        "size": size,
        "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    })
    _write_manifest(case_dir, manifest)

@forensics_bp.route("/api/forensics/case/create", methods=["POST"])
def api_forensics_case_create():
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    case_dir = os.path.join(EVIDENCE_ROOT, f"CASE-{ts}")
    os.makedirs(case_dir, exist_ok=True)
    logger.info(f"[CASE_CREATE] REPO_ROOT={REPO_ROOT}")
    logger.info(f"[CASE_CREATE] EVIDENCE_ROOT={EVIDENCE_ROOT}")
    logger.info(f"[CASE_CREATE] case_dir={case_dir}")
    logger.info(f"[CASE_CREATE] ACTIVE_CASE_PTR={os.path.join(EVIDENCE_ROOT, '_active_case.txt')}")
    # Subdirs estándar
    for d in ["metadata", "network", "disk", "memory", "industrial", "analysis", "derived"]:
        os.makedirs(os.path.join(case_dir, d), exist_ok=True)

    ensure_case_layout(case_dir)

    set_active_case_dir(case_dir)
    logger.info("[CASE_CREATE] active case pointer written")
    # custody file + register in manifest
    _ensure_custody_file(case_dir)

    # manifest
    manifest = {
        "case_dir": case_dir,
        "created_at": _utc_now_iso(),
        "artifacts": []
    }
    _write_manifest(case_dir, manifest)

    _append_custody_entry(case_dir, "case_created", "forensics_api", run_id="R1", details={"case_dir": case_dir})

    _register_custody_artifact(case_dir)
    _export_time_sync(case_dir, run_id="R1")
    _write_case_digest(case_dir, run_id="R1")

    # events file (vacío)
    evp = _events_path(case_dir)
    if not os.path.exists(evp):
        Path(evp).touch()

    return jsonify({"case_dir": case_dir}), 200

@forensics_bp.route("/api/forensics/case/manifest", methods=["GET"])
def api_forensics_case_manifest():
    case_dir = request.args.get("case_dir", "")
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    ensure_case_layout(case_dir)

    try:
        return jsonify(_read_manifest(case_dir)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@forensics_bp.route("/api/forensics/case/download", methods=["GET"])
def api_forensics_case_download():
    case_dir = request.args.get("case_dir", "")
    rel = request.args.get("rel", "")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not rel or ".." in rel or rel.startswith("/") or rel.startswith("\\"):
        return jsonify({"error": "rel inválido"}), 400
    
    ensure_case_layout(case_dir)

    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return jsonify({"error": "Archivo no existe"}), 404

    directory = os.path.dirname(abs_path)
    filename = os.path.basename(abs_path)
    return send_from_directory(directory, filename, as_attachment=True)

def _run_script(script_path: str, args: list, cwd: str = None, timeout: int = 60 * 60):
    if not os.path.exists(script_path):
        return (1, "", f"Script no encontrado: {script_path}")

    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass

    proc = subprocess.run(
        ["bash", script_path] + args,
        cwd=cwd or REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout
    )
    return (proc.returncode, proc.stdout, proc.stderr)





@forensics_bp.route("/api/forensics/acquire/disk_kolla", methods=["POST"])
def api_forensics_acquire_disk():
    data = request.get_json(force=True, silent=True) or {}
    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    container_name = data.get("container_name", "nova_libvirt")
    run_id = (data.get("run_id") or "R1").strip()
    alert_ts_utc = (data.get("alert_ts_utc") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id:
        return jsonify({"error": "vm_id requerido"}), 400

    _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)

  

    _append_custody_entry(
        case_dir,
        "acquire_start",
        "forensics_api",
        run_id=run_id,
        details={"kind": "disk", "vm_id": vm_id}
    )
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")

    _append_case_event(case_dir, "disk_start", run_id=run_id, meta={"vm_id": vm_id, "container": container_name})

    t0 = time.time()
    rc, out, err = _run_script(script, [case_dir, vm_id, container_name], cwd=REPO_ROOT, timeout=60 * 60)
    t1 = time.time()

    disk_rel = None
    disk_size = None
    sha_value = None

    if rc == 0:
        disk_rel, disk_size, sha_value = _register_disk_from_metadata(case_dir, vm_id)

    _append_case_event(
        case_dir,
        "disk_preserved" if (rc == 0 and disk_rel) else "disk_failed",
        run_id=run_id,
        meta={
            "vm_id": vm_id,
            "rel": disk_rel,
            "size": disk_size,
            "sha256": sha_value,
            "exit_code": rc,
            "elapsed_s": round(t1 - t0, 3),
        }
    )

    if disk_rel:
        _append_custody_entry(
            case_dir,
            "acquire_preserved",
            "forensics_api",
            run_id=run_id,
            artifact_rel=disk_rel,
            outcome="ok" if rc == 0 else "error",
            details={"kind": "disk", "vm_id": vm_id, "sha256": sha_value, "size": disk_size}
        )
    else:
        _append_custody_entry(
            case_dir,
            "acquire_failed",
            "forensics_api",
            run_id=run_id,
            outcome="error",
            details={"kind": "disk", "vm_id": vm_id, "exit_code": rc}
        )

    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    return jsonify({
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "disk_raw": disk_rel,
        "sha256": sha_value
    }), 200 if rc == 0 else 500











@forensics_bp.route("/api/forensics/acquire/disk_kolla/stream", methods=["GET"])
def api_forensics_acquire_disk_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    container_name = request.args.get("container_name", "nova_libvirt")
    run_id = (request.args.get("run_id") or "R1").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id:
        return jsonify({"error": "vm_id requerido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    def generate():
        start_ts = time.time()
        script_name = os.path.basename(script)

        _append_case_event(case_dir, "disk_start", run_id=run_id, meta={"vm_id": vm_id, "container": container_name})

        yield f"data: [START] {script_name} {case_dir} {vm_id} {container_name}\n\n"

        p = subprocess.Popen(
            ["bash", script, case_dir, vm_id, container_name],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        for line in p.stdout:
            line = (line or "").rstrip("\n")
            if line.strip():
                last_line = line.strip()
            yield f"data: {line}\n\n"

        p.wait()
        rc = p.returncode if p.returncode is not None else 1

        disk_rel = None
        disk_size = None
        sha_value = None

        if rc == 0:
            disk_rel, disk_size, sha_value = _register_disk_from_metadata(case_dir, vm_id)

        _append_case_event(
            case_dir,
            "disk_preserved" if (rc == 0 and disk_rel) else "disk_failed",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "rel": disk_rel,
                "size": disk_size,
                "sha256": sha_value,
                "exit_code": rc,
                "elapsed_s": round(time.time() - start_ts, 3),
            }
        )

        payload = {
            "result": "ok" if rc == 0 else "error",
            "exit_code": rc,
            "last": last_line,
            "disk_raw": disk_rel,
            "sha256": sha_value,
            "script": script_name
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(generate(), mimetype="text/event-stream")



@forensics_bp.route("/api/forensics/analyze/memory_vol3", methods=["POST"])
def api_forensics_analyze_memory():
    data = request.get_json(force=True, silent=True) or {}

    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    dump_file = data.get("dump_file") or data.get("dump")  # rel o abs
    symbols_dir = data.get("symbols_dir")
    vol_cmd = data.get("vol_cmd", "vol")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not dump_file or not symbols_dir:
        return jsonify({"error": "vm_id, dump_file, symbols_dir requeridos"}), 400

    # Resolver dump_file: si es relativo, lo hacemos relativo al case_dir
    dump_path = dump_file
    if not os.path.isabs(dump_path):
        dump_path = os.path.join(case_dir, dump_file)

    if not os.path.exists(dump_path):
        return jsonify({"error": f"Dump no existe: {dump_file}"}), 404

    # Script
    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_memory_vol3.sh")

    # Args EXACTOS que vas a pasar al .sh
    args = [case_dir, dump_path, symbols_dir, vol_cmd, vm_id]

    # Imprime en consola (logs del backend) antes de ejecutar
    print("[VOL3] analyze_memory_vol3.sh will run with:")
    print(f"[VOL3]   case_dir     = {case_dir}")
    print(f"[VOL3]   dump_file    = {dump_file}")
    print(f"[VOL3]   dump_path    = {dump_path}")
    print(f"[VOL3]   symbols_dir  = {symbols_dir}")
    print(f"[VOL3]   vol_cmd      = {vol_cmd}")
    print(f"[VOL3]   vm_id        = {vm_id}")
    print(f"[VOL3]   args         = {args}")
    print(f"[VOL3]   cwd          = {REPO_ROOT}")
    print(f"[VOL3]   script       = {script}")

    rc, out, err = _run_script(
        script,
        args,
        cwd=REPO_ROOT,
        timeout=60 * 60
    )

    # Convención mínima: analysis/vol3/<vm_id>/
    rel_out = os.path.join("analysis", "vol3", vm_id)
    abs_out = os.path.join(case_dir, rel_out)
    if os.path.isdir(abs_out):
        manifest = _read_manifest(case_dir)
        manifest.setdefault("artifacts", []).append({
            "type": "vol3_output_dir",
            "rel_path": rel_out,
            "sha256": None,
            "size": None,
            "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        })
        _write_manifest(case_dir, manifest)

    return jsonify({
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "out_dir": rel_out if os.path.isdir(abs_out) else None,

        # Esto te lo devuelve el endpoint para verificar lo que se pasó al .sh
        "debug": {
            "script": script,
            "cwd": REPO_ROOT,
            "case_dir": case_dir,
            "dump_file": dump_file,
            "dump_path": dump_path,
            "symbols_dir": symbols_dir,
            "vol_cmd": vol_cmd,
            "vm_id": vm_id,
            "args": args,
        }
    }), 200 if rc == 0 else 500


@forensics_bp.route("/api/forensics/case/list", methods=["GET"])
def api_forensics_case_list():
    try:
        cases = []
        if os.path.isdir(EVIDENCE_ROOT):
            for name in os.listdir(EVIDENCE_ROOT):
                if not name.startswith("CASE-"):
                    continue
                case_dir = os.path.join(EVIDENCE_ROOT, name)
                if not os.path.isdir(case_dir):
                    continue

                mp = _manifest_path(case_dir)
                created_at = None
                artifacts_count = 0

                if os.path.exists(mp):
                    try:
                        m = _read_manifest(case_dir)
                        created_at = m.get("created_at")
                        artifacts_count = len(m.get("artifacts", []) or [])
                    except Exception:
                        pass

                cases.append({
                    "name": name,
                    "case_dir": case_dir,
                    "created_at": created_at,
                    "artifacts_count": artifacts_count
                })

        # Orden: más reciente primero (por nombre CASE-YYYYMMDD-HHMMSS)
        cases.sort(key=lambda x: x["name"], reverse=True)

        return jsonify({"cases": cases}), 200
    except Exception as e:
        logger.error(f"Error /api/forensics/case/list: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500




def _run_script_sse(script_path: str, args: list, cwd: str = None, timeout: int = 60 * 60):
    if not os.path.exists(script_path):
        def gen_err():
            yield "data: [ERROR] Script no encontrado: {}\n\n".format(script_path)
            payload = {"result": "error", "exit_code": 127, "last": "", "script": os.path.basename(script_path)}
            yield "event: done\ndata: {}\n\n".format(json.dumps(payload))
        return Response(gen_err(), mimetype="text/event-stream")

    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass

    def generate():
        start_ts = time.time()
        script_name = os.path.basename(script_path)

        yield f"data: [START] {script_name} {' '.join(args)}\n\n"

        p = subprocess.Popen(
            ["bash", script_path] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        timed_out = False

        try:
            for line in p.stdout:
                line = (line or "").rstrip("\n")
                if line.strip():
                    last_line = line.strip()

                yield f"data: {line}\n\n"

                if timeout and (time.time() - start_ts) > timeout:
                    timed_out = True
                    try:
                        p.kill()
                    except Exception:
                        pass
                    yield "data: [ERROR] Timeout alcanzado, proceso abortado\n\n"
                    break
        finally:
            try:
                p.wait(timeout=5)
            except Exception:
                pass

        exit_code = p.returncode if p.returncode is not None else 1
        result = "ok" if (exit_code == 0 and not timed_out) else "error"

        yield f"data: [EXIT] {exit_code}\n\n"
        if last_line:
            yield f"data: [LAST] {last_line}\n\n"

        payload = {
            "result": result,
            "exit_code": exit_code,
            "last": last_line,
            "script": script_name,
        }
        # Evento que el front SÍ puede capturar con addEventListener("done", ...)
        yield "event: done\ndata: {}\n\n".format(json.dumps(payload))

    return Response(generate(), mimetype="text/event-stream")


@forensics_bp.route("/api/forensics/vol3/symbols/generate/stream", methods=["GET"])
def api_vol3_symbols_generate_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    vm_ip = request.args.get("vm_ip", "")
    ssh_user = (request.args.get("ssh_user", "debian") or "debian").strip()
    ssh_key = (request.args.get("ssh_key", "") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "generate_vol3_symbols_ssh.sh")
    return _run_script_sse(script, [case_dir, vm_id, vm_ip, ssh_user, ssh_key], cwd=REPO_ROOT, timeout=60 * 60)





@forensics_bp.route("/api/forensics/acquire/memory_lime", methods=["POST"])
def api_forensics_acquire_memory():
    data = request.get_json(force=True, silent=True) or {}
    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    vm_ip = data.get("vm_ip")
    ssh_user = data.get("ssh_user", "debian")
    ssh_key = data.get("ssh_key", "")
    mode = data.get("mode", "build")
    run_id = (data.get("run_id") or "R1").strip()
    alert_ts_utc = (data.get("alert_ts_utc") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido (path en el servidor)"}), 400

    _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)

    _append_custody_entry(
        case_dir, "acquire_start", "forensics_api",
        run_id=run_id, details={"kind": "memory", "vm_id": vm_id, "vm_ip": vm_ip, "mode": mode}
    )
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_memory_lime_ssh.sh")

    _append_case_event(case_dir, "memory_start", run_id=run_id, meta={
        "vm_id": vm_id, "vm_ip": vm_ip, "ssh_user": ssh_user, "mode": mode
    })

    def _run_for_user(user: str):
        return _run_script(
            script,
            [case_dir, vm_id, vm_ip, user, ssh_key, mode],
            cwd=REPO_ROOT,
            timeout=60 * 60
        )

    attempted_users = [ssh_user] if ssh_user else []
    t0 = time.time()
    rc, out, err = _run_for_user(ssh_user)

    auth_fail = (rc == 255) and ("Permission denied (publickey)" in (err or "") or "Permission denied" in (err or ""))
    if auth_fail:
        for candidate_user in ["ubuntu", "debian"]:
            if candidate_user in attempted_users:
                continue
            attempted_users.append(candidate_user)
            rc, out, err = _run_for_user(candidate_user)
            if rc == 0:
                ssh_user = candidate_user
                break
    t1 = time.time()

    mem_rel = mem_size = sha_value = None
    if rc == 0:
        mem_rel, mem_size, sha_value = _register_memory_from_metadata(case_dir, vm_ip=vm_ip)

        if not mem_rel:
            produced_abs = ""
            try:
                lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
                if lines:
                    candidate = lines[-1]
                    if os.path.isabs(candidate) and os.path.exists(candidate):
                        produced_abs = candidate
            except Exception:
                produced_abs = ""

            if produced_abs:
                try:
                    mem_rel = os.path.relpath(produced_abs, case_dir)
                    if mem_rel.startswith("..") or os.path.isabs(mem_rel):
                        mem_rel = None
                except Exception:
                    mem_rel = None

                if mem_rel:
                    try:
                        mem_size = os.path.getsize(os.path.join(case_dir, mem_rel))
                    except Exception:
                        mem_size = None
                    _add_artifact(case_dir, mem_rel, "memory_lime")

    _append_case_event(
        case_dir,
        "memory_preserved" if (rc == 0 and mem_rel) else "memory_failed",
        run_id=run_id,
        meta={
            "vm_id": vm_id,
            "vm_ip": vm_ip,
            "rel": mem_rel,
            "size": mem_size,
            "sha256": sha_value,
            "exit_code": rc,
            "elapsed_s": round(t1 - t0, 3),
            "ssh_user_used": ssh_user,
            "attempted_users": attempted_users,
            "mode": mode,
        }
    )

    if mem_rel:
        _append_custody_entry(
            case_dir, "acquire_preserved", "forensics_api",
            run_id=run_id, artifact_rel=mem_rel,
            outcome="ok" if rc == 0 else "error",
            details={
                "kind": "memory",
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "sha256": sha_value,
                "size": mem_size,
                "mode": mode
            }
        )
    else:
        _append_custody_entry(
            case_dir, "acquire_failed", "forensics_api",
            run_id=run_id, outcome="error",
            details={
                "kind": "memory",
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "exit_code": rc,
                "mode": mode
            }
        )

    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    return jsonify({
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "mem_dump": mem_rel,
        "sha256": sha_value,
        "ssh_user_used": ssh_user,
        "attempted_users": attempted_users
    }), 200 if rc == 0 else 500


@forensics_bp.route("/api/forensics/acquire/memory_lime/stream", methods=["GET"])
def api_forensics_acquire_memory_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    vm_ip = request.args.get("vm_ip", "")
    ssh_user = request.args.get("ssh_user", "debian")
    ssh_key = request.args.get("ssh_key", "")
    mode = request.args.get("mode", "build")
    run_id = (request.args.get("run_id") or "R1").strip()
    alert_ts_utc = (request.args.get("alert_ts_utc") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido"}), 400

    _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)

    _append_custody_entry(
        case_dir, "acquire_start", "forensics_api",
        run_id=run_id, details={"kind": "memory", "vm_id": vm_id, "vm_ip": vm_ip, "mode": mode}
    )
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_memory_lime_ssh.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    candidates = [ssh_user] + [u for u in ["ubuntu", "debian"] if u != ssh_user]

    def sse():
        def emit(line: str):
            return f"data: {(line or '').rstrip(chr(10))}\n\n"

        start_ts = time.time()

        _append_case_event(case_dir, "memory_start", run_id=run_id, meta={
            "vm_id": vm_id, "vm_ip": vm_ip, "ssh_user": ssh_user, "mode": mode
        })

        yield emit(
            f"[SISTEMA] Starting memory acquisition (LiME) "
            f"vm_id={vm_id} ip={vm_ip} user={ssh_user} mode={mode} run_id={run_id}"
        )

        used_user = None
        final_rc = 1
        final_out = ""
        last_stdout_line = ""

        for user in candidates:
            used_user = user
            yield emit(f"[SISTEMA] Trying ssh_user={user}")

            cmd = [
                "bash", "-lc",
                f"stdbuf -oL -eL bash '{script}' '{case_dir}' '{vm_id}' '{vm_ip}' '{user}' '{ssh_key}' '{mode}'"
            ]
            proc = subprocess.Popen(
                cmd,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            lines = []
            for line in proc.stdout:
                lines.append(line)
                if (line or "").strip():
                    last_stdout_line = line.strip()
                yield emit(line.rstrip("\n"))

            proc.wait()
            final_rc = proc.returncode
            final_out = "".join(lines)

            if final_rc == 0:
                break
            if "Permission denied" in final_out:
                yield emit("[SISTEMA] Auth failed, retrying with next user...")
                continue
            break

        mem_rel = mem_size = sha_value = None
        if final_rc == 0:
            mem_rel, mem_size, sha_value = _register_memory_from_metadata(case_dir, vm_ip=vm_ip)

            if not mem_rel and last_stdout_line and os.path.isabs(last_stdout_line) and os.path.exists(last_stdout_line):
                try:
                    mem_rel = os.path.relpath(last_stdout_line, case_dir)
                    if mem_rel.startswith("..") or os.path.isabs(mem_rel):
                        mem_rel = None
                except Exception:
                    mem_rel = None

                if mem_rel:
                    try:
                        mem_size = os.path.getsize(os.path.join(case_dir, mem_rel))
                    except Exception:
                        mem_size = None
                    _add_artifact(case_dir, mem_rel, "memory_lime")

        _append_case_event(
            case_dir,
            "memory_preserved" if (final_rc == 0 and mem_rel) else "memory_failed",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "rel": mem_rel,
                "size": mem_size,
                "sha256": sha_value,
                "exit_code": final_rc,
                "elapsed_s": round(time.time() - start_ts, 3),
                "ssh_user_used": used_user,
                "mode": mode,
            }
        )

        if mem_rel:
            _append_custody_entry(
                case_dir, "acquire_preserved", "forensics_api",
                run_id=run_id, artifact_rel=mem_rel,
                outcome="ok",
                details={
                    "kind": "memory",
                    "vm_id": vm_id,
                    "vm_ip": vm_ip,
                    "sha256": sha_value,
                    "size": mem_size,
                    "mode": mode
                }
            )
        else:
            _append_custody_entry(
                case_dir, "acquire_failed", "forensics_api",
                run_id=run_id, outcome="error",
                details={
                    "kind": "memory",
                    "vm_id": vm_id,
                    "vm_ip": vm_ip,
                    "exit_code": final_rc,
                    "mode": mode
                }
            )

        _register_custody_artifact(case_dir)
        _write_case_digest(case_dir, run_id=run_id)

        payload = {
            "result": "ok" if final_rc == 0 else "error",
            "exit_code": final_rc,
            "mem_dump": mem_rel,
            "sha256": sha_value,
            "ssh_user_used": used_user,
            "last": last_stdout_line,
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")





def _read_text_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return (f.readline() or "").strip()
    except Exception:
        return ""














def _find_latest_disk_metadata(case_dir: str, vm_id: str):
    meta_dir = os.path.join(case_dir, "metadata")
    if not os.path.isdir(meta_dir):
        return (None, None)

    cands = []
    for fn in os.listdir(meta_dir):
        if fn.startswith(vm_id) and fn.endswith(".disk.metadata.json"):
            p = os.path.join(meta_dir, fn)
            try:
                cands.append((os.path.getmtime(p), p))
            except Exception:
                continue

    if not cands:
        return (None, None)

    cands.sort(key=lambda x: x[0], reverse=True)
    meta_path = cands[0][1]

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta_obj = json.load(f)
        if not isinstance(meta_obj, dict):
            return (None, None)
        return (meta_path, meta_obj)
    except Exception:
        return (None, None)

def _register_disk_from_metadata(case_dir: str, vm_id: str):
    """
    Registra en manifest:
      - disk/<final_raw> como disk_raw usando sha del metadata/.sha256 (sin recalcular SHA del RAW)
      - metadata/<...>.disk.metadata.json como disk_metadata
      - metadata/<...>.disk.sha256 como disk_sha256_file (si existe)
    Devuelve: (disk_rel, disk_size, sha_value)
    """
    meta_path, meta_obj = _find_latest_disk_metadata(case_dir, vm_id)
    if not meta_path or not meta_obj:
        return (None, None, None)

    final_raw_name = (meta_obj.get("final_raw") or "").strip()
    if not final_raw_name:
        return (None, None, None)

    disk_rel = os.path.join("disk", final_raw_name)
    disk_abs = os.path.join(case_dir, disk_rel)
    if not os.path.exists(disk_abs):
        return (None, None, None)

    # base (para localizar el sha file)
    base = os.path.basename(meta_path).replace(".disk.metadata.json", "")
    sha_rel = os.path.join("metadata", f"{base}.disk.sha256")
    sha_abs = os.path.join(case_dir, sha_rel)

    sha_value = (meta_obj.get("sha256") or "").strip() or None
    if not sha_value and os.path.exists(sha_abs):
        sha_value = _read_text_first_line(sha_abs) or None

    try:
        disk_size = os.path.getsize(disk_abs)
    except Exception:
        disk_size = None

    # RAW (sin re-hash)
    _add_artifact_fast(case_dir, disk_rel, "disk_raw", sha256=sha_value, size=disk_size)

    # metadata.json (pequeño -> ok rehash)
    try:
        meta_rel = os.path.relpath(meta_path, case_dir)
        if not meta_rel.startswith("..") and not os.path.isabs(meta_rel):
            _add_artifact(case_dir, meta_rel, "disk_metadata")
    except Exception:
        pass

    # sha file (pequeño -> ok rehash)
    try:
        if os.path.exists(sha_abs):
            _add_artifact(case_dir, sha_rel, "disk_sha256_file")
    except Exception:
        pass

    return (disk_rel, disk_size, sha_value)







def _register_memory_from_metadata(case_dir: str, vm_ip: str = None):
    """
    Registra en manifest el dump LiME y sus ficheros metadata/sha.
    NO recalcula SHA del dump (usa metadata.json / .sha256 generados por el script).
    Devuelve: (mem_rel, mem_size, sha_value)
    """
    meta_dir = os.path.join(case_dir, "metadata")
    mem_dir  = os.path.join(case_dir, "memory")

    if not os.path.isdir(meta_dir):
        return (None, None, None)

    # Buscar el metadata más reciente de LiME
    cands = []
    for fn in os.listdir(meta_dir):
        # script: memdump_<VM_IP>_<UTC>.lime.metadata.json
        if not fn.endswith(".lime.metadata.json"):
            continue
        if vm_ip and (vm_ip not in fn):
            continue
        p = os.path.join(meta_dir, fn)
        try:
            cands.append((os.path.getmtime(p), p))
        except Exception:
            continue

    if not cands:
        return (None, None, None)

    cands.sort(key=lambda x: x[0], reverse=True)
    meta_path = cands[0][1]

    meta_obj = None
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta_obj = json.load(f)
    except Exception:
        meta_obj = None

    dump_file = ((meta_obj or {}).get("dump_file") or "").strip()
    sha_value = ((meta_obj or {}).get("sha256") or "").strip() or None

    if not dump_file:
        return (None, None, sha_value)

    dump_abs = os.path.join(mem_dir, dump_file)
    if not os.path.exists(dump_abs):
        return (None, None, sha_value)

    mem_rel = os.path.join("memory", dump_file)

    # sha fallback: leer el .sha256 si no viene en metadata.json
    base_sha = os.path.basename(meta_path).replace(".metadata.json", "")
    sha_rel  = os.path.join("metadata", f"{base_sha}.sha256")
    sha_abs  = os.path.join(case_dir, sha_rel)

    if not sha_value and os.path.exists(sha_abs):
        try:
            with open(sha_abs, "r", encoding="utf-8") as f:
                sha_value = (f.read() or "").strip() or None
        except Exception:
            sha_value = None

    # size
    try:
        mem_size = os.path.getsize(dump_abs)
    except Exception:
        mem_size = None

    # Registrar dump (rápido)
    _add_artifact_fast(case_dir, mem_rel, "memory_lime", sha256=sha_value, size=mem_size)

    # Registrar metadata (pequeños)
    try:
        rel_mp = os.path.relpath(meta_path, case_dir)
        if not rel_mp.startswith("..") and not os.path.isabs(rel_mp):
            _add_artifact(case_dir, rel_mp, "memory_metadata")
    except Exception:
        pass

    try:
        if os.path.exists(sha_abs):
            _add_artifact(case_dir, sha_rel, "memory_sha256_file")
    except Exception:
        pass

    return (mem_rel, mem_size, sha_value)






@forensics_bp.route("/api/forensics/analyze/all/stream", methods=["GET"])
def api_forensics_analyze_all_stream():
    case_dir = request.args.get("case_dir", "").strip()
    symbols_dir = request.args.get("symbols_dir", "").strip()  # opcional pero necesario para vol3
    vol_cmd = (request.args.get("vol_cmd", "vol") or "vol").strip()
    run_id = (request.args.get("run_id") or "R1").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_case_all.sh")

    _append_case_event(case_dir, "analysis_all_start", run_id=run_id, meta={
        "symbols_dir": symbols_dir or None,
        "vol_cmd": vol_cmd
    })

    # SSE: ejecuta el script y al final emite done
    resp = _run_script_sse(
        script,
        [case_dir, symbols_dir, vol_cmd],
        cwd=REPO_ROOT,
        timeout=60 * 60
    )

    return resp






# ============================================================
# DISK ANALYSIS (TSK) - SSE
# ============================================================

def _safe_join_case(case_dir: str, rel_path: str) -> str:
    """
    Une case_dir + rel_path de forma segura evitando traversal.
    Devuelve abs_path si es seguro; si no, devuelve "".
    """
    if not rel_path:
        return ""
    rel_path = rel_path.strip()

    # prohibiciones básicas
    if rel_path.startswith("/") or rel_path.startswith("\\"):
        return ""
    if ".." in rel_path.replace("\\", "/").split("/"):
        return ""

    abs_path = os.path.normpath(os.path.join(case_dir, rel_path))
    case_norm = os.path.normpath(case_dir)

    # asegurar que queda dentro del case_dir
    if not abs_path.startswith(case_norm + os.sep):
        return ""
    return abs_path


def _register_dir_artifact(case_dir: str, rel_dir: str, a_type: str):
    """
    Registra un directorio como artefacto (sin sha/size).
    """
    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": a_type,
        "rel_path": rel_dir,
        "sha256": None,
        "size": None,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)


@forensics_bp.route("/api/forensics/analyze/disk_tsk/stream", methods=["GET"])
def api_forensics_analyze_disk_tsk_stream():
    case_dir = (request.args.get("case_dir") or "").strip()
    disk_rel = (request.args.get("disk") or "").strip()
    run_id = (request.args.get("run_id") or "R1").strip() or "R1"

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not disk_rel:
        return jsonify({"error": "disk requerido (rel_path desde manifest)"}), 400

    # Resolver path del disco dentro del caso
    disk_abs = _safe_join_case(case_dir, disk_rel)
    if not disk_abs:
        return jsonify({"error": "disk rel_path inválido"}), 400
    if not os.path.exists(disk_abs):
        return jsonify({"error": f"Disk no existe: {disk_rel}"}), 404

    # Output dir: analysis/tsk/<run_id>/<basename-disco-sin-ext>
    disk_base = os.path.basename(disk_rel)
    disk_stem = re.sub(r"\.(raw|img|dd|qcow2|vmdk)$", "", disk_base, flags=re.IGNORECASE)
    out_rel = os.path.join("analysis", "tsk", run_id, disk_stem)
    out_abs = os.path.join(case_dir, out_rel)
    os.makedirs(out_abs, exist_ok=True)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_disk_tsk.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404
    try:
        os.chmod(script, 0o755)
    except Exception:
        pass

    def sse():
        def emit(line: str):
            line = (line or "").rstrip("\n")
            return f"data: {line}\n\n"

        start_ts = time.time()
        script_name = os.path.basename(script)

        _append_case_event(case_dir, "disk_analysis_start", run_id=run_id, meta={
            "disk_rel": disk_rel,
            "out_rel": out_rel,
            "script": script_name
        })

        yield emit(f"[SISTEMA] Starting TSK analysis run_id={run_id}")
        yield emit(f"[SISTEMA] disk={disk_rel}")
        yield emit(f"[SISTEMA] out_dir={out_rel}")
        yield emit(f"[START] {script_name} {disk_abs} -> {out_abs}")

        # Ejecuta script con salida en vivo
        p = subprocess.Popen(
            ["bash", script, case_dir, disk_abs, out_abs],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        for line in p.stdout:
            line = (line or "").rstrip("\n")
            if line.strip():
                last_line = line.strip()
            yield emit(line)

        p.wait()
        rc = p.returncode if p.returncode is not None else 1

        # Registrar artefacto si hay output
        if rc == 0 and os.path.isdir(out_abs):
            try:
                _register_dir_artifact(case_dir, out_rel, "tsk_output_dir")
            except Exception:
                pass

        _append_case_event(case_dir, "disk_analysis_done" if rc == 0 else "disk_analysis_failed", run_id=run_id, meta={
            "disk_rel": disk_rel,
            "out_rel": out_rel,
            "exit_code": rc,
            "elapsed_s": round(time.time() - start_ts, 3),
            "last": last_line
        })

        payload = {
            "result": "ok" if rc == 0 else "error",
            "exit_code": rc,
            "out_dir": out_rel if (rc == 0 and os.path.isdir(out_abs)) else None,
            "last": last_line,
            "disk": disk_rel,
            "run_id": run_id,
            "script": script_name
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")







@forensics_bp.route("/api/forensics/traffic/preserve/stream", methods=["GET"])
def api_forensics_traffic_preserve_stream():
    case_dir = (request.args.get("case_dir") or "").strip()
    run_id = (request.args.get("run_id") or "R1").strip() or "R1"

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    # Script: repo root
    script = os.path.join(REPO_ROOT, "nics_scenario_traffic_preserve_summary.sh")
    if not os.path.exists(script):
        # fallback
        script2 = os.path.join(FORENSICS_SCRIPTS_DIR, "nics_scenario_traffic_preserve_summary.sh")
        script = script2

    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    try:
        os.chmod(script, 0o755)
    except Exception:
        pass

    def sse():
        def emit(line: str):
            line = (line or "").rstrip("\n")
            return f"data: {line}\n\n"

        start_ts = time.time()
        script_name = os.path.basename(script)

        ensure_case_layout(case_dir)

        # Eventos M2: inicio captura/preservación (lo usamos como pcap_start)
        _append_case_event(case_dir, "pcap_start", run_id=run_id, meta={
            "script": script_name,
            "mode": "preserve_summary",
        })
        _append_case_event(case_dir, "traffic_preserve_start", run_id=run_id, meta={
            "script": script_name,
        })

        yield emit(f"[SISTEMA] Starting traffic preserve: case_dir={case_dir} run_id={run_id}")
        yield emit(f"[START] {script_name}")

        p = subprocess.Popen(
            ["bash", script],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        for line in p.stdout:
            line = (line or "").rstrip("\n")
            if line.strip():
                last_line = line.strip()
            yield emit(line)

        p.wait()
        rc = p.returncode if p.returncode is not None else 1

        # POST: indexar PCAP preservados dentro del CASE al manifest
        index_summary = {"count": 0, "total_bytes": 0, "added": 0, "already_present": 0}
        if rc == 0:
            try:
                index_summary = _index_preserved_pcaps_into_manifest(
                    case_dir,
                    preserve_rel_root="network/traffic_preserved/full_scenario_captures",
                    artifact_type="network_pcap",
                )
            except Exception as e:
                # si falla el indexado, lo reflejamos como warning pero no rompemos el preserve
                yield emit(f"[WARN] PCAP indexing failed: {e}")

        # Eventos M2: fin (lo usamos como pcap_preserved)
        _append_case_event(
            case_dir,
            "pcap_preserved" if (rc == 0) else "pcap_failed",
            run_id=run_id,
            meta={
                "script": script_name,
                "exit_code": rc,
                "elapsed_s": round(time.time() - start_ts, 3),
                "last": last_line,
                "pcaps_count": index_summary.get("count"),
                "pcaps_added": index_summary.get("added"),
                "pcaps_already_present": index_summary.get("already_present"),
                "pcaps_total_bytes": index_summary.get("total_bytes"),
            }
        )
        _append_case_event(
            case_dir,
            "traffic_preserve_done" if (rc == 0) else "traffic_preserve_failed",
            run_id=run_id,
            meta={
                "script": script_name,
                "exit_code": rc,
                "elapsed_s": round(time.time() - start_ts, 3),
                "last": last_line,
                "pcaps_count": index_summary.get("count"),
                "pcaps_total_bytes": index_summary.get("total_bytes"),
            }
        )

        payload = {
            "result": "ok" if rc == 0 else "error",
            "exit_code": rc,
            "last": last_line,
            "script": script_name,
            "run_id": run_id,
            "indexed": index_summary,
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")







def _list_case_memory_lime(case_dir: str):
    """
    Lista TODOS los memory dumps .lime dentro del caso:
      - Busca en <case_dir>/memory/*.lime
      - Cruza SHA con manifest si existe
      - Ordena por mtime (más reciente primero)
    """
    mem_dir = os.path.join(case_dir, "memory")
    out = []

    sha_by_rel = {}
    try:
        m = _read_manifest(case_dir)
        for a in (m.get("artifacts") or []):
            rel = a.get("rel_path")
            if not rel:
                continue
            # pillamos sha si es un dump real
            if a.get("type") == "memory_lime" or (str(rel).startswith("memory/") and str(rel).endswith(".lime")):
                sha_by_rel[str(rel)] = a.get("sha256")
    except Exception:
        pass

    if not os.path.isdir(mem_dir):
        return out

    for fn in os.listdir(mem_dir):
        if not fn.lower().endswith(".lime"):
            continue

        abs_p = os.path.join(mem_dir, fn)
        if not os.path.isfile(abs_p):
            continue

        rel = os.path.join("memory", fn)
        try:
            st = os.stat(abs_p)
            out.append({
                "rel_path": rel,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "sha256": sha_by_rel.get(rel)
            })
        except Exception:
            out.append({"rel_path": rel, "size": None, "mtime": 0, "sha256": sha_by_rel.get(rel)})

    out.sort(key=lambda x: x.get("mtime", 0), reverse=True)
    return out



@forensics_bp.route("/api/forensics/case/memory/list", methods=["GET"])
def api_forensics_case_memory_list():
    case_dir = (request.args.get("case_dir") or "").strip()
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    try:
        dumps = _list_case_memory_lime(case_dir)
        return jsonify({"case_dir": case_dir, "dumps": dumps}), 200
    except Exception as e:
        logger.error(f"Error /api/forensics/case/memory/list: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500




def _index_preserved_pcaps_into_manifest(
    case_dir: str,
    preserve_rel_root: str = "network/traffic_preserved/full_scenario_captures",
    artifact_type: str = "network_pcap",
) -> dict:
    """
    Indexa TODOS los *.pcap bajo:
      CASE/.../<preserve_rel_root>/**
    y los registra en manifest.json como artifacts con:
      type=artifact_type, rel_path, sha256, size, ts
    Devuelve resumen: {count, total_bytes, added, already_present}
    """
    ensure_case_layout(case_dir)

    preserve_abs_root = os.path.join(case_dir, preserve_rel_root)
    if not os.path.isdir(preserve_abs_root):
        return {"count": 0, "total_bytes": 0, "added": 0, "already_present": 0}

    manifest = _read_manifest(case_dir)
    artifacts = manifest.setdefault("artifacts", [])

    existing = set()
    for a in artifacts:
        rp = str(a.get("rel_path") or "")
        if rp:
            existing.add(rp)

    added = 0
    already = 0
    total_bytes = 0
    count = 0

    for root, _, files in os.walk(preserve_abs_root):
        for fn in files:
            if not fn.endswith(".pcap"):
                continue

            abs_p = os.path.join(root, fn)
            rel_p = os.path.relpath(abs_p, case_dir).replace("\\", "/")

            try:
                sz = os.path.getsize(abs_p)
            except Exception:
                sz = None

            # dedup por rel_path
            if rel_p in existing:
                already += 1
                # aun así contamos sizes para resumen
                if isinstance(sz, int):
                    total_bytes += sz
                    count += 1
                continue

            try:
                sha = _sha256_file(abs_p)
            except Exception:
                sha = None

            artifacts.append({
                "type": artifact_type,
                "rel_path": rel_p,
                "sha256": sha,
                "size": sz,
                "ts": _utc_now_iso(),
            })
            existing.add(rel_p)

            added += 1
            if isinstance(sz, int):
                total_bytes += sz
            count += 1

    _write_manifest(case_dir, manifest)

    return {
        "count": count,
        "total_bytes": total_bytes,
        "added": added,
        "already_present": already,
    }






    # ============================================================
# CHAIN OF CUSTODY (append-only + hash chaining)
# ============================================================

def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")  # JSONL append-only

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _read_last_custody_hash(case_dir: str) -> str:
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        return "0" * 64

    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size <= 0:
                return "0" * 64

            back = min(8192, size)
            f.seek(-back, os.SEEK_END)
            tail = f.read().decode("utf-8", errors="ignore")

        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return "0" * 64

        last = json.loads(lines[-1])
        h = (last.get("entry_hash") or "").strip()
        return h if h else "0" * 64
    except Exception:
        return "0" * 64

def _ensure_custody_file(case_dir: str) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        try:
            Path(p).touch()
        except Exception:
            pass

def _append_custody_entry(
    case_dir: str,
    action: str,
    actor: str,
    run_id: str = "R1",
    artifact_rel: str = None,
    outcome: str = "ok",
    details: dict = None,
) -> None:
    if not _is_safe_case_dir(case_dir):
        return

    ensure_case_layout(case_dir)
    _ensure_custody_file(case_dir)

    prev_hash = _read_last_custody_hash(case_dir)
    ts = _utc_now_iso()

    entry = {
        "ts_utc": ts,
        "ts_epoch": iso_to_epoch(ts),
        "run_id": (run_id or "R1"),
        "actor": actor,
        "action": action,
        "artifact_rel": artifact_rel,
        "outcome": outcome,
        "details": (details or {}),
        "prev_hash": prev_hash,
    }

    payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    entry_hash = _sha256_hex(payload)
    entry["entry_hash"] = entry_hash

    with open(_custody_path(case_dir), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def _register_custody_artifact(case_dir: str) -> None:
    """
    Registra chain_of_custody.log en manifest (sha/size).
    """
    rel = "chain_of_custody.log"
    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return

    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None

    _add_artifact_fast(case_dir, rel, "custody_log", sha256=sha, size=size)









