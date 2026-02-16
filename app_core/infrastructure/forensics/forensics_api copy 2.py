import os
import re
import json
import time
import hashlib
import logging
import threading
import subprocess
from datetime import datetime

from flask import Blueprint, request, jsonify, Response, send_from_directory
import openstack

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

    manifest = {
        "case_dir": case_dir,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifacts": []
    }
    _write_manifest(case_dir, manifest)
    return jsonify({"case_dir": case_dir}), 200

@forensics_bp.route("/api/forensics/case/manifest", methods=["GET"])
def api_forensics_case_manifest():
    case_dir = request.args.get("case_dir", "")
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
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

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id:
        return jsonify({"error": "vm_id requerido"}), 400

    # Esperado: tú pones este script (o lo ajustas a tu realidad)
    # Debe escribir dentro de case_dir (recomendado: disk/<vm_id>.raw)
    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")

    rc, out, err = _run_script(script, [case_dir, vm_id, container_name], cwd=REPO_ROOT, timeout=60 * 60)

    # Intento: si el script generó un RAW típico, lo registramos
    # Convención mínima: disk/<vm_id>.raw
    rel_guess = os.path.join("disk", f"{vm_id}.raw")
    abs_guess = os.path.join(case_dir, rel_guess)
    if os.path.exists(abs_guess):
        _add_artifact(case_dir, rel_guess, "disk_raw")

    return jsonify({
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "disk_raw": rel_guess if os.path.exists(abs_guess) else None
    }), 200 if rc == 0 else 500




@forensics_bp.route("/api/forensics/acquire/disk_kolla/stream", methods=["GET"])
def api_forensics_acquire_disk_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    container_name = request.args.get("container_name", "nova_libvirt")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id:
        return jsonify({"error": "vm_id requerido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")
    return _run_script_sse(script, [case_dir, vm_id, container_name], cwd=REPO_ROOT, timeout=60 * 60)






@forensics_bp.route("/api/forensics/acquire/memory_lime", methods=["POST"])
def api_forensics_acquire_memory():
    data = request.get_json(force=True, silent=True) or {}
    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    vm_ip = data.get("vm_ip")
    ssh_user = data.get("ssh_user", "debian")
    ssh_key = data.get("ssh_key", "")
    mode = data.get("mode", "build")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido (path en el servidor)"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_memory_lime_ssh.sh")

    def _run_for_user(user: str):
        return _run_script(
            script,
            [case_dir, vm_id, vm_ip, user, ssh_key, mode],
            cwd=REPO_ROOT,
            timeout=60 * 60
        )

    # 1) Intento con el usuario recibido
    attempted_users = [ssh_user] if ssh_user else []
    rc, out, err = _run_for_user(ssh_user)

    # 2) Si falla por auth, reintentar con usuarios típicos (ubuntu/debian)
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

    # 3) Extraer ruta absoluta del dump (última línea del stdout) SOLO si rc==0
    produced_abs = ""
    mem_rel = None

    if rc == 0:
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
            except Exception:
                mem_rel = None

            # Safety anti-traversal
            if mem_rel and (mem_rel.startswith("..") or os.path.isabs(mem_rel)):
                mem_rel = None

        if mem_rel:
            _add_artifact(case_dir, mem_rel, "memory_lime")

    return jsonify({
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "mem_dump": mem_rel,
        "ssh_user_used": ssh_user,
        "attempted_users": attempted_users
    }), 200 if rc == 0 else 500


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

    # Esperado: tú pones este script (o lo ajustas)
    # Debe escribir dentro de case_dir (recomendado: analysis/vol3/<vm_id>/...)
    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_memory_vol3.sh")

    rc, out, err = _run_script(script, [case_dir, dump_path, symbols_dir, vol_cmd], cwd=REPO_ROOT, timeout=60 * 60)

    # Convención mínima: analysis/vol3/<vm_id>/
    rel_out = os.path.join("analysis", "vol3", vm_id)
    abs_out = os.path.join(case_dir, rel_out)
    if os.path.isdir(abs_out):
        # Registramos como artifact "dir" (sha None)
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
        "out_dir": rel_out if os.path.isdir(abs_out) else None
    }), 200 if rc == 0 else 500



@forensics_bp.route("/api/forensics/acquire/memory_lime/stream", methods=["GET"])
def api_forensics_acquire_memory_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    vm_ip = request.args.get("vm_ip", "")
    ssh_user = request.args.get("ssh_user", "debian")
    ssh_key = request.args.get("ssh_key", "")
    mode = request.args.get("mode", "build")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_memory_lime_ssh.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    # Reutiliza tu lógica robusta de usuario (ubuntu/debian) pero en streaming:
    candidates = [ssh_user] + [u for u in ["ubuntu", "debian"] if u != ssh_user]

    def sse():
        def emit(line: str):
            line = (line or "").rstrip("\n")
            return f"data: {line}\n\n"

        # Cabecera
        yield emit(f"[SISTEMA] Starting memory acquisition (LiME) vm_id={vm_id} ip={vm_ip} user={ssh_user} mode={mode}")

        last_stdout_line = ""
        used_user = None
        final_rc = 1
        final_out = ""
        final_err = ""

        for user in candidates:
            used_user = user
            yield emit(f"[SISTEMA] Trying ssh_user={user}")

            # Nota: stdbuf ayuda a line-buffering para ver progreso en vivo
            cmd = ["bash", "-lc", f"stdbuf -oL -eL bash '{script}' '{case_dir}' '{vm_id}' '{vm_ip}' '{user}' '{ssh_key}' '{mode}'"]
            proc = subprocess.Popen(
                cmd,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Stream en vivo
            lines = []
            for line in proc.stdout:
                lines.append(line)
                last_stdout_line = line.strip()
                yield emit(line.rstrip("\n"))

            proc.wait()
            final_rc = proc.returncode
            final_out = "".join(lines)
            final_err = ""  # stderr va junto con stdout (STDOUT)

            # Si éxito -> parar
            if final_rc == 0:
                break

            # Si fallo por permisos, probar siguiente
            if "Permission denied" in final_out or "Permission denied" in (final_err or ""):
                yield emit("[SISTEMA] Auth failed, retrying with next user...")
                continue

            # Fallo no-auth: no tiene sentido reintentar usuarios
            break

        mem_rel = None
        if final_rc == 0 and last_stdout_line and os.path.isabs(last_stdout_line) and os.path.exists(last_stdout_line):
            try:
                mem_rel = os.path.relpath(last_stdout_line, case_dir)
                if mem_rel.startswith("..") or os.path.isabs(mem_rel):
                    mem_rel = None
            except Exception:
                mem_rel = None

            if mem_rel:
                _add_artifact(case_dir, mem_rel, "memory_lime")

        # Evento final (JSON) para que la UI sepa qué pasó y qué archivo bajar/mostrar
        payload = {
            "result": "ok" if final_rc == 0 else "error",
            "exit_code": final_rc,
            "mem_dump": mem_rel,
            "ssh_user_used": used_user,
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")




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




