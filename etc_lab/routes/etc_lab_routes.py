import json
import logging
import os
import signal
import subprocess
import threading
import time
from datetime import datetime

from flask import Blueprint, jsonify, request, Response, send_from_directory

logger = logging.getLogger("app_logger")

etc_lab_bp = Blueprint("etc_lab", __name__)

# ============================================================
# PATHS
# ============================================================

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
ETC_PACKAGE_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(ETC_PACKAGE_ROOT, ".."))

APP_CORE_STATIC_DIR = os.path.join(PROJECT_ROOT, "app_core", "static")

ETC_MODULE_DIR = ETC_PACKAGE_ROOT
ETC_STATE_DIR = os.path.join(ETC_MODULE_DIR, "state")
ETC_LOG_DIR = os.path.join(ETC_MODULE_DIR, "logs")
ETC_LOCAL_BASE_DIR = os.path.join(ETC_MODULE_DIR, "runtime")

os.makedirs(ETC_STATE_DIR, exist_ok=True)
os.makedirs(ETC_LOG_DIR, exist_ok=True)
os.makedirs(ETC_LOCAL_BASE_DIR, exist_ok=True)

ETC_INSTALL_SCRIPT = os.path.join(ETC_MODULE_DIR, "setup_packet_level_etc.sh")
ETC_STATE_FILE = os.path.join(ETC_STATE_DIR, "etc_module_state.json")
ETC_PID_FILE = os.path.join(ETC_STATE_DIR, "etc_dash.pid")
ETC_INSTALL_LOG = os.path.join(ETC_LOG_DIR, "etc_install.log")
ETC_DASH_LOG = os.path.join(ETC_LOG_DIR, "etc_dash.log")

ETC_DEFAULT_STATE = {
    "module": "etc_lab",
    "installed": False,
    "installing": False,
    "model_ready": False,
    "running": False,
    "last_install_at": None,
    "last_start_at": None,
    "repo_dir": None,
    "pcap_dir": None,
    "dashboard_url": "http://127.0.0.1:8050/",
    "dataset_name": "nics_etc",
    "model_name": "randomforest",
    "message": "ETC module not installed"
}

# ============================================================
# HELPERS
# ============================================================

def etc_read_state():
    if not os.path.exists(ETC_STATE_FILE):
        with open(ETC_STATE_FILE, "w") as f:
            json.dump(ETC_DEFAULT_STATE, f, indent=4)
        return dict(ETC_DEFAULT_STATE)

    try:
        with open(ETC_STATE_FILE, "r") as f:
            data = json.load(f)
        merged = dict(ETC_DEFAULT_STATE)
        merged.update(data)
        return merged
    except Exception:
        return dict(ETC_DEFAULT_STATE)


def etc_write_state(patch: dict):
    state = etc_read_state()
    state.update(patch)
    with open(ETC_STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)
    return state


def etc_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def etc_get_repo_dir():
    state = etc_read_state()
    if state.get("repo_dir"):
        return state["repo_dir"]
    return os.path.join(ETC_LOCAL_BASE_DIR, "packet-level-etc")


def etc_get_pcap_dir():
    return os.path.join(etc_get_repo_dir(), "pcaps")


def etc_get_venv_python():
    repo_dir = etc_get_repo_dir()
    return os.path.join(repo_dir, ".venv", "bin", "python")


def etc_get_dash_app():
    repo_dir = etc_get_repo_dir()
    return os.path.join(repo_dir, "dash_app.py")


def etc_get_model_paths():
    state = etc_read_state()
    repo_dir = etc_get_repo_dir()
    dataset = state.get("dataset_name", "nics_etc")
    model_name = state.get("model_name", "randomforest")

    return {
        "model": os.path.join(repo_dir, "models", f"{model_name}_{dataset}_N100_BIT8.joblib"),
        "scaler": os.path.join(repo_dir, "models", f"scaler_{dataset}_N100_BIT8.joblib"),
        "encoder": os.path.join(repo_dir, "models", f"le_{dataset}_N100_BIT8.joblib"),
        "config": os.path.join(repo_dir, "models", f"{model_name}_{dataset}_N100_BIT8.json"),
    }


def etc_detect_installation():
    repo_dir = etc_get_repo_dir()
    python_bin = etc_get_venv_python()
    dash_file = etc_get_dash_app()
    model_paths = etc_get_model_paths()

    installed = (
        os.path.isdir(repo_dir)
        and os.path.exists(python_bin)
        and os.path.exists(dash_file)
    )

    model_ready = (
        os.path.exists(model_paths["model"])
        and os.path.exists(model_paths["scaler"])
        and os.path.exists(model_paths["encoder"])
        and os.path.exists(model_paths["config"])
    )

    return {
        "repo_dir": repo_dir,
        "python_bin": python_bin,
        "dash_app": dash_file,
        "artifacts": model_paths,
        "installed": installed,
        "model_ready": model_ready
    }


def etc_detect_running():
    if not os.path.exists(ETC_PID_FILE):
        return False, None

    try:
        with open(ETC_PID_FILE, "r") as f:
            pid = int(f.read().strip())
    except Exception:
        return False, None

    if etc_pid_running(pid):
        return True, pid

    try:
        os.remove(ETC_PID_FILE)
    except Exception:
        pass

    return False, None


# ============================================================
# FRONTEND
# ============================================================

@etc_lab_bp.route("/etc/frontend", methods=["GET"])
def api_etc_frontend():
    file_path = os.path.join(APP_CORE_STATIC_DIR, "etc_lab.html")

    if not os.path.exists(file_path):
        logger.error(f"etc_lab.html not found in: {file_path}")
        return jsonify({
            "status": "error",
            "message": f"Frontend not found: {file_path}"
        }), 404

    return send_from_directory(APP_CORE_STATIC_DIR, "etc_lab.html")


# ============================================================
# STATUS
# ============================================================

@etc_lab_bp.route("/etc/status", methods=["GET"])
def api_etc_status():
    try:
        state = etc_read_state()
        installation = etc_detect_installation()
        running, pid = etc_detect_running()

        state["installed"] = installation["installed"]
        state["model_ready"] = installation["model_ready"]
        state["repo_dir"] = installation["repo_dir"]
        state["pcap_dir"] = etc_get_pcap_dir()
        state["running"] = running
        state["pid"] = pid
        state["artifacts"] = installation["artifacts"]

        if running:
            state["message"] = "ETC dashboard running"
        elif installation["model_ready"]:
            state["message"] = "ETC module ready"
        elif installation["installed"]:
            state["message"] = "ETC module installed but model is not ready"
        elif state.get("installing"):
            state["message"] = "ETC module installing"
        else:
            state["message"] = "ETC module not installed"

        etc_write_state(state)
        return jsonify(state), 200

    except Exception as e:
        logger.error(f"Error in /etc/status: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================================
# INSTALL
# ============================================================

@etc_lab_bp.route("/etc/install", methods=["POST"])
def api_etc_install():
    try:
        data = request.get_json(silent=True) or {}

        repo_url = data.get("repo_url", "https://github.com/nicslabdev/packet-level-etc.git")
        base_dir = data.get("base_dir", ETC_LOCAL_BASE_DIR)
        capture_iface = data.get("capture_iface", "")
        capture_seconds = str(data.get("capture_seconds", 60))
        dataset_name = data.get("dataset_name", "nics_etc")
        model_name = data.get("model_name", "randomforest")

        os.makedirs(base_dir, exist_ok=True)

        if not os.path.exists(ETC_INSTALL_SCRIPT):
            return jsonify({
                "status": "error",
                "message": f"Install script not found: {ETC_INSTALL_SCRIPT}"
            }), 404

        state = etc_read_state()
        if state.get("installing"):
            return jsonify({
                "status": "blocked",
                "message": "ETC installation is already running"
            }), 409

        etc_write_state({
            "installing": True,
            "installed": False,
            "model_ready": False,
            "running": False,
            "repo_dir": os.path.join(base_dir, "packet-level-etc"),
            "pcap_dir": os.path.join(base_dir, "packet-level-etc", "pcaps"),
            "dataset_name": dataset_name,
            "model_name": model_name,
            "message": "ETC installation started"
        })

        def worker():
            env = os.environ.copy()
            env["REPO_URL"] = repo_url
            env["BASE_DIR"] = base_dir
            env["DATASET_NAME"] = dataset_name
            env["MODEL_NAME"] = model_name
            env["LAUNCH_DASH"] = "0"

            if capture_iface:
                env["CAPTURE_IFACE"] = capture_iface
                env["CAPTURE_SECONDS"] = capture_seconds

            rc = -1
            try:
                with open(ETC_INSTALL_LOG, "w") as logf:
                    proc = subprocess.Popen(
                        ["bash", ETC_INSTALL_SCRIPT],
                        cwd=ETC_MODULE_DIR,
                        stdout=logf,
                        stderr=subprocess.STDOUT,
                        text=True,
                        env=env
                    )
                    rc = proc.wait()
            except Exception as e:
                logger.error(f"ETC install worker failed: {e}", exc_info=True)

            installation = etc_detect_installation()

            etc_write_state({
                "installing": False,
                "installed": installation["installed"],
                "model_ready": installation["model_ready"],
                "repo_dir": installation["repo_dir"],
                "pcap_dir": os.path.join(installation["repo_dir"], "pcaps"),
                "last_install_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": "ETC installation finished correctly" if rc == 0 else "ETC installation finished with pending data pipeline steps"
            })

        threading.Thread(target=worker, daemon=True).start()

        return jsonify({
            "status": "running",
            "message": "ETC installation started"
        }), 202

    except Exception as e:
        logger.error(f"Error in /etc/install: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@etc_lab_bp.route("/etc/install/log", methods=["GET"])
def api_etc_install_log():
    def generate():
        last_size = 0

        while True:
            state = etc_read_state()

            if os.path.exists(ETC_INSTALL_LOG):
                with open(ETC_INSTALL_LOG, "r") as f:
                    f.seek(last_size)
                    chunk = f.read()
                    last_size = f.tell()

                    if chunk:
                        for line in chunk.splitlines():
                            yield f"data: {line}\n\n"

            if not state.get("installing"):
                yield "event: done\ndata: ETC installation stream finished\n\n"
                break

            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream")


# ============================================================
# START DASH
# ============================================================

@etc_lab_bp.route("/etc/start", methods=["POST"])
def api_etc_start():
    try:
        installation = etc_detect_installation()

        if not installation["installed"]:
            return jsonify({
                "status": "error",
                "message": "ETC module base environment is not installed"
            }), 409

        if not installation["model_ready"]:
            return jsonify({
                "status": "error",
                "message": "ETC module is installed, but the model is not ready yet. Add PCAP files to the repo pcaps directory and run extraction and training first."
            }), 409

        running, pid = etc_detect_running()
        if running:
            return jsonify({
                "status": "success",
                "message": "ETC dashboard already running",
                "pid": pid,
                "url": "http://127.0.0.1:8050/"
            }), 200

        python_bin = installation["python_bin"]
        dash_app = installation["dash_app"]

        if not os.path.exists(python_bin):
            return jsonify({
                "status": "error",
                "message": f"Python not found: {python_bin}"
            }), 500

        if not os.path.exists(dash_app):
            return jsonify({
                "status": "error",
                "message": f"dash_app.py not found: {dash_app}"
            }), 500

        logf = open(ETC_DASH_LOG, "a")

        proc = subprocess.Popen(
            [python_bin, dash_app],
            cwd=installation["repo_dir"],
            stdout=logf,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid
        )

        with open(ETC_PID_FILE, "w") as f:
            f.write(str(proc.pid))

        etc_write_state({
            "running": True,
            "last_start_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": "ETC dashboard started"
        })

        return jsonify({
            "status": "success",
            "message": "ETC dashboard started",
            "pid": proc.pid,
            "url": "http://127.0.0.1:8050/"
        }), 200

    except Exception as e:
        logger.error(f"Error in /etc/start: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================================
# STOP DASH
# ============================================================

@etc_lab_bp.route("/etc/stop", methods=["POST"])
def api_etc_stop():
    try:
        running, pid = etc_detect_running()
        if not running or not pid:
            return jsonify({
                "status": "success",
                "message": "ETC dashboard already stopped"
            }), 200

        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass

        try:
            os.remove(ETC_PID_FILE)
        except Exception:
            pass

        etc_write_state({
            "running": False,
            "message": "ETC dashboard stopped"
        })

        return jsonify({
            "status": "success",
            "message": "ETC dashboard stopped"
        }), 200

    except Exception as e:
        logger.error(f"Error in /etc/stop: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================================
# DASH LOG
# ============================================================

@etc_lab_bp.route("/etc/dash/log", methods=["GET"])
def api_etc_dash_log():
    try:
        if not os.path.exists(ETC_DASH_LOG):
            return jsonify({"log": ""}), 200

        with open(ETC_DASH_LOG, "r") as f:
            content = f.read()

        return jsonify({"log": content}), 200

    except Exception as e:
        logger.error(f"Error in /etc/dash/log: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500