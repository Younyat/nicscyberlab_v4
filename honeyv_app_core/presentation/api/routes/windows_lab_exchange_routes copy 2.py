from __future__ import annotations

import os
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from honeyv_app_core.infrastructure.services.windows_lab_exchange_service import (
    ExchangeConfig,
    WindowsLabExchangeService,
)

windows_lab_exchange_bp = Blueprint(
    "windows_lab_exchange",
    __name__,
    url_prefix="/api/windows-lab-exchange",
)


def _build_service() -> WindowsLabExchangeService:
    workspace = Path(
        os.getenv(
            "WINDOWS_EXCHANGE_WORKSPACE",
            "/tmp/nics_windows_lab_exchange",
        )
    ).expanduser().resolve()

    raw_roots = os.getenv(
        "WINDOWS_EXCHANGE_ALLOWED_ROOTS",
        "/home,/tmp",
    ).split(",")

    allowed_roots = [
        Path(item.strip()).expanduser().resolve()
        for item in raw_roots
        if item.strip()
    ]

    config = ExchangeConfig(
        workspace=workspace,
        allowed_roots=allowed_roots,
        windows_host=os.getenv("WINDOWS_LAB_HOST", "").strip(),
        windows_port=int(os.getenv("WINDOWS_LAB_PORT", "22")),
        windows_user=os.getenv("WINDOWS_LAB_USER", "").strip(),
        windows_password=os.getenv("WINDOWS_LAB_PASSWORD", ""),
        windows_remote_dir=os.getenv(
            "WINDOWS_LAB_REMOTE_DIR",
            "C:/NICS_Windows_Lab/incoming",
        ),
        ssh_timeout=int(os.getenv("WINDOWS_LAB_SSH_TIMEOUT", "15")),
        ssh_auth_type=os.getenv("WINDOWS_LAB_AUTH_TYPE", "password").strip().lower(),
        ssh_key_path=os.getenv("WINDOWS_LAB_KEY_PATH", "").strip(),
        ssh_key_passphrase=os.getenv("WINDOWS_LAB_KEY_PASSPHRASE", ""),
    )
    return WindowsLabExchangeService(config)


@windows_lab_exchange_bp.get("/health")
def health():
    return jsonify({"ok": True, "status": "online"}), 200


@windows_lab_exchange_bp.get("/bootstrap")
def bootstrap():
    service = _build_service()
    roots = service.get_roots()
    initial_path = roots[0] if roots else "/tmp"

    return jsonify({
        "ok": True,
        "data": {
            "allowed_roots": roots,
            "initial_path": initial_path,
        }
    }), 200


@windows_lab_exchange_bp.post("/api/list")
def list_directory():
    try:
        payload = request.get_json(force=True) or {}
        requested_path = payload.get("path", "")
        data = _build_service().list_directory(requested_path)
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange list_directory failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/upload")
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "No file part"}), 400

        file_storage = request.files["file"]

        if not file_storage or not file_storage.filename:
            return jsonify({"ok": False, "error": "Empty file"}), 400

        metadata = _build_service().save_uploaded_file(file_storage)
        return jsonify({"ok": True, "data": metadata}), 200

    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange upload_file failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/zip")
def create_zip():
    try:
        payload = request.get_json(force=True) or {}
        selected_paths = payload.get("paths", [])
        zip_name = payload.get("zip_name")
        metadata = _build_service().create_zip_from_paths(
            selected_paths,
            zip_name=zip_name,
        )
        return jsonify({"ok": True, "data": metadata}), 200

    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange create_zip failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/send")
def send_to_windows():
    try:
        payload = request.get_json(force=True) or {}
        local_file_path = payload.get("path", "")
        result = _build_service().send_file_to_windows(local_file_path)
        return jsonify({"ok": True, "data": result}), 200

    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange send_to_windows failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.get("/api/ssh/config")
def get_ssh_config():
    try:
        data = _build_service().get_current_target_config()
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange get_ssh_config failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/ssh/config")
def set_ssh_config():
    try:
        payload = request.get_json(force=True) or {}
        data = _build_service().update_target_config(payload)
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange set_ssh_config failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/ssh/test")
def test_ssh():
    try:
        data = _build_service().test_ssh_connection()
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange test_ssh failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/ssh/verify-remote-file")
def verify_remote_file():
    try:
        payload = request.get_json(force=True) or {}
        remote_path = payload.get("remote_path", "")
        data = _build_service().verify_remote_file(remote_path)
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange verify_remote_file failed")
        return jsonify({"ok": False, "error": str(exc)}), 400


@windows_lab_exchange_bp.post("/api/ssh/exec")
def execute_remote():
    try:
        payload = request.get_json(force=True) or {}
        exec_type = payload.get("exec_type", "command")
        command = payload.get("command", "")
        cwd = payload.get("cwd", "")
        timeout = int(payload.get("timeout", 120))
        post_check = payload.get("post_check", "none")
        target_file = payload.get("target_file", "")

        data = _build_service().execute_remote(
            exec_type=exec_type,
            command=command,
            cwd=cwd,
            timeout=timeout,
            post_check=post_check,
            target_file=target_file,
        )
        return jsonify({"ok": True, "data": data}), 200
    except Exception as exc:
        current_app.logger.exception("windows_lab_exchange execute_remote failed")
        return jsonify({"ok": False, "error": str(exc)}), 400