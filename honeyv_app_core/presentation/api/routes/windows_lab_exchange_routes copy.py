from __future__ import annotations

import os
from pathlib import Path

from flask import Blueprint, current_app, jsonify, render_template, request

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






