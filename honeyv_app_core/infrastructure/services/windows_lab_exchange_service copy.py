from __future__ import annotations

import hashlib
import json
import posixpath
import stat
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko
from werkzeug.utils import secure_filename


@dataclass
class ExchangeConfig:
    workspace: Path
    allowed_roots: list[Path]
    windows_host: str
    windows_port: int
    windows_user: str
    windows_password: str
    windows_remote_dir: str
    ssh_timeout: int = 15


class WindowsLabExchangeService:
    def __init__(self, config: ExchangeConfig) -> None:
        self.config = config
        self.workspace = config.workspace.resolve()
        self.uploads_dir = self.workspace / "uploads"
        self.archives_dir = self.workspace / "archives"
        self.manifests_dir = self.workspace / "manifests"

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.archives_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def get_roots(self) -> list[str]:
        return [str(root) for root in self.config.allowed_roots]

    def list_directory(self, requested_path: str) -> dict[str, Any]:
        safe_path = self._resolve_allowed_path(requested_path)

        if not safe_path.exists():
            raise FileNotFoundError(f"Path does not exist: {safe_path}")

        if not safe_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {safe_path}")

        entries: list[dict[str, Any]] = []

        for entry in sorted(safe_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                entry_stat = entry.stat()
                entries.append(
                    {
                        "name": entry.name,
                        "path": str(entry),
                        "is_dir": entry.is_dir(),
                        "size": entry_stat.st_size if entry.is_file() else None,
                        "modified_utc": datetime.fromtimestamp(
                            entry_stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                )
            except OSError:
                continue

        parent_path = safe_path.parent if safe_path.parent != safe_path else safe_path

        return {
            "current_path": str(safe_path),
            "parent_path": str(parent_path),
            "entries": entries,
            "allowed_roots": self.get_roots(),
        }

    def save_uploaded_file(self, file_storage) -> dict[str, Any]:
        original_name = file_storage.filename or "upload.bin"
        safe_name = secure_filename(original_name)

        if not safe_name:
            safe_name = f"upload_{uuid.uuid4().hex}.bin"

        final_name = f"{self._utc_compact()}_{uuid.uuid4().hex[:8]}_{safe_name}"
        destination = self.uploads_dir / final_name
        file_storage.save(destination)

        metadata = self._build_file_metadata(destination, original_name=original_name)

        self._write_manifest(
            {
                "event": "upload_file",
                "uploaded_at_utc": datetime.now(timezone.utc).isoformat(),
                "original_name": original_name,
                "stored_name": destination.name,
                "path": str(destination),
                "size": metadata["size"],
                "sha256": metadata["sha256"],
            }
        )

        return metadata

    def create_zip_from_paths(self, selected_paths: list[str], zip_name: str | None = None) -> dict[str, Any]:
        if not selected_paths:
            raise ValueError("No paths were selected")

        resolved_paths = [self._resolve_allowed_path(path) for path in selected_paths]

        for path in resolved_paths:
            if not path.exists():
                raise FileNotFoundError(f"Path does not exist: {path}")

        safe_zip_name = secure_filename(zip_name or "")
        if safe_zip_name:
            if not safe_zip_name.lower().endswith(".zip"):
                safe_zip_name += ".zip"
            final_zip_name = f"{self._utc_compact()}_{safe_zip_name}"
        else:
            final_zip_name = f"{self._utc_compact()}_{uuid.uuid4().hex[:8]}_bundle.zip"

        zip_path = self.archives_dir / final_zip_name

        with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in resolved_paths:
                self._add_path_to_zip(zf, path)

        metadata = self._build_file_metadata(zip_path, original_name=final_zip_name)

        self._write_manifest(
            {
                "event": "create_zip",
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "zip_path": str(zip_path),
                "zip_name": zip_path.name,
                "source_paths": [str(path) for path in resolved_paths],
                "size": metadata["size"],
                "sha256": metadata["sha256"],
            }
        )

        return metadata

    def send_file_to_windows(self, local_file_path: str) -> dict[str, Any]:
        local_path = Path(local_file_path).expanduser().resolve()
        allowed_send_roots = [self.workspace] + self.config.allowed_roots

        if not any(self._is_relative_to(local_path, root.resolve()) for root in allowed_send_roots):
            raise PermissionError(f"Local file not allowed for transfer: {local_path}")

        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        if not local_path.is_file():
            raise ValueError(f"Path is not a file: {local_path}")

        if not self.config.windows_host:
            raise ValueError("WINDOWS_LAB_HOST is not configured")

        if not self.config.windows_user:
            raise ValueError("WINDOWS_LAB_USER is not configured")

        remote_dir = self.config.windows_remote_dir.replace("\\", "/")
        remote_filename = local_path.name
        remote_path = posixpath.join(remote_dir, remote_filename)

        transport = None
        sftp = None

        try:
            transport = paramiko.Transport((self.config.windows_host, self.config.windows_port))
            transport.banner_timeout = self.config.ssh_timeout
            transport.connect(
                username=self.config.windows_user,
                password=self.config.windows_password,
            )
            sftp = paramiko.SFTPClient.from_transport(transport)

            self._ensure_remote_dir_exists(sftp, remote_dir)
            sftp.put(str(local_path), remote_path)

        finally:
            if sftp is not None:
                sftp.close()
            if transport is not None:
                transport.close()

        metadata = self._build_file_metadata(local_path, original_name=local_path.name)

        self._write_manifest(
            {
                "event": "send_file_to_windows",
                "sent_at_utc": datetime.now(timezone.utc).isoformat(),
                "local_path": str(local_path),
                "remote_path": remote_path,
                "windows_host": self.config.windows_host,
                "windows_port": self.config.windows_port,
                "windows_user": self.config.windows_user,
                "size": metadata["size"],
                "sha256": metadata["sha256"],
            }
        )

        return {
            "status": "sent",
            "local_path": str(local_path),
            "remote_path": remote_path,
            "sha256": metadata["sha256"],
            "size": metadata["size"],
        }

    def _resolve_allowed_path(self, requested_path: str) -> Path:
        if not requested_path:
            raise ValueError("requested_path is required")

        candidate = Path(requested_path).expanduser().resolve()

        for root in self.config.allowed_roots:
            if self._is_relative_to(candidate, root.resolve()):
                return candidate

        raise PermissionError(f"Path outside allowed roots: {candidate}")

    def _build_file_metadata(self, path: Path, original_name: str) -> dict[str, Any]:
        stat_info = path.stat()
        return {
            "original_name": original_name,
            "stored_name": path.name,
            "path": str(path),
            "size": stat_info.st_size,
            "sha256": self._sha256(path),
            "created_utc": datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc).isoformat(),
        }

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _add_path_to_zip(self, zf: zipfile.ZipFile, source_path: Path) -> None:
        source_path = source_path.resolve()

        if source_path.is_file():
            zf.write(source_path, arcname=self._safe_arcname(source_path))
            return

        if source_path.is_dir():
            for item in source_path.rglob("*"):
                if item.is_file():
                    zf.write(item, arcname=self._safe_arcname(item))

    def _safe_arcname(self, path: Path) -> str:
        path = path.resolve()

        for root in self.config.allowed_roots + [self.workspace]:
            root_resolved = root.resolve()
            if self._is_relative_to(path, root_resolved):
                return str(path.relative_to(root_resolved))

        return path.name

    def _write_manifest(self, content: dict[str, Any]) -> None:
        manifest_name = f"{self._utc_compact()}_{uuid.uuid4().hex[:8]}.json"
        manifest_path = self.manifests_dir / manifest_name
        manifest_path.write_text(
            json.dumps(content, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _utc_compact(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def _ensure_remote_dir_exists(self, sftp: paramiko.SFTPClient, remote_dir: str) -> None:
        parts = remote_dir.replace("\\", "/").split("/")
        current = ""

        for part in parts:
            if not part:
                continue

            current = f"{current}/{part}" if current else part

            try:
                attrs = sftp.stat(current)
                if not stat.S_ISDIR(attrs.st_mode):
                    raise NotADirectoryError(f"Remote path exists but is not a directory: {current}")
            except FileNotFoundError:
                sftp.mkdir(current)

    @staticmethod
    def _is_relative_to(path: Path, base: Path) -> bool:
        try:
            path.relative_to(base)
            return True
        except ValueError:
            return False