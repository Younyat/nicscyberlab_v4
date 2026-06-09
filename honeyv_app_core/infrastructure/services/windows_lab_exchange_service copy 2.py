from __future__ import annotations

import hashlib
import json
import posixpath
import socket
import stat
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import base64
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
    ssh_auth_type: str = "password"
    ssh_key_path: str = ""
    ssh_key_passphrase: str = ""


class WindowsLabExchangeService:
    def __init__(self, config: ExchangeConfig) -> None:
        self.config = config
        self.workspace = config.workspace.resolve()
        self.uploads_dir = self.workspace / "uploads"
        self.archives_dir = self.workspace / "archives"
        self.manifests_dir = self.workspace / "manifests"
        self.config_dir = self.workspace / "config"
        self.runtime_dir = self.workspace / "runtime"
        self.config_file = self.config_dir / "ssh_target.json"
        self.runtime_file = self.runtime_dir / "runtime_state.json"

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.archives_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

        if not self.runtime_file.exists():
            self._write_json(
                self.runtime_file,
                {
                    "last_remote_path": "",
                    "last_test_at_utc": "",
                },
            )

    def get_roots(self) -> list[str]:
        return [str(root) for root in self.config.allowed_roots]

    def list_directory(self, requested_path: str) -> dict[str, Any]:
        safe_path = self._resolve_allowed_path(requested_path)

        if not safe_path.exists():
            raise FileNotFoundError(f"Path does not exist: {safe_path}")

        if not safe_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {safe_path}")

        entries: list[dict[str, Any]] = []

        try:
            raw_entries = list(safe_path.iterdir())
        except PermissionError as exc:
            raise PermissionError(f"Permission denied for directory: {safe_path}") from exc

        for entry in sorted(raw_entries, key=lambda p: (not p.is_dir(), p.name.lower())):
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

    def get_current_target_config(self) -> dict[str, Any]:
        cfg = self._load_effective_target_config()
        runtime = self._read_json(self.runtime_file, default={})

        return self._public_target_config(
            {
                "host": cfg.windows_host,
                "port": cfg.windows_port,
                "user": cfg.windows_user,
                "remote_dir": cfg.windows_remote_dir,
                "timeout": cfg.ssh_timeout,
                "auth_type": cfg.ssh_auth_type,
                "key_path": cfg.ssh_key_path,
                "last_remote_path": runtime.get("last_remote_path", ""),
                "last_test_at_utc": runtime.get("last_test_at_utc", ""),
            }
        )

    def update_target_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        host = str(payload.get("host", "")).strip()
        user = str(payload.get("user", "")).strip()
        remote_dir = str(payload.get("remote_dir", "")).strip()
        auth_type = str(payload.get("auth_type", "password")).strip().lower()
        key_path = str(payload.get("key_path", "")).strip()
        key_passphrase = str(payload.get("key_passphrase", ""))
        password = str(payload.get("password", ""))

        try:
            port = int(payload.get("port", 22))
        except Exception:
            raise ValueError("Invalid port")

        try:
            timeout = int(payload.get("timeout", 15))
        except Exception:
            raise ValueError("Invalid timeout")

        if not host:
            raise ValueError("SSH host is required")

        if not user:
            raise ValueError("SSH user is required")

        if not remote_dir:
            raise ValueError("Remote directory is required")

        if auth_type not in {"password", "key"}:
            raise ValueError("auth_type must be 'password' or 'key'")

        if auth_type == "password" and not password:
            existing = self._read_json(self.config_file, default={})
            if not existing.get("password"):
                raise ValueError("Password is required for password authentication")

        if auth_type == "key" and not key_path:
            raise ValueError("key_path is required for key authentication")

        existing = self._read_json(self.config_file, default={})

        stored = {
            "host": host,
            "port": port,
            "user": user,
            "remote_dir": remote_dir,
            "timeout": timeout,
            "auth_type": auth_type,
            "key_path": key_path if auth_type == "key" else "",
            "key_passphrase": key_passphrase if auth_type == "key" and key_passphrase else existing.get("key_passphrase", "") if auth_type == "key" else "",
            "password": password if auth_type == "password" and password else existing.get("password", "") if auth_type == "password" else "",
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        self._write_json(self.config_file, stored)

        self._write_manifest(
            {
                "event": "update_ssh_target_config",
                "updated_at_utc": stored["updated_at_utc"],
                "host": host,
                "port": port,
                "user": user,
                "remote_dir": remote_dir,
                "timeout": timeout,
                "auth_type": auth_type,
                "key_path": stored["key_path"],
            }
        )

        return self.get_current_target_config()

    def test_ssh_connection(self) -> dict[str, Any]:
        started = time.time()
        client = None

        try:
            cfg = self._load_effective_target_config()
            self._validate_target_config(cfg)

            self._tcp_probe(cfg.windows_host, cfg.windows_port, cfg.ssh_timeout)
            client = self._connect_ssh_client(cfg)

            transport = client.get_transport()
            banner = transport.remote_version if transport else ""

            result = {
                "connected": True,
                "banner": banner,
                "host": cfg.windows_host,
                "port": cfg.windows_port,
                "user": cfg.windows_user,
                "remote_dir": cfg.windows_remote_dir,
                "duration_ms": int((time.time() - started) * 1000),
                "tested_at_utc": datetime.now(timezone.utc).isoformat(),
                "config": self.get_current_target_config(),
            }

            self._update_runtime_state(last_test_at_utc=result["tested_at_utc"])

            self._write_manifest(
                {
                    "event": "test_ssh_connection",
                    **result,
                }
            )

            return result

        except Exception as exc:
            tested_at = datetime.now(timezone.utc).isoformat()
            self._update_runtime_state(last_test_at_utc=tested_at)

            return {
                "connected": False,
                "error": str(exc),
                "duration_ms": int((time.time() - started) * 1000),
                "tested_at_utc": tested_at,
                "config": self.get_current_target_config(),
            }
        finally:
            if client is not None:
                client.close()

    def verify_remote_file(self, remote_path: str) -> dict[str, Any]:
        if not remote_path:
            raise ValueError("remote_path is required")

        cfg = self._load_effective_target_config()
        self._validate_target_config(cfg)

        client = None
        sftp = None

        try:
            client = self._connect_ssh_client(cfg)
            sftp = client.open_sftp()

            attrs = sftp.stat(remote_path)
            remote_sha256 = self._try_get_remote_sha256(client, remote_path)

            result = {
                "exists": True,
                "remote_path": remote_path,
                "size": attrs.st_size,
                "modified_utc": datetime.fromtimestamp(attrs.st_mtime, tz=timezone.utc).isoformat(),
                "sha256": remote_sha256,
            }

            self._write_manifest(
                {
                    "event": "verify_remote_file",
                    "verified_at_utc": datetime.now(timezone.utc).isoformat(),
                    "host": cfg.windows_host,
                    "port": cfg.windows_port,
                    "user": cfg.windows_user,
                    **result,
                }
            )

            return result

        except FileNotFoundError:
            return {
                "exists": False,
                "remote_path": remote_path,
            }
        finally:
            if sftp is not None:
                sftp.close()
            if client is not None:
                client.close()

    def send_file_to_windows(self, local_file_path: str) -> dict[str, Any]:
        local_path = Path(local_file_path).expanduser().resolve()
        allowed_send_roots = [self.workspace] + self.config.allowed_roots

        if not any(self._is_relative_to(local_path, root.resolve()) for root in allowed_send_roots):
            raise PermissionError(f"Local file not allowed for transfer: {local_path}")

        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        if not local_path.is_file():
            raise ValueError(f"Path is not a file: {local_path}")

        cfg = self._load_effective_target_config()
        self._validate_target_config(cfg)

        remote_dir = cfg.windows_remote_dir.replace("\\", "/")
        remote_filename = local_path.name
        remote_path = self._remote_join(remote_dir, remote_filename)

        client = None
        sftp = None

        try:
            client = self._connect_ssh_client(cfg)
            sftp = client.open_sftp()

            self._ensure_remote_dir_exists(sftp, remote_dir)
            sftp.put(str(local_path), remote_path)

            try:
                attrs = sftp.stat(remote_path)
                remote_exists = True
                remote_size = attrs.st_size
            except FileNotFoundError:
                remote_exists = False
                remote_size = None

            local_metadata = self._build_file_metadata(local_path, original_name=local_path.name)
            remote_sha256 = self._try_get_remote_sha256(client, remote_path)

            verified = bool(
                remote_exists
                and remote_size == local_metadata["size"]
                and (remote_sha256 == local_metadata["sha256"] if remote_sha256 else True)
            )

            self._update_runtime_state(last_remote_path=remote_path)

            self._write_manifest(
                {
                    "event": "send_file_to_windows",
                    "sent_at_utc": datetime.now(timezone.utc).isoformat(),
                    "local_path": str(local_path),
                    "remote_path": remote_path,
                    "windows_host": cfg.windows_host,
                    "windows_port": cfg.windows_port,
                    "windows_user": cfg.windows_user,
                    "size": local_metadata["size"],
                    "sha256": local_metadata["sha256"],
                    "remote_exists": remote_exists,
                    "remote_size": remote_size,
                    "remote_sha256": remote_sha256,
                    "verified": verified,
                }
            )

            return {
                "status": "sent",
                "local_path": str(local_path),
                "remote_path": remote_path,
                "sha256": local_metadata["sha256"],
                "size": local_metadata["size"],
                "remote_exists": remote_exists,
                "remote_size": remote_size,
                "remote_sha256": remote_sha256,
                "verified": verified,
            }

        finally:
            if sftp is not None:
                sftp.close()
            if client is not None:
                client.close()

    def execute_remote(
        self,
        exec_type: str,
        command: str,
        cwd: str = "",
        timeout: int = 120,
        post_check: str = "none",
        target_file: str = "",
    ) -> dict[str, Any]:
        if not command.strip():
            raise ValueError("command is required")

        cfg = self._load_effective_target_config()
        self._validate_target_config(cfg)

        client = None

        try:
            client = self._connect_ssh_client(cfg)

            final_command = self._build_remote_command(
                exec_type=exec_type,
                command=command,
                cwd=cwd,
            )

            stdin, stdout, stderr = client.exec_command(final_command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")

            result: dict[str, Any] = {
                "exec_type": exec_type,
                "command": command,
                "cwd": cwd,
                "final_command": final_command,
                "timeout": timeout,
                "exit_code": exit_code,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "executed_at_utc": datetime.now(timezone.utc).isoformat(),
            }

            if post_check == "verify_target_file" and target_file:
                post = self.verify_remote_file(target_file)
                result["post_check"] = post
                if post.get("remote_path"):
                    self._update_runtime_state(last_remote_path=post["remote_path"])
            else:
                result["post_check"] = None

            self._write_manifest(
                {
                    "event": "execute_remote",
                    "host": cfg.windows_host,
                    "port": cfg.windows_port,
                    "user": cfg.windows_user,
                    **result,
                }
            )

            return result

        finally:
            if client is not None:
                client.close()

    def _load_effective_target_config(self) -> ExchangeConfig:
        stored = self._read_json(self.config_file, default={})

        merged = ExchangeConfig(
            workspace=self.config.workspace,
            allowed_roots=self.config.allowed_roots,
            windows_host=str(stored.get("host", self.config.windows_host)).strip(),
            windows_port=int(stored.get("port", self.config.windows_port)),
            windows_user=str(stored.get("user", self.config.windows_user)).strip(),
            windows_password=str(stored.get("password", self.config.windows_password)),
            windows_remote_dir=str(stored.get("remote_dir", self.config.windows_remote_dir)).strip(),
            ssh_timeout=int(stored.get("timeout", self.config.ssh_timeout)),
            ssh_auth_type=str(stored.get("auth_type", self.config.ssh_auth_type or "password")).strip().lower(),
            ssh_key_path=str(stored.get("key_path", self.config.ssh_key_path)).strip(),
            ssh_key_passphrase=str(stored.get("key_passphrase", self.config.ssh_key_passphrase)),
        )
        return merged

    def _validate_target_config(self, cfg: ExchangeConfig) -> None:
        if not cfg.windows_host:
            raise ValueError("SSH host is not configured")

        if not cfg.windows_user:
            raise ValueError("SSH user is not configured")

        if not cfg.windows_remote_dir:
            raise ValueError("SSH remote_dir is not configured")

        if cfg.ssh_auth_type not in {"password", "key"}:
            raise ValueError("Invalid SSH auth type")

        if cfg.ssh_auth_type == "password" and not cfg.windows_password:
            raise ValueError("SSH password is not configured")

        if cfg.ssh_auth_type == "key" and not cfg.ssh_key_path:
            raise ValueError("SSH key path is not configured")

    def _connect_ssh_client(self, cfg: ExchangeConfig) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs: dict[str, Any] = {
            "hostname": cfg.windows_host,
            "port": cfg.windows_port,
            "username": cfg.windows_user,
            "timeout": cfg.ssh_timeout,
            "banner_timeout": cfg.ssh_timeout,
            "auth_timeout": cfg.ssh_timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if cfg.ssh_auth_type == "password":
            kwargs["password"] = cfg.windows_password
        else:
            pkey = self._load_private_key(cfg.ssh_key_path, cfg.ssh_key_passphrase)
            kwargs["pkey"] = pkey

        client.connect(**kwargs)
        return client
    def _load_private_key(self, key_path: str, passphrase: str):
        key_file = Path(key_path).expanduser().resolve()

        if not key_file.exists():
            raise FileNotFoundError(f"SSH private key not found: {key_file}")

        loaders = [
            ("RSA", paramiko.RSAKey.from_private_key_file),
            ("Ed25519", paramiko.Ed25519Key.from_private_key_file),
            ("ECDSA", paramiko.ECDSAKey.from_private_key_file),
        ]

        if hasattr(paramiko, "DSSKey"):
            loaders.append(("DSS", paramiko.DSSKey.from_private_key_file))

        errors = []

        for key_type, loader in loaders:
            try:
                return loader(str(key_file), password=passphrase or None)
            except Exception as exc:
                errors.append(f"{key_type}: {exc}")

        raise ValueError(
            "Unable to load SSH private key. Tried: " + " | ".join(errors)
        )
    def _tcp_probe(self, host: str, port: int, timeout: int) -> None:
        with socket.create_connection((host, port), timeout=timeout):
            return

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
        normalized = remote_dir.replace("\\", "/").strip()
        if not normalized:
            raise ValueError("Remote directory is empty")

        if ":" in normalized[:3]:
            drive, rest = normalized.split(":", 1)
            current = f"{drive}:"
            parts = [part for part in rest.split("/") if part]
        else:
            current = ""
            parts = [part for part in normalized.split("/") if part]

        for part in parts:
            current = f"{current}/{part}" if current else part

            try:
                attrs = sftp.stat(current)
                if not stat.S_ISDIR(attrs.st_mode):
                    raise NotADirectoryError(f"Remote path exists but is not a directory: {current}")
            except FileNotFoundError:
                sftp.mkdir(current)

    def _try_get_remote_sha256(self, client: paramiko.SSHClient, remote_path: str) -> str | None:
        ps_path = self._ps_single_quote(remote_path)

        candidates = [
            f"powershell -NoProfile -Command \"if (Test-Path -LiteralPath '{ps_path}') {{ (Get-FileHash -LiteralPath '{ps_path}' -Algorithm SHA256).Hash }}\"",
            f"powershell -NoProfile -Command \"if (Test-Path -LiteralPath '{ps_path}') {{ certutil -hashfile '{ps_path}' SHA256 | Select-Object -Skip 1 -First 1 }}\"",
            f"sha256sum {self._sh_single_quote(remote_path)} | awk '{{print $1}}'",
        ]

        for cmd in candidates:
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                exit_code = stdout.channel.recv_exit_status()
                out = stdout.read().decode("utf-8", errors="replace").strip()
                err = stderr.read().decode("utf-8", errors="replace").strip()

                if exit_code == 0 and out:
                    line = out.splitlines()[0].strip()
                    cleaned = "".join(ch for ch in line if ch.isalnum()).lower()
                    if len(cleaned) == 64:
                        return cleaned
                if err:
                    continue
            except Exception:
                continue

        return None

    def _build_remote_command(self, exec_type: str, command: str, cwd: str = "") -> str:
        exec_type = (exec_type or "command").strip().lower()
        cwd = (cwd or "").strip()

        if exec_type == "powershell":
            script = command
            if cwd:
                script = f"Set-Location -LiteralPath '{self._ps_single_quote(cwd)}';\n{script}"
            encoded = self._powershell_encoded(script)
            return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"

        final = command
        if cwd:
            final = f'cd /d "{cwd}" && {command}'
        return final

    def _powershell_encoded(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _public_target_config(self, data: dict[str, Any]) -> dict[str, Any]:
        safe = dict(data)
        safe["password_configured"] = bool(
            self._read_json(self.config_file, default={}).get("password")
        )
        safe["key_passphrase_configured"] = bool(
            self._read_json(self.config_file, default={}).get("key_passphrase")
        )
        return safe

    def _update_runtime_state(
        self,
        last_remote_path: str | None = None,
        last_test_at_utc: str | None = None,
    ) -> None:
        state = self._read_json(self.runtime_file, default={})
        if last_remote_path is not None:
            state["last_remote_path"] = last_remote_path
        if last_test_at_utc is not None:
            state["last_test_at_utc"] = last_test_at_utc
        self._write_json(self.runtime_file, state)

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def _read_json(self, path: Path, default: dict[str, Any]) -> dict[str, Any]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return dict(default)

    def _remote_join(self, remote_dir: str, filename: str) -> str:
        remote_dir = remote_dir.replace("\\", "/").rstrip("/")
        return f"{remote_dir}/{filename}" if remote_dir else filename

    def _ps_single_quote(self, value: str) -> str:
        return value.replace("'", "''")

    def _sh_single_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def _is_relative_to(path: Path, base: Path) -> bool:
        try:
            path.relative_to(base)
            return True
        except ValueError:
            return False