from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"
RUNTIME_ASSETS_PATH = REPO_ROOT / "app_core" / "infrastructure" / "attack" / "runtime" / "industrial_runtime_assets.json"
SCENARIO_FILE = REPO_ROOT / "scenario" / "scenario_file.json"
SYMBOL_ROOT = REPO_ROOT / "app_core" / "infrastructure" / "forensics" / "volatility_symbol_store"
SYMBOL_LINUX_DIR = SYMBOL_ROOT / "linux"
SYMBOL_METADATA_DIR = SYMBOL_ROOT / "metadata"
VOL3_PLUGIN_SPECS = [
    ("banners", "banners.Banners"),
    ("pslist", "linux.pslist.PsList"),
    ("lsmod", "linux.lsmod.Lsmod"),
    ("sockstat", "linux.sockstat.Sockstat"),
    ("check_syscall", "linux.check_syscall.Check_syscall"),
    ("bash", "linux.bash.Bash"),
]
JOB_POLL_DONE = {"completed", "failed", "blocked"}

_JOBS_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _which(*candidates: str) -> str | None:
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _vol_cmd() -> str | None:
    return _which("vol", "volatility3")


def _vol_version() -> str:
    vol = _vol_cmd()
    if not vol:
        return "not_available"
    try:
        proc = subprocess.run([vol, "-h"], capture_output=True, text=True, check=False)
    except Exception:
        return "unknown"
    combined = "\n".join(part for part in [proc.stdout, proc.stderr] if part)
    match = re.search(r"Volatility 3 Framework\s+([0-9.]+)", combined)
    return match.group(1) if match else "unknown"


def _resolve_ssh_key_path(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    expanded = os.path.abspath(os.path.expanduser(os.path.expandvars(value)))
    return expanded if os.path.isfile(expanded) else ""


def _detect_ssh_key_path(keypair_name: str | None = None) -> str:
    candidates = [
        os.environ.get("NICS_DFIR_SSH_KEY", ""),
        os.environ.get("SSH_KEY", ""),
        f"~/.ssh/{(keypair_name or '').strip()}",
        "~/.ssh/my_key",
        "~/.ssh/id_ed25519",
        "~/.ssh/id_rsa",
    ]
    for candidate in candidates:
        resolved = _resolve_ssh_key_path(candidate)
        if resolved:
            return resolved
    return ""


def _classify_role(name: str) -> str:
    lowered = (name or "").lower()
    if "monitor" in lowered or "wazuh" in lowered:
        return "monitor"
    if "fuxa" in lowered or "scada" in lowered:
        return "scada"
    if "plc" in lowered:
        return "plc"
    if "attack" in lowered:
        return "attacker"
    if "victim" in lowered:
        return "victim"
    return "unknown"


def _map_ssh_user(image_or_os: str) -> str:
    lowered = (image_or_os or "").lower()
    if "ubuntu" in lowered:
        return "ubuntu"
    if "kali" in lowered:
        return "kali"
    return "debian"


def _scenario_nodes() -> list[dict]:
    payload = _read_json(SCENARIO_FILE)
    nodes = payload.get("nodes") if isinstance(payload, dict) else []
    return nodes if isinstance(nodes, list) else []


def _runtime_inventory() -> list[dict]:
    payload = _read_json(RUNTIME_ASSETS_PATH)
    if not isinstance(payload, dict):
        return []
    candidates = payload.get("inventory_candidates")
    if isinstance(candidates, list) and candidates:
        return candidates
    fallback = []
    for key in ("scada", "plc"):
        item = payload.get(key)
        if isinstance(item, dict) and item.get("instance_id"):
            fallback.append(item)
    return fallback


def _runtime_nodes() -> list[dict]:
    scenario_by_name = {}
    for node in _scenario_nodes():
        scenario_by_name[(node.get("name") or "").strip().lower()] = node
    out = []
    for raw in _runtime_inventory():
        name = raw.get("name") or raw.get("instance_name") or raw.get("hostname") or raw.get("instance_id")
        scenario_node = scenario_by_name.get((name or "").strip().lower(), {})
        props = scenario_node.get("properties") or {}
        role = raw.get("role") or _classify_role(name or "")
        image = raw.get("image") or props.get("image") or props.get("os") or ""
        keypair = props.get("keypair") or "my_key"
        out.append(
            {
                "instance_id": raw.get("instance_id") or raw.get("id"),
                "name": name,
                "role": role,
                "image": image,
                "os": raw.get("os") or image,
                "status": raw.get("status"),
                "floating_ip": raw.get("floating_ip") or raw.get("ip"),
                "private_ip": raw.get("private_ip"),
                "networks": raw.get("networks") or [],
                "ssh_user": _map_ssh_user(image or role),
                "keypair": keypair,
                "hostname": raw.get("hostname") or name,
            }
        )
    return out


def _find_runtime_node(*, instance_id: str | None = None, ip: str | None = None, role: str | None = None) -> dict | None:
    for node in _runtime_nodes():
        if instance_id and node.get("instance_id") == instance_id:
            return node
        if ip and ip in {node.get("floating_ip"), node.get("private_ip")}:
            return node
        if role and node.get("role") == role:
            return node
    return None


def _case_dir(case_id: str) -> Path | None:
    candidate = EVIDENCE_ROOT / case_id
    return candidate if candidate.is_dir() else None


def _case_id_from_dir(case_dir: str | Path) -> str:
    return Path(case_dir).resolve().name


def _memory_metadata_path(case_dir: Path, dump_path: Path) -> Path:
    return case_dir / "metadata" / f"{dump_path.name}.metadata.json"


def _read_memory_metadata(case_dir: Path, dump_path: Path) -> dict:
    payload = _read_json(_memory_metadata_path(case_dir, dump_path))
    return payload if isinstance(payload, dict) else {}


def _list_memory_dumps(case_dir: Path) -> list[dict]:
    dumps = []
    for dump_path in sorted((case_dir / "memory").glob("*.lime")):
        metadata = _read_memory_metadata(case_dir, dump_path)
        dumps.append(
            {
                "memory_artifact_id": dump_path.name,
                "dump_name": dump_path.name,
                "dump_path": str(dump_path),
                "metadata_path": str(_memory_metadata_path(case_dir, dump_path)),
                "metadata": metadata,
                "vm_id": metadata.get("vm_id"),
                "vm_ip": metadata.get("vm_ip"),
                "ssh_user": metadata.get("ssh_user"),
                "sha256": metadata.get("sha256"),
                "created_utc": metadata.get("created_utc"),
            }
        )
    return dumps


def _resolve_dump(case_id: str, memory_artifact_id: str | None = None) -> tuple[Path, dict]:
    case_dir = _case_dir(case_id)
    if not case_dir:
        raise FileNotFoundError(f"case_not_found:{case_id}")
    dumps = _list_memory_dumps(case_dir)
    if not dumps:
        raise FileNotFoundError(f"no_memory_dumps:{case_id}")
    if memory_artifact_id:
        for item in dumps:
            if item["memory_artifact_id"] == memory_artifact_id or item["dump_name"] == memory_artifact_id:
                return case_dir, item
        raise FileNotFoundError(f"memory_artifact_not_found:{memory_artifact_id}")
    return case_dir, dumps[0]


def _parse_linux_banner(text: str) -> dict:
    for line in (text or "").splitlines():
        if "Linux version " not in line:
            continue
        kernel_match = re.search(r"Linux version\s+([^\s]+)", line)
        kernel = kernel_match.group(1).strip() if kernel_match else None
        lowered = line.lower()
        os_id = "unknown"
        codename = None
        if "ubuntu" in lowered:
            os_id = "ubuntu"
            jammy = re.search(r"ubuntu\s+([a-z0-9._-]+)", lowered)
            codename = jammy.group(1) if jammy else None
        elif "debian" in lowered:
            os_id = "debian"
            deb = re.search(r"debian\s+([0-9a-z._-]+)", lowered)
            codename = deb.group(1) if deb else None
            if codename and codename.isdigit():
                codename = None
        return {"banner": line.strip(), "kernel": kernel, "os_id": os_id, "os_codename": codename}
    return {"banner": "", "kernel": None, "os_id": "unknown", "os_codename": None}


def _run_banners(dump_path: Path) -> dict:
    vol = _vol_cmd()
    if not vol:
        return {"ok": False, "stdout": "", "stderr": "volatility3_not_available", "command": [], "exit_code": 127}
    command = [vol, "-f", str(dump_path), "banners.Banners"]
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    return {"ok": proc.returncode == 0, "stdout": stdout, "stderr": stderr, "command": command, "exit_code": proc.returncode}


def _cached_banner_run(case_dir: Path, dump_name: str, vm_ip: str | None) -> dict | None:
    candidates = [
        case_dir / "analysis" / "04_memory" / dump_name.replace(".lime", "") / "banners.stdout.log",
        case_dir / "analysis" / "04_memory" / dump_name.replace(".lime", "") / "vol3_banners.txt",
    ]
    if vm_ip:
        candidates.extend(
            [
                case_dir / "memory" / f"volatility_results_{vm_ip}" / "banners.txt",
                case_dir / "memory" / f"volatility_results_{vm_ip}" / "01_banners.txt",
            ]
        )
    for path in candidates:
        if not path.is_file():
            continue
        return {
            "ok": True,
            "stdout": path.read_text(encoding="utf-8", errors="ignore"),
            "stderr": "",
            "command": ["cached_banner", str(path)],
            "exit_code": 0,
        }
    return None


def _parse_metadata_text(path: Path) -> dict:
    data: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    except Exception:
        return {}
    return data


@dataclass
class ResolvedTarget:
    case_id: str
    case_dir: Path
    dump_path: Path
    memory_artifact_id: str
    target_node_id: str | None
    target_name: str
    target_role: str
    target_ip: str
    target_private_ip: str | None
    target_hostname: str
    target_ssh_user: str
    target_os_id: str
    target_os_codename: str | None
    target_os_pretty: str | None
    target_kernel: str | None
    target_architecture: str | None
    target_kernel_package_version: str | None
    builder_node_id: str
    builder_name: str
    builder_ip: str
    builder_ssh_user: str
    builder_hostname: str
    ssh_key_path: str
    metadata: dict
    banner_info: dict


class SymbolInventoryService:
    def __init__(self, symbol_root: Path | None = None):
        self.symbol_root = symbol_root or SYMBOL_ROOT
        self.linux_dir = self.symbol_root / "linux"
        self.metadata_dir = self.symbol_root / "metadata"

    @staticmethod
    def _symbol_file_paths(root: Path) -> list[Path]:
        if not root.is_dir():
            return []
        return sorted([path for path in root.iterdir() if path.is_file() and path.name.endswith((".json", ".json.xz", ".zip"))])

    @staticmethod
    def _derive_symbol_identity(path: Path) -> tuple[str | None, str | None, str | None]:
        base = path.name
        for suffix in (".json.xz", ".json", ".zip"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        match = re.match(r"^(ubuntu|debian)-(.+?)-([0-9][A-Za-z0-9._-]+)$", base)
        if not match:
            return None, None, None
        os_id = match.group(1)
        codename = match.group(2).rstrip("_")
        kernel = match.group(3)
        return os_id, codename, kernel

    def _metadata_for_symbol(self, symbol_path: Path) -> dict:
        meta_json = self.metadata_dir / f"{symbol_path.name}.metadata.json"
        meta_txt = self.metadata_dir / f"{symbol_path.name}.metadata.txt"
        if meta_json.is_file():
            payload = _read_json(meta_json)
            return payload if isinstance(payload, dict) else {}
        if meta_txt.is_file():
            return _parse_metadata_text(meta_txt)
        legacy_txt = self.metadata_dir / f"{symbol_path.name}.metadata.txt"
        if legacy_txt.is_file():
            return _parse_metadata_text(legacy_txt)
        legacy_txt = self.metadata_dir / f"{symbol_path.name}.metadata"
        if legacy_txt.is_file():
            return _parse_metadata_text(legacy_txt)
        legacy_txt = self.metadata_dir / f"{symbol_path.name}.metadata.txt"
        return _parse_metadata_text(legacy_txt) if legacy_txt.is_file() else {}

    def list_symbols(self) -> list[dict]:
        symbols = []
        for symbol_path in self._symbol_file_paths(self.linux_dir):
            metadata = self._metadata_for_symbol(symbol_path)
            os_id, codename, kernel = self._derive_symbol_identity(symbol_path)
            kernel = metadata.get("target_kernel") or kernel
            os_id = metadata.get("target_os_id") or os_id
            codename = metadata.get("target_debian_codename") or metadata.get("target_ubuntu_codename") or metadata.get("os_codename") or codename
            arch = metadata.get("target_architecture") or metadata.get("architecture") or "amd64"
            sha256 = metadata.get("sha256")
            if not sha256:
                try:
                    sha256 = _sha256_file(symbol_path)
                except Exception:
                    sha256 = None
            entry = {
                "symbol_id": f"{os_id}-{codename}-{kernel}" if os_id and codename and kernel else symbol_path.stem,
                "os_id": os_id,
                "os_codename": codename,
                "kernel": kernel,
                "architecture": arch,
                "path": str(symbol_path),
                "sha256": sha256,
                "generated_utc": metadata.get("generated_utc"),
                "generation_mode": metadata.get("generation_mode"),
                "source_package": metadata.get("debug_package") or metadata.get("dbgsym_package"),
                "source_package_url": metadata.get("debug_package_url"),
                "builder_node": metadata.get("builder_node"),
                "target_node": metadata.get("target_node"),
                "target_hostname": metadata.get("target_hostname"),
                "metadata_path": str((self.metadata_dir / f"{symbol_path.name}.metadata.json")) if (self.metadata_dir / f"{symbol_path.name}.metadata.json").exists() else str((self.metadata_dir / f"{symbol_path.name}.metadata.txt")),
            }
            symbols.append(entry)
        return symbols

    def find_compatible(self, *, kernel: str | None, os_id: str | None = None, codename: str | None = None, architecture: str | None = None) -> list[dict]:
        if not kernel:
            return []
        exact = []
        partial = []
        for item in self.list_symbols():
            if item.get("kernel") != kernel:
                continue
            if os_id and item.get("os_id") and item.get("os_id") != os_id:
                continue
            if architecture and item.get("architecture") and item.get("architecture") != architecture:
                continue
            if codename and item.get("os_codename") and item.get("os_codename") != codename:
                partial.append(item)
                continue
            exact.append(item)
        return exact or partial


class SymbolResolverService:
    def __init__(self, inventory: SymbolInventoryService | None = None):
        self.inventory = inventory or SymbolInventoryService()

    def resolve_target(self, case_id: str, memory_artifact_id: str | None = None) -> ResolvedTarget:
        case_dir, dump = _resolve_dump(case_id, memory_artifact_id)
        metadata = dump.get("metadata") or {}
        target_node = _find_runtime_node(instance_id=dump.get("vm_id"), ip=dump.get("vm_ip"))
        if not target_node:
            target_node = {
                "instance_id": dump.get("vm_id"),
                "name": dump.get("vm_id") or dump.get("vm_ip") or dump["memory_artifact_id"],
                "role": "unknown",
                "image": "",
                "os": "",
                "floating_ip": dump.get("vm_ip"),
                "private_ip": None,
                "ssh_user": metadata.get("ssh_user") or "debian",
                "hostname": dump.get("vm_ip") or dump["memory_artifact_id"],
                "keypair": "my_key",
            }
        builder_node = _find_runtime_node(role="monitor")
        if not builder_node:
            raise RuntimeError("No monitor builder node could be resolved from runtime inventory")
        ssh_key_path = _detect_ssh_key_path(target_node.get("keypair") or builder_node.get("keypair"))
        if not ssh_key_path:
            raise RuntimeError("No SSH key path could be resolved from env/default paths")
        banner_run = _cached_banner_run(case_dir, dump["dump_name"], dump.get("vm_ip")) or _run_banners(Path(dump["dump_path"]))
        banner_info = _parse_linux_banner((banner_run.get("stdout") or "") + "\n" + (banner_run.get("stderr") or ""))
        target_os_id = banner_info.get("os_id")
        target_os_codename = banner_info.get("os_codename")
        target_pretty = None
        if target_os_id == "ubuntu":
            target_pretty = "Ubuntu Linux"
        elif target_os_id == "debian":
            target_pretty = "Debian GNU/Linux"
        image_hint = target_node.get("image") or target_node.get("os") or ""
        if target_os_id == "unknown":
            target_os_id = "ubuntu" if "ubuntu" in image_hint.lower() else ("debian" if "debian" in image_hint.lower() else "unknown")
        if not target_os_codename and "jammy" in image_hint.lower():
            target_os_codename = "jammy"
        if not target_os_codename and "bookworm" in image_hint.lower():
            target_os_codename = "bookworm"
        return ResolvedTarget(
            case_id=case_id,
            case_dir=case_dir,
            dump_path=Path(dump["dump_path"]),
            memory_artifact_id=dump["memory_artifact_id"],
            target_node_id=target_node.get("instance_id"),
            target_name=target_node.get("name") or dump["memory_artifact_id"],
            target_role=target_node.get("role") or "unknown",
            target_ip=target_node.get("floating_ip") or dump.get("vm_ip") or "",
            target_private_ip=target_node.get("private_ip"),
            target_hostname=target_node.get("hostname") or target_node.get("name") or "",
            target_ssh_user=metadata.get("ssh_user") or target_node.get("ssh_user") or "debian",
            target_os_id=target_os_id or "unknown",
            target_os_codename=target_os_codename,
            target_os_pretty=target_pretty or target_node.get("os"),
            target_kernel=banner_info.get("kernel"),
            target_architecture=None,
            target_kernel_package_version=None,
            builder_node_id=builder_node.get("instance_id"),
            builder_name=builder_node.get("name"),
            builder_ip=builder_node.get("floating_ip") or builder_node.get("private_ip") or "",
            builder_ssh_user=builder_node.get("ssh_user") or "ubuntu",
            builder_hostname=builder_node.get("hostname") or builder_node.get("name") or "",
            ssh_key_path=ssh_key_path,
            metadata=metadata,
            banner_info={
                **banner_info,
                "volatility3_available": bool(_vol_cmd()),
                "volatility3_version": _vol_version(),
                "banner_command": banner_run.get("command") or [],
                "banner_exit_code": banner_run.get("exit_code"),
                "banner_stdout": banner_run.get("stdout"),
                "banner_stderr": banner_run.get("stderr"),
            },
        )

    def resolve_status(self, case_id: str, memory_artifact_id: str | None = None) -> dict:
        target = self.resolve_target(case_id, memory_artifact_id)
        matches = self.inventory.find_compatible(
            kernel=target.target_kernel,
            os_id=target.target_os_id if target.target_os_id != "unknown" else None,
            codename=target.target_os_codename,
            architecture=target.target_architecture,
        )
        if matches:
            status = "symbol_available" if len(matches) == 1 else "symbol_ambiguous"
            reason = None if len(matches) == 1 else f"Multiple compatible symbol candidates were found for kernel {target.target_kernel}"
        else:
            status = "symbol_missing"
            reason = f"No Volatility 3 Linux ISF symbol was found for kernel {target.target_kernel}" if target.target_kernel else "Kernel could not be determined from dump banner"
        return {
            "status": status,
            "reason": reason,
            "required_kernel": target.target_kernel,
            "required_os_id": target.target_os_id,
            "required_os_codename": target.target_os_codename,
            "memory_artifact_id": target.memory_artifact_id,
            "dump_path": str(target.dump_path),
            "target_node_id": target.target_node_id,
            "target_node_name": target.target_name,
            "target_ip": target.target_ip,
            "builder_node_id": target.builder_node_id,
            "builder_node_name": target.builder_name,
            "builder_ip": target.builder_ip,
            "symbol_candidates": matches,
            "recommended_action": "generate_symbols" if not matches and target.target_kernel else "inspect_banner",
            "banner_info": target.banner_info,
        }


def _job_snapshot(job: dict) -> dict:
    return json.loads(json.dumps(job))


def _create_job(kind: str, payload: dict) -> dict:
    with _JOBS_LOCK:
        job_id = str(uuid.uuid4())
        job = {
            "job_id": job_id,
            "kind": kind,
            "status": "queued",
            "created_utc": _utc_now(),
            "updated_utc": _utc_now(),
            "steps": [],
            "logs": [],
            **payload,
        }
        _JOBS[job_id] = job
        return _job_snapshot(job)


def _append_log(job_id: str, message: str) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["logs"].append({"ts": _utc_now(), "message": message})
        job["updated_utc"] = _utc_now()


def _set_status(job_id: str, status: str, **extra) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["status"] = status
        job["updated_utc"] = _utc_now()
        job.update(extra)


def _set_step(job_id: str, step_key: str, status: str, detail: str = "") -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        steps = job.setdefault("steps", [])
        found = None
        for step in steps:
            if step.get("key") == step_key:
                found = step
                break
        if not found:
            found = {"key": step_key, "status": status, "detail": detail, "updated_utc": _utc_now()}
            steps.append(found)
        else:
            found["status"] = status
            found["detail"] = detail
            found["updated_utc"] = _utc_now()
        job["updated_utc"] = _utc_now()


def get_job(job_id: str) -> dict | None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        return _job_snapshot(job) if job else None


def _run_command(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, input=input_text, text=True, capture_output=True, check=False)


def _ssh_command(user: str, ip: str, key_path: str) -> list[str]:
    return [
        "ssh",
        "-i",
        key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=4",
        f"{user}@{ip}",
    ]


def _scp_from_command(user: str, ip: str, key_path: str, remote_path: str, local_path: str) -> list[str]:
    return [
        "scp",
        "-i",
        key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{user}@{ip}:{remote_path}",
        local_path,
    ]


def _scp_to_command(user: str, ip: str, key_path: str, local_path: str, remote_path: str) -> list[str]:
    return [
        "scp",
        "-i",
        key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        local_path,
        f"{user}@{ip}:{remote_path}",
    ]


def _remote_run(user: str, ip: str, key_path: str, script: str, args: list[str]) -> subprocess.CompletedProcess:
    command = _ssh_command(user, ip, key_path) + ["bash", "-s", "--", *args]
    return _run_command(command, input_text=script)


def _system_map_valid(local_path: Path) -> bool:
    try:
        return local_path.is_file() and local_path.stat().st_size > 1024
    except Exception:
        return False


def _symbol_filename(os_id: str, codename: str | None, kernel: str) -> str:
    if os_id == "debian":
        return f"debian-{(codename or 'unknown')}_-{kernel}.json.xz"
    return f"{os_id}-{(codename or 'unknown')}-{kernel}.json.xz"


BUILDER_GENERATE_SCRIPT = r"""#!/usr/bin/env bash
set -Eeuo pipefail

WORK_DIR="$1"
TARGET_OS_ID="$2"
TARGET_CODENAME="$3"
TARGET_KERNEL="$4"
TARGET_ARCH="$5"
TARGET_KERNEL_PACKAGE_VERSION="$6"
SYMBOL_FILENAME="$7"
SYSTEM_MAP_PATH="$8"

mkdir -p "$WORK_DIR/bin" "$WORK_DIR/download" "$WORK_DIR/extract" "$WORK_DIR/output"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] Missing command on builder: $1"; exit 1; }
}

for cmd in curl wget ar tar dpkg-deb xz sha256sum find stat uname; do
  need_cmd "$cmd"
done

BUILDER_ARCH="$(uname -m)"
DWARF_BIN="$WORK_DIR/bin/dwarf2json"
if [[ ! -x "$DWARF_BIN" ]]; then
  DWARF_URL="https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-amd64"
  if [[ "$BUILDER_ARCH" == "aarch64" || "$BUILDER_ARCH" == "arm64" ]]; then
    DWARF_URL="https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-arm64"
  fi
  wget -q -O "$DWARF_BIN" "$DWARF_URL"
  chmod +x "$DWARF_BIN"
fi

PKG_URL=""
PKG_FILE=""

if [[ "$TARGET_OS_ID" == "ubuntu" ]]; then
  BASE="https://ddebs.ubuntu.com/pool/main/l/linux/"
  PKG_FILE="$(curl -fsSL "$BASE" | grep -oP "linux-image-unsigned-${TARGET_KERNEL}-dbgsym_[^\" ]+_${TARGET_ARCH}\.(?:deb|ddeb)" | head -1 || true)"
  if [[ -z "$PKG_FILE" ]]; then
    PKG_FILE="$(curl -fsSL "$BASE" | grep -oP "linux-image-${TARGET_KERNEL}-dbgsym_[^\" ]+_${TARGET_ARCH}\.(?:deb|ddeb)" | head -1 || true)"
  fi
  [[ -n "$PKG_FILE" ]] || { echo "[ERROR] No Ubuntu dbgsym package found for kernel ${TARGET_KERNEL}"; exit 1; }
  PKG_URL="${BASE}${PKG_FILE}"
else
  [[ -n "$TARGET_KERNEL_PACKAGE_VERSION" ]] || { echo "[ERROR] Missing Debian kernel package version"; exit 1; }
  PKG_FILE="linux-image-${TARGET_KERNEL}-dbg_${TARGET_KERNEL_PACKAGE_VERSION}_${TARGET_ARCH}.deb"
  for BASE in \
    "https://deb.debian.org/debian-security/pool/updates/main/l/linux/" \
    "https://deb.debian.org/debian/pool/main/l/linux/" \
    "https://security.debian.org/debian-security/pool/updates/main/l/linux/"
  do
    if curl -fsI "${BASE}${PKG_FILE}" >/dev/null 2>&1; then
      PKG_URL="${BASE}${PKG_FILE}"
      break
    fi
  done
  [[ -n "$PKG_URL" ]] || { echo "[ERROR] No Debian debug package URL found for ${PKG_FILE}"; exit 1; }
fi

PKG_LOCAL="$WORK_DIR/download/${PKG_FILE}"
wget -q -O "$PKG_LOCAL" "$PKG_URL"

pushd "$WORK_DIR/download" >/dev/null
rm -f control.tar.* data.tar.* debian-binary
ar x "$PKG_LOCAL"
DATA_TAR="$(find . -maxdepth 1 -type f -name 'data.tar*' | head -1)"
[[ -n "$DATA_TAR" ]] || { echo "[ERROR] No data.tar archive inside debug package"; exit 1; }
tar -xf "$DATA_TAR" -C "$WORK_DIR/extract"
popd >/dev/null

VMLINUX="$WORK_DIR/extract/usr/lib/debug/boot/vmlinux-${TARGET_KERNEL}"
if [[ ! -f "$VMLINUX" ]]; then
  VMLINUX="$WORK_DIR/extract/usr/lib/debug/lib/modules/${TARGET_KERNEL}/vmlinux"
fi
[[ -f "$VMLINUX" ]] || { echo "[ERROR] No vmlinux extracted for kernel ${TARGET_KERNEL}"; exit 1; }

OUT_JSON="$WORK_DIR/output/${SYMBOL_FILENAME%.xz}"
SYSTEMMAP_USED="no"
if [[ -n "$SYSTEM_MAP_PATH" && -f "$SYSTEM_MAP_PATH" ]]; then
  SIZE="$(stat -c %s "$SYSTEM_MAP_PATH" 2>/dev/null || echo 0)"
  if [[ "${SIZE}" -gt 1024 ]]; then
    "$DWARF_BIN" linux --elf "$VMLINUX" --system-map "$SYSTEM_MAP_PATH" > "$OUT_JSON"
    SYSTEMMAP_USED="yes"
  fi
fi
if [[ "$SYSTEMMAP_USED" != "yes" ]]; then
  "$DWARF_BIN" linux --elf "$VMLINUX" > "$OUT_JSON"
fi

xz -f -z -T0 "$OUT_JSON"
OUT_XZ="${OUT_JSON}.xz"
SHA256="$(sha256sum "$OUT_XZ" | awk '{print $1}')"
SIZE_BYTES="$(stat -c %s "$OUT_XZ")"

printf 'OUT_XZ=%q\n' "$OUT_XZ"
printf 'SHA256=%q\n' "$SHA256"
printf 'SIZE_BYTES=%q\n' "$SIZE_BYTES"
printf 'SYSTEMMAP_USED=%q\n' "$SYSTEMMAP_USED"
printf 'PKG_URL=%q\n' "$PKG_URL"
printf 'PKG_FILE=%q\n' "$PKG_FILE"
printf 'VMLINUX=%q\n' "$VMLINUX"
"""


TARGET_INFO_SCRIPT = r"""#!/usr/bin/env bash
set -Eeuo pipefail
KERNEL="$(uname -r)"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
HOSTNAME_VALUE="$(hostname)"
OS_ID="unknown"
CODENAME=""
PRETTY="unknown"
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  CODENAME="${VERSION_CODENAME:-}"
  PRETTY="${PRETTY_NAME:-unknown}"
fi
if [[ -z "$CODENAME" ]] && command -v lsb_release >/dev/null 2>&1; then
  CODENAME="$(lsb_release -sc 2>/dev/null || true)"
fi
KERNEL_PACKAGE_VERSION=""
if [[ "$OS_ID" == "debian" ]] && command -v dpkg-query >/dev/null 2>&1; then
  KERNEL_PACKAGE_VERSION="$(dpkg-query -W -f='${Version}' "linux-image-${KERNEL}" 2>/dev/null || true)"
fi
printf 'TARGET_KERNEL=%q\n' "$KERNEL"
printf 'TARGET_ARCH=%q\n' "$ARCH"
printf 'TARGET_HOSTNAME=%q\n' "$HOSTNAME_VALUE"
printf 'TARGET_OS_ID=%q\n' "$OS_ID"
printf 'TARGET_CODENAME=%q\n' "$CODENAME"
printf 'TARGET_PRETTY=%q\n' "$PRETTY"
printf 'TARGET_KERNEL_PACKAGE_VERSION=%q\n' "$KERNEL_PACKAGE_VERSION"
"""


class SymbolGenerationService:
    def __init__(self, inventory: SymbolInventoryService | None = None, resolver: SymbolResolverService | None = None):
        self.inventory = inventory or SymbolInventoryService()
        self.resolver = resolver or SymbolResolverService(self.inventory)

    def _prepare_target(self, case_id: str, memory_artifact_id: str | None) -> ResolvedTarget:
        target = self.resolver.resolve_target(case_id, memory_artifact_id)
        _append_log(getattr(self, "_job_id", ""), f"Resolved target dump {target.memory_artifact_id} -> {target.target_name} ({target.target_ip})")
        return target

    def _live_target_info(self, target: ResolvedTarget) -> dict:
        result = _remote_run(
            target.target_ssh_user,
            target.target_ip,
            target.ssh_key_path,
            TARGET_INFO_SCRIPT,
            [],
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "Failed to read target OS/kernel information over SSH").strip())
        env = {}
        for line in (result.stdout or "").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip("'")
        return env

    def generate(self, *, case_id: str, memory_artifact_id: str | None, overwrite: bool, mode: str = "manual") -> dict:
        target = self.resolver.resolve_target(case_id, memory_artifact_id)
        live = self._live_target_info(target)
        target = ResolvedTarget(
            **{
                **target.__dict__,
                "target_kernel": live.get("TARGET_KERNEL") or target.target_kernel,
                "target_architecture": live.get("TARGET_ARCH") or target.target_architecture or "amd64",
                "target_os_id": live.get("TARGET_OS_ID") or target.target_os_id,
                "target_os_codename": live.get("TARGET_CODENAME") or target.target_os_codename,
                "target_os_pretty": live.get("TARGET_PRETTY") or target.target_os_pretty,
                "target_hostname": live.get("TARGET_HOSTNAME") or target.target_hostname,
                "target_kernel_package_version": live.get("TARGET_KERNEL_PACKAGE_VERSION") or target.target_kernel_package_version,
            }
        )
        matches = self.inventory.find_compatible(kernel=target.target_kernel, os_id=target.target_os_id, codename=target.target_os_codename)
        if matches and not overwrite:
            return {
                "status": "completed",
                "result": "symbols_already_exist",
                "target_node": target.target_name,
                "kernel": target.target_kernel,
                "os_id": target.target_os_id,
                "symbol": matches[0],
            }

        run_id = f"{_utc_now().replace(':', '').replace('-', '')}-{uuid.uuid4().hex[:8]}"
        host_tmp = Path("/tmp") / f"nics-vol3-symbol-{run_id}"
        host_tmp.mkdir(parents=True, exist_ok=True)
        builder_work = f"/home/{target.builder_ssh_user}/nics-vol3-symbol-{run_id}"
        local_system_map = host_tmp / f"System.map-{target.target_kernel or 'unknown'}"
        remote_system_map = f"{builder_work}/input/{local_system_map.name}"
        system_map_for_builder = ""
        try:
            scp = _run_command(
                _scp_from_command(
                    target.target_ssh_user,
                    target.target_ip,
                    target.ssh_key_path,
                    f"/boot/System.map-{target.target_kernel}",
                    str(local_system_map),
                )
            )
            if scp.returncode == 0 and _system_map_valid(local_system_map):
                _run_command(_ssh_command(target.builder_ssh_user, target.builder_ip, target.ssh_key_path) + [f"mkdir -p '{builder_work}/input' '{builder_work}/output' '{builder_work}/extract' '{builder_work}/download' '{builder_work}/bin'"])
                scp_to = _run_command(_scp_to_command(target.builder_ssh_user, target.builder_ip, target.ssh_key_path, str(local_system_map), remote_system_map))
                if scp_to.returncode == 0:
                    system_map_for_builder = remote_system_map
            symbol_filename = _symbol_filename(target.target_os_id, target.target_os_codename, target.target_kernel or "unknown")
            builder_info = _remote_run(
                target.builder_ssh_user,
                target.builder_ip,
                target.ssh_key_path,
                BUILDER_GENERATE_SCRIPT,
                [
                    builder_work,
                    target.target_os_id,
                    target.target_os_codename or "",
                    target.target_kernel or "",
                    target.target_architecture or "amd64",
                    target.target_kernel_package_version or "",
                    symbol_filename,
                    system_map_for_builder,
                ],
            )
            if builder_info.returncode != 0:
                raise RuntimeError((builder_info.stderr or builder_info.stdout or "builder generation failed").strip())
            env = {}
            for line in (builder_info.stdout or "").splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip("'")
            remote_symbol = env.get("OUT_XZ")
            if not remote_symbol:
                raise RuntimeError("Builder did not return OUT_XZ")
            SYMBOL_LINUX_DIR.mkdir(parents=True, exist_ok=True)
            SYMBOL_METADATA_DIR.mkdir(parents=True, exist_ok=True)
            local_symbol_path = SYMBOL_LINUX_DIR / symbol_filename
            scp_back = _run_command(_scp_from_command(target.builder_ssh_user, target.builder_ip, target.ssh_key_path, remote_symbol, str(local_symbol_path)))
            if scp_back.returncode != 0 or not local_symbol_path.is_file():
                raise RuntimeError((scp_back.stderr or scp_back.stdout or "Failed to copy generated symbol to host").strip())
            sha256 = _sha256_file(local_symbol_path)
            metadata = {
                "symbol_id": f"{target.target_os_id}-{target.target_os_codename}-{target.target_kernel}",
                "target_node_id": target.target_node_id,
                "target_name": target.target_name,
                "target_node": f"{target.target_ssh_user}@{target.target_ip}",
                "target_ip": target.target_ip,
                "target_hostname": target.target_hostname,
                "target_os_id": target.target_os_id,
                "target_os": target.target_os_pretty,
                "target_kernel": target.target_kernel,
                "target_debian_codename": target.target_os_codename if target.target_os_id == "debian" else None,
                "target_ubuntu_codename": target.target_os_codename if target.target_os_id == "ubuntu" else None,
                "target_architecture": target.target_architecture or "amd64",
                "target_kernel_package_version": target.target_kernel_package_version,
                "builder_node_id": target.builder_node_id,
                "builder_node": f"{target.builder_ssh_user}@{target.builder_ip}",
                "builder_ip": target.builder_ip,
                "builder_hostname": target.builder_hostname,
                "local_symbol": str(local_symbol_path),
                "sha256": sha256,
                "size_bytes": local_symbol_path.stat().st_size,
                "generated_utc": _utc_now(),
                "generation_mode": (
                    "builder_monitor_node_debian_direct_download_no_repo_no_wazuh"
                    if target.target_os_id == "debian"
                    else "builder_monitor_node_ubuntu_direct_download_no_repo_no_wazuh"
                ),
                "debug_package": env.get("PKG_FILE"),
                "debug_package_url": env.get("PKG_URL"),
                "remote_vmlinux": env.get("VMLINUX"),
                "system_map_used": env.get("SYSTEMMAP_USED"),
                "wazuh_touched": "no",
                "builder_large_temp_files_cleaned": "pending",
                "source_case_id": case_id,
                "source_memory_artifact_id": target.memory_artifact_id,
                "mode": mode,
            }
            metadata_json_path = SYMBOL_METADATA_DIR / f"{symbol_filename}.metadata.json"
            metadata_txt_path = SYMBOL_METADATA_DIR / f"{symbol_filename}.metadata.txt"
            _write_json(metadata_json_path, metadata)
            metadata_txt_path.write_text("\n".join(f"{k}={v}" for k, v in metadata.items() if v not in (None, "")) + "\n", encoding="utf-8")
            return {
                "status": "completed",
                "target_node": target.target_name,
                "kernel": target.target_kernel,
                "os_id": target.target_os_id,
                "symbol_path": str(local_symbol_path),
                "sha256": sha256,
                "metadata_path": str(metadata_json_path),
                "source_package": env.get("PKG_FILE"),
                "source_package_url": env.get("PKG_URL"),
                "system_map_used": env.get("SYSTEMMAP_USED"),
            }
        finally:
            try:
                _remote_run(target.builder_ssh_user, target.builder_ip, target.ssh_key_path, "rm -rf \"$1\"\n", [builder_work])
            except Exception:
                pass
            shutil.rmtree(host_tmp, ignore_errors=True)


def _plugin_outcome(text: str, exit_code: int, symbol_dependent: bool) -> str:
    lowered = (text or "").lower()
    if exit_code == 0 and "unsatisfied requirement" not in lowered and "unable to validate plugin requirements" not in lowered:
        return "success"
    if symbol_dependent and ("symbol_table_name" in lowered or "layer_name" in lowered or "unsatisfied requirement" in lowered):
        return "partial_missing_symbols"
    if "invalid" in lowered and "dump" in lowered:
        return "failed_invalid_dump"
    return "failed_plugin_error"


class MemoryAnalysisService:
    def __init__(self, inventory: SymbolInventoryService | None = None, resolver: SymbolResolverService | None = None, generator: SymbolGenerationService | None = None):
        self.inventory = inventory or SymbolInventoryService()
        self.resolver = resolver or SymbolResolverService(self.inventory)
        self.generator = generator or SymbolGenerationService(self.inventory, self.resolver)

    def analyze(self, *, case_id: str, memory_artifact_id: str | None, auto_generate_symbols: bool, overwrite_symbols: bool = False) -> dict:
        target = self.resolver.resolve_target(case_id, memory_artifact_id)
        status = self.resolver.resolve_status(case_id, memory_artifact_id)
        case_dir = target.case_dir
        memory_dir = case_dir / "memory"
        out_dir = memory_dir / f"volatility_results_{target.target_ip or target.target_node_id or 'unknown'}"
        out_dir.mkdir(parents=True, exist_ok=True)
        preflight_path = memory_dir / "memory_preflight.json"
        findings_path = memory_dir / "memory_findings.json"
        preflight = {
            "case_id": case_id,
            "memory_artifact_id": target.memory_artifact_id,
            "memory_dumps_found": len(_list_memory_dumps(case_dir)),
            "dump_path": str(target.dump_path),
            "dump_size": target.dump_path.stat().st_size if target.dump_path.exists() else None,
            "dump_sha256": target.metadata.get("sha256"),
            "source_node": target.target_name,
            "source_node_id": target.target_node_id,
            "detected_os": target.target_os_id,
            "detected_kernel": target.target_kernel,
            "symbol_search_paths": [str(SYMBOL_ROOT), str(SYMBOL_LINUX_DIR)],
            "symbols_found": bool(status.get("symbol_candidates")),
            "symbol_candidates": status.get("symbol_candidates") or [],
            "volatility3_available": bool(_vol_cmd()),
            "volatility3_version": _vol_version(),
            "analysis_possible": bool(status.get("symbol_candidates")),
            "blocking_reason": status.get("reason") if not status.get("symbol_candidates") else None,
            "warnings": [],
        }
        _write_json(preflight_path, preflight)
        if not status.get("symbol_candidates") and auto_generate_symbols:
            generation = self.generator.generate(case_id=case_id, memory_artifact_id=memory_artifact_id, overwrite=overwrite_symbols, mode="auto")
            if generation.get("status") == "completed":
                status = self.resolver.resolve_status(case_id, memory_artifact_id)
                preflight["symbols_found"] = bool(status.get("symbol_candidates"))
                preflight["symbol_candidates"] = status.get("symbol_candidates") or []
                preflight["analysis_possible"] = bool(status.get("symbol_candidates"))
                preflight["blocking_reason"] = None if status.get("symbol_candidates") else preflight["blocking_reason"]
                _write_json(preflight_path, preflight)
        if not status.get("symbol_candidates"):
            findings = {
                "status": "failed",
                "analysis_completed": False,
                "reason": "missing_linux_symbols",
                "blocking_errors": [status.get("reason")],
                "symbols_required": True,
                "symbols_found": False,
                "recommended_action": "Generate Volatility Symbols and rerun memory analysis.",
                "memory_preflight": str(preflight_path),
            }
            _write_json(findings_path, findings)
            return {
                "analysis_status": "blocked",
                "reason": "missing_linux_symbols",
                "kernel": target.target_kernel,
                "node": target.target_name,
                "action": "generate_symbols_available",
                "memory_preflight_path": str(preflight_path),
                "memory_findings_path": str(findings_path),
            }
        symbol_path = status["symbol_candidates"][0]["path"]
        vol = _vol_cmd()
        plugins = []
        completed = []
        failed = []
        for plugin_key, plugin_name in VOL3_PLUGIN_SPECS:
            out_file = out_dir / f"{plugin_key}.txt"
            command = [vol, "-s", str(SYMBOL_ROOT), "-f", str(target.dump_path), plugin_name]
            try:
                proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)
                combined = "\n".join(part for part in [proc.stdout, proc.stderr] if part)
                outcome = _plugin_outcome(combined, proc.returncode, plugin_key != "banners")
                exit_code = proc.returncode
            except subprocess.TimeoutExpired as exc:
                combined = (exc.stdout or "") + ("\n" + exc.stderr if exc.stderr else "")
                if not combined.strip():
                    combined = f"Plugin timed out after 600 seconds: {plugin_name}"
                outcome = "failed_timeout"
                exit_code = 124
            out_file.write_text(combined, encoding="utf-8")
            entry = {
                "plugin": plugin_name,
                "key": plugin_key,
                "command": command,
                "exit_code": exit_code,
                "output_file": str(out_file),
                "status": outcome,
            }
            plugins.append(entry)
            if outcome == "success":
                completed.append(plugin_key)
            else:
                failed.append(plugin_key)
        if len(completed) == len(VOL3_PLUGIN_SPECS):
            findings_status = "completed"
            analysis_status = "success"
        elif any(entry["status"] == "partial_missing_symbols" for entry in plugins):
            findings_status = "partial"
            analysis_status = "partial_missing_symbols"
        elif any(entry["status"] == "failed_timeout" for entry in plugins):
            findings_status = "failed"
            analysis_status = "failed_timeout"
        elif any(entry["status"] == "failed_invalid_dump" for entry in plugins):
            findings_status = "failed"
            analysis_status = "failed_invalid_dump"
        else:
            findings_status = "failed" if not completed else "partial"
            analysis_status = "failed_plugin_error"
        findings = {
            "status": findings_status,
            "analysis_status": analysis_status,
            "analysis_completed": findings_status == "completed",
            "completed_plugins": completed,
            "failed_plugins": failed,
            "partial_findings": [] if findings_status == "completed" else [{"available_plugins": completed}],
            "limitations": [] if findings_status == "completed" else ["Some Volatility plugins did not complete successfully."],
            "tools_used": ["volatility3"],
            "tool_versions": {"volatility3": _vol_version()},
            "input_artifacts": [str(target.dump_path)],
            "output_files": [entry["output_file"] for entry in plugins],
            "selected_symbol": symbol_path,
        }
        _write_json(findings_path, findings)
        return {
            "analysis_status": analysis_status,
            "kernel": target.target_kernel,
            "node": target.target_name,
            "memory_preflight_path": str(preflight_path),
            "memory_findings_path": str(findings_path),
            "output_dir": str(out_dir),
            "plugins": plugins,
            "selected_symbol": symbol_path,
        }


def symbols_inventory_payload(case_id: str | None = None) -> dict:
    inventory = SymbolInventoryService()
    resolver = SymbolResolverService(inventory)
    payload = {
        "generated_utc": _utc_now(),
        "symbol_root": str(SYMBOL_ROOT),
        "linux_dir": str(SYMBOL_LINUX_DIR),
        "metadata_dir": str(SYMBOL_METADATA_DIR),
        "symbols": inventory.list_symbols(),
    }
    if case_id:
        case_dir = _case_dir(case_id)
        dumps = []
        if case_dir:
            for dump in _list_memory_dumps(case_dir):
                try:
                    dumps.append(resolver.resolve_status(case_id, dump["memory_artifact_id"]))
                except Exception as exc:
                    dumps.append(
                        {
                            "status": "symbol_generation_failed",
                            "memory_artifact_id": dump["memory_artifact_id"],
                            "reason": str(exc),
                        }
                    )
        payload["case_id"] = case_id
        payload["dumps"] = dumps
    return payload


def start_symbol_generation_job(*, case_id: str, memory_artifact_id: str | None, overwrite: bool, mode: str) -> dict:
    resolver = SymbolResolverService(SymbolInventoryService())
    target = resolver.resolve_target(case_id, memory_artifact_id)
    job = _create_job(
        "symbol_generation",
        {
            "case_id": case_id,
            "memory_artifact_id": target.memory_artifact_id,
            "target_node": target.target_name,
            "target_node_id": target.target_node_id,
            "kernel": target.target_kernel,
            "os_id": target.target_os_id,
            "builder_node": target.builder_name,
            "builder_node_id": target.builder_node_id,
            "mode": mode,
            "overwrite": overwrite,
        },
    )
    service = SymbolGenerationService()

    def runner() -> None:
        try:
            _set_status(job["job_id"], "running")
            _set_step(job["job_id"], "reading_target_info", "running", f"Resolving target dump {target.memory_artifact_id}")
            _append_log(job["job_id"], f"Target node: {target.target_name} ({target.target_ip})")
            _set_step(job["job_id"], "reading_target_info", "completed", f"{target.target_os_id} {target.target_kernel}")
            _set_step(job["job_id"], "checking_existing_symbols", "running", "Checking host symbol inventory")
            existing = service.inventory.find_compatible(kernel=target.target_kernel, os_id=target.target_os_id, codename=target.target_os_codename)
            if existing and not overwrite:
                _set_step(job["job_id"], "checking_existing_symbols", "completed", f"Existing symbol reused: {existing[0]['path']}")
                _set_status(job["job_id"], "completed", symbol_path=existing[0]["path"], sha256=existing[0].get("sha256"), result="reused_existing_symbol")
                return
            _set_step(job["job_id"], "checking_existing_symbols", "completed", "No reusable symbol found; generation required")
            for step in ("preparing_builder", "downloading_debug_package", "extracting_vmlinux", "generating_isf", "compressing_symbol", "copying_to_host", "writing_metadata", "cleaning_builder"):
                _set_step(job["job_id"], step, "running", "")
            result = service.generate(case_id=case_id, memory_artifact_id=target.memory_artifact_id, overwrite=overwrite, mode=mode)
            _set_step(job["job_id"], "preparing_builder", "completed", f"Builder: {target.builder_name} ({target.builder_ip})")
            _set_step(job["job_id"], "downloading_debug_package", "completed", result.get("source_package") or "downloaded")
            _set_step(job["job_id"], "extracting_vmlinux", "completed", "vmlinux extracted on builder")
            _set_step(job["job_id"], "generating_isf", "completed", "dwarf2json completed")
            _set_step(job["job_id"], "compressing_symbol", "completed", result.get("symbol_path", "compressed"))
            _set_step(job["job_id"], "copying_to_host", "completed", result.get("symbol_path", "copied"))
            _set_step(job["job_id"], "writing_metadata", "completed", result.get("metadata_path", "metadata written"))
            _set_step(job["job_id"], "cleaning_builder", "completed", "temporary builder workspace cleaned")
            _set_status(job["job_id"], "completed", **result)
        except Exception as exc:
            _append_log(job["job_id"], f"[ERROR] {exc}")
            _set_status(job["job_id"], "failed", error=str(exc))

    threading.Thread(target=runner, daemon=True).start()
    return job


def start_memory_analysis_job(*, case_id: str, memory_artifact_id: str | None, auto_generate_symbols: bool, overwrite_symbols: bool = False) -> dict:
    resolver = SymbolResolverService(SymbolInventoryService())
    target = resolver.resolve_target(case_id, memory_artifact_id)
    job = _create_job(
        "memory_analysis",
        {
            "case_id": case_id,
            "memory_artifact_id": target.memory_artifact_id,
            "target_node": target.target_name,
            "target_node_id": target.target_node_id,
            "kernel": target.target_kernel,
            "auto_generate_symbols": auto_generate_symbols,
            "overwrite_symbols": overwrite_symbols,
        },
    )
    service = MemoryAnalysisService()

    def runner() -> None:
        try:
            _set_status(job["job_id"], "running")
            for step_key in (
                "preflight_validation",
                "evidence_inventory",
                "memory_dump_discovery",
                "volatility3_availability_check",
                "symbol_discovery",
                "memory_analysis_execution",
                "output_validation",
                "report_generation",
            ):
                _set_step(job["job_id"], step_key, "pending", "")
            _set_step(job["job_id"], "preflight_validation", "running", "Resolving dump and node context")
            _set_step(job["job_id"], "preflight_validation", "completed", target.memory_artifact_id)
            _set_step(job["job_id"], "evidence_inventory", "completed", str(target.dump_path))
            _set_step(job["job_id"], "memory_dump_discovery", "completed", target.memory_artifact_id)
            _set_step(job["job_id"], "volatility3_availability_check", "completed" if _vol_cmd() else "failed", _vol_version())
            _set_step(job["job_id"], "symbol_discovery", "running", "Checking compatible symbols")
            result = service.analyze(
                case_id=case_id,
                memory_artifact_id=memory_artifact_id,
                auto_generate_symbols=auto_generate_symbols,
                overwrite_symbols=overwrite_symbols,
            )
            if result.get("analysis_status") == "blocked":
                _set_step(job["job_id"], "symbol_discovery", "failed", result.get("reason") or "missing symbols")
                _set_status(job["job_id"], "blocked", **result)
                return
            _set_step(job["job_id"], "symbol_discovery", "completed", result.get("selected_symbol") or "symbol resolved")
            _set_step(job["job_id"], "memory_analysis_execution", "completed", result.get("output_dir") or "plugins executed")
            _set_step(job["job_id"], "output_validation", "completed", result.get("memory_findings_path") or "validated")
            _set_step(job["job_id"], "report_generation", "completed", result.get("memory_preflight_path") or "report written")
            _set_status(job["job_id"], "completed", **result)
        except Exception as exc:
            _append_log(job["job_id"], f"[ERROR] {exc}")
            _set_status(job["job_id"], "failed", error=str(exc))

    threading.Thread(target=runner, daemon=True).start()
    return job
