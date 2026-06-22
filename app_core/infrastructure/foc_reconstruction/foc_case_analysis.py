import json
import logging
import os
import shlex
import shutil
import subprocess
import threading
import time
import uuid
import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .foc_config import HASH_REASONABLE_BINARY_MAX_BYTES
from .foc_hashing import hash_file
from .foc_manifest_manager import read_generated_json, regenerate_foc
from .foc_paths import project_path, relative_path
from .foc_sources import utc_now

logger = logging.getLogger(__name__)

CASE_ROOT = project_path("app_core", "infrastructure", "forensics", "evidence_store")
FORENSICS_SCRIPTS_DIR = project_path("app_core", "infrastructure", "forensics", "scripts")
PROJECT_SCRIPT_DIR = project_path()
VOL3_SYMBOLS_DIR = project_path("app_core", "infrastructure", "forensics", "volatility_symbol_store", "linux")
MEMORY_PLUGIN_SPECS = [
    {"key": "banners", "plugin": "banners.Banners", "filename": "vol3_banners.txt", "symbol_dependent": False},
    {"key": "pslist", "plugin": "linux.pslist.PsList", "filename": "vol3_pslist.txt", "symbol_dependent": True},
    {"key": "sockstat", "plugin": "linux.sockstat.Sockstat", "filename": "vol3_sockstat.txt", "symbol_dependent": True},
    {"key": "lsmod", "plugin": "linux.lsmod.Lsmod", "filename": "vol3_lsmod.txt", "symbol_dependent": True},
    {"key": "check_syscall", "plugin": "linux.check_syscall.Check_syscall", "filename": "vol3_check_syscall.txt", "symbol_dependent": True},
    {"key": "bash", "plugin": "linux.bash.Bash", "filename": "vol3_bash.txt", "symbol_dependent": True},
]
MEMORY_OUTPUT_ROOT = "04_memory"
MEMORY_LEGACY_OUTPUT_ROOT = "vol3"
SYMBOL_FILENAME_SUFFIXES = (".json", ".json.xz", ".zip", ".isf")

ANALYSIS_PHASES = [
    ("preflight_validation", "Pre-flight validation", None),
    ("evidence_inventory", "Evidence inventory", "00_inventory/evidence_inventory.json"),
    ("integrity_custody_validation", "Integrity and custody validation", "01_integrity_custody/integrity_custody_report.json"),
    ("temporal_validation", "Temporal validation", "02_time_validation/clock_offset_report.json"),
    ("network_analysis", "Network analysis", "03_network/network_findings.json"),
    ("memory_analysis", "Memory analysis", "04_memory/memory_findings.json"),
    ("disk_analysis", "Disk analysis", "05_disk/disk_findings.json"),
    ("ot_export_analysis", "OT export analysis", "06_ot/ot_findings.json"),
    ("alerts_detection_analysis", "Alerts and detection analysis", "07_alerts/alert_findings.json"),
    ("pipeline_custody_analysis", "Pipeline and custody analysis", "08_pipeline_custody/pipeline_findings.json"),
    ("unified_forensic_timeline", "Unified forensic timeline", "09_timeline/unified_forensic_timeline.json"),
    ("cross_layer_findings", "Cross-layer findings", "10_findings/cross_layer_findings.json"),
    ("forensic_analysis_report_generation", "Forensic Analysis Report generation", "forensic_analysis_report.json"),
    ("foc_readiness_update", "FOC readiness update", "foc_readiness_update.json"),
]

_ANALYSIS_STATE_LOCK = threading.Lock()
_RUNNING_ANALYSES: dict[str, threading.Thread] = {}


def _json_load(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _jsonl_load(path: Path) -> list[dict]:
    out: list[dict] = []
    if not path.is_file():
        return out
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                out.append(payload)
    return out


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)
    tmp.replace(path)


def _safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "item"))


def _parse_ts(value) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    if normalized.endswith("+0000") or normalized.endswith("-0000"):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _which(*candidates: str) -> str | None:
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _ensure_symbol_store() -> dict:
    """Ensure VOL3_SYMBOLS_DIR exists and is writable. Returns dict with status info."""
    out = {"path": str(VOL3_SYMBOLS_DIR), "exists": False, "writable": False}
    try:
        VOL3_SYMBOLS_DIR.mkdir(parents=True, exist_ok=True)
        out["exists"] = True
        try:
            VOL3_SYMBOLS_DIR.chmod(0o755)
        except Exception:
            pass
        out["writable"] = os.access(VOL3_SYMBOLS_DIR, os.W_OK)
    except Exception:
        out["exists"] = VOL3_SYMBOLS_DIR.exists()
        out["writable"] = False
    return out


def _shell_join(command: list[str]) -> str:
    try:
        return shlex.join(command)
    except Exception:
        return " ".join(command)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _message_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, dict):
        preferred = value.get("message") or value.get("error_message") or value.get("reason") or value.get("phase")
        return [str(preferred)] if preferred is not None else [json.dumps(value, ensure_ascii=False, sort_keys=True)]
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(_message_list(item))
        return [item for item in out if item]
    return [str(value)]


def _volatility_version() -> str:
    python3 = _which("python3")
    if python3:
        candidates = [
            "import volatility3, sys; print(getattr(volatility3, '__version__', 'unknown'))",
            "from volatility3.framework import constants; print(getattr(constants, 'PACKAGE_VERSION', 'unknown'))",
        ]
        for snippet in candidates:
            try:
                proc = subprocess.run([python3, "-c", snippet], capture_output=True, text=True, check=False)
            except Exception:
                continue
            value = (proc.stdout or "").strip() or (proc.stderr or "").strip()
            if proc.returncode == 0 and value:
                return value
    vol_cmd = _which("volatility3", "vol")
    if vol_cmd:
        try:
            proc = subprocess.run([vol_cmd, "-h"], capture_output=True, text=True, check=False)
        except Exception:
            proc = None
        if proc:
            combined = "\n".join(part for part in [proc.stdout, proc.stderr] if part)
            match = re.search(r"Volatility 3 Framework\s+([0-9.]+)", combined)
            if match:
                return match.group(1)
    return "unknown"


def _memory_output_dir(case_dir: Path, dump_id: str) -> Path:
    return _analysis_dir(case_dir) / MEMORY_OUTPUT_ROOT / dump_id


def _memory_legacy_output_dir(case_dir: Path, dump_id: str) -> Path:
    return _analysis_dir(case_dir) / MEMORY_LEGACY_OUTPUT_ROOT / dump_id


def _symbol_search_roots() -> list[Path]:
    roots: list[Path] = []
    env_candidates = []
    for key in ("VOLATILITY_SYMBOL_PATH", "VOLATILITY3_SYMBOL_PATH", "VOL3_SYMBOLS_DIR", "VOLATILITY_SYMBOL_DIRS"):
        raw = str(os.environ.get(key) or "").strip()
        if raw:
            env_candidates.extend(part for part in re.split(r"[;:]", raw) if part.strip())
    for raw in env_candidates:
        roots.append(Path(raw).expanduser())
    roots.extend(
        [
            VOL3_SYMBOLS_DIR,
            VOL3_SYMBOLS_DIR.parent,
            project_path("app_core", "infrastructure", "forensics", "volatility_symbol_store"),
            project_path("app_core", "infrastructure", "forensics", "volatility_symbol_store", "linux"),
            Path.home() / "vol3_symbols_cache",
            Path.home() / "vol3_symbols_cache" / "symbols",
            Path.home() / ".cache" / "volatility3",
            Path.home() / ".cache" / "volatility3" / "symbols",
            Path.home() / "volatility3",
            Path.home() / "volatility3" / "symbols",
            project_path("symbols"),
            project_path("foc-reconstruction", "symbols"),
            project_path("app_core", "infrastructure", "forensics", "symbols"),
        ]
    )
    seen: set[str] = set()
    out: list[Path] = []
    for root in roots:
        normalized = str(root)
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(root)
    return out


def _discover_symbol_files() -> tuple[list[str], list[Path]]:
    checked: list[str] = []
    files: list[Path] = []
    seen_files: set[str] = set()
    for root in _symbol_search_roots():
        checked.append(str(root))
        if root.is_file():
            if root.name.endswith(SYMBOL_FILENAME_SUFFIXES):
                files.append(root)
            continue
        if not root.is_dir():
            continue
        for suffix in SYMBOL_FILENAME_SUFFIXES:
            for candidate in root.rglob(f"*{suffix}"):
                normalized = str(candidate)
                if normalized in seen_files:
                    continue
                seen_files.add(normalized)
                files.append(candidate)
    return checked, sorted(files)


def _symbol_kernel_name(path: Path) -> str:
    name = path.name
    for suffix in (".json.xz", ".json", ".zip", ".isf"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def _parse_linux_banner(text: str) -> tuple[str | None, str | None]:
    for line in text.splitlines():
        if "Linux version " not in line:
            continue
        kernel_match = re.search(r"Linux version\s+([^\s]+)", line)
        kernel = kernel_match.group(1).strip() if kernel_match else None
        distro = None
        if "Ubuntu" in line:
            distro = "Ubuntu"
        elif "Debian" in line:
            distro = "Debian"
        elif "CentOS" in line:
            distro = "CentOS"
        elif "Red Hat" in line or "RHEL" in line:
            distro = "RHEL"
        elif "SUSE" in line:
            distro = "SUSE"
        return distro, kernel
    return None, None


def _matching_symbol_files(kernel: str | None, symbol_files: list[Path]) -> list[Path]:
    if not kernel:
        return []
    exact = [path for path in symbol_files if _symbol_kernel_name(path) == kernel]
    if exact:
        return exact
    partial = [path for path in symbol_files if kernel in path.name or _symbol_kernel_name(path) in kernel]
    return partial


def _symbols_manifest_path() -> Path:
    # manifest lives next to the linux symbols directory (parent)
    parent = VOL3_SYMBOLS_DIR.parent
    return parent / "symbols_manifest.json"


def _update_symbols_manifest(kernel_name: str, source: str, path: Path) -> None:
    manifest_path = _symbols_manifest_path()
    try:
        manifest = _json_load(manifest_path) or {}
    except Exception:
        manifest = {}
    if not isinstance(manifest, dict):
        manifest = {}
    entries = manifest.get("symbols") or []
    entry = {"kernel": kernel_name, "source": source, "path": str(path), "generated_at": utc_now()}
    # avoid duplicates
    if not any(e.get("kernel") == kernel_name and e.get("path") == str(path) for e in entries):
        entries.append(entry)
    manifest["symbols"] = entries
    try:
        _write_json(manifest_path, manifest)
    except Exception:
        pass


def _find_local_vmlinux_candidates(case_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    # look in common places inside the case (disk analysis outputs, metadata, extracted files)
    for p in (
        case_dir.rglob("vmlinux*"),
        case_dir.rglob("*vmlinux*.elf"),
        case_dir.rglob("System.map*"),
        case_dir.rglob("*vmlinux*.bin"),
    ):
        for path in p:
            if path.is_file():
                candidates.append(path)
    # dedupe
    out = []
    seen = set()
    for c in candidates:
        if str(c) in seen:
            continue
        seen.add(str(c))
        out.append(c)
    return out


def _generate_symbol_from_vmlinux(case_dir: Path, detected_kernel: str | None) -> Path | None:
    """Attempt to generate a volatility symbol JSON for detected_kernel using local vmlinux and dwarf2json.
    Returns the generated symbol path or None."""
    dwarf = _which("dwarf2json")
    if not dwarf:
        return None
    if not detected_kernel:
        return None
    # prepare output dir
    try:
        VOL3_SYMBOLS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    try:
        VOL3_SYMBOLS_DIR.chmod(0o755)
    except Exception:
        pass
    out_path = VOL3_SYMBOLS_DIR / f"{detected_kernel}.json"
    # if already exists, return
    if out_path.exists():
        return out_path
    # find candidates in case dir
    for candidate in _find_local_vmlinux_candidates(case_dir):
        # run dwarf2json linux --elf <candidate> > out_path
        try:
            cmd = [dwarf, "linux", "--elf", str(candidate)]
            tmp_out = out_path.with_suffix(".tmp")
            with tmp_out.open("w", encoding="utf-8") as fh:
                proc = subprocess.run(cmd, cwd=str(case_dir), stdout=fh, stderr=subprocess.PIPE, text=True)
            if proc.returncode == 0:
                tmp_out.replace(out_path)
                _update_symbols_manifest(detected_kernel, "generated_from_case_vmlinux", out_path)
                return out_path
        except Exception:
            continue
    return None


def _generate_symbol_via_ssh(case_dir: Path, output_dir: Path, dump_file: Path, detected_kernel: str | None, metadata: dict) -> dict | None:
    """Run the `generate_vol3_symbols_ssh.sh` helper with credentials from metadata if available.
    Writes a `symbol_generation_report.json` in `output_dir` and returns the report dict, or None
    if not attempted.
    """
    script = FORENSICS_SCRIPTS_DIR / "generate_vol3_symbols_ssh.sh"
    if not script.is_file():
        return None

    # look for explicit creds file
    creds_path = case_dir / "metadata" / "vm_ssh_credentials.json"
    ssh_user = None
    ssh_key = None
    vm_ip = None
    vm_id = None
    if creds_path.is_file():
        try:
            creds = _json_load(creds_path) or {}
            ssh_user = creds.get("ssh_user")
            ssh_key = creds.get("ssh_key")
            vm_ip = creds.get("vm_ip")
            vm_id = creds.get("vm_id")
        except Exception:
            pass

    # fallback to dump metadata
    vm_ip = vm_ip or metadata.get("vm_ip") or metadata.get("ip")
    vm_id = vm_id or metadata.get("vm_id")

    # environment fallbacks
    ssh_user = ssh_user or os.environ.get("VOL3_SYMBOLS_SSH_USER")
    ssh_key = ssh_key or os.environ.get("VOL3_SYMBOLS_SSH_KEY")

    if not vm_ip or not ssh_user or not ssh_key:
        return None

    stdout_path = output_dir / "symbol_generation.stdout.log"
    stderr_path = output_dir / "symbol_generation.stderr.log"
    report_path = output_dir / "symbol_generation_report.json"

    cmd = ["bash", str(script), str(case_dir), str(vm_id or ""), str(vm_ip), str(ssh_user), str(ssh_key)]
    rc, _ = _run_command(cmd, case_dir, stdout_path, stderr_path)

    # refresh symbol discovery
    _, symbol_files = _discover_symbol_files()
    matched = _matching_symbol_files(detected_kernel, symbol_files)

    report = {
        "command": cmd,
        "command_text": _shell_join(cmd),
        "exit_code": rc,
        "stdout_path": relative_path(stdout_path),
        "stderr_path": relative_path(stderr_path),
        "matched": bool(matched),
        "matched_symbols": [str(p) for p in matched],
        "generated_at": utc_now(),
    }
    try:
        _write_json(report_path, report)
    except Exception:
        pass

    # update manifest for new matches
    for p in matched:
        try:
            _update_symbols_manifest(_symbol_kernel_name(p), "generated_via_ssh", p)
        except Exception:
            pass

    return report


def _extract_unsatisfied_requirements(text: str) -> list[str]:
    requirements = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Unsatisfied requirement"):
            requirements.append(stripped)
    return requirements


def _symbol_table_status_from_text(text: str) -> str:
    if "kernel.symbol_table_name" in text:
        return "missing_symbol_table"
    if "symbol_table_name" in text:
        return "symbol_table_requirement_failed"
    return "resolved_or_not_required"


def _kernel_layer_status_from_text(text: str) -> str:
    if "kernel.layer_name" in text:
        return "missing_kernel_layer"
    if "layer_name" in text:
        return "kernel_layer_requirement_failed"
    return "resolved_or_not_required"


def _suggest_memory_fix(plugin_result: dict, preflight_dump: dict) -> str:
    if plugin_result.get("missing_requirement"):
        kernel = preflight_dump.get("detected_kernel") or "unknown_kernel"
        return (
            "Provide a Volatility 3 Linux symbol file matching "
            f"`{kernel}` in one of the checked local symbol directories and rerun memory analysis."
        )
    if not plugin_result.get("analysis_possible", True):
        return "Review the memory pre-flight report and verify Volatility 3, dump readability and local symbol paths."
    return "Inspect the exact stdout/stderr paths for this plugin and rerun the plugin manually for deeper debugging."


def _extract_output_summary(text: str, plugin_key: str) -> dict:
    lines = [line for line in text.splitlines() if line.strip()]
    if plugin_key == "pslist":
        return {"processes_extracted": max(0, len(lines) - 1)}
    if plugin_key == "sockstat":
        return {"sockets_extracted": max(0, len(lines) - 1)}
    if plugin_key == "lsmod":
        return {"modules_extracted": max(0, len(lines) - 1)}
    if plugin_key == "bash":
        return {"bash_history_entries": max(0, len(lines) - 1)}
    if plugin_key == "banners":
        return {"banners_detected": sum(1 for line in lines if "Linux version " in line)}
    return {}


def _manifest_artifact_map(case_dir: Path) -> dict[str, dict]:
    manifest = _json_load(case_dir / "manifest.json") or {}
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    out: dict[str, dict] = {}
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if not isinstance(artifact, dict):
            continue
        rel_path = str(artifact.get("rel_path") or "").strip()
        if rel_path:
            out[rel_path] = artifact
    return out


def _custody_entries_for_artifact(case_dir: Path, rel_path: str) -> list[dict]:
    entries = []
    accepted = {str(rel_path or "").strip()}
    if accepted == {""}:
        accepted = set()
    prefixed = relative_path(case_dir / rel_path) if rel_path else None
    if prefixed:
        accepted.add(prefixed)
    for event in _jsonl_load(case_dir / "chain_of_custody.log"):
        if str(event.get("artifact_rel") or "").strip() in accepted:
            entries.append(event)
    return entries


def _dump_metadata(case_dir: Path, dump_file: Path) -> dict:
    metadata_path = case_dir / "metadata" / f"{dump_file.name}.metadata.json"
    payload = _json_load(metadata_path)
    return payload if isinstance(payload, dict) else {}


def _dump_identifier(dump_file: Path, metadata: dict) -> str:
    for candidate in (metadata.get("vm_id"), dump_file.stem):
        value = str(candidate or "").strip()
        if value:
            return _safe_slug(value)
    return _safe_slug(dump_file.name)


def _phase_labels() -> dict[str, str]:
    return {key: label for key, label, _ in ANALYSIS_PHASES}


def _phase_output_rel(phase_key: str) -> str | None:
    for key, _, rel in ANALYSIS_PHASES:
        if key == phase_key:
            return rel
    return None


def _case_dir_from_entry(case_entry: dict) -> Path:
    case_path = str(case_entry.get("path") or "").strip()
    if case_path:
        return project_path(*case_path.split("/"))
    return CASE_ROOT / str(case_entry.get("source_case_name") or "")


def _analysis_dir(case_dir: Path) -> Path:
    return case_dir / "analysis"


def _analysis_status_path(case_dir: Path) -> Path:
    return _analysis_dir(case_dir) / "analysis_status.json"


def _analysis_logs_dir(case_dir: Path) -> Path:
    return _analysis_dir(case_dir) / "logs"


def _analysis_visual_dir(case_dir: Path) -> Path:
    return _analysis_dir(case_dir) / "visual"


def _analysis_visual_summary_path(case_dir: Path) -> Path:
    return _analysis_visual_dir(case_dir) / "analysis_visual_summary.json"


def _phase_log_paths(case_dir: Path, phase_key: str) -> tuple[Path, Path]:
    base = _analysis_logs_dir(case_dir) / phase_key
    return base.with_suffix(".stdout.log"), base.with_suffix(".stderr.log")


def _phase_output_path(case_dir: Path, phase_key: str) -> Path | None:
    rel = _phase_output_rel(phase_key)
    if not rel:
        if phase_key == "preflight_validation":
            return _analysis_dir(case_dir) / "preflight_validation.json"
        return None
    return _analysis_dir(case_dir) / rel


def _first_nonempty(*values):
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value not in (None, "", [], {}, ()):
            return value
    return None


def _friendly_status_label(value: str | None) -> str:
    raw = str(value or "unknown").strip().replace("_", " ")
    if not raw:
        raw = "unknown"
    return raw[:1].upper() + raw[1:]


def _phase_payload(case_dir: Path, phase_key: str) -> dict:
    payload = _json_load(_phase_output_path(case_dir, phase_key) or Path())
    return payload if isinstance(payload, dict) else {}


def _phase_short_limitation(payload: dict, phase_status: str) -> str | None:
    return _first_nonempty(
        payload.get("not_executed_reason"),
        (_message_list(payload.get("errors")) or [None])[0],
        (_message_list(payload.get("limitations")) or [None])[0],
        phase_status,
    )


def _completed_has_useful_output(phase_key: str, payload: dict) -> tuple[bool, str | None]:
    findings = payload.get("findings")
    if phase_key == "memory_analysis":
        dump_results = payload.get("findings", {}).get("results") or []
        dumps_analyzed = int(payload.get("findings", {}).get("dumps_analyzed") or 0)
        completed_plugins = 0
        for item in dump_results:
            completed_plugins += len(item.get("completed_plugins") or [])
        if dumps_analyzed <= 0 or completed_plugins <= 0:
            return False, "Memory layer available and preflight passed, but no memory dump was effectively analyzed."
        return True, None
    if phase_key == "network_analysis":
        analyzed = int((findings or {}).get("pcaps_analyzed") or 0)
        return (analyzed > 0, None if analyzed > 0 else "Network phase completed but produced no effective PCAP analysis.")
    if phase_key == "disk_analysis":
        analyzed = int((findings or {}).get("disk_images_analyzed") or 0)
        return (analyzed > 0, None if analyzed > 0 else "Disk phase completed but produced no effective disk-image analysis.")
    if phase_key == "ot_export_analysis":
        files = (findings or {}).get("files") or []
        return (len(files) > 0, None if files else "OT export phase completed but produced no effective OT findings.")
    if phase_key == "alerts_detection_analysis":
        total = int((findings or {}).get("alerts_total") or 0)
        return (total > 0, None if total > 0 else "Alert-analysis phase completed but no effective preserved alerts were summarized.")
    if phase_key == "pipeline_custody_analysis":
        total = int((findings or {}).get("pipeline_events_total") or 0) + int((findings or {}).get("custody_events_total") or 0)
        return (total > 0, None if total > 0 else "Pipeline and custody phase completed but produced no effective event inventory.")
    if phase_key == "unified_forensic_timeline":
        rows = findings if isinstance(findings, list) else []
        return (len(rows) > 0, None if rows else "Unified forensic timeline phase completed but no effective timeline rows were generated.")
    if phase_key == "cross_layer_findings":
        rows = findings if isinstance(findings, list) else []
        return (len(rows) > 0, None if rows else "Cross-layer phase completed but produced no effective cross-layer findings.")
    if phase_key == "forensic_analysis_report_generation":
        return (bool(payload.get("analysis_status")), None if payload.get("analysis_status") else "Forensic report phase completed but no effective report status was produced.")
    if phase_key == "foc_readiness_update":
        return (bool((payload.get("findings") or {}).get("foc_manifest_updated_at")), None if (payload.get("findings") or {}).get("foc_manifest_updated_at") else "FOC readiness update completed but no effective refresh marker was produced.")
    if phase_key == "preflight_validation":
        return (bool(payload.get("findings")), None if payload.get("findings") else "Pre-flight validation completed but produced no effective findings.")
    if phase_key == "evidence_inventory":
        total = int((findings or {}).get("artifacts_total") or 0)
        return (total > 0, None if total > 0 else "Evidence inventory completed but no effective artifacts were indexed.")
    if phase_key == "integrity_custody_validation":
        return (bool(payload.get("findings")), None if payload.get("findings") else "Integrity and custody validation completed but produced no effective output.")
    if phase_key == "temporal_validation":
        return (bool(payload.get("findings")), None if payload.get("findings") else "Temporal validation completed but produced no effective output.")
    return (bool(findings) or bool(payload.get("tool_used")), None if (bool(findings) or bool(payload.get("tool_used"))) else "Completed phase produced no effective output.")


def _derive_phase_visual_state(phase_key: str, phase_status: str, payload: dict) -> tuple[str, str, str | None]:
    normalized = str(phase_status or "unknown")
    if normalized == "running":
        return "running", "running", _phase_short_limitation(payload, normalized)
    if normalized == "pending":
        return "pending", "pending", _phase_short_limitation(payload, normalized)
    if normalized.startswith("failed"):
        return "error", normalized, _phase_short_limitation(payload, normalized)
    if normalized.startswith("skipped"):
        return "unavailable", normalized, _phase_short_limitation(payload, normalized)
    if normalized.startswith("partial"):
        return "warning", normalized, _phase_short_limitation(payload, normalized)
    if normalized == "completed":
        useful, message = _completed_has_useful_output(phase_key, payload)
        if useful:
            return "success", "completed_with_useful_output", None
        if phase_key == "memory_analysis":
            return "warning", "completed_no_effective_memory_analysis", message
        return "warning", "completed_no_effective_output", message
    return "unavailable", normalized or "unknown", _phase_short_limitation(payload, normalized)


def _phase_visual_summary_text(phase_key: str, payload: dict) -> str:
    findings = payload.get("findings") or {}
    if phase_key == "evidence_inventory":
        return f"Artifacts indexed: {int(findings.get('artifacts_total') or 0)}"
    if phase_key == "network_analysis":
        return f"PCAPs analyzed: {int(findings.get('pcaps_analyzed') or 0)}"
    if phase_key == "memory_analysis":
        return f"Dumps analyzed: {int(findings.get('dumps_analyzed') or 0)}"
    if phase_key == "disk_analysis":
        return f"Disk images analyzed: {int(findings.get('disk_images_analyzed') or 0)}"
    if phase_key == "ot_export_analysis":
        return f"OT files: {len(findings.get('files') or [])}"
    if phase_key == "alerts_detection_analysis":
        return f"Alerts summarized: {int(findings.get('alerts_total') or 0)}"
    if phase_key == "pipeline_custody_analysis":
        return f"Pipeline events: {int(findings.get('pipeline_events_total') or 0)}, custody events: {int(findings.get('custody_events_total') or 0)}"
    if phase_key == "unified_forensic_timeline":
        return f"Timeline entries: {len(findings) if isinstance(findings, list) else 0}"
    if phase_key == "cross_layer_findings":
        return f"Cross-layer findings: {len(findings) if isinstance(findings, list) else 0}"
    if phase_key == "forensic_analysis_report_generation":
        return f"Report status: {payload.get('analysis_status') or payload.get('status') or 'unknown'}"
    if phase_key == "foc_readiness_update":
        return f"FOC manifest updated: {((payload.get('findings') or {}).get('foc_manifest_updated_at') or 'not_available')}"
    return _friendly_status_label(payload.get("status"))


def _build_pipeline_timeline_entries(status: dict) -> list[dict]:
    rows: list[dict] = []
    for phase_key, label, _ in ANALYSIS_PHASES:
        phase = (status.get("phases") or {}).get(phase_key) or {}
        rows.append(
            {
                "phase": phase_key,
                "label": label,
                "status": phase.get("status") or "pending",
                "started_at": phase.get("started_at"),
                "finished_at": phase.get("finished_at"),
                "stdout_path": phase.get("stdout_path"),
                "stderr_path": phase.get("stderr_path"),
                "artifact_path": phase.get("output_path"),
            }
        )
    return rows


def _build_forensic_timeline_entries(case_dir: Path) -> list[dict]:
    payload = _phase_payload(case_dir, "unified_forensic_timeline")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []
    rows = []
    for item in findings[:160]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "timestamp": item.get("timestamp"),
                "source": item.get("source"),
                "event": item.get("event"),
                "details": item.get("details") or {},
            }
        )
    return rows


def _analysis_visual_summary(case_entry: dict, case_dir: Path, status: dict) -> dict:
    report = _json_load(_analysis_dir(case_dir) / "forensic_analysis_report.json") or {}
    memory_findings = _phase_payload(case_dir, "memory_analysis")
    layer_statuses: dict[str, dict] = {}
    blockers: list[str] = []
    warnings: list[str] = []
    artifact_paths: dict[str, str | None] = {}
    stdout_log_paths: dict[str, str | None] = {}
    stderr_log_paths: dict[str, str | None] = {}

    for phase_key, label, _ in ANALYSIS_PHASES:
        phase = (status.get("phases") or {}).get(phase_key) or {}
        payload = _phase_payload(case_dir, phase_key)
        phase_status = str(phase.get("status") or "pending")
        visual_state, effective_status, limitation = _derive_phase_visual_state(phase_key, phase_status, payload)
        phase_warning = None
        if visual_state == "warning":
            phase_warning = limitation or _phase_short_limitation(payload, phase_status)
        summary = _phase_visual_summary_text(phase_key, payload)
        layer_statuses[phase_key] = {
            "phase": phase_key,
            "label": label,
            "status": phase_status,
            "effective_status": effective_status,
            "artifact_path": phase.get("output_path"),
            "stdout_log_path": phase.get("stdout_path"),
            "stderr_log_path": phase.get("stderr_path"),
            "warning": phase_warning,
            "visual_state": visual_state,
            "short_limitation": limitation,
            "summary": summary,
        }
        artifact_paths[phase_key] = phase.get("output_path")
        stdout_log_paths[phase_key] = phase.get("stdout_path")
        stderr_log_paths[phase_key] = phase.get("stderr_path")
        if visual_state == "error":
            blockers.append(f"{label}: {limitation or 'phase failed'}")
        elif visual_state == "warning":
            warnings.append(f"{label}: {phase_warning or 'limited output'}")

    memory_layer = layer_statuses.get("memory_analysis") or {}
    if memory_layer.get("effective_status") == "completed_no_effective_memory_analysis":
        blockers.append("Memory analysis finished, but no dump produced effective plugin results.")
    if "integrity_custody_validation" in (status.get("partial_phases") or []):
        blockers.append("Integrity or custody validation remains partial.")
    blockers.append("Semantic reconstruction has not been generated.")
    blockers.append("Causal reconstruction has not been generated.")

    success_count = sum(1 for item in layer_statuses.values() if item["visual_state"] == "success")
    warning_count = sum(1 for item in layer_statuses.values() if item["visual_state"] == "warning")
    error_count = sum(1 for item in layer_statuses.values() if item["visual_state"] == "error")

    if success_count == 0 and error_count == 0 and warning_count == 0:
        evidence_analysis_status = "not_started"
    elif error_count == 0 and warning_count == 0:
        evidence_analysis_status = "completed"
    elif success_count >= max(3, warning_count + error_count):
        evidence_analysis_status = "mostly_completed"
    else:
        evidence_analysis_status = "partial"

    forensic_reconstruction_status = "partial" if status.get("status") in {"completed", "partial", "running", "failed", "cancelled"} else "not_started"
    if status.get("status") == "not_started":
        forensic_reconstruction_status = "not_started"

    if error_count > 0 or "integrity_custody_validation" in (status.get("partial_phases") or []) or memory_layer.get("effective_status") == "completed_no_effective_memory_analysis":
        confidence_state = "limited"
    elif warning_count > 0:
        confidence_state = "constrained"
    else:
        confidence_state = "strong"

    main_limitation = _first_nonempty(
        blockers[0] if blockers else None,
        report.get("status_note"),
        "Pipeline execution completed, but forensic reconstruction remains partial because some layers are partial and semantic or causal reconstruction have not yet been generated.",
    )

    graph_nodes = [
        {"id": "case", "label": case_entry.get("source_case_name") or case_entry.get("case_id"), "type": "case", "status": status.get("status"), "visual_state": "success", "summary": "Selected forensic case."},
        {"id": "analysis_execution", "label": "Analysis execution", "type": "analysis", "status": status.get("status"), "visual_state": "success" if status.get("status") in {"completed", "partial"} else ("running" if status.get("status") == "running" else "warning"), "summary": f"Pipeline execution status: {status.get('status') or 'unknown'}"},
        {"id": "evidence_inventory", "label": "Evidence inventory", "type": "layer", "status": layer_statuses["evidence_inventory"]["effective_status"], "visual_state": layer_statuses["evidence_inventory"]["visual_state"], "summary": layer_statuses["evidence_inventory"]["summary"]},
        {"id": "integrity_custody_validation", "label": "Integrity and custody", "type": "layer", "status": layer_statuses["integrity_custody_validation"]["effective_status"], "visual_state": layer_statuses["integrity_custody_validation"]["visual_state"], "summary": layer_statuses["integrity_custody_validation"]["summary"]},
        {"id": "network_findings", "label": "Network findings", "type": "layer", "status": layer_statuses["network_analysis"]["effective_status"], "visual_state": layer_statuses["network_analysis"]["visual_state"], "summary": layer_statuses["network_analysis"]["summary"]},
        {"id": "disk_findings", "label": "Disk findings", "type": "layer", "status": layer_statuses["disk_analysis"]["effective_status"], "visual_state": layer_statuses["disk_analysis"]["visual_state"], "summary": layer_statuses["disk_analysis"]["summary"]},
        {"id": "memory_findings", "label": "Memory findings", "type": "layer", "status": layer_statuses["memory_analysis"]["effective_status"], "visual_state": layer_statuses["memory_analysis"]["visual_state"], "summary": layer_statuses["memory_analysis"]["summary"]},
        {"id": "ot_findings", "label": "OT findings", "type": "layer", "status": layer_statuses["ot_export_analysis"]["effective_status"], "visual_state": layer_statuses["ot_export_analysis"]["visual_state"], "summary": layer_statuses["ot_export_analysis"]["summary"]},
        {"id": "alert_findings", "label": "Alert findings", "type": "layer", "status": layer_statuses["alerts_detection_analysis"]["effective_status"], "visual_state": layer_statuses["alerts_detection_analysis"]["visual_state"], "summary": layer_statuses["alerts_detection_analysis"]["summary"]},
        {"id": "timeline", "label": "Unified timeline", "type": "layer", "status": layer_statuses["unified_forensic_timeline"]["effective_status"], "visual_state": layer_statuses["unified_forensic_timeline"]["visual_state"], "summary": layer_statuses["unified_forensic_timeline"]["summary"]},
        {"id": "cross_layer_findings", "label": "Cross-layer findings", "type": "layer", "status": layer_statuses["cross_layer_findings"]["effective_status"], "visual_state": layer_statuses["cross_layer_findings"]["visual_state"], "summary": layer_statuses["cross_layer_findings"]["summary"]},
        {"id": "reconstruction_blockers", "label": "Reconstruction blockers", "type": "blockers", "status": "present" if blockers else "none", "visual_state": "warning" if blockers else "success", "summary": f"Blockers: {len(blockers)}"},
    ]
    graph_edges = [
        {"from": "case", "to": "analysis_execution", "label": "drives"},
        {"from": "analysis_execution", "to": "evidence_inventory", "label": "produces"},
        {"from": "analysis_execution", "to": "integrity_custody_validation", "label": "produces"},
        {"from": "analysis_execution", "to": "network_findings", "label": "produces"},
        {"from": "analysis_execution", "to": "disk_findings", "label": "produces"},
        {"from": "analysis_execution", "to": "memory_findings", "label": "produces"},
        {"from": "analysis_execution", "to": "ot_findings", "label": "produces"},
        {"from": "analysis_execution", "to": "alert_findings", "label": "produces"},
        {"from": "analysis_execution", "to": "timeline", "label": "produces"},
        {"from": "analysis_execution", "to": "cross_layer_findings", "label": "produces"},
        {"from": "integrity_custody_validation", "to": "reconstruction_blockers", "label": "limits"},
        {"from": "memory_findings", "to": "reconstruction_blockers", "label": "limits"},
        {"from": "cross_layer_findings", "to": "reconstruction_blockers", "label": "informs"},
        {"from": "timeline", "to": "cross_layer_findings", "label": "supports"},
        {"from": "alert_findings", "to": "cross_layer_findings", "label": "supports"},
    ]

    visual_recommendations = []
    if memory_layer.get("effective_status") == "completed_no_effective_memory_analysis":
        visual_recommendations.append("Review preserved memory artifacts and verify that at least one dump produces effective Volatility plugin output before treating the memory layer as evidentially useful.")
    if "integrity_custody_validation" in (status.get("partial_phases") or []):
        visual_recommendations.append("Review integrity and custody outputs before assigning high scientific confidence to downstream interpretations.")
    if layer_statuses.get("unified_forensic_timeline", {}).get("visual_state") != "success":
        visual_recommendations.append("Regenerate or inspect the unified forensic timeline before treating cross-layer chronology as complete.")
    visual_recommendations.append("Semantic reconstruction is not generated in this stage.")
    visual_recommendations.append("Causal reconstruction remains blocked until dedicated causal artifacts are generated.")

    return {
        "case_id": case_entry.get("case_id"),
        "analysis_id": status.get("analysis_id"),
        "case_path": relative_path(case_dir),
        "started_at": status.get("started_at"),
        "finished_at": status.get("finished_at"),
        "progress_percent": status.get("progress_percent"),
        "execution_status": status.get("status"),
        "evidence_analysis_status": evidence_analysis_status,
        "forensic_reconstruction_status": forensic_reconstruction_status,
        "confidence_state": confidence_state,
        "main_limitation": main_limitation,
        "main_warnings": warnings[:12],
        "blockers": blockers[:16],
        "available_layers": status.get("available_layers") or {},
        "layer_statuses": layer_statuses,
        "artifact_paths": artifact_paths,
        "stdout_log_paths": stdout_log_paths,
        "stderr_log_paths": stderr_log_paths,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "pipeline_timeline_entries": _build_pipeline_timeline_entries(status),
        "forensic_timeline_entries": _build_forensic_timeline_entries(case_dir),
        "visual_recommendations": visual_recommendations,
        "generated_report_path": status.get("forensic_analysis_report_path") or (relative_path(_analysis_dir(case_dir) / "forensic_analysis_report.json") if (_analysis_dir(case_dir) / "forensic_analysis_report.json").exists() else None),
    }


def _refresh_analysis_visual_summary(case_dir: Path, status: dict) -> None:
    case_entry = get_case_entry(str(status.get("case_id")))
    if not case_entry:
        return
    payload = _analysis_visual_summary(case_entry, case_dir, status)
    _write_json(_analysis_visual_summary_path(case_dir), payload)


def _list_case_entries() -> list[dict]:
    cases_index = read_generated_json(project_path("foc-reconstruction", "indexes", "cases_index.json")) or {}
    cases = cases_index.get("cases") if isinstance(cases_index, dict) else None
    if isinstance(cases, list) and cases:
        return cases
    out = []
    for case_dir in sorted(CASE_ROOT.glob("CASE-*")):
        out.append(
            {
                "case_id": f"case-{hashlib.sha1(case_dir.name.encode('utf-8')).hexdigest()[:8]}",
                "source_case_name": case_dir.name,
                "path": relative_path(case_dir),
                "artifacts_count": 0,
                "manifest_path": f"{relative_path(case_dir)}/manifest.json",
                "pipeline_path": f"{relative_path(case_dir)}/metadata/pipeline_events.jsonl",
                "custody_path": f"{relative_path(case_dir)}/chain_of_custody.log",
                "target_node_ids": [],
                "target_instance_ids": [],
            }
        )
    return out


def get_case_entry(case_id: str) -> dict | None:
    for entry in _list_case_entries():
        if str(entry.get("case_id")) == str(case_id):
            return entry
    return None


def _artifact_inventory(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "manifest.json") or {}
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    artifacts = artifacts if isinstance(artifacts, list) else []
    counts = Counter(str(item.get("type") or "unknown") for item in artifacts if isinstance(item, dict))
    return {
        "manifest_present": (case_dir / "manifest.json").is_file(),
        "custody_present": (case_dir / "chain_of_custody.log").is_file(),
        "pipeline_present": (case_dir / "metadata" / "pipeline_events.jsonl").is_file(),
        "analysis_dir_present": _analysis_dir(case_dir).exists(),
        "analysis_dir_writable": os.access(_analysis_dir(case_dir), os.W_OK) if _analysis_dir(case_dir).exists() else os.access(case_dir, os.W_OK),
        "artifacts_total": len(artifacts),
        "artifact_type_counts": dict(sorted(counts.items())),
        "layers": {
            "network": bool(counts.get("pcap")),
            "memory": bool(counts.get("memory_lime")),
            "disk": bool(counts.get("disk_raw")),
            "ot_exports": bool(counts.get("industrial_ot_export_modbus_tcp")),
            "alerts": any((case_dir / "alerts").glob("*.json")),
            "chain_of_custody": (case_dir / "chain_of_custody.log").is_file(),
            "time_sync": bool(counts.get("time_sync")) or (case_dir / "metadata" / "time_sync.json").is_file(),
        },
    }


def _default_analysis_status(case_entry: dict) -> dict:
    case_dir = _case_dir_from_entry(case_entry)
    inventory = _artifact_inventory(case_dir)
    analysis_dir = _analysis_dir(case_dir)
    report_path = analysis_dir / "forensic_analysis_report.json"
    manifest_path = analysis_dir / "forensic_analysis_manifest.json"
    visual_summary_path = _analysis_visual_summary_path(case_dir)
    status = "not_started"
    if report_path.is_file():
        status = "completed"
    elif analysis_dir.exists() and any(analysis_dir.iterdir()):
        status = "partial"
    return {
        "case_id": case_entry.get("case_id"),
        "analysis_id": None,
        "started_at": None,
        "updated_at": utc_now(),
        "finished_at": None,
        "status": status,
        "current_phase": None,
        "phases": {},
        "completed_phases": [],
        "partial_phases": [],
        "failed_phases": [],
        "skipped_phases": [],
        "progress_percent": 0,
        "errors": [],
        "warnings": [],
        "output_files": [],
        "case_path": relative_path(case_dir),
        "analysis_dir": relative_path(analysis_dir),
        "forensic_analysis_report_path": relative_path(report_path) if report_path.exists() else None,
        "forensic_analysis_manifest_path": relative_path(manifest_path) if manifest_path.exists() else None,
        "analysis_visual_summary_path": relative_path(visual_summary_path) if visual_summary_path.exists() else None,
        "evidence_available": inventory["artifacts_total"] > 0,
        "available_layers": inventory["layers"],
        "inventory_summary": inventory["artifact_type_counts"],
    }


def load_analysis_status(case_id: str) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(case_entry)
    status_path = _analysis_status_path(case_dir)
    payload = _json_load(status_path)
    if not isinstance(payload, dict):
        return _default_analysis_status(case_entry)
    payload.setdefault("case_id", case_id)
    payload.setdefault("case_path", relative_path(case_dir))
    payload.setdefault("analysis_dir", relative_path(_analysis_dir(case_dir)))
    payload.setdefault("partial_phases", [])
    report_path = _analysis_dir(case_dir) / "forensic_analysis_report.json"
    manifest_path = _analysis_dir(case_dir) / "forensic_analysis_manifest.json"
    visual_summary_path = _analysis_visual_summary_path(case_dir)
    payload["forensic_analysis_report_path"] = relative_path(report_path) if report_path.exists() else None
    payload["forensic_analysis_manifest_path"] = relative_path(manifest_path) if manifest_path.exists() else None
    payload["analysis_visual_summary_path"] = relative_path(visual_summary_path) if visual_summary_path.exists() else None
    inventory = _artifact_inventory(case_dir)
    payload["available_layers"] = inventory["layers"]
    payload["inventory_summary"] = inventory["artifact_type_counts"]
    payload["evidence_available"] = inventory["artifacts_total"] > 0
    return payload


def _write_status(case_dir: Path, status: dict) -> None:
    status["updated_at"] = utc_now()
    status["completed_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")) == "completed"]
    status["partial_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")).startswith("partial")]
    status["failed_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")).startswith("failed")]
    status["skipped_phases"] = [key for key, phase in (status.get("phases") or {}).items() if str(phase.get("status")).startswith("skipped")]
    _write_json(_analysis_status_path(case_dir), status)
    try:
        _refresh_analysis_visual_summary(case_dir, status)
    except Exception:
        logger.warning("Failed to refresh analysis visual summary for %s", case_dir, exc_info=True)


def _init_status(case_entry: dict, force: bool = False) -> dict:
    case_dir = _case_dir_from_entry(case_entry)
    analysis_id = f"analysis-{uuid.uuid4().hex[:12]}"
    phases = {}
    for key, label, rel in ANALYSIS_PHASES:
        phases[key] = {
            "phase": key,
            "label": label,
            "status": "pending",
            "output_path": relative_path(_phase_output_path(case_dir, key)) if _phase_output_path(case_dir, key) else None,
            "stdout_path": relative_path(_phase_log_paths(case_dir, key)[0]),
            "stderr_path": relative_path(_phase_log_paths(case_dir, key)[1]),
        }
    status = {
        "case_id": case_entry.get("case_id"),
        "analysis_id": analysis_id,
        "started_at": utc_now(),
        "updated_at": utc_now(),
        "finished_at": None,
        "status": "running",
        "current_phase": "preflight_validation",
        "phases": phases,
        "completed_phases": [],
        "partial_phases": [],
        "failed_phases": [],
        "skipped_phases": [],
        "progress_percent": 0,
        "errors": [],
        "warnings": [],
        "output_files": [],
        "case_path": relative_path(case_dir),
        "analysis_dir": relative_path(_analysis_dir(case_dir)),
        "force_rerun": bool(force),
    }
    _analysis_dir(case_dir).mkdir(parents=True, exist_ok=True)
    _analysis_logs_dir(case_dir).mkdir(parents=True, exist_ok=True)
    _write_status(case_dir, status)
    return status


def _set_phase_status(case_dir: Path, status: dict, phase_key: str, phase_status: str, extra: dict | None = None) -> None:
    phase = (status.get("phases") or {}).get(phase_key) or {}
    phase["status"] = phase_status
    if extra:
        phase.update(extra)
    status["phases"][phase_key] = phase
    phase_states = [str(item.get("status") or "") for item in (status.get("phases") or {}).values()]
    completed = len([item for item in phase_states if item == "completed"])
    partial = len([item for item in phase_states if item.startswith("partial")])
    skipped = len([item for item in phase_states if item.startswith("skipped")])
    failed = len([item for item in phase_states if item.startswith("failed")])
    total = max(1, len(ANALYSIS_PHASES))
    status["progress_percent"] = round(((completed + partial + skipped + failed) / total) * 100, 2)
    _write_status(case_dir, status)


def _record_phase_transition(case_dir: Path, status: dict, phase_key: str, phase_status: str, extra: dict | None = None) -> None:
    status["current_phase"] = phase_key if phase_status == "running" else status.get("current_phase")
    _set_phase_status(case_dir, status, phase_key, phase_status, extra=extra)


def _analysis_cancel_path(case_dir: Path) -> Path:
    return _analysis_dir(case_dir) / "analysis_cancel.request"


def _run_command(command: list[str], cwd: Path, stdout_path: Path, stderr_path: Path) -> tuple[int, str | None]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    # Run with Popen so we can poll and terminate if a cancellation request appears.
    with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
        try:
            proc = subprocess.Popen(command, cwd=str(cwd), stdout=out, stderr=err, text=True)
        except Exception as exc:
            return 1, f"popen_failed: {exc}"
        # Poll loop
        while True:
            rc = proc.poll()
            if rc is not None:
                return rc, None
            # check for cancellation file
            try:
                cancel_file = _analysis_dir(cwd) / "analysis_cancel.request"
                if cancel_file.exists():
                    try:
                        proc.terminate()
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    return -1, "killed_by_cancel"
            except Exception:
                pass
            # sleep briefly
            time.sleep(0.5)


def _validate_phase_payload(payload: dict) -> tuple[bool, str | None]:
    if not isinstance(payload, dict):
        return False, "phase output is not a JSON object"
    if "status" not in payload:
        return False, "missing status field"
    if "input_artifacts" not in payload:
        return False, "missing input_artifacts field"
    if "findings" not in payload and "limitations" not in payload and "errors" not in payload:
        return False, "missing findings/limitations/errors field"
    if payload.get("status", "").startswith("skipped"):
        if "not_executed_reason" not in payload:
            return False, "missing not_executed_reason field"
    else:
        if "tool_used" not in payload:
            return False, "missing tool_used field"
    return True, None


def _finalize_phase_output(case_dir: Path, status: dict, phase_key: str, payload: dict) -> dict:
    output_path = _phase_output_path(case_dir, phase_key)
    if output_path:
        _write_json(output_path, payload)
    valid, reason = _validate_phase_payload(payload)
    if not valid:
        raise RuntimeError(f"{phase_key} validation failed: {reason}")
    if output_path:
        status["output_files"].append(relative_path(output_path))
    return payload


def _case_paths(case_dir: Path) -> dict:
    return {
        "manifest": case_dir / "manifest.json",
        "custody": case_dir / "chain_of_custody.log",
        "pipeline": case_dir / "metadata" / "pipeline_events.jsonl",
        "time_sync": case_dir / "metadata" / "time_sync.json",
        "alerts": sorted((case_dir / "alerts").glob("*.json")),
        "pcaps": sorted((case_dir / "network").rglob("*.pcap")),
        "memory": sorted((case_dir / "memory").glob("*.lime")),
        "disks": sorted((case_dir / "disk").glob("*.raw")),
        "ot_exports": sorted((case_dir / "industrial").glob("ot_export_*.json")),
    }


def _build_preflight(case_entry: dict, case_dir: Path) -> dict:
    paths = _case_paths(case_dir)
    analysis_dir = _analysis_dir(case_dir)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    tools = {
        "tshark": _which("tshark"),
        "volatility3": _which("volatility3", "vol"),
        "mmls": _which("mmls"),
        "fsstat": _which("fsstat"),
        "fls": _which("fls"),
        "mactime": _which("mactime"),
        "strings": _which("strings"),
        "python3": _which("python3"),
    }
    scripts = {
        "analyze_network_pcap.sh": FORENSICS_SCRIPTS_DIR / "analyze_network_pcap.sh",
        "analyze_memory_vol3.sh": FORENSICS_SCRIPTS_DIR / "analyze_memory_vol3.sh",
        "analyze_disk_tsk.sh": FORENSICS_SCRIPTS_DIR / "analyze_disk_tsk.sh",
        "build_case_timeline.py": FORENSICS_SCRIPTS_DIR / "build_case_timeline.py",
        "e2_max_clock_offset.sh": PROJECT_SCRIPT_DIR / "e2_max_clock_offset.sh",
    }
    script_checks = {name: {"path": relative_path(path), "available": path.is_file()} for name, path in scripts.items()}
    required_ok = all(
        [
            case_dir.is_dir(),
            paths["manifest"].is_file(),
            paths["custody"].is_file(),
            os.access(case_dir, os.R_OK),
            os.access(analysis_dir, os.W_OK),
        ]
    )
    warnings = []
    if not paths["pipeline"].is_file():
        warnings.append("pipeline_events.jsonl not found; some temporal and custody context will be partial")
    if not paths["time_sync"].is_file():
        warnings.append("time_sync.json not found; temporal validation may be skipped")
    for tool_name in ("tshark", "volatility3", "mmls", "fsstat", "fls", "mactime"):
        if not tools.get(tool_name):
            warnings.append(f"{tool_name} not available; one or more layers may be skipped or fail")
    status = "completed" if required_ok else "failed"
    return {
        "phase": "preflight_validation",
        "status": status,
        "input_artifacts": [
            relative_path(paths["manifest"]) if paths["manifest"].exists() else "missing",
            relative_path(paths["custody"]) if paths["custody"].exists() else "missing",
            relative_path(paths["pipeline"]) if paths["pipeline"].exists() else "missing",
        ],
        "tool_used": "python3",
        "findings": {
            "case_exists": case_dir.is_dir(),
            "manifest_exists": paths["manifest"].is_file(),
            "chain_of_custody_exists": paths["custody"].is_file(),
            "evidence_store_exists": case_dir.is_dir(),
            "analysis_directory": relative_path(analysis_dir),
            "analysis_directory_writable": os.access(analysis_dir, os.W_OK),
            "case_readable": os.access(case_dir, os.R_OK),
            "tools": tools,
            "scripts": script_checks,
            "symbols_dir": str(VOL3_SYMBOLS_DIR),
            "symbols_dir_exists": VOL3_SYMBOLS_DIR.is_dir(),
        },
        "limitations": warnings,
        "errors": [] if required_ok else ["Case directory, manifest, chain of custody, or analysis directory permissions are invalid."],
        "mandatory_requirements_ok": required_ok,
    }


def _phase_evidence_inventory(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "manifest.json") or {}
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    artifacts = artifacts if isinstance(artifacts, list) else []
    counts = Counter(str(item.get("type") or "unknown") for item in artifacts if isinstance(item, dict))
    return {
        "phase": "evidence_inventory",
        "status": "completed",
        "input_artifacts": [relative_path(case_dir / "manifest.json")],
        "tool_used": "python3",
        "findings": {
            "case_dir": relative_path(case_dir),
            "artifacts_total": len(artifacts),
            "artifact_type_counts": dict(sorted(counts.items())),
            "layers_available": _artifact_inventory(case_dir)["layers"],
        },
        "limitations": [],
        "errors": [],
    }


def _phase_integrity_custody(case_dir: Path) -> dict:
    manifest = _json_load(case_dir / "manifest.json") or {}
    custody = _jsonl_load(case_dir / "chain_of_custody.log")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else []
    artifacts = artifacts if isinstance(artifacts, list) else []
    missing = []
    validated = []
    skipped_hash = []
    for item in artifacts:
        rel = str(item.get("rel_path") or "")
        artifact_path = case_dir / rel
        if not artifact_path.exists():
            missing.append(rel)
            continue
        expected_hash = str(item.get("sha256") or "").strip()
        if artifact_path.is_file() and artifact_path.stat().st_size <= HASH_REASONABLE_BINARY_MAX_BYTES and expected_hash:
            actual = hash_file(artifact_path)
            validated.append({"rel_path": rel, "sha256_match": actual == expected_hash, "sha256": actual})
        else:
            skipped_hash.append(rel)
    chain_ok = True
    prev = "0" * 64
    for entry in custody:
        if str(entry.get("prev_hash") or "") != prev:
            chain_ok = False
            break
        prev = str(entry.get("entry_hash") or prev)
    status = "completed" if not missing and chain_ok else "partial"
    return {
        "phase": "integrity_custody_validation",
        "status": status,
        "input_artifacts": [
            relative_path(case_dir / "manifest.json"),
            relative_path(case_dir / "chain_of_custody.log"),
        ],
        "tool_used": "python3",
        "findings": {
            "manifest_artifacts_total": len(artifacts),
            "missing_artifacts": missing,
            "hash_validated_artifacts": len(validated),
            "hash_skipped_large_or_nohash": skipped_hash,
            "custody_events": len(custody),
            "custody_chain_valid": chain_ok,
        },
        "limitations": [
            "Large binary artifacts are not rehashed during this phase to avoid unnecessary latency; manifest-preserved hashes are trusted unless the file is small enough for direct validation."
        ],
        "errors": [] if not missing and chain_ok else ["Integrity or custody validation reported missing artifacts or a broken custody chain."],
    }


def _phase_temporal_validation(case_dir: Path) -> dict:
    time_sync_path = case_dir / "metadata" / "time_sync.json"
    if not time_sync_path.is_file():
        return {
            "phase": "temporal_validation",
            "status": "skipped_no_time_sync_artifact",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved time_sync.json was found for this case."],
            "errors": [],
            "not_executed_reason": "No preserved time_sync artifact found for this case.",
        }
    payload = _json_load(time_sync_path) or {}
    max_offset = payload.get("max_offset_ms")
    generated_at = payload.get("generated_at_utc")
    return {
        "phase": "temporal_validation",
        "status": "completed",
        "input_artifacts": [relative_path(time_sync_path)],
        "tool_used": "python3",
        "findings": {
            "generated_at_utc": generated_at,
            "max_offset_ms": max_offset,
            "time_sync_schema": payload.get("schema"),
            "synchronized": "System clock synchronized: yes" in str((payload.get("raw") or {}).get("timedatectl") or ""),
        },
        "limitations": [] if max_offset is not None else ["time_sync artifact exists but max_offset_ms is not available"],
        "errors": [],
    }


def _phase_network(case_dir: Path) -> dict:
    pcaps = sorted((case_dir / "network").rglob("*.pcap"))
    if not pcaps:
        return {
            "phase": "network_analysis",
            "status": "skipped_no_network_evidence",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved PCAP files were found for this case."],
            "errors": [],
            "not_executed_reason": "No RAW network evidence was found for this case.",
        }
    tshark = _which("tshark")
    if not tshark:
        return {
            "phase": "network_analysis",
            "status": "failed_missing_dependency",
            "input_artifacts": [relative_path(p) for p in pcaps],
            "findings": {},
            "limitations": [],
            "errors": ["Tool tshark not found"],
            "not_executed_reason": "tshark is required to analyze preserved PCAP files.",
            "tool_used": "not_available",
        }
    findings = []
    out_root = _analysis_dir(case_dir) / "03_network"
    def _parse_frames(log_path: Path) -> int:
        text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
        for line in text.splitlines():
            if "<>" in line and "|" in line:
                match = re.search(r"\|\s*([\d]+)\s*\|\s*([\d]+)\s*\|", line)
                if match:
                    try:
                        return int(match.group(1))
                    except Exception:
                        return 0
        return 0
    for pcap in pcaps:
        slug = _safe_slug(pcap.stem)
        detail_dir = out_root / "by_pcap" / slug
        detail_dir.mkdir(parents=True, exist_ok=True)
        total_cmd = [tshark, "-r", str(pcap), "-q", "-z", "io,stat,0"]
        total_rc, _ = _run_command(total_cmd, case_dir, detail_dir / "frames.stdout.log", detail_dir / "frames.stderr.log")
        modbus_cmd = [tshark, "-r", str(pcap), "-Y", "tcp.port==502", "-q", "-z", "io,stat,0"]
        modbus_rc, _ = _run_command(modbus_cmd, case_dir, detail_dir / "modbus.stdout.log", detail_dir / "modbus.stderr.log")
        total_frames = _parse_frames(detail_dir / "frames.stdout.log") if total_rc == 0 else 0
        modbus_frames = _parse_frames(detail_dir / "modbus.stdout.log") if modbus_rc == 0 else 0
        findings.append(
            {
                "pcap": relative_path(pcap),
                "size_bytes": pcap.stat().st_size,
                "total_frames": total_frames,
                "modbus_frames": modbus_frames,
                "tool_used": "tshark",
                "commands": [total_cmd, modbus_cmd],
                "stdout_paths": [
                    relative_path(detail_dir / "frames.stdout.log"),
                    relative_path(detail_dir / "modbus.stdout.log"),
                ],
                "stderr_paths": [
                    relative_path(detail_dir / "frames.stderr.log"),
                    relative_path(detail_dir / "modbus.stderr.log"),
                ],
            }
        )
    return {
        "phase": "network_analysis",
        "status": "completed",
        "input_artifacts": [relative_path(p) for p in pcaps],
        "tool_used": "tshark",
        "findings": {
            "pcaps_analyzed": len(findings),
            "files": findings,
        },
        "limitations": ["This phase performs lightweight tshark-based summaries and does not replace full manual packet-forensics review."],
        "errors": [],
    }


def _phase_memory(case_dir: Path) -> dict:
    dumps = sorted((case_dir / "memory").glob("*.lime"))
    preflight_path = _analysis_dir(case_dir) / MEMORY_OUTPUT_ROOT / "memory_preflight.json"
    findings_path = _analysis_dir(case_dir) / MEMORY_OUTPUT_ROOT / "memory_findings.json"
    phase_stdout_path, phase_stderr_path = _phase_log_paths(case_dir, "memory_analysis")
    if not dumps:
        preflight_payload = {
            "case_id": case_dir.name,
            "memory_dumps_found": 0,
            "dump_path": None,
            "dump_size": None,
            "dump_sha256": None,
            "source_node": None,
            "manifest_linked": False,
            "custody_linked": False,
            "detected_os": None,
            "detected_kernel": None,
            "symbol_search_paths": [str(path) for path in _symbol_search_roots()],
            "symbols_found": False,
            "volatility3_available": bool(_which("volatility3", "vol")),
            "volatility3_version": _volatility_version(),
            "analysis_possible": False,
            "blocking_reason": "No LiME memory dump was found for this case.",
            "warnings": [],
            "dumps": [],
        }
        _write_json(preflight_path, preflight_payload)
        return {
            "phase": "memory_analysis",
            "status": "skipped_no_memory_dump",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved memory dump was found for this case."],
            "errors": [],
            "not_executed_reason": "No LiME memory dump was found for this case.",
        }
    vol_cmd = _which("volatility3", "vol")
    symbol_search_paths, symbol_files = _discover_symbol_files()
    manifest_map = _manifest_artifact_map(case_dir)
    volatility_available = bool(vol_cmd)
    volatility_version = _volatility_version() if volatility_available else "not_available"
    if not vol_cmd:
        preflight_payload = {
            "case_id": case_dir.name,
            "memory_dumps_found": len(dumps),
            "dump_path": relative_path(dumps[0]) if len(dumps) == 1 else None,
            "dump_size": dumps[0].stat().st_size if len(dumps) == 1 else None,
            "dump_sha256": (_dump_metadata(case_dir, dumps[0]).get("sha256") if len(dumps) == 1 else None),
            "source_node": (_dump_metadata(case_dir, dumps[0]).get("vm_ip") if len(dumps) == 1 else None),
            "manifest_linked": False,
            "custody_linked": False,
            "detected_os": None,
            "detected_kernel": None,
            "symbol_search_paths": symbol_search_paths,
            "symbols_found": bool(symbol_files),
            "volatility3_available": False,
            "volatility3_version": volatility_version,
            "analysis_possible": False,
            "blocking_reason": "Volatility 3 executable was not found on the host.",
            "warnings": [],
            "dumps": [],
        }
        _write_json(preflight_path, preflight_payload)
        _write_json(
            findings_path,
            {
                "case_id": case_dir.name,
                "status": "failed",
                "analysis_completed": False,
                "reason": "volatility3_not_available",
                "blocking_errors": ["Volatility 3 executable was not found on the host."],
                "symbols_required": True,
                "symbols_found": bool(symbol_files),
                "recommended_action": "Install or expose the existing Volatility 3 command locally before retrying memory analysis.",
                "input_artifacts": [relative_path(p) for p in dumps],
                "output_files": [relative_path(preflight_path)],
            },
        )
        phase_stdout_path.write_text(
            "\n".join(
                [
                    "[memory_analysis] dependency check failed",
                    f"memory_findings={relative_path(findings_path)}",
                    f"memory_preflight={relative_path(preflight_path)}",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        phase_stderr_path.write_text("Volatility 3 executable was not found on the host.\n", encoding="utf-8")
        return {
            "phase": "memory_analysis",
            "status": "failed_missing_dependency",
            "input_artifacts": [relative_path(p) for p in dumps],
            "findings": {},
            "limitations": [],
            "errors": ["Volatility 3 executable was not found on the host."],
            "not_executed_reason": "volatility3 is not available on the host.",
            "tool_used": "not_available",
        }

    preflight_dumps: list[dict] = []
    dump_results: list[dict] = []
    all_blocking_errors: list[str] = []
    completed_plugins_total: set[str] = set()
    failed_plugins_total: set[str] = set()
    partial_findings: list[dict] = []
    warnings: list[str] = []

    for dump_file in dumps:
        metadata = _dump_metadata(case_dir, dump_file)
        dump_id = _dump_identifier(dump_file, metadata)
        rel_dump = relative_path(dump_file)
        case_rel_dump = dump_file.relative_to(case_dir).as_posix()
        artifact = manifest_map.get(case_rel_dump) or manifest_map.get(rel_dump) or {}
        custody_entries = _custody_entries_for_artifact(case_dir, case_rel_dump) or _custody_entries_for_artifact(case_dir, rel_dump)
        output_dir = _memory_output_dir(case_dir, dump_id)
        legacy_dir = _memory_legacy_output_dir(case_dir, dump_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        legacy_dir.mkdir(parents=True, exist_ok=True)

        plugin_reports: list[dict] = []
        progress_phases = [
            {"phase": "preflight_validation", "status": "completed"},
            {"phase": "evidence_inventory", "status": "completed"},
            {"phase": "memory_dump_discovery", "status": "completed"},
            {"phase": "volatility3_availability_check", "status": "completed" if volatility_available else "failed"},
            {"phase": "symbol_discovery", "status": "running"},
            {"phase": "memory_analysis_execution", "status": "pending"},
            {"phase": "output_validation", "status": "pending"},
            {"phase": "report_generation", "status": "pending"},
            {"phase": "foc_readiness_update", "status": "pending"},
        ]

        banners_spec = MEMORY_PLUGIN_SPECS[0]
        banners_stdout = output_dir / banners_spec["filename"]
        banners_stderr = output_dir / "vol3_banners.stderr.txt"
        banner_cmd = [vol_cmd, "--offline", "-f", str(dump_file)]
        if symbol_search_paths:
            banner_cmd.extend(["-s", ";".join(symbol_search_paths)])
        banner_cmd.append(banners_spec["plugin"])
        banner_rc, _ = _run_command(banner_cmd, case_dir, banners_stdout, banners_stderr)
        shutil.copy2(banners_stdout, legacy_dir / "01_banners.txt")
        banner_text = _read_text(banners_stdout)
        banner_err = _read_text(banners_stderr)
        detected_os, detected_kernel = _parse_linux_banner(banner_text)
        matched_symbols = _matching_symbol_files(detected_kernel, symbol_files)
        # If no local symbol matched, attempt to generate a symbol from any local vmlinux candidate
        if not matched_symbols:
            try:
                gen = _generate_symbol_from_vmlinux(case_dir, detected_kernel)
                if gen:
                    # refresh discovered symbols and re-evaluate matches
                    _, symbol_files = _discover_symbol_files()
                    matched_symbols = _matching_symbol_files(detected_kernel, symbol_files)
            except Exception:
                # best-effort generation; continue if it fails
                matched_symbols = matched_symbols
        # If still no matched symbols, attempt SSH-based generation using helper script and available creds
        symbol_generation_report_path = None
        if not matched_symbols:
            try:
                ssh_report = _generate_symbol_via_ssh(case_dir, output_dir, dump_file, detected_kernel, metadata)
                if ssh_report:
                    symbol_generation_report_path = output_dir / "symbol_generation_report.json"
                    # refresh discovered symbols and re-evaluate matches
                    _, symbol_files = _discover_symbol_files()
                    matched_symbols = _matching_symbol_files(detected_kernel, symbol_files)
            except Exception:
                pass
        progress_phases[4]["status"] = "completed" if matched_symbols else "partial"

        dump_preflight = {
            "dump_id": dump_id,
            "dump_path": rel_dump,
            "dump_size": int(dump_file.stat().st_size),
            "dump_sha256": metadata.get("sha256") or artifact.get("sha256"),
            "source_node": metadata.get("vm_ip") or metadata.get("vm_id"),
            "manifest_linked": bool(artifact),
            "manifest_artifact_rel": case_rel_dump if artifact else None,
            "custody_linked": bool(custody_entries),
            "custody_link": relative_path(case_dir / "chain_of_custody.log") if custody_entries else None,
            "detected_os": detected_os,
            "detected_kernel": detected_kernel,
            "symbol_search_paths": symbol_search_paths,
            "symbols_found": bool(matched_symbols),
            "candidate_symbols": [str(path) for path in matched_symbols],
                "symbol_generation_report": relative_path(symbol_generation_report_path) if symbol_generation_report_path else None,
            "volatility3_available": volatility_available,
            "volatility3_version": volatility_version,
            "analysis_possible": bool(matched_symbols),
            "blocking_reason": None if matched_symbols else "No compatible local Linux symbol file was matched to the captured kernel.",
            "warnings": [],
            "metadata_path": relative_path(case_dir / "metadata" / f"{dump_file.name}.metadata.json") if (case_dir / "metadata" / f"{dump_file.name}.metadata.json").is_file() else None,
            "banner_command": _shell_join(banner_cmd),
            "banner_stdout_path": relative_path(banners_stdout),
            "banner_stderr_path": relative_path(banners_stderr),
            "symbol_selection_decision": (
                f"Selected exact local symbol candidate `{matched_symbols[0].name}` for kernel `{detected_kernel}`."
                if matched_symbols else
                f"No compatible local symbol candidate matched kernel `{detected_kernel or 'unknown'}`."
            ),
            "symbol_table_status": _symbol_table_status_from_text(banner_text + "\n" + banner_err),
            "kernel_layer_status": _kernel_layer_status_from_text(banner_text + "\n" + banner_err),
        }
        if banner_rc != 0:
            dump_preflight["warnings"].append("Volatility banners plugin exited non-zero; kernel detection may be incomplete.")
        if not detected_kernel:
            dump_preflight["warnings"].append("Kernel banner could not be extracted from the dump.")
        preflight_dumps.append(dump_preflight)
        interim_analysis_possible = any(bool(item.get("analysis_possible")) for item in preflight_dumps)
        _write_json(
            preflight_path,
            {
                "case_id": case_dir.name,
                "memory_dumps_found": len(preflight_dumps),
                "dump_path": preflight_dumps[0]["dump_path"] if len(preflight_dumps) == 1 else None,
                "dump_size": preflight_dumps[0]["dump_size"] if len(preflight_dumps) == 1 else None,
                "dump_sha256": preflight_dumps[0]["dump_sha256"] if len(preflight_dumps) == 1 else None,
                "source_node": preflight_dumps[0]["source_node"] if len(preflight_dumps) == 1 else None,
                "manifest_linked": all(bool(item.get("manifest_linked")) for item in preflight_dumps),
                "custody_linked": all(bool(item.get("custody_linked")) for item in preflight_dumps),
                "detected_os": preflight_dumps[0]["detected_os"] if len(preflight_dumps) == 1 else None,
                "detected_kernel": preflight_dumps[0]["detected_kernel"] if len(preflight_dumps) == 1 else None,
                "symbol_search_paths": symbol_search_paths,
                "symbols_found": any(bool(item.get("symbols_found")) for item in preflight_dumps),
                "volatility3_available": volatility_available,
                "volatility3_version": volatility_version,
                "analysis_possible": interim_analysis_possible,
                "blocking_reason": None if interim_analysis_possible else "No compatible local Linux symbol file was matched to the discovered kernel(s) so far.",
                "warnings": warnings + [warning for item in preflight_dumps for warning in (item.get("warnings") or [])],
                "dumps": preflight_dumps,
            },
        )

        banners_report = {
            "plugin_key": "banners",
            "plugin": banners_spec["plugin"],
            "status": "completed" if banner_rc == 0 and banner_text.strip() else "failed",
            "command": banner_cmd,
            "command_text": _shell_join(banner_cmd),
            "exit_code": banner_rc,
            "stdout_path": relative_path(banners_stdout),
            "stderr_path": relative_path(banners_stderr),
            "stdout": banner_text,
            "stderr": banner_err,
            "error_message": None if banner_rc == 0 else (banner_err.strip() or banner_text.strip() or "Volatility banners execution failed."),
            "missing_requirement": None,
            "symbol_table_status": dump_preflight["symbol_table_status"],
            "kernel_layer_status": dump_preflight["kernel_layer_status"],
            "suggested_fix": "Inspect the raw banner output and verify that the memory dump is readable by Volatility 3." if banner_rc != 0 else None,
            "summary": _extract_output_summary(banner_text, "banners"),
            "analysis_possible": bool(matched_symbols),
        }
        plugin_reports.append(banners_report)
        if banners_report["status"] == "completed":
            completed_plugins_total.add("banners")
        else:
            failed_plugins_total.add("banners")
            all_blocking_errors.append(f"{dump_id}: banners failed")

        progress_phases[5]["status"] = "running"
        plugin_name_map = {
            "pslist": "02_pslist.txt",
            "sockstat": "04_sockstat.txt",
            "lsmod": "05_lsmod.txt",
            "bash": "06_bash.txt",
            "check_syscall": "07_syscalls.txt",
        }
        for spec in MEMORY_PLUGIN_SPECS[1:]:
            stdout_path = output_dir / spec["filename"]
            stderr_path = output_dir / f"{spec['key']}.stderr.txt"
            cmd = [vol_cmd, "--offline", "-f", str(dump_file)]
            if symbol_search_paths:
                cmd.extend(["-s", ";".join(symbol_search_paths)])
            cmd.append(spec["plugin"])
            rc, _ = _run_command(cmd, case_dir, stdout_path, stderr_path)
            stdout_text = _read_text(stdout_path)
            stderr_text = _read_text(stderr_path)
            combined = f"{stdout_text}\n{stderr_text}"
            missing_requirements = _extract_unsatisfied_requirements(combined)
            failed = rc != 0 or bool(missing_requirements)
            status_value = "failed" if failed else "completed"
            report = {
                "plugin_key": spec["key"],
                "plugin": spec["plugin"],
                "status": status_value,
                "command": cmd,
                "command_text": _shell_join(cmd),
                "exit_code": rc,
                "stdout_path": relative_path(stdout_path),
                "stderr_path": relative_path(stderr_path),
                "stdout": stdout_text,
                "stderr": stderr_text,
                "error_message": (
                    missing_requirements[0]
                    if missing_requirements else
                    (stderr_text.strip() or stdout_text.strip() or None) if failed else None
                ),
                "missing_requirement": missing_requirements[0] if missing_requirements else None,
                "symbol_table_status": _symbol_table_status_from_text(combined),
                "kernel_layer_status": _kernel_layer_status_from_text(combined),
                "summary": _extract_output_summary(stdout_text, spec["key"]),
                "analysis_possible": bool(matched_symbols),
            }
            report["suggested_fix"] = _suggest_memory_fix(report, dump_preflight) if failed else None
            plugin_reports.append(report)
            legacy_name = plugin_name_map.get(spec["key"])
            if legacy_name:
                shutil.copy2(stdout_path, legacy_dir / legacy_name)
            if status_value == "completed":
                completed_plugins_total.add(spec["key"])
            else:
                failed_plugins_total.add(spec["key"])
                if report["error_message"]:
                    all_blocking_errors.append(f"{dump_id}: {spec['key']} -> {report['error_message']}")

        progress_phases[5]["status"] = "completed" if all(item["status"] == "completed" for item in plugin_reports) else "partial"
        progress_phases[6]["status"] = "completed"
        progress_phases[7]["status"] = "completed"
        progress_phases[8]["status"] = "pending"

        execution_report = {
            "case_id": case_dir.name,
            "dump_id": dump_id,
            "dump_path": rel_dump,
            "detected_os": detected_os,
            "detected_kernel": detected_kernel,
            "symbol_search_paths": symbol_search_paths,
            "candidate_symbols": [str(path) for path in matched_symbols],
            "selected_symbol": str(matched_symbols[0]) if matched_symbols else None,
            "symbol_generation_report_path": relative_path(symbol_generation_report_path) if symbol_generation_report_path else None,
            "volatility3_available": volatility_available,
            "volatility3_version": volatility_version,
            "analysis_possible": bool(matched_symbols),
            "plugin_results": plugin_reports,
            "progress_phases": progress_phases,
            "generated_at": utc_now(),
        }
        execution_report_path = output_dir / "vol3_execution_report.json"
        _write_json(execution_report_path, execution_report)

        completed_plugins = [item["plugin_key"] for item in plugin_reports if item["status"] == "completed"]
        failed_plugins = [item["plugin_key"] for item in plugin_reports if item["status"] == "failed"]
        dump_status = "completed" if failed_plugins == [] else "partial" if completed_plugins else "failed"
        dump_results.append(
            {
                "dump_id": dump_id,
                "dump": rel_dump,
                "status": dump_status,
                "detected_os": detected_os,
                "detected_kernel": detected_kernel,
                "completed_plugins": completed_plugins,
                "failed_plugins": failed_plugins,
                "output_dir": relative_path(output_dir),
                "legacy_output_dir": relative_path(legacy_dir),
                "execution_report_path": relative_path(execution_report_path),
                "output_files": sorted(relative_path(path) for path in output_dir.glob("*") if path.is_file()),
            }
        )
        partial_findings.append(
            {
                "dump_id": dump_id,
                "detected_kernel": detected_kernel,
                "completed_plugins": completed_plugins,
                "failed_plugins": failed_plugins,
            }
        )

    any_symbols_found = any(bool(item.get("symbols_found")) for item in preflight_dumps)
    analysis_possible = any(bool(item.get("analysis_possible")) for item in preflight_dumps)
    blocking_reason = None if analysis_possible else "Memory analysis could not complete because no compatible local Volatility 3 Linux symbol file was matched."
    preflight_payload = {
        "case_id": case_dir.name,
        "memory_dumps_found": len(preflight_dumps),
        "dump_path": preflight_dumps[0]["dump_path"] if len(preflight_dumps) == 1 else None,
        "dump_size": preflight_dumps[0]["dump_size"] if len(preflight_dumps) == 1 else None,
        "dump_sha256": preflight_dumps[0]["dump_sha256"] if len(preflight_dumps) == 1 else None,
        "source_node": preflight_dumps[0]["source_node"] if len(preflight_dumps) == 1 else None,
        "manifest_linked": all(bool(item.get("manifest_linked")) for item in preflight_dumps),
        "custody_linked": all(bool(item.get("custody_linked")) for item in preflight_dumps),
        "detected_os": preflight_dumps[0]["detected_os"] if len(preflight_dumps) == 1 else None,
        "detected_kernel": preflight_dumps[0]["detected_kernel"] if len(preflight_dumps) == 1 else None,
        "symbol_search_paths": symbol_search_paths,
        "symbols_found": any_symbols_found,
        "volatility3_available": volatility_available,
        "volatility3_version": volatility_version,
        "analysis_possible": analysis_possible,
        "blocking_reason": blocking_reason,
        "warnings": warnings + [warning for item in preflight_dumps for warning in (item.get("warnings") or [])],
        "dumps": preflight_dumps,
    }
    _write_json(preflight_path, preflight_payload)

    all_completed = all(item["status"] == "completed" for item in dump_results)
    any_completed = any(item["status"] != "failed" for item in dump_results)
    if all_completed:
        findings_status = "completed"
        phase_status = "completed"
    elif any_completed:
        findings_status = "partial"
        phase_status = "partial_missing_symbols" if not analysis_possible else "partial"
    else:
        findings_status = "failed"
        phase_status = "failed_missing_symbols" if not analysis_possible else "failed"

    memory_findings = {
        "case_id": case_dir.name,
        "status": findings_status,
        "analysis_completed": all_completed,
        "reason": None if all_completed else ("missing_symbols" if not analysis_possible else "plugin_execution_failures"),
        "blocking_errors": sorted(set(all_blocking_errors)),
        "symbols_required": True,
        "symbols_found": any_symbols_found,
        "recommended_action": (
            "Memory analysis could not be completed because Volatility 3 symbols for the captured kernel were not available or could not be matched."
            if not analysis_possible else
            "Review the per-plugin Volatility execution reports and rerun the failed plugins with the reported commands for deeper debugging."
        ),
        "completed_plugins": sorted(completed_plugins_total),
        "failed_plugins": sorted(failed_plugins_total),
        "partial_findings": partial_findings if findings_status != "completed" else [],
        "limitations": (
            ["Memory analysis is incomplete; use outputs from completed plugins only and do not infer unsupported conclusions."]
            if findings_status != "completed" else
            []
        ),
        "findings": partial_findings if findings_status == "completed" else [],
        "tools_used": ["volatility3"],
        "tool_versions": {"volatility3": volatility_version},
        "input_artifacts": [relative_path(p) for p in dumps],
        "output_files": [relative_path(preflight_path)] + [item["execution_report_path"] for item in dump_results],
        "dumps_analyzed": dump_results,
    }
    _write_json(findings_path, memory_findings)
    phase_stdout_lines = [
        "[memory_analysis] phase summary",
        f"memory_preflight={relative_path(preflight_path)}",
        f"memory_findings={relative_path(findings_path)}",
        f"status={phase_status}",
        f"dumps={len(dump_results)}",
    ]
    for item in dump_results:
        phase_stdout_lines.append(
            " | ".join(
                [
                    f"dump_id={item['dump_id']}",
                    f"status={item['status']}",
                    f"kernel={item.get('detected_kernel') or 'unknown'}",
                    f"completed_plugins={','.join(item.get('completed_plugins') or []) or 'none'}",
                    f"failed_plugins={','.join(item.get('failed_plugins') or []) or 'none'}",
                    f"execution_report={item['execution_report_path']}",
                ]
            )
        )
    phase_stdout_path.write_text("\n".join(phase_stdout_lines) + "\n", encoding="utf-8")
    phase_stderr_lines = memory_findings["blocking_errors"] or ["No blocking memory errors recorded."]
    phase_stderr_path.write_text("\n".join(phase_stderr_lines) + "\n", encoding="utf-8")

    return {
        "phase": "memory_analysis",
        "status": phase_status,
        "input_artifacts": [relative_path(p) for p in dumps],
        "tool_used": "volatility3",
        "findings": {
            "memory_preflight_path": relative_path(preflight_path),
            "memory_findings_path": relative_path(findings_path),
            "dumps_analyzed": len(dump_results),
            "results": dump_results,
        },
        "limitations": memory_findings["limitations"],
        "errors": memory_findings["blocking_errors"],
    }


def _phase_disk(case_dir: Path) -> dict:
    raws = sorted((case_dir / "disk").glob("*.raw"))
    if not raws:
        return {
            "phase": "disk_analysis",
            "status": "skipped_no_disk_image",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved RAW disk image was found for this case."],
            "errors": [],
            "not_executed_reason": "No RAW disk image found for this case.",
        }
    required_tools = {"mmls": _which("mmls"), "fsstat": _which("fsstat"), "fls": _which("fls"), "mactime": _which("mactime"), "strings": _which("strings")}
    script_path = FORENSICS_SCRIPTS_DIR / "analyze_disk_tsk.sh"
    if not script_path.is_file() or not all(required_tools.values()):
        missing = [name for name, value in required_tools.items() if not value]
        if not script_path.is_file():
            missing.append("analyze_disk_tsk.sh")
        return {
            "phase": "disk_analysis",
            "status": "failed_missing_dependency",
            "input_artifacts": [relative_path(p) for p in raws],
            "findings": {},
            "limitations": [],
            "errors": [f"Missing dependency: {name}" for name in missing],
            "not_executed_reason": "One or more Sleuth Kit dependencies are missing.",
            "tool_used": "not_available",
        }
    results = []
    for raw in raws:
        slug = _safe_slug(raw.stem)
        out_dir = _analysis_dir(case_dir) / "05_disk" / slug
        stdout_path, stderr_path = _phase_log_paths(case_dir, f"disk_analysis_{slug}")
        cmd = ["bash", str(script_path), str(case_dir), str(raw), str(out_dir)]
        rc, _ = _run_command(cmd, case_dir, stdout_path, stderr_path)
        results.append(
            {
                "disk_image": relative_path(raw),
                "command": cmd,
                "exit_code": rc,
                "stdout_path": relative_path(stdout_path),
                "stderr_path": relative_path(stderr_path),
                "output_dir": relative_path(out_dir),
                "produced_files": sorted(relative_path(p) for p in out_dir.rglob("*") if p.is_file())[:50],
            }
        )
    failed = [item for item in results if item["exit_code"] != 0]
    return {
        "phase": "disk_analysis",
        "status": "completed" if not failed else "partial",
        "input_artifacts": [relative_path(p) for p in raws],
        "tool_used": "sleuthkit",
        "findings": {
            "disk_images_analyzed": len(results),
            "results": results,
        },
        "limitations": [] if not failed else ["One or more disk-analysis helper executions exited non-zero; inspect stdout/stderr logs for details."],
        "errors": [] if not failed else [f"{len(failed)} disk-analysis executions exited non-zero"],
    }


def _phase_ot(case_dir: Path) -> dict:
    exports = sorted((case_dir / "industrial").glob("ot_export_*.json"))
    if not exports:
        return {
            "phase": "ot_export_analysis",
            "status": "skipped_no_ot_export",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved OT export was found for this case."],
            "errors": [],
            "not_executed_reason": "No OT export files were found for this case.",
        }
    op_counts = Counter()
    fc_counts = Counter()
    observations = []
    for export_path in exports:
        data = _json_load(export_path) or {}
        records = data.get("records") if isinstance(data, dict) else []
        records = records if isinstance(records, list) else []
        for record in records:
            op_counts[str(record.get("op") or "unknown")] += 1
            fc_counts[str(record.get("fc") or "unknown")] += 1
        observations.append(
            {
                "file": relative_path(export_path),
                "vm_id": data.get("vm_id"),
                "run_id": data.get("run_id"),
                "records": len(records),
            }
        )
    return {
        "phase": "ot_export_analysis",
        "status": "completed",
        "input_artifacts": [relative_path(p) for p in exports],
        "tool_used": "python3",
        "findings": {
            "files": observations,
            "operations": dict(op_counts.most_common()),
            "function_codes": dict(fc_counts.most_common()),
        },
        "limitations": [],
        "errors": [],
    }


def _phase_alerts(case_dir: Path) -> dict:
    alerts = sorted((case_dir / "alerts").glob("*.json"))
    if not alerts:
        return {
            "phase": "alerts_detection_analysis",
            "status": "skipped_no_alerts",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No preserved alert files were found for this case."],
            "errors": [],
            "not_executed_reason": "No preserved alert JSON files were found for this case.",
        }
    severity = Counter()
    collectors = Counter()
    protocols = Counter()
    rules = Counter()
    signatures = Counter()
    sensors = Counter()
    for alert_path in alerts:
        data = _json_load(alert_path) or {}
        severity[str(data.get("rule_level") or data.get("severity") or "unknown")] += 1
        collectors[str(data.get("source") or "unknown")] += 1
        protocols[str(data.get("protocol") or "unknown")] += 1
        rules[str(data.get("rule_id") or "unknown")] += 1
        signatures[str(data.get("signature") or "unknown")] += 1
        raw = data.get("raw") or {}
        sensors[str((raw.get("rule") or {}).get("groups", ["unknown"])[0] if isinstance(raw.get("rule"), dict) else "unknown")] += 1
    return {
        "phase": "alerts_detection_analysis",
        "status": "completed",
        "input_artifacts": [relative_path(p) for p in alerts[:50]] + (["..."] if len(alerts) > 50 else []),
        "tool_used": "python3",
        "findings": {
            "alerts_total": len(alerts),
            "severity_distribution": dict(severity.most_common()),
            "collectors": dict(collectors.most_common()),
            "protocols": dict(protocols.most_common()),
            "top_rules": dict(rules.most_common(20)),
            "top_signatures": dict(signatures.most_common(20)),
            "rule_group_distribution": dict(sensors.most_common()),
        },
        "limitations": ["This phase summarizes preserved alerts and does not replace full analyst review of every individual event."],
        "errors": [],
    }


def _phase_pipeline_custody(case_dir: Path) -> dict:
    pipeline_events = _jsonl_load(case_dir / "metadata" / "pipeline_events.jsonl")
    custody_events = _jsonl_load(case_dir / "chain_of_custody.log")
    if not pipeline_events and not custody_events:
        return {
            "phase": "pipeline_custody_analysis",
            "status": "skipped_no_pipeline_or_custody",
            "input_artifacts": [],
            "findings": {},
            "limitations": ["No pipeline or custody logs were found for this case."],
            "errors": [],
            "not_executed_reason": "Neither pipeline_events.jsonl nor chain_of_custody.log was found.",
        }
    pipeline_counts = Counter(str(item.get("event") or item.get("event_type") or "unknown") for item in pipeline_events)
    custody_actions = Counter(str(item.get("action") or "unknown") for item in custody_events)
    custody_actors = Counter(str(item.get("actor") or "unknown") for item in custody_events)
    return {
        "phase": "pipeline_custody_analysis",
        "status": "completed",
        "input_artifacts": [
            relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").exists() else "missing",
            relative_path(case_dir / "chain_of_custody.log") if (case_dir / "chain_of_custody.log").exists() else "missing",
        ],
        "tool_used": "python3",
        "findings": {
            "pipeline_events_total": len(pipeline_events),
            "pipeline_event_distribution": dict(pipeline_counts.most_common()),
            "custody_events_total": len(custody_events),
            "custody_action_distribution": dict(custody_actions.most_common()),
            "custody_actor_distribution": dict(custody_actors.most_common()),
        },
        "limitations": [],
        "errors": [],
    }


def _phase_timeline(case_dir: Path) -> dict:
    timeline_out = _analysis_dir(case_dir) / "09_timeline" / "unified_forensic_timeline.json"
    timeline_out.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for event in _jsonl_load(case_dir / "metadata" / "pipeline_events.jsonl"):
        rows.append(
            {
                "timestamp": event.get("ts_utc"),
                "ts_epoch": event.get("ts_epoch"),
                "source": "pipeline",
                "event": event.get("event") or event.get("event_type"),
                "details": event.get("meta") or {},
            }
        )
    for event in _jsonl_load(case_dir / "chain_of_custody.log"):
        rows.append(
            {
                "timestamp": event.get("ts_utc"),
                "ts_epoch": event.get("ts_epoch"),
                "source": "custody",
                "event": event.get("action"),
                "details": {"actor": event.get("actor"), "artifact_rel": event.get("artifact_rel"), "outcome": event.get("outcome")},
            }
        )
    for export_path in sorted((case_dir / "industrial").glob("ot_export_*.json")):
        data = _json_load(export_path) or {}
        for record in data.get("records") or []:
            rows.append(
                {
                    "timestamp": record.get("ts_utc_ms") or record.get("ts_utc"),
                    "ts_epoch": record.get("ts_epoch"),
                    "source": "ot_export",
                    "event": f"ot:{record.get('op') or 'unknown'}",
                    "details": {
                        "fc": record.get("fc"),
                        "address": record.get("address"),
                        "value": record.get("value"),
                        "src_ip": record.get("src_ip"),
                        "dst_ip": record.get("dst_ip"),
                    },
                }
            )
    rows = [row for row in rows if row.get("timestamp") or row.get("ts_epoch")]
    rows.sort(key=lambda item: (_parse_ts(item.get("timestamp")) if item.get("timestamp") else None) or float(item.get("ts_epoch") or 0.0))
    return {
        "phase": "unified_forensic_timeline",
        "status": "completed" if rows else "partial",
        "input_artifacts": [
            relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").exists() else "missing",
            relative_path(case_dir / "chain_of_custody.log") if (case_dir / "chain_of_custody.log").exists() else "missing",
        ],
        "tool_used": "python3",
        "findings": rows,
        "limitations": [] if rows else ["No timestamped rows were recovered from preserved pipeline, custody, or OT-export sources."],
        "errors": [],
    }


def _phase_cross_layer(case_dir: Path) -> dict:
    alerts = _json_load(_analysis_dir(case_dir) / "07_alerts" / "alert_findings.json") or {}
    ot = _json_load(_analysis_dir(case_dir) / "06_ot" / "ot_findings.json") or {}
    network = _json_load(_analysis_dir(case_dir) / "03_network" / "network_findings.json") or {}
    time_validation = _json_load(_analysis_dir(case_dir) / "02_time_validation" / "clock_offset_report.json") or {}
    findings = []
    top_signatures = (alerts.get("findings") or {}).get("top_signatures") or {}
    ot_ops = (ot.get("findings") or {}).get("operations") or {}
    modbus_frames = sum(int((item or {}).get("modbus_frames") or 0) for item in ((network.get("findings") or {}).get("files") or []))
    if modbus_frames and ot_ops:
        findings.append(
            {
                "finding": "Preserved PCAP evidence and OT exports both indicate Modbus activity for this case.",
                "evidence_refs": [
                    relative_path(_analysis_dir(case_dir) / "03_network" / "network_findings.json"),
                    relative_path(_analysis_dir(case_dir) / "06_ot" / "ot_findings.json"),
                ],
                "confidence": "medium",
            }
        )
    if any("/etc/shadow_backup" in str(k) for k in top_signatures.keys()):
        findings.append(
            {
                "finding": "High-severity file-integrity activity was preserved and should be interpreted together with disk and memory layers if available.",
                "evidence_refs": [relative_path(_analysis_dir(case_dir) / "07_alerts" / "alert_findings.json")],
                "confidence": "medium",
            }
        )
    max_offset = (time_validation.get("findings") or {}).get("max_offset_ms")
    if isinstance(max_offset, (int, float)) and max_offset > 1000:
        findings.append(
            {
                "finding": "Clock offset is materially high; timeline interpretation should account for temporal uncertainty.",
                "evidence_refs": [relative_path(_analysis_dir(case_dir) / "02_time_validation" / "clock_offset_report.json")],
                "confidence": "high",
            }
        )
    return {
        "phase": "cross_layer_findings",
        "status": "completed",
        "input_artifacts": [
            relative_path(_analysis_dir(case_dir) / "03_network" / "network_findings.json"),
            relative_path(_analysis_dir(case_dir) / "06_ot" / "ot_findings.json"),
            relative_path(_analysis_dir(case_dir) / "07_alerts" / "alert_findings.json"),
        ],
        "tool_used": "python3",
        "findings": findings,
        "limitations": ["Cross-layer findings are conservative and only rely on outputs generated during this analysis workflow."],
        "errors": [],
    }


def _phase_final_report(case_entry: dict, case_dir: Path, status: dict) -> dict:
    report_path = _analysis_dir(case_dir) / "forensic_analysis_report.json"
    manifest_path = _analysis_dir(case_dir) / "forensic_analysis_manifest.json"
    summary_path = _analysis_dir(case_dir) / "forensic_analysis_summary.md"
    phase_statuses = {key: (status.get("phases") or {}).get(key, {}).get("status") for key, _, _ in ANALYSIS_PHASES}
    failed = [key for key, value in phase_statuses.items() if str(value).startswith("failed")]
    partial = [key for key, value in phase_statuses.items() if str(value).startswith("partial")]
    skipped = [key for key, value in phase_statuses.items() if str(value).startswith("skipped")]
    memory_findings = _json_load(_analysis_dir(case_dir) / MEMORY_OUTPUT_ROOT / "memory_findings.json") or {}
    memory_preflight = _json_load(_analysis_dir(case_dir) / MEMORY_OUTPUT_ROOT / "memory_preflight.json") or {}
    report = {
        "phase": "forensic_analysis_report_generation",
        "status": "completed" if not failed and not partial else "partial",
        "tool_used": "python3",
        "case_id": case_entry.get("case_id"),
        "source_case_name": case_entry.get("source_case_name"),
        "generated_at": utc_now(),
        "analysis_id": status.get("analysis_id"),
        "analysis_status": "completed" if not failed and not partial else "partial",
        "status_note": (
            "Forensic analysis completed with some skipped, partial or failed layers."
            if failed or partial or skipped else
            "Forensic analysis completed successfully."
        ),
        "input_artifacts": [
            relative_path(case_dir / "manifest.json"),
            relative_path(case_dir / "chain_of_custody.log"),
            relative_path(case_dir / "metadata" / "pipeline_events.jsonl") if (case_dir / "metadata" / "pipeline_events.jsonl").exists() else "missing",
        ],
        "errors": status.get("errors") or [],
        "findings": {
            "completed_phases": status.get("completed_phases") or [],
            "partial_phases": status.get("partial_phases") or [],
            "failed_phases": status.get("failed_phases") or [],
            "skipped_phases": status.get("skipped_phases") or [],
        },
        "limitations": [
            "Semantic and causal reconstruction remain blocked until explicitly generated in later phases.",
            "Skipped layers indicate missing evidence or missing dependencies, not fabricated success.",
        ],
        "related_outputs": [path for path in status.get("output_files") if path.endswith(".json")],
        "layer_status": {
            key: {
                "label": label,
                "status": phase_statuses.get(key, "unknown"),
                "output_path": relative_path(_phase_output_path(case_dir, key)) if _phase_output_path(case_dir, key) else None,
            }
            for key, label, _ in ANALYSIS_PHASES
        },
        "memory_analysis": {
            "status": memory_findings.get("status") or phase_statuses.get("memory_analysis"),
            "analysis_completed": bool(memory_findings.get("analysis_completed")),
            "reason": memory_findings.get("reason"),
            "blocking_errors": memory_findings.get("blocking_errors") or [],
            "recommended_action": memory_findings.get("recommended_action"),
            "dumps_analysed": len(memory_findings.get("dumps_analyzed") or []),
            "plugins_completed": sorted(memory_findings.get("completed_plugins") or []),
            "plugins_failed": sorted(memory_findings.get("failed_plugins") or []),
            "limitations": memory_findings.get("limitations") or [],
            "preflight": {
                "memory_dumps_found": memory_preflight.get("memory_dumps_found"),
                "symbols_found": memory_preflight.get("symbols_found"),
                "analysis_possible": memory_preflight.get("analysis_possible"),
                "blocking_reason": memory_preflight.get("blocking_reason"),
                "symbol_search_paths": memory_preflight.get("symbol_search_paths") or [],
            },
            "dumps": memory_findings.get("dumps_analyzed") or [],
        },
        "summary_preview": None,
    }
    _write_json(report_path, report)
    _write_json(
        manifest_path,
        {
            "case_id": case_entry.get("case_id"),
            "analysis_id": status.get("analysis_id"),
            "generated_at": report["generated_at"],
            "status": report["analysis_status"],
            "report_path": relative_path(report_path),
            "summary_path": relative_path(summary_path),
            "phases": {key: (status.get("phases") or {}).get(key, {}).get("status") for key, _, _ in ANALYSIS_PHASES},
        },
    )
    summary_lines = [
        f"# Forensic Analysis Summary for {case_entry.get('source_case_name')}",
        "",
        f"- Case ID: `{case_entry.get('case_id')}`",
        f"- Analysis ID: `{status.get('analysis_id')}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Overall analysis status: `{report['analysis_status']}`",
        "",
        "## Phase Status",
        "",
    ]
    for key, label, _ in ANALYSIS_PHASES:
        summary_lines.append(f"- `{label}`: `{phase_statuses.get(key, 'unknown')}`")
    summary_lines.extend(
        [
            "",
            "## Memory Analysis",
            "",
            f"- Status: `{report['memory_analysis']['status']}`",
            f"- Dumps analysed: `{report['memory_analysis']['dumps_analysed']}`",
            f"- Completed plugins: `{', '.join(report['memory_analysis']['plugins_completed']) or 'none'}`",
            f"- Failed plugins: `{', '.join(report['memory_analysis']['plugins_failed']) or 'none'}`",
        ]
    )
    if report["memory_analysis"]["preflight"].get("blocking_reason"):
        summary_lines.append(f"- Blocking reason: {report['memory_analysis']['preflight']['blocking_reason']}")
    if report["memory_analysis"].get("blocking_errors"):
        summary_lines.extend(["", "### Memory blocking errors", ""])
        summary_lines.extend(f"- {item}" for item in report["memory_analysis"]["blocking_errors"])
    summary_lines.extend(
        [
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
        ]
    )
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
    report["summary_preview"] = "\n".join(summary_lines)
    report["findings"]["report_path"] = relative_path(report_path)
    report["findings"]["manifest_path"] = relative_path(manifest_path)
    report["findings"]["summary_path"] = relative_path(summary_path)
    _write_json(report_path, report)
    status["output_files"].append(relative_path(manifest_path))
    status["output_files"].append(relative_path(summary_path))
    return report


def _phase_foc_refresh(case_dir: Path) -> dict:
    manifest = regenerate_foc()
    return {
        "phase": "foc_readiness_update",
        "status": "completed",
        "input_artifacts": [relative_path(_analysis_dir(case_dir) / "forensic_analysis_report.json")],
        "tool_used": "python3",
        "findings": {
            "foc_manifest_updated_at": manifest.get("updated_at"),
            "scenario_id": manifest.get("scenario_id"),
            "generation_status": manifest.get("generation_status"),
        },
        "limitations": ["Causal reconstruction remains intentionally blocked after forensic analysis completion."],
        "errors": [],
    }


def _run_phase(case_entry: dict, case_dir: Path, status: dict, phase_key: str) -> dict:
    if phase_key == "preflight_validation":
        return _build_preflight(case_entry, case_dir)
    if phase_key == "evidence_inventory":
        return _phase_evidence_inventory(case_dir)
    if phase_key == "integrity_custody_validation":
        return _phase_integrity_custody(case_dir)
    if phase_key == "temporal_validation":
        return _phase_temporal_validation(case_dir)
    if phase_key == "network_analysis":
        return _phase_network(case_dir)
    if phase_key == "memory_analysis":
        return _phase_memory(case_dir)
    if phase_key == "disk_analysis":
        return _phase_disk(case_dir)
    if phase_key == "ot_export_analysis":
        return _phase_ot(case_dir)
    if phase_key == "alerts_detection_analysis":
        return _phase_alerts(case_dir)
    if phase_key == "pipeline_custody_analysis":
        return _phase_pipeline_custody(case_dir)
    if phase_key == "unified_forensic_timeline":
        return _phase_timeline(case_dir)
    if phase_key == "cross_layer_findings":
        return _phase_cross_layer(case_dir)
    if phase_key == "forensic_analysis_report_generation":
        return _phase_final_report(case_entry, case_dir, status)
    if phase_key == "foc_readiness_update":
        return _phase_foc_refresh(case_dir)
    raise KeyError(f"Unknown phase: {phase_key}")


def _worker(case_entry: dict, force: bool) -> None:
    case_id = str(case_entry.get("case_id"))
    case_dir = _case_dir_from_entry(case_entry)
    status = _init_status(case_entry, force=force)
    try:
        for phase_key, label, _ in ANALYSIS_PHASES:
            # check for user cancellation before starting each phase
            try:
                if _analysis_cancel_path(case_dir).exists():
                    status["status"] = "cancelled"
                    status["finished_at"] = utc_now()
                    status["current_phase"] = None
                    status["errors"].append({"phase": phase_key, "message": "cancelled_by_user"})
                    _write_status(case_dir, status)
                    # remove cancel request file
                    try:
                        _analysis_cancel_path(case_dir).unlink()
                    except Exception:
                        pass
                    return
            except Exception:
                pass
            _record_phase_transition(case_dir, status, phase_key, "running", {"started_at": utc_now()})
            try:
                payload = _run_phase(case_entry, case_dir, status, phase_key)
                payload = _finalize_phase_output(case_dir, status, phase_key, payload)
                phase_status = str(payload.get("status") or "completed")
                extra = {
                    "finished_at": utc_now(),
                    "output_path": relative_path(_phase_output_path(case_dir, phase_key)) if _phase_output_path(case_dir, phase_key) else None,
                    "errors": payload.get("errors") or [],
                    "limitations": payload.get("limitations") or [],
                }
                if phase_key == "memory_analysis" and isinstance(payload.get("findings"), dict):
                    extra["memory_preflight_path"] = payload["findings"].get("memory_preflight_path")
                    extra["memory_findings_path"] = payload["findings"].get("memory_findings_path")
                    extra["memory_results"] = payload["findings"].get("results") or []
                if phase_status.startswith("failed"):
                    phase_messages = _message_list(payload.get("errors")) or [phase_status]
                    status["errors"].append({"phase": phase_key, "message": "; ".join(phase_messages)})
                elif phase_status.startswith("partial"):
                    phase_messages = _message_list(payload.get("errors")) or _message_list(payload.get("limitations")) or [phase_status]
                    status["warnings"].append({"phase": phase_key, "message": "; ".join(phase_messages)})
                elif phase_status.startswith("skipped"):
                    status["warnings"].append({"phase": phase_key, "message": payload.get("not_executed_reason") or phase_status})
                _set_phase_status(case_dir, status, phase_key, phase_status, extra=extra)
            except Exception as exc:
                logger.warning("FOC analysis phase failed case=%s phase=%s: %s", case_id, phase_key, exc, exc_info=True)
                stdout_path, stderr_path = _phase_log_paths(case_dir, phase_key)
                error_payload = {
                    "phase": phase_key,
                    "status": "failed",
                    "input_artifacts": [],
                    "tool_used": "not_available",
                    "findings": {},
                    "limitations": [],
                    "errors": [str(exc)],
                }
                output_path = _phase_output_path(case_dir, phase_key)
                if output_path:
                    _write_json(output_path, error_payload)
                status["errors"].append(
                    {
                        "phase": phase_key,
                        "command": None,
                        "exit_code": None,
                        "stdout_path": relative_path(stdout_path),
                        "stderr_path": relative_path(stderr_path),
                        "error_message": str(exc),
                        "failed_input_artifact": None,
                        "suggested_debug_action": "Open debug details to inspect the exact command, stderr and expected output.",
                    }
                )
                _set_phase_status(
                    case_dir,
                    status,
                    phase_key,
                    "failed",
                    extra={
                        "finished_at": utc_now(),
                        "output_path": relative_path(output_path) if output_path else None,
                        "stderr_path": relative_path(stderr_path),
                    },
                )
        if status.get("failed_phases") or status.get("partial_phases"):
            status["status"] = "partial" if (case_dir / "analysis" / "forensic_analysis_report.json").is_file() else "failed"
        else:
            status["status"] = "completed"
        status["finished_at"] = utc_now()
    finally:
        status["current_phase"] = None
        _write_status(case_dir, status)
        with _ANALYSIS_STATE_LOCK:
            _RUNNING_ANALYSES.pop(case_id, None)


def run_analysis(case_id: str, force: bool = False) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    current = load_analysis_status(case_id)
    with _ANALYSIS_STATE_LOCK:
        thread = _RUNNING_ANALYSES.get(case_id)
        if thread and thread.is_alive():
            return {"error": "analysis_already_running", "case_id": case_id}
        if current.get("status") == "running":
            return {"error": "analysis_already_running", "case_id": case_id}
        worker = threading.Thread(target=_worker, args=(case_entry, force), daemon=True, name=f"foc-analysis-{case_id}")
        _RUNNING_ANALYSES[case_id] = worker
        worker.start()
    return {"result": "started", "case_id": case_id, "force": force}


def validate_analysis(case_id: str) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(case_entry)
    status = load_analysis_status(case_id)
    phases = status.get("phases") or {}
    validation = []
    for phase_key, _, _ in ANALYSIS_PHASES:
        output_path = _phase_output_path(case_dir, phase_key)
        if not output_path or not output_path.exists():
            validation.append({"phase": phase_key, "status": "missing_output", "output_path": relative_path(output_path) if output_path else None})
            continue
        payload = _json_load(output_path)
        ok, reason = _validate_phase_payload(payload if isinstance(payload, dict) else {})
        validation.append({"phase": phase_key, "status": "valid" if ok else "invalid", "reason": reason, "output_path": relative_path(output_path)})
    return {
        "case_id": case_id,
        "validated_at": utc_now(),
        "status": status.get("status"),
        "validation": validation,
    }


def analysis_logs(case_id: str) -> dict:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(case_entry)
    logs = []
    for stdout_path in sorted(_analysis_logs_dir(case_dir).glob("*.stdout.log")):
        stderr_path = stdout_path.with_name(stdout_path.name.replace(".stdout.log", ".stderr.log"))
        tail_stdout = "\n".join(stdout_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:]) if stdout_path.exists() else ""
        tail_stderr = "\n".join(stderr_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-20:]) if stderr_path.exists() else ""
        logs.append(
            {
                "phase": stdout_path.name.replace(".stdout.log", ""),
                "stdout_path": relative_path(stdout_path),
                "stderr_path": relative_path(stderr_path),
                "stdout_tail": tail_stdout,
                "stderr_tail": tail_stderr,
            }
        )
    return {"case_id": case_id, "logs": logs}


def analysis_report(case_id: str) -> dict | None:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return None
    case_dir = _case_dir_from_entry(case_entry)
    report_path = _analysis_dir(case_dir) / "forensic_analysis_report.json"
    report = _json_load(report_path)
    if not isinstance(report, dict):
        return None
    summary_path = _analysis_dir(case_dir) / "forensic_analysis_summary.md"
    report["summary_path"] = relative_path(summary_path) if summary_path.exists() else None
    report["summary_preview"] = summary_path.read_text(encoding="utf-8", errors="ignore")[:4000] if summary_path.exists() else None
    return report


def analysis_visual_summary(case_id: str) -> dict | None:
    case_entry = get_case_entry(case_id)
    if not case_entry:
        return None
    case_dir = _case_dir_from_entry(case_entry)
    summary_path = _analysis_visual_summary_path(case_dir)
    payload = _json_load(summary_path)
    if isinstance(payload, dict):
        return payload
    status = load_analysis_status(case_id)
    if status.get("error"):
        return None
    try:
        payload = _analysis_visual_summary(case_entry, case_dir, status)
        _write_json(summary_path, payload)
        return payload
    except Exception:
        logger.warning("Failed to build analysis visual summary for case %s", case_id, exc_info=True)
        return None


def generate_symbols_for_case(case_id: str, dump_id: str | None = None, ssh_user: str | None = None, ssh_key: str | None = None, vm_ip: str | None = None, vm_id: str | None = None) -> dict:
    """Public helper to attempt generating volatility symbols for a case/dump.
    It will try local vmlinux-based generation first, then SSH-based helper if credentials provided.
    Returns a report dict with attempted actions and found symbols.
    """
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    dumps = sorted((case_dir / "memory").glob("*.lime"))
    if not dumps:
        return {"error": "no_memory_dumps", "case_id": case_id}
    # find dump by id or use first
    target_dump = None
    if dump_id:
        for d in dumps:
            if _dump_identifier(d, _dump_metadata(case_dir, d)) == dump_id:
                target_dump = d
                break
    if not target_dump:
        target_dump = dumps[0]
    metadata = _dump_metadata(case_dir, target_dump)
    detected_kernel = None
    # attempt to read existing banners output if present
    output_dir = _memory_output_dir(case_dir, _dump_identifier(target_dump, metadata))
    banners_path = output_dir / "vol3_banners.txt"
    if banners_path.exists():
        try:
            text = _read_text(banners_path)
            _, detected_kernel = _parse_linux_banner(text)
        except Exception:
            detected_kernel = None

    result = {
        "case_id": case_id,
        "dump": relative_path(target_dump),
        "detected_kernel": detected_kernel,
        "attempts": [],
        "symbols_found": [],
    }

    # Refresh symbol list
    search_roots, symbol_files = _discover_symbol_files()
    matched = _matching_symbol_files(detected_kernel, symbol_files)
    if matched:
        result["symbols_found"] = [str(p) for p in matched]
        result["status"] = "already_present"
        return result

    # try local generation from vmlinux in case dir
    gen = _generate_symbol_from_vmlinux(case_dir, detected_kernel)
    if gen:
        result["attempts"].append({"method": "local_dwarf2json", "path": str(gen)})
        search_roots, symbol_files = _discover_symbol_files()
        matched = _matching_symbol_files(detected_kernel, symbol_files)
        if matched:
            result["symbols_found"] = [str(p) for p in matched]
            result["status"] = "generated_local"
            return result

    # try SSH-based generation if SSH params present
    # allow passing via args or metadata
    creds = {"ssh_user": ssh_user, "ssh_key": ssh_key, "vm_ip": vm_ip, "vm_id": vm_id}
    # merge with metadata if any field missing
    if not creds.get("vm_ip"):
        creds["vm_ip"] = metadata.get("vm_ip") or metadata.get("ip")
    if not creds.get("vm_id"):
        creds["vm_id"] = metadata.get("vm_id")
    # write a minimal creds file into metadata if ssh_key provided as content path
    if creds.get("ssh_key"):
        # no-op here; _generate_symbol_via_ssh reads creds file or env
        pass
    ssh_report = _generate_symbol_via_ssh(case_dir, output_dir, target_dump, detected_kernel, metadata)
    if ssh_report:
        result["attempts"].append({"method": "ssh_helper", "report": ssh_report})
        if ssh_report.get("matched"):
            result["symbols_found"] = ssh_report.get("matched_symbols") or []
            result["status"] = "generated_via_ssh"
            return result

    result["status"] = "failed_to_generate"
    return result


def cases_with_analysis_state() -> dict:
    enriched = []
    for entry in _list_case_entries():
        status = load_analysis_status(str(entry.get("case_id")))
        case_dir = _case_dir_from_entry(entry)
        inventory = _artifact_inventory(case_dir)
        try:
            from ..foc_causal_reconstruction.service import summarize_case_causal_state

            causal_state = summarize_case_causal_state(str(entry.get("case_id")), case_dir, analysis_status=status)
        except Exception:
            logger.warning("Failed to summarize causal reconstruction state for case %s", entry.get("case_id"), exc_info=True)
            causal_state = None
        enriched.append(
            {
                **entry,
                "analysis_status": status.get("status"),
                "analysis_ready_to_run": bool(inventory["artifacts_total"]),
                "available_layers": inventory["layers"],
                "inventory_summary": inventory["artifact_type_counts"],
                "analysis_report_path": status.get("forensic_analysis_report_path"),
                "causal_state": causal_state,
            }
        )
    return {"generated_at": utc_now(), "cases": enriched}
