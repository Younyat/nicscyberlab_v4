"""
Level C Campaign Orchestrator
==============================
Manages a full scenario redeployment cycle:
  Destroy → Clean → Deploy IT → Deploy OT → Wait Nodes →
  Install Tools → Run Level B → Capture Snapshot
  (repeat N times, then compare snapshots)

Scientific tool installation order — 4 phases, strictly sequential:

  Phase 1 – IT SERVERS (monitor, then attack)
      Wazuh Manager and Caldera Server must be fully running before any
      agent anywhere tries to connect.
        monitor: wazuh (Manager), nmap
        attack:  caldera (Server), caldera_ot_plugins, mbpoll, nmap

  Phase 2 – IT VICTIM
      All victim tools installed after servers are up.
      Suricata runs before agents (IDS ready first).
        victim: suricata, nmap, wazuh_agent, caldera_agent

  Phase 3 – OT BASE TOOLS (plc, then fuxa, then scada)
      Suricata sensor installed before wazuh_agent on each OT node.
        plc/fuxa/scada: suricata, wazuh_agent

  Phase 4 – OT CONFIGS
      ALL phase-3 tools (suricata + wazuh_agent) must be present.
      rollback_wazuh_suricata_integration requires BOTH.
      wazuh_fim_realtime requires wazuh_agent to be enrolled.
        plc/fuxa/scada: rollback_suricata_ping_detection,
                        rollback_suricata_modbus_register_detection,
                        rollback_wazuh_suricata_integration,
                        wazuh_fim_realtime

  Within each phase, nodes are processed in order:
      monitor → attack → victim → plc → fuxa → scada
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve()
PROJECT_ROOT = _HERE.parents[3]

JOBS_DIR = PROJECT_ROOT / "runtime" / "level_c_jobs"
TOOLS_INSTALLED_DIR = PROJECT_ROOT / "tools-installer" / "installed"
TOOLS_TMP_DIR = PROJECT_ROOT / "tools-installer-tmp"
TOOLS_SCRIPTS_DIR = PROJECT_ROOT / "tools-installer" / "scripts"
SNAPSHOTS_DIR = PROJECT_ROOT / "runtime" / "scenario_snapshots"
SCENARIO_FILE = PROJECT_ROOT / "scenario" / "scenario_file.json"
SCENARIO_FILE_BACKUP = PROJECT_ROOT / "app_core" / "infrastructure" / "redeployment_module" / "scenario_file.json"
INDUSTRIAL_FILE = PROJECT_ROOT / "industrial-scenario" / "scenarios" / "industrial_industrial_file.json"
DEPLOY_IT_SCRIPT = PROJECT_ROOT / "app_core" / "infrastructure" / "redeployment_module" / "deploy_scenario_from_json.sh"
DEPLOY_PLC_SCRIPT = PROJECT_ROOT / "industrial-scenario" / "PLC" / "deploy_plc_scenario.sh"
DEPLOY_FUXA_SCRIPT = PROJECT_ROOT / "industrial-scenario" / "FUXA" / "deploy_fuxa_vm.sh"
ADMIN_OPENRC = PROJECT_ROOT / "admin-openrc.sh"
DEPLOY_STATUS_FILE = PROJECT_ROOT / "scenario" / "deployment_status.json"

# ---------------------------------------------------------------------------
# Sentinel values
# ---------------------------------------------------------------------------
CONFIRMATION_TOKEN = "LAUNCH_LEVEL_C"

PHASES = [
    "IDLE",
    "VALIDATING",
    "DESTROYING",
    "CLEANING",
    "DEPLOYING_IT",
    "DEPLOYING_OT",
    "WAITING_NODES",
    "INSTALLING_TOOLS",
    "RUNNING_LEVEL_B",
    "WAITING_LEVEL_B",
    "CAPTURING_SNAPSHOT",
    "COMPARING",
    "COMPLETED",
    "FAILED",
    "ABORTED",
]

# Scientific tool dependency order: (instance_role_pattern, tool_name, phase)
# role_pattern is matched as a substring of the instance name (case-insensitive).
# Within each phase, nodes run in _NODE_INSTALL_ORDER sequence (enforced by sorting).
_TOOL_SCIENTIFIC_ORDER: list[tuple[str, str, int]] = [
    # ── Phase 1: IT SERVERS ──────────────────────────────────────────────────
    # monitor first (Wazuh Manager), then attack (Caldera Server).
    # Agents in later phases connect to these — they MUST be running.
    ("monitor",  "wazuh",                1),   # Wazuh Manager — first of all
    ("monitor",  "nmap",                 1),
    ("attack",   "caldera",              1),   # Caldera Server — before caldera_agent
    ("attack",   "caldera_ot_plugins",   1),
    ("attack",   "mbpoll",               1),
    ("attack",   "nmap",                 1),

    # ── Phase 2: IT VICTIM ───────────────────────────────────────────────────
    # Suricata (IDS) before agents — sensor running before agents enrol.
    ("victim",   "suricata",             2),
    ("victim",   "nmap",                 2),
    ("victim",   "wazuh_agent",          2),   # Connects to Wazuh Manager (phase 1)
    ("victim",   "caldera_agent",        2),   # Connects to Caldera Server (phase 1)

    # ── Phase 3: OT BASE TOOLS ───────────────────────────────────────────────
    # suricata before wazuh_agent on every OT node (sensor ready before agent).
    # Processed node by node: plc → fuxa → scada.
    ("plc",      "suricata",             3),
    ("fuxa",     "suricata",             3),
    ("scada",    "suricata",             3),
    ("plc",      "wazuh_agent",          3),   # Connects to Wazuh Manager (phase 1)
    ("fuxa",     "wazuh_agent",          3),
    ("scada",    "wazuh_agent",          3),

    # ── Phase 4: OT CONFIGS ──────────────────────────────────────────────────
    # All phase-3 tools (suricata + wazuh_agent) must be installed on the node.
    # rollback_wazuh_suricata_integration needs BOTH suricata AND wazuh_agent.
    # wazuh_fim_realtime needs wazuh_agent enrolled and active.
    ("plc",      "rollback_suricata_ping_detection",            4),
    ("plc",      "rollback_suricata_modbus_register_detection", 4),
    ("plc",      "rollback_wazuh_suricata_integration",         4),
    ("plc",      "wazuh_fim_realtime",                          4),
    ("fuxa",     "rollback_suricata_ping_detection",            4),
    ("fuxa",     "rollback_suricata_modbus_register_detection", 4),
    ("fuxa",     "rollback_wazuh_suricata_integration",         4),
    ("fuxa",     "wazuh_fim_realtime",                          4),
    ("scada",    "rollback_suricata_ping_detection",            4),
    ("scada",    "rollback_suricata_modbus_register_detection", 4),
    ("scada",    "rollback_wazuh_suricata_integration",         4),
    ("scada",    "wazuh_fim_realtime",                          4),
]

# Node installation priority — enforces the within-phase order.
# Lower value = installed first.  Nodes not listed sort last.
_NODE_INSTALL_ORDER = ["monitor", "attack", "victim", "plc", "fuxa", "scada"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _log(state: dict, level: str, msg: str) -> None:
    entry = {"ts": _utc_now(), "level": level, "msg": msg}
    state.setdefault("log", []).append(entry)


def _save_state(job_dir: Path, state: dict) -> None:
    _write_json(job_dir / "job_state.json", state)


def _run_cmd(
    cmd: list[str],
    cwd: Path,
    timeout: int = 600,
    job_dir: Path | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr).

    When job_dir is provided the process is launched with Popen and the stop
    flag is polled every 2 s.  If the flag is set the subprocess is terminated
    immediately (returncode -2) so the background thread can exit without
    waiting for the full Terraform/script timeout.
    When job_dir is None the call blocks until completion (legacy behaviour).
    """
    try:
        env = {**os.environ}
        if job_dir is None:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                env=env,
            )
            return proc.returncode, proc.stdout, proc.stderr

        # Interruptible path — poll stop flag every 2 s
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        deadline = time.time() + timeout
        while proc.poll() is None:
            if time.time() >= deadline:
                proc.kill()
                stdout, stderr = proc.communicate()
                return -1, stdout or "", f"Command timed out after {timeout}s\n{stderr or ''}"
            if _is_stop_requested(job_dir):
                proc.terminate()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = "", ""
                return -2, stdout or "", "Process killed: stop requested by user."
            time.sleep(2)

        stdout, stderr = proc.communicate()
        return proc.returncode, stdout or "", stderr or ""

    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return -1, "", str(exc)


def _source_openrc_env() -> dict:
    """Source admin-openrc.sh and return the resulting env vars."""
    if not ADMIN_OPENRC.is_file():
        return dict(os.environ)
    cmd = ["bash", "-c", f"source {ADMIN_OPENRC} >/dev/null 2>&1 && env"]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=10)
        env = dict(os.environ)
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                env[k] = v
        return env
    except Exception:
        return dict(os.environ)


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

def _phase_validate(state: dict, job_dir: Path, config: dict) -> bool:
    """Check prerequisites before starting any destructive action."""
    _log(state, "INFO", "Validating prerequisites for Level C campaign...")
    errors = []

    # Snapshot must exist
    snaps = sorted(SNAPSHOTS_DIR.glob("SS-*/snapshot_manifest.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not snaps:
        errors.append("No scenario snapshot found. Capture a snapshot first.")
    else:
        snap = _load_json(snaps[0])
        state["source_snapshot_id"] = snap.get("snapshot_id")
        _log(state, "INFO", f"Using source snapshot: {snap.get('snapshot_id')}")

    # IT scenario deploy script must exist
    if not DEPLOY_IT_SCRIPT.is_file():
        errors.append(f"IT deploy script missing: {DEPLOY_IT_SCRIPT.relative_to(PROJECT_ROOT)}")

    # IT scenario file must exist (or restorable from backup)
    if not SCENARIO_FILE.is_file() and not SCENARIO_FILE_BACKUP.is_file():
        errors.append(f"IT scenario file missing: {SCENARIO_FILE.relative_to(PROJECT_ROOT)} (and no backup in redeployment_module)")

    # Campaign must exist and be Level B
    campaign_id = config.get("campaign_id")
    if not campaign_id:
        errors.append("campaign_id is required.")
    else:
        from app_core.infrastructure.foc_experimentation.campaign_service import get_campaign
        camp = get_campaign(campaign_id)
        if not camp:
            errors.append(f"Campaign not found: {campaign_id}")
        elif str(camp.get("level") or camp.get("config", {}).get("level") or "").upper() != "B":
            errors.append(f"Campaign {campaign_id} is not Level B.")
        else:
            attack_id = (camp.get("config") or {}).get("attack_id")
            if not attack_id:
                errors.append(f"Campaign {campaign_id} has no attack_id configured.")
            else:
                _log(state, "INFO", f"Level B campaign OK: {campaign_id} | attack: {attack_id}")

    # Destruction / reconstruction readiness check.
    # Level C destroys the scenario itself in each cycle, so it is valid to start
    # even if the scenario is ALREADY destroyed from a previous failed cycle — as
    # long as the reconstruction blueprint exists so we can redeploy.
    try:
        from app_core.infrastructure.foc_experimentation.scenario_destruction_service import validate_scenario_destruction
        from app_core.infrastructure.foc_experimentation.scientific_memory_sync import get_active_scenario_memory_hint
        val = validate_scenario_destruction()
        if val.get("error") == "scenario_not_found":
            # No scenario card at all — genuinely blocked
            errors.append(f"Scenario card not found. Deploy and snapshot a scenario first.")
        elif val.get("error"):
            errors.append(f"Scenario destruction validation: {val.get('message')}")
        elif not val.get("ready"):
            blocking = val.get("missing_blocking", [])
            # If the only blocker is active_scenario_exists, it means the scenario
            # was already destroyed by a previous Level C cycle. This is fine — we
            # skip destruction and go straight to redeployment.
            only_missing_active = blocking == ["active_scenario_exists"] or (
                len(blocking) == 1 and "active_scenario" in blocking[0]
            )
            if only_missing_active:
                _log(state, "INFO", "Scenario already destroyed from previous cycle. Redeployment will proceed directly.")
            else:
                errors.append(f"Scenario not ready for Level C: missing {blocking}. Capture a snapshot first.")
        else:
            _log(state, "INFO", "Scenario destruction validation: READY")
    except Exception as exc:
        errors.append(f"Scenario destruction validation failed: {exc}")

    if errors:
        for e in errors:
            _log(state, "ERROR", e)
        state["validation_errors"] = errors
        return False

    state["validation_errors"] = []
    _log(state, "INFO", "Validation passed.")
    return True


def _all_openstack_servers(env: dict | None = None) -> list[dict]:
    """Return all OpenStack servers as list of {id, name, status} dicts."""
    try:
        rc, stdout, _ = _run_cmd(
            ["openstack", "server", "list", "--format", "json"],
            cwd=PROJECT_ROOT, timeout=45,
        )
        if rc != 0 or not stdout.strip():
            return []
        import json as _json
        return [{"id": s.get("ID", ""), "name": s.get("Name", ""), "status": s.get("Status", "")}
                for s in _json.loads(stdout)]
    except Exception:
        return []


def _scenario_node_names() -> set[str]:
    """Collect all known IT node names from scenario files (current + backup)."""
    names: set[str] = set()
    for src in (SCENARIO_FILE, SCENARIO_FILE_BACKUP):
        if src.is_file():
            try:
                import json as _json
                sc = _json.loads(src.read_text())
                for n in sc.get("nodes", []):
                    if n.get("name"):
                        names.add(n["name"].strip())
            except Exception:
                pass
    return names


def _openstack_sweep_delete(state: dict, rep_num: int, env: dict) -> None:
    """After the main destroy, delete any surviving scenario instances directly.

    Targets: known OT names + all IT node names from scenario files.
    This catches nodes from previous deployments that are no longer tracked
    by Terraform and would otherwise survive the standard destroy script.
    """
    ot_fixed = {"PLC_Instance", "FUXA_Instance", "SCADA_Instance"}
    it_names = _scenario_node_names()
    target_names = ot_fixed | it_names

    servers = _all_openstack_servers(env)
    remaining = [s for s in servers if s["name"] in target_names and s["status"] not in ("DELETED", "SOFT_DELETED")]

    if not remaining:
        _log(state, "INFO", f"  [Sweep] No surviving scenario instances found.")
        return

    _log(state, "WARN", f"  [Sweep] {len(remaining)} instance(s) survived standard destroy: {[s['name'] for s in remaining]}")
    for srv in remaining:
        _log(state, "INFO", f"  [Sweep] Deleting {srv['name']} ({srv['id']})...")
        rc, _, stderr = _run_cmd(
            ["openstack", "server", "delete", srv["id"]],
            cwd=PROJECT_ROOT, timeout=60,
        )
        if rc == 0:
            _log(state, "INFO", f"  [Sweep] Deleted {srv['name']} OK.")
        else:
            _log(state, "WARN", f"  [Sweep] Delete {srv['name']} returned rc={rc}: {stderr[:120]}")


def _wait_openstack_clean(state: dict, job_dir: Path, rep_num: int, env: dict, timeout_s: int = 240) -> bool:
    """Poll OpenStack until all known scenario instances are fully gone."""
    ot_fixed = {"PLC_Instance", "FUXA_Instance", "SCADA_Instance"}
    target_names = ot_fixed | _scenario_node_names()
    deadline = time.time() + timeout_s
    poll = 10

    _log(state, "INFO", f"  [Wait] Polling OpenStack until all scenario instances are gone (up to {timeout_s}s)...")
    while time.time() < deadline:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", "  [Wait] Stop requested — aborting OpenStack clean wait.")
            return False
        servers = _all_openstack_servers(env)
        alive = [s for s in servers if s["name"] in target_names and s["status"] not in ("DELETED", "SOFT_DELETED")]
        if not alive:
            _log(state, "INFO", "  [Wait] OpenStack is clean — no scenario instances remaining.")
            return True
        _log(state, "INFO", f"  [Wait] Still waiting: {[s['name']+'/'+s['status'] for s in alive]}")
        time.sleep(poll)

    # One last check
    servers = _all_openstack_servers(env)
    alive = [s for s in servers if s["name"] in target_names and s["status"] not in ("DELETED", "SOFT_DELETED")]
    if alive:
        _log(state, "ERROR", f"  [Wait] Timeout: instances still present after {timeout_s}s: {[s['name'] for s in alive]}")
        return False
    return True


def _phase_destroy(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Destroy IT + OT scenario.

    Strategy:
    1. Run destroy_full_scenario() (Terraform + OT named deletes).
    2. Do a sweep-delete of any surviving scenario instances (catches stale
       nodes from older deployments not tracked by current Terraform state).
    3. Poll OpenStack until zero scenario instances remain.

    Never skip based on scientific memory alone — always verify via OpenStack.
    """
    _log(state, "INFO", f"[Rep {rep_num}] Destroying active scenario (IT + OT)...")

    env = _source_openrc_env()

    # Step 1: run the standard destroy service
    try:
        from app_core.infrastructure.foc_experimentation.scenario_destruction_service import destroy_full_scenario
        result = destroy_full_scenario(
            confirmation="OK",
            operator=f"level_c_orchestrator_rep_{rep_num}",
        )
        if result.get("error") and result["error"] != "scenario_not_found":
            _log(state, "WARN", f"Destroy service: {result.get('message')} — continuing with sweep.")
        elif not result.get("error"):
            destroyed = result.get("resources_destroyed", [])
            failed = result.get("resources_failed", [])
            _log(state, "INFO", f"Destroy service: {len(destroyed)} destroyed, {len(failed)} failed.")
            for f in failed:
                _log(state, "WARN", f"  Destroy warning: {f}")
    except Exception as exc:
        _log(state, "WARN", f"Destroy service exception (continuing with sweep): {exc}")

    # Step 2: sweep any survivors (stale nodes from previous deployments)
    _openstack_sweep_delete(state, rep_num, env)

    # Step 3: wait for OpenStack to confirm all instances are gone
    clean = _wait_openstack_clean(state, job_dir, rep_num, env)
    if not clean:
        _log(state, "ERROR", "OpenStack still has scenario instances after destroy+sweep (or stop requested). Aborting.")
        return False

    _log(state, "INFO", f"[Rep {rep_num}] Destroy complete — OpenStack confirmed clean.")
    return True


def _phase_clean_cases(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Clean disabled/archived cases and old campaign data to start fresh."""
    _log(state, "INFO", f"[Rep {rep_num}] Cleaning old cases and validation reports...")
    try:
        from app_core.infrastructure.foc_experimentation.global_cleanup_service import (
            list_cleanup_inventory,
            execute_cleanup,
        )
        inventory = list_cleanup_inventory()
        items = inventory.get("items", [])
        # Select: disabled cases and validation reports only (NOT campaigns, NOT snapshots)
        eligible_ids = [
            item["item_id"]
            for item in items
            if item.get("deletable") and item.get("item_type") in (
                "forensic_case", "validation_report", "scientific_report"
            )
        ]
        if not eligible_ids:
            _log(state, "INFO", "No eligible items to clean.")
            return True
        result = execute_cleanup(
            selected_item_ids=eligible_ids,
            confirmation="OK",
            operator=f"level_c_orchestrator_rep_{rep_num}",
        )
        deleted = result.get("deleted_count", 0)
        _log(state, "INFO", f"Cleanup completed: {deleted} items deleted.")
        return True
    except Exception as exc:
        _log(state, "WARN", f"Cleanup warning (non-fatal): {exc}")
        return True  # Non-fatal


def _phase_clean_installed_records(state: dict, job_dir: Path, rep_num: int) -> None:
    """Remove stale tools-installer/installed/*.json after destruction, and reset
    'installed' tool statuses in tools-installer-tmp/*.json to 'pending'.

    After redeploy, new instances need fresh tool installation. If tools-installer-tmp
    files still have status 'installed' from the previous run, tools_install_master.sh
    will skip them, leaving new instances incomplete.
    """
    _log(state, "INFO", f"[Rep {rep_num}] Cleaning stale tool-installed records...")
    removed = []
    try:
        if TOOLS_INSTALLED_DIR.is_dir():
            for f in TOOLS_INSTALLED_DIR.glob("*.json"):
                try:
                    f.unlink()
                    removed.append(f.name)
                except Exception as exc:
                    _log(state, "WARN", f"  Could not remove {f.name}: {exc}")
        _log(state, "INFO", f"  Removed {len(removed)} stale record(s): {removed}")
    except Exception as exc:
        _log(state, "WARN", f"  Stale record cleanup warning: {exc}")

    # Reset 'installed' → 'pending' in all tools-installer-tmp/*.json so that
    # fresh instances always get all tools re-installed after each redeploy.
    reset_count = 0
    try:
        if TOOLS_TMP_DIR.is_dir():
            for f in TOOLS_TMP_DIR.glob("*.json"):
                try:
                    data = _load_json(f)
                    if not isinstance(data, dict):
                        continue
                    tools = data.get("tools")
                    if not isinstance(tools, dict):
                        continue
                    changed = False
                    for tool, status in tools.items():
                        if status == "installed":
                            tools[tool] = "pending"
                            changed = True
                    if changed:
                        _write_json(f, data)
                        reset_count += 1
                except Exception as exc:
                    _log(state, "WARN", f"  Could not reset statuses in {f.name}: {exc}")
        _log(state, "INFO", f"  Reset 'installed'→'pending' in {reset_count} tmp file(s).")
    except Exception as exc:
        _log(state, "WARN", f"  Tmp file status reset warning: {exc}")


def _phase_deploy_it(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Run the IT scenario deployment script."""
    _log(state, "INFO", f"[Rep {rep_num}] Deploying IT scenario from {SCENARIO_FILE.relative_to(PROJECT_ROOT)}...")
    if not DEPLOY_IT_SCRIPT.is_file():
        _log(state, "ERROR", "IT deploy script not found.")
        return False

    # After each destruction cycle, scenario/scenario_file.json is deleted by the
    # destroy service. Restore it from the redeployment module backup copy.
    if not SCENARIO_FILE.is_file():
        if SCENARIO_FILE_BACKUP.is_file():
            import shutil
            try:
                SCENARIO_FILE.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(SCENARIO_FILE_BACKUP), str(SCENARIO_FILE))
                _log(state, "INFO", f"  Restored scenario_file.json from redeployment module backup.")
            except Exception as exc:
                _log(state, "ERROR", f"  Could not restore scenario_file.json: {exc}")
                return False
        else:
            _log(state, "ERROR", "IT scenario file not found and no backup available.")
            return False

    rc, stdout, stderr = _run_cmd(
        ["bash", str(DEPLOY_IT_SCRIPT), str(SCENARIO_FILE)],
        cwd=PROJECT_ROOT,
        timeout=900,  # 15 min — OpenStack VM creation can be slow
        job_dir=job_dir,  # allow stop to kill the subprocess
    )
    _log(state, "INFO", f"IT deploy exit code: {rc}")
    if stdout:
        for line in stdout.strip().splitlines()[-20:]:
            _log(state, "STDOUT", line)
    if stderr:
        for line in stderr.strip().splitlines()[-10:]:
            _log(state, "STDERR", line)
    if rc != 0:
        _log(state, "ERROR", f"IT deployment failed (rc={rc})")
        return False
    _log(state, "INFO", "IT scenario deployed successfully.")
    return True


def _phase_deploy_ot(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Deploy OT nodes (PLC + FUXA/SCADA) via existing deploy scripts."""
    _log(state, "INFO", f"[Rep {rep_num}] Deploying OT nodes (PLC + FUXA)...")
    results = {}

    for component, script in [("plc", DEPLOY_PLC_SCRIPT), ("fuxa", DEPLOY_FUXA_SCRIPT)]:
        if not script.is_file():
            _log(state, "WARN", f"OT deploy script not found for {component}: {script}")
            results[component] = "script_missing"
            continue
        _log(state, "INFO", f"Deploying {component.upper()} via {script.name}...")
        rc, stdout, stderr = _run_cmd(
            ["bash", str(script)],
            cwd=PROJECT_ROOT,
            timeout=900,
            job_dir=job_dir,  # allow stop to kill the subprocess
        )
        if rc == 0:
            _log(state, "INFO", f"{component.upper()} deployed OK.")
            results[component] = "ok"
        else:
            _log(state, "WARN", f"{component.upper()} deploy failed (rc={rc}): {stderr[:200]}")
            results[component] = f"failed_rc_{rc}"

    state.setdefault("rep_results", {}).setdefault(str(rep_num), {})["ot_deploy"] = results
    # Non-fatal: OT nodes can be missing in some configurations
    return True


def _phase_wait_nodes(state: dict, job_dir: Path, rep_num: int, timeout_seconds: int = 300) -> bool:
    """Poll until IT nodes are SSH-reachable (via openstack server list)."""
    _log(state, "INFO", f"[Rep {rep_num}] Waiting for nodes to be ACTIVE in OpenStack (up to {timeout_seconds}s)...")
    env = _source_openrc_env()
    deadline = time.time() + timeout_seconds
    poll_interval = 15

    while time.time() < deadline:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", "Stop requested — aborting node wait.")
            return False
        rc, stdout, _ = _run_cmd(
            ["openstack", "server", "list", "--format", "json", "--status", "ACTIVE"],
            cwd=PROJECT_ROOT,
            timeout=30,
        )
        if rc == 0:
            try:
                servers = json.loads(stdout) if stdout.strip() else []
                if len(servers) >= 3:  # At least IT nodes up
                    _log(state, "INFO", f"Nodes active: {[s.get('Name') for s in servers]}")
                    return True
            except Exception:
                pass
        remaining = int(deadline - time.time())
        _log(state, "INFO", f"Waiting for nodes... ({remaining}s remaining)")
        time.sleep(poll_interval)

    _log(state, "WARN", "Node wait timeout — proceeding anyway.")
    return True  # Non-fatal: tool installer will report per-node errors


def _resolve_instance_info(instance_name: str) -> dict:
    """Query OpenStack for the ID, private IP, and floating IP of an instance by name."""
    rc, stdout, _ = _run_cmd(
        ["openstack", "server", "show", instance_name, "--format", "json"],
        cwd=PROJECT_ROOT,
        timeout=20,
    )
    if rc != 0:
        return {}
    try:
        data = json.loads(stdout)
        instance_id = data.get("id") or data.get("ID")
        nets = data.get("addresses") or {}
        ip_private = None
        ip_floating = None
        for _net, addrs in nets.items():
            for addr in addrs:
                if isinstance(addr, dict):
                    # Detailed format: {"addr": "x.x.x.x", "OS-EXT-IPS:type": "fixed"/"floating"}
                    t = addr.get("OS-EXT-IPS:type", "")
                    a = addr.get("addr") or addr.get("ip") or ""
                    if t == "fixed" and not ip_private:
                        ip_private = a
                    elif t == "floating" and not ip_floating:
                        ip_floating = a
                    elif not t and a and not ip_private:
                        ip_private = a
                elif isinstance(addr, str):
                    # Compact format: plain IP strings; classify by subnet prefix
                    # 192.168.x.x = internal private; anything else = floating/routable
                    if addr.startswith("192.168.") and not ip_private:
                        ip_private = addr
                    elif not ip_floating and not addr.startswith("192.168."):
                        ip_floating = addr
            if not ip_private and not ip_floating:
                for addr in addrs:
                    raw = addr.get("addr") if isinstance(addr, dict) else addr
                    if raw:
                        ip_private = raw
                        break
        return {
            "id": instance_id,
            "ip_private": ip_private,
            "ip_floating": ip_floating,
        }
    except Exception:
        return {}


def _build_instance_tool_map() -> list[dict]:
    """
    Build the list of instances + their tools to reinstall.
    Reads from tools-installer-tmp/ (permanent definitions, never wiped),
    groups by node role, merges tools from all files for the same role,
    then resolves current OpenStack instance names (which change after
    each redeploy — e.g. 'monitor 1' becomes 'monitor 11').
    Returns list of {instance_id, instance_name, tools: [str]}.
    """
    if not TOOLS_TMP_DIR.is_dir():
        return []

    # Group tools by role (union across multiple files for same role)
    role_tools: dict[str, set[str]] = {}
    for f in TOOLS_TMP_DIR.glob("*.json"):
        data = _load_json(f)
        if not isinstance(data, dict):
            continue
        name = (data.get("instance_name") or data.get("name") or f.stem).lower()
        tools_raw = data.get("tools") or data.get("installed_tools") or {}
        tools = list(tools_raw.keys()) if isinstance(tools_raw, dict) else list(tools_raw)
        if not tools:
            continue
        role = None
        for r in _NODE_INSTALL_ORDER:
            if r in name:
                role = r
                break
        if role is None:
            continue
        role_tools.setdefault(role, set()).update(tools)

    if not role_tools:
        return []

    # Query live OpenStack to get current instance names (they change each redeploy)
    try:
        rc, stdout, _ = _run_cmd(
            ["openstack", "server", "list", "--format", "json"],
            cwd=PROJECT_ROOT, timeout=30,
        )
        servers = json.loads(stdout) if rc == 0 and stdout.strip() else []
    except Exception:
        servers = []

    role_to_server: dict[str, dict] = {}
    for srv in servers:
        srv_name = (srv.get("Name") or srv.get("name") or "").lower()
        for r in _NODE_INSTALL_ORDER:
            if r in srv_name and r not in role_to_server:
                role_to_server[r] = {
                    "instance_id":   srv.get("ID")   or srv.get("id")   or "",
                    "instance_name": srv.get("Name") or srv.get("name") or "",
                }
                break

    result = []
    for role, tools in role_tools.items():
        srv_info = role_to_server.get(role)
        if srv_info:
            result.append({
                "instance_id":   srv_info["instance_id"],
                "instance_name": srv_info["instance_name"],
                "tools":         sorted(tools),
            })
        else:
            result.append({
                "instance_id":   role,
                "instance_name": role,
                "tools":         sorted(tools),
            })
    return result


def _scientific_tool_phases(instance_tool_map: list[dict]) -> list[list[dict]]:
    """
    Assign each (instance, tool) to one of 4 phases and sort within each phase.

    Sort key: (phase, node_priority, tool_position_in_order)
      - node_priority follows _NODE_INSTALL_ORDER: monitor→attack→victim→plc→fuxa→scada
      - tool_position is the index in _TOOL_SCIENTIFIC_ORDER, preserving declared order
        within each node (e.g. suricata before wazuh_agent)
      - Unknown tools (not in the table) go to phase 4, node last, position last.
    """
    phases: list[list[dict]] = [[], [], [], []]  # phases 1–4

    def _node_priority(inst_name: str) -> int:
        n = inst_name.lower()
        for i, pattern in enumerate(_NODE_INSTALL_ORDER):
            if pattern in n:
                return i
        return len(_NODE_INSTALL_ORDER)

    def _phase_and_pos(inst_name: str, tool: str) -> tuple[int, int]:
        n = inst_name.lower()
        t = tool.lower()
        for pos, (role_pattern, t2, ph) in enumerate(_TOOL_SCIENTIFIC_ORDER):
            if role_pattern.lower() in n and t2.lower() == t:
                return ph, pos
        return 4, len(_TOOL_SCIENTIFIC_ORDER)  # unknown → last phase, last position

    # Collect all (sort_key, item) tuples, then sort before appending to phases
    all_items: list[tuple[int, int, int, dict]] = []
    for inst in instance_tool_map:
        node_pri = _node_priority(inst["instance_name"])
        for tool in inst["tools"]:
            ph, tool_pos = _phase_and_pos(inst["instance_name"], tool)
            all_items.append((ph, node_pri, tool_pos, {
                "instance_name": inst["instance_name"],
                "instance_id":   inst["instance_id"],
                "tool": tool,
            }))

    all_items.sort(key=lambda x: (x[0], x[1], x[2]))

    for ph, _node_pri, _tool_pos, item in all_items:
        phases[ph - 1].append(item)

    return phases


def _install_tool_on_instance(instance_name: str, tool: str, log: list,
                               instance_info: dict | None = None) -> bool:
    """Install a single tool on an instance via backend HTTP API.

    Mirrors exactly what the dashboard JS sends so that tools_install_master.sh
    can resolve the SSH user and IP from OpenStack without guessing.
    """
    import urllib.request
    base = "http://127.0.0.1:5001"

    # Resolve OpenStack instance info if not provided
    info = instance_info or _resolve_instance_info(instance_name)
    instance_id = info.get("id")
    ip_private  = info.get("ip_private")
    ip_floating = info.get("ip_floating")

    # Step 1: Register the tool in tools-installer-tmp/<safe_name>_tools.json
    # Payload matches what index-tools.js sends (fields read by tools_install_master.sh)
    reg_payload = json.dumps({
        "name":        instance_name,   # tools_install_master.sh reads .name
        "id":          instance_id,
        "instance":    instance_name,   # also send for legacy compatibility
        "ip_private":  ip_private,
        "ip_floating": ip_floating,
        "tools":       {tool: "pending"},
    }).encode()
    try:
        req = urllib.request.Request(
            f"{base}/api/add_tool_to_instance",
            data=reg_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 201):
                log.append(f"  [WARN] add_tool_to_instance {instance_name}/{tool}: HTTP {resp.status}")
    except Exception as exc:
        log.append(f"  [WARN] add_tool_to_instance {instance_name}/{tool}: {exc}")
        return False

    # Step 2: Run installation — the response is SSE (text/event-stream).
    # HTTP status is always 200 regardless of script exit code; success is
    # indicated by "[SUCCESS]" in the body or "[FIN] Exit Code: 0".
    try:
        inst_payload = json.dumps({
            "instance":    instance_name,
            "instance_id": instance_id,
            "tools":       [tool],
        }).encode()
        req2 = urllib.request.Request(
            f"{base}/api/install_tools",
            data=inst_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req2, timeout=600) as resp:
            output = resp.read().decode(errors="replace")
        tail = output[-400:].strip()
        log.append(f"  {instance_name}/{tool}: {tail}")
        # Determine real success from SSE body content
        success = ("[SUCCESS]" in output) or ("Exit Code: 0" in output)
        if not success:
            log.append(f"  [WARN] {instance_name}/{tool}: script did not report [SUCCESS]")
        return success
    except Exception as exc:
        log.append(f"  [ERROR] install_tools {instance_name}/{tool}: {exc}")
        return False


def _phase_install_tools(state: dict, job_dir: Path, rep_num: int) -> bool:
    """Install tools in 4-phase scientific dependency order."""
    _log(state, "INFO", f"[Rep {rep_num}] Installing tools in scientific order (4 phases)...")

    instance_tool_map = _build_instance_tool_map()
    if not instance_tool_map:
        _log(state, "WARN", "No tool installation records found — skipping tool install.")
        return True

    # Resolve fresh OpenStack info for each instance ONCE (IPs change after redeploy)
    _log(state, "INFO", "  Resolving current OpenStack instance info...")
    instance_info_cache: dict[str, dict] = {}
    for inst in instance_tool_map:
        name = inst["instance_name"]
        info = _resolve_instance_info(name)
        instance_info_cache[name] = info
        _log(state, "INFO",
             f"  {name}: id={info.get('id') or 'not_found'} "
             f"ip={info.get('ip_private') or info.get('ip_floating') or 'not_found'}")

    # Pre-update ALL tools-installer-tmp JSON files with fresh IPs so that
    # tools_install_master.sh (which processes ALL files on every invocation)
    # never reads stale IPs from a previous deployment.
    import re as _re
    for inst in instance_tool_map:
        name = inst["instance_name"]
        info = instance_info_cache.get(name, {})
        if not info:
            continue
        safe = _re.sub(r"[^a-zA-Z0-9_-]", "_", name.lower())
        tmp_path = TOOLS_TMP_DIR / f"{safe}_tools.json"
        if tmp_path.exists():
            try:
                fdata = _load_json(tmp_path) or {}
                fdata["ip_private"] = info.get("ip_private")
                fdata["ip_floating"] = info.get("ip_floating")
                if info.get("id"):
                    fdata["instance_id"] = info["id"]
                _write_json(tmp_path, fdata)
                _log(state, "INFO",
                     f"  Updated IP in {tmp_path.name}: float={info.get('ip_floating')}")
            except Exception as exc:
                _log(state, "WARN", f"  Could not update IP in {tmp_path.name}: {exc}")

    phases = _scientific_tool_phases(instance_tool_map)
    phase_labels = [
        "Phase 1 — IT SERVERS  (monitor: Wazuh Manager → attack: Caldera Server)",
        "Phase 2 — IT VICTIM   (suricata → wazuh_agent → caldera_agent)",
        "Phase 3 — OT TOOLS    (plc/fuxa: suricata → wazuh_agent)",
        "Phase 4 — OT CONFIGS  (rollback rules, Wazuh-Suricata integration, FIM)",
    ]
    # After phase 1 (servers): 90 s — Wazuh Manager + Caldera must be fully UP
    #   before agents in phases 2–3 try to enrol/connect.
    # After phases 2, 3: 15 s — settling buffer before dependent installs.
    phase_waits = [90, 15, 15]

    for ph_idx, phase_items in enumerate(phases):
        label = phase_labels[ph_idx]
        if not phase_items:
            _log(state, "INFO", f"  {label}: nothing to install, skipping.")
            continue
        _log(state, "INFO", f"  {label} — {len(phase_items)} install(s)")
        ph_log: list[str] = []
        stopped_mid_phase = False
        for item in phase_items:
            if _is_stop_requested(job_dir):
                _log(state, "WARN", f"  Stop requested — halting tool installation mid-phase.")
                stopped_mid_phase = True
                break
            info = instance_info_cache.get(item["instance_name"], {})
            ok = _install_tool_on_instance(item["instance_name"], item["tool"], ph_log,
                                            instance_info=info)
            status = "OK" if ok else "WARN"
            _log(state, status,
                 f"    {item['instance_name']} ← {item['tool']}: {'installed' if ok else 'failed/skipped'}")
        for line in ph_log:
            _log(state, "STDOUT", line)
        if stopped_mid_phase:
            return False  # caller will pick up stop flag via _check_stop()
        if ph_idx < len(phase_waits) and phase_items:
            wait_s = phase_waits[ph_idx]
            _log(state, "INFO", f"  Waiting {wait_s}s before next phase...")
            time.sleep(wait_s)

    _log(state, "INFO", "Tool installation phases completed.")
    return True  # Non-fatal: individual tool failures don't abort Level C


def _phase_run_level_b(state: dict, job_dir: Path, rep_num: int, config: dict) -> str | None:
    """Launch Level B repetitions. Returns job_id or None on failure."""
    campaign_id = config["campaign_id"]
    requested_reps = int(config.get("level_b_repetitions") or 10)
    nested_a_reps = int(config.get("level_a_repetitions") or requested_reps)

    _log(state, "INFO",
         f"[Rep {rep_num}] Launching Level B: campaign={campaign_id} reps={requested_reps} nested_A={nested_a_reps}")

    try:
        from app_core.infrastructure.foc_experimentation.level_b_repetition_runner import (
            start_level_b_repetitions_job,
        )
        result = start_level_b_repetitions_job(
            campaign_id=campaign_id,
            confirmation="OK",
            requested_repetitions=requested_reps,
            requested_nested_level_a_repetitions=nested_a_reps,
            cleanup_old_cases=True,
            dfir_mode_before="full",
            dfir_mode_after="full",
        )
        if result.get("error"):
            _log(state, "ERROR", f"Level B launch error: {result.get('message')}")
            return None
        job_id = result.get("job_id")
        _log(state, "INFO", f"Level B job started: {job_id}")
        return job_id
    except Exception as exc:
        _log(state, "ERROR", f"Level B launch exception: {exc}")
        return None


def _phase_wait_level_b(state: dict, job_dir: Path, rep_num: int,
                         job_id: str, timeout_seconds: int = 7200) -> bool:
    """Poll until the Level B job is done."""
    from app_core.infrastructure.foc_experimentation.job_runner import get_job
    _log(state, "INFO", f"[Rep {rep_num}] Waiting for Level B job {job_id} (up to {timeout_seconds}s)...")

    deadline = time.time() + timeout_seconds
    poll_interval = 15

    status = "unknown"
    while time.time() < deadline:
        if _is_stop_requested(job_dir):
            _log(state, "WARN", f"Stop requested — aborting wait for Level B job {job_id}.")
            return False
        try:
            job = get_job(job_id)
            status = (job or {}).get("status", "unknown")
            if status in ("completed", "completed_with_warnings", "completed_with_degradation",
                          "completed_with_failures"):
                _log(state, "INFO", f"Level B job {job_id} completed: {status}")
                return True
            if status in ("failed", "error", "cancelled"):
                _log(state, "ERROR", f"Level B job {job_id} ended with: {status}")
                return False
        except Exception as exc:
            _log(state, "WARN", f"Polling Level B job {job_id}: {exc}")

        remaining = int(deadline - time.time())
        _log(state, "INFO", f"Level B running... ({remaining}s remaining, status={status})")
        time.sleep(poll_interval)

    _log(state, "WARN", f"Level B job {job_id} timed out — proceeding to snapshot.")
    return True  # Take snapshot anyway


def _phase_capture_snapshot(state: dict, job_dir: Path, rep_num: int) -> str | None:
    """Capture a snapshot and return its ID."""
    _log(state, "INFO", f"[Rep {rep_num}] Capturing scenario snapshot...")
    try:
        from app_core.infrastructure.scenario_snapshot.service import capture_snapshot
        result = capture_snapshot()
        snap_id = result.get("snapshot_id")
        _log(state, "INFO", f"Snapshot captured: {snap_id}")
        return snap_id
    except Exception as exc:
        _log(state, "ERROR", f"Snapshot capture failed: {exc}")
        return None


def _phase_compare_snapshots(state: dict, job_dir: Path, snapshot_ids: list[str]) -> dict:
    """
    Compare all Level C snapshots scientifically.
    Returns a comparison report with ΔWCPR, ΔCPR, reproducibility index.
    """
    _log(state, "INFO", f"Comparing {len(snapshot_ids)} Level C snapshots...")
    if len(snapshot_ids) < 2:
        return {"status": "single_repetition", "message": "Only one Level C repetition — no cross-deployment comparison."}

    try:
        from app_core.infrastructure.scenario_snapshot.service import (
            get_snapshot,
            diff_snapshots,
        )
        comparisons = []
        for i in range(len(snapshot_ids) - 1):
            a_id = snapshot_ids[i]
            b_id = snapshot_ids[i + 1]
            diff = diff_snapshots(a_id, b_id)
            cpr_a = _extract_cpr_from_snapshot(get_snapshot(a_id))
            cpr_b = _extract_cpr_from_snapshot(get_snapshot(b_id))
            delta_cpr = round(abs((cpr_b or 0) - (cpr_a or 0)), 4)
            wcpr_a = _extract_wcpr_from_snapshot(get_snapshot(a_id))
            wcpr_b = _extract_wcpr_from_snapshot(get_snapshot(b_id))
            delta_wcpr = round(abs((wcpr_b or 0) - (wcpr_a or 0)), 4)
            comparisons.append({
                "rep_a": i + 1,
                "rep_b": i + 2,
                "snapshot_a": a_id,
                "snapshot_b": b_id,
                "delta_cpr": delta_cpr,
                "delta_wcpr": delta_wcpr,
                "delta_wcpr_acceptable": delta_wcpr <= 0.05,
                "diff_summary": diff.get("summary") or {},
            })
            _log(state, "INFO",
                 f"  Rep {i+1} vs Rep {i+2}: ΔCPR={delta_cpr:.4f} ΔWCPR={delta_wcpr:.4f} "
                 f"{'✓ ACCEPTABLE' if delta_wcpr <= 0.05 else '⚠ EXCEEDS 5% THRESHOLD'}")

        all_acceptable = all(c["delta_wcpr_acceptable"] for c in comparisons)
        max_delta_wcpr = max((c["delta_wcpr"] for c in comparisons), default=0)
        reproducibility_index = round(max(0.0, 1.0 - max_delta_wcpr * 10), 4)

        report = {
            "status": "ok",
            "level_c_repetitions": len(snapshot_ids),
            "comparisons": comparisons,
            "all_delta_wcpr_acceptable": all_acceptable,
            "max_delta_wcpr": max_delta_wcpr,
            "reproducibility_index": reproducibility_index,
            "verdict": (
                "REPRODUCIBLE — All Level C deployments yield consistent forensic evidence chains."
                if all_acceptable else
                "NON-REPRODUCIBLE — ΔWCPR exceeds 5% threshold. Review environment stability."
            ),
        }
        _write_json(job_dir / "comparison_report.json", report)
        return report
    except Exception as exc:
        _log(state, "ERROR", f"Comparison failed: {exc}")
        return {"status": "error", "error": str(exc)}


def _extract_cpr_from_snapshot(snap: dict | None) -> float | None:
    if not snap:
        return None
    camps = snap.get("campaigns") or {}
    stats = camps.get("level_b_stats") or {}
    return stats.get("cpr_mean")


def _extract_wcpr_from_snapshot(snap: dict | None) -> float | None:
    if not snap:
        return None
    camps = snap.get("campaigns") or {}
    stats = camps.get("level_b_stats") or {}
    return stats.get("wcpr_mean")


# ---------------------------------------------------------------------------
# Main orchestration loop
# ---------------------------------------------------------------------------

def _is_stop_requested(job_dir: Path) -> bool:
    return (job_dir / "stop.flag").exists()


def _run_level_c_job(job_id: str, job_dir: Path, config: dict) -> None:
    """Background thread: runs the full Level C state machine."""
    state_path = job_dir / "job_state.json"
    state = _load_json(state_path) or {}

    def _save():
        state["updated_at"] = _utc_now()
        _save_state(job_dir, state)

    def _set_phase(phase: str):
        state["phase"] = phase
        state["phase_started_at"] = _utc_now()
        _log(state, "PHASE", f"→ {phase}")
        _save()

    def _check_stop() -> bool:
        """Return True and set STOPPED state if stop was requested."""
        if _is_stop_requested(job_dir):
            _log(state, "INFO", "Stop requested — halting campaign.")
            _set_phase("STOPPED")
            state["status"] = "stopped"
            state["error"] = "Campaign stopped by user request."
            _save()
            return True
        return False

    level_c_reps = int(config.get("level_c_repetitions") or 1)
    snapshot_ids: list[str] = []

    # ── VALIDATE ─────────────────────────────────────────────────────────────
    _set_phase("VALIDATING")
    if _check_stop(): return
    if not _phase_validate(state, job_dir, config):
        _set_phase("FAILED")
        state["error"] = "Validation failed. See log for details."
        _save()
        return

    # ── REPETITION LOOP ──────────────────────────────────────────────────────
    for rep in range(1, level_c_reps + 1):
        if _check_stop(): return
        state["current_repetition"] = rep
        _log(state, "INFO", f"━━━ Starting Level C repetition {rep}/{level_c_reps} ━━━")

        # DESTROY
        _set_phase(f"DESTROYING (rep {rep}/{level_c_reps})")
        if _check_stop(): return
        if not _phase_destroy(state, job_dir, rep):
            if _check_stop(): return  # stop was requested inside destroy
            _set_phase("FAILED")
            state["error"] = f"Destruction failed at rep {rep}."
            _save()
            return
        _save()
        time.sleep(10)

        # CLEAN
        if _check_stop(): return
        _set_phase(f"CLEANING (rep {rep}/{level_c_reps})")
        _phase_clean_cases(state, job_dir, rep)
        _phase_clean_installed_records(state, job_dir, rep)
        _save()

        # DEPLOY IT
        if _check_stop(): return
        _set_phase(f"DEPLOYING_IT (rep {rep}/{level_c_reps})")
        if not _phase_deploy_it(state, job_dir, rep):
            if _check_stop(): return  # stop was requested inside deploy
            _set_phase("FAILED")
            state["error"] = f"IT deployment failed at rep {rep}."
            _save()
            return
        _save()

        # DEPLOY OT
        if _check_stop(): return
        _set_phase(f"DEPLOYING_OT (rep {rep}/{level_c_reps})")
        _phase_deploy_ot(state, job_dir, rep)
        _save()

        # WAIT NODES
        if _check_stop(): return
        _set_phase(f"WAITING_NODES (rep {rep}/{level_c_reps})")
        if not _phase_wait_nodes(state, job_dir, rep):
            if _check_stop(): return  # stop was requested during wait
            # timeout is non-fatal — continue to tool install
        _save()

        # INSTALL TOOLS
        if _check_stop(): return
        _set_phase(f"INSTALLING_TOOLS (rep {rep}/{level_c_reps})")
        if not _phase_install_tools(state, job_dir, rep):
            if _check_stop(): return  # stop was requested mid-install
        _save()

        # RUN LEVEL B
        if _check_stop(): return
        _set_phase(f"RUNNING_LEVEL_B (rep {rep}/{level_c_reps})")
        b_job_id = _phase_run_level_b(state, job_dir, rep, config)
        _save()
        if not b_job_id:
            if _check_stop(): return  # stop was requested
            _set_phase("FAILED")
            state["error"] = f"Level B launch failed at rep {rep}."
            _save()
            return

        # WAIT LEVEL B
        if _check_stop(): return
        _set_phase(f"WAITING_LEVEL_B (rep {rep}/{level_c_reps})")
        if not _phase_wait_level_b(state, job_dir, rep, b_job_id):
            if _check_stop(): return  # stop was requested during wait
            # Level B failure is non-fatal — still capture snapshot
        _save()

        # SNAPSHOT
        if _check_stop(): return
        _set_phase(f"CAPTURING_SNAPSHOT (rep {rep}/{level_c_reps})")
        snap_id = _phase_capture_snapshot(state, job_dir, rep)
        if snap_id:
            snapshot_ids.append(snap_id)
        _save()

    state["level_c_snapshot_ids"] = snapshot_ids

    # ── COMPARE ───────────────────────────────────────────────────────────────
    if _check_stop(): return
    _set_phase("COMPARING")
    comparison = _phase_compare_snapshots(state, job_dir, snapshot_ids)
    state["comparison_report"] = comparison
    _save()

    # ── DONE ──────────────────────────────────────────────────────────────────
    _set_phase("COMPLETED")
    state["completed_at"] = _utc_now()
    state["level_c_snapshot_ids"] = snapshot_ids
    _log(state, "INFO", f"Level C campaign completed. {len(snapshot_ids)} snapshots captured.")
    _save()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_active_jobs: dict[str, threading.Thread] = {}


def launch_level_c(
    *,
    campaign_id: str,
    level_c_repetitions: int = 1,
    level_b_repetitions: int = 10,
    level_a_repetitions: int | None = None,
    confirmation: str = "",
) -> dict:
    """Launch a Level C campaign orchestration job. Returns job info immediately."""
    if confirmation.strip() != CONFIRMATION_TOKEN:
        return {
            "error": "confirmation_required",
            "message": f'Type exactly "{CONFIRMATION_TOKEN}" to confirm. This will DESTROY the active scenario and redeploy from scratch.',
            "confirmation_token": CONFIRMATION_TOKEN,
        }

    job_id = f"LC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "campaign_id": campaign_id,
        "level_c_repetitions": max(1, min(5, level_c_repetitions)),
        "level_b_repetitions": max(1, min(50, level_b_repetitions)),
        "level_a_repetitions": level_a_repetitions or level_b_repetitions,
    }

    initial_state = {
        "job_id": job_id,
        "job_type": "level_c_campaign",
        "phase": "QUEUED",
        "status": "running",
        "config": config,
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "current_repetition": 0,
        "level_c_snapshot_ids": [],
        "comparison_report": None,
        "validation_errors": [],
        "log": [],
    }
    _save_state(job_dir, initial_state)

    thread = threading.Thread(
        target=_run_level_c_job,
        args=(job_id, job_dir, config),
        daemon=True,
    )
    _active_jobs[job_id] = thread
    thread.start()

    return {
        "job_id": job_id,
        "status": "started",
        "config": config,
        "message": f"Level C campaign launched (job {job_id}).",
    }


def get_job_status(job_id: str) -> dict | None:
    path = JOBS_DIR / job_id / "job_state.json"
    return _load_json(path)


def stop_job(job_id: str) -> dict:
    """Request graceful stop of a running Level C job.

    Two strategies depending on whether the background thread is still alive:

    • Thread alive (updated_at recent): write stop.flag — the thread picks it up
      within 2 s (Popen poll) or 15 s (status poll) and transitions to STOPPED.

    • Thread dead (Flask restart / crash, updated_at > 60 s old): write STOPPED
      directly to job_state.json so the UI exits "Stopping…" immediately instead
      of being stuck forever.
    """
    job_dir = JOBS_DIR / job_id
    if not job_dir.is_dir():
        return {"error": "job_not_found", "message": f"Job {job_id} does not exist."}

    flag = job_dir / "stop.flag"
    flag.touch()

    state_path = job_dir / "job_state.json"
    state = _load_json(state_path) or {}
    phase = state.get("phase", "unknown")

    if state.get("status") in ("stopped", "completed", "failed"):
        return {"status": "ok", "job_id": job_id, "current_phase": phase,
                "message": "Job is already in a terminal state."}

    # Detect whether the background thread is still alive by checking when the
    # state was last written.  If >60 s old, the thread is gone and nobody will
    # ever process the stop.flag — write STOPPED directly.
    thread_alive = False
    updated_at_str = state.get("updated_at", "")
    if updated_at_str:
        try:
            updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
            age_s = (datetime.now(timezone.utc) - updated_at).total_seconds()
            thread_alive = age_s < 60
        except Exception:
            pass

    if not thread_alive:
        # Thread is dead — set STOPPED directly so the UI clears immediately
        state["phase"] = "STOPPED"
        state["status"] = "stopped"
        state["stop_requested"] = False
        state["error"] = "Campaign stopped (background thread was no longer active)."
        state["updated_at"] = _utc_now()
        _write_json(state_path, state)
        return {
            "status": "ok",
            "job_id": job_id,
            "current_phase": "STOPPED",
            "message": "Thread was no longer running — state set to STOPPED immediately.",
        }

    # Thread is alive — mark stop_requested so UI shows "Stopping…" right away,
    # the thread will pick up stop.flag within 2–15 s and write STOPPED itself.
    state["stop_requested"] = True
    state["stop_requested_at"] = _utc_now()
    _write_json(state_path, state)
    return {
        "status": "ok",
        "job_id": job_id,
        "current_phase": phase,
        "message": f"Stop requested. Job will halt within ~2–15 s. Current phase: {phase}.",
    }


def list_jobs() -> list[dict]:
    if not JOBS_DIR.is_dir():
        return []
    result = []
    for job_dir in sorted(JOBS_DIR.iterdir(), reverse=True):
        state_file = job_dir / "job_state.json"
        if not state_file.is_file():
            continue
        state = _load_json(state_file) or {}
        result.append({
            "job_id": state.get("job_id", job_dir.name),
            "phase": state.get("phase"),
            "status": state.get("status", "unknown"),
            "current_repetition": state.get("current_repetition", 0),
            "level_c_repetitions": (state.get("config") or {}).get("level_c_repetitions", 1),
            "level_c_snapshot_ids": state.get("level_c_snapshot_ids", []),
            "created_at": state.get("created_at"),
            "completed_at": state.get("completed_at"),
            "error": state.get("error"),
        })
    return result


def get_comparison_report(job_id: str) -> dict | None:
    path = JOBS_DIR / job_id / "comparison_report.json"
    return _load_json(path)
