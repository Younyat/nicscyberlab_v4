#!/usr/bin/env bash
set -uo pipefail

# ============================================================
# RESTART SCENARIO CAPTURE — NICS CyberLab (2026-07-17)
# ============================================================
# Stops the currently-running nics_scenario_captures.sh (rolling full-
# scenario pcap capture) and starts a fresh, detached instance so it picks
# up code changes (e.g. the CAPTURE_SCOPE=roles filter added this session).
#
# Deliberately does NOT touch the in-flight tcpdump child processes of the
# old instance -- only the parent script gets a SIGTERM. Any tcpdump still
# mid-rotation finishes naturally within its own timeout (<=120s) instead
# of being force-killed, so no pcap file gets truncated. The new instance's
# next rotation is what actually applies the new interface selection.
#
# Runs as root via the existing NOPASSWD sudoers rule for
# tools-installer/scripts-host/*.sh -- no new sudo privilege was granted to
# add this script.
# ============================================================

REPO_ROOT="/home/younes/nicscyberlab_v3"
CAPTURE_SCRIPT="${REPO_ROOT}/nics_scenario_captures.sh"
OUT_BASE="${REPO_ROOT}/app_core/infrastructure/ics_traffic/captures/full_scenario_captures"
PID_FILE="${OUT_BASE}/scenario_captures.pid"
LOG_DIR="${OUT_BASE}/logs"
RESTART_LOG="${LOG_DIR}/restart_$(date -u +%Y%m%dT%H%M%SZ).log"

mkdir -p "$LOG_DIR"

log_msg() {
    echo "data: [$1] $2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [RESTART-CAPTURE] [$1] $2" >> "$RESTART_LOG"
}

if [ "$(id -u)" -ne 0 ]; then
    log_msg "ERROR" "Must run as root (invoke via sudo)."
    exit 1
fi

OLD_PID=""
if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
fi

if [ -n "$OLD_PID" ] && ps -p "$OLD_PID" >/dev/null 2>&1; then
    log_msg "INFO" "Stopping old rolling-capture instance (pid=$OLD_PID)..."
    kill -TERM "$OLD_PID" 2>/dev/null || true
    for i in $(seq 1 15); do
        ps -p "$OLD_PID" >/dev/null 2>&1 || break
        sleep 1
    done
    if ps -p "$OLD_PID" >/dev/null 2>&1; then
        log_msg "WARN" "Old instance (pid=$OLD_PID) still alive after 15s -- leaving it, will not force-kill (its in-flight tcpdump children are left untouched either way)."
    else
        log_msg "INFO" "Old instance stopped cleanly."
    fi
else
    log_msg "INFO" "No live old instance found (pid_file=$PID_FILE, pid=${OLD_PID:-none})."
fi

log_msg "INFO" "Starting new rolling-capture instance..."
nohup bash "$CAPTURE_SCRIPT" >> "${LOG_DIR}/scenario_captures_stdout.log" 2>&1 < /dev/null &
disown
NEW_PID=$!
sleep 2
if ps -p "$NEW_PID" >/dev/null 2>&1; then
    log_msg "DONE" "New rolling-capture instance started (pid=$NEW_PID)."
    exit 0
else
    log_msg "ERROR" "New instance did not stay alive -- check ${LOG_DIR}/scenario_captures_stdout.log"
    exit 1
fi
