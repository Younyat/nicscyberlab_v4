#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab - Full Scenario Capture Cleaner
# ============================================================
# What it does:
#   1. Stops any active nics_scenario_captures.sh process.
#   2. Removes the capture lock directory.
#   3. Removes scenario_captures.pid.
#   4. Removes daily capture folders named YYYYMMDD.
#   5. Optionally removes log files.
#
# Usage:
#   sudo bash nics_clean_scenario_captures.sh
#   sudo bash nics_clean_scenario_captures.sh --all
#   sudo bash nics_clean_scenario_captures.sh --dry-run --all
#   sudo bash nics_clean_scenario_captures.sh --all --keep-today
#
# Options:
#   --dry-run       Show what would be removed, without deleting anything.
#   --keep-today    Keep today's UTC daily capture folder.
#   --logs          Also remove log files.
#   --all           Remove daily captures, logs, lock and PID file.
# ============================================================

DRY_RUN=0
KEEP_TODAY=0
CLEAN_LOGS=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

CAPTURE_ROOT_DEFAULT="$REPO_ROOT/app_core/infrastructure/ics_traffic/captures/full_scenario_captures"
CAPTURE_ROOT="${CAPTURE_ROOT:-$CAPTURE_ROOT_DEFAULT}"

SCRIPT_NAME="nics_scenario_captures.sh"
LOCK_DIR="$CAPTURE_ROOT/.nics_scenario_captures.lock"
PID_FILE="$CAPTURE_ROOT/scenario_captures.pid"
LOG_DIR="$CAPTURE_ROOT/logs"

TODAY_UTC="$(date -u +%Y%m%d)"

usage() {
  cat <<EOF
Usage:
  sudo bash $0 [options]

Options:
  --dry-run       Show actions without killing processes or deleting files.
  --keep-today    Keep today's UTC capture folder: $TODAY_UTC
  --logs          Also clean log files.
  --all           Clean daily captures, logs, lock and PID file.
  -h, --help      Show this help message.

Optional variable:
  CAPTURE_ROOT=/path/to/full_scenario_captures sudo bash $0 --all
EOF
}

log()  { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
info() { log "[INFO]  $*"; }
ok()   { log "[OK]    $*"; }
warn() { log "[WARN]  $*"; }
err()  { log "[ERROR] $*"; }

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[DRY-RUN] $*"
  else
    eval "$@"
  fi
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run this script with sudo."
    echo "Example:"
    echo "  sudo bash $0 --all"
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --keep-today)
        KEEP_TODAY=1
        shift
        ;;
      --logs)
        CLEAN_LOGS=1
        shift
        ;;
      --all)
        CLEAN_LOGS=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

check_paths() {
  if [[ ! -d "$CAPTURE_ROOT" ]]; then
    err "Capture directory does not exist:"
    err "$CAPTURE_ROOT"
    exit 1
  fi

  info "Capture root: $CAPTURE_ROOT"
  info "Today UTC:    $TODAY_UTC"
}

show_current_state() {
  echo
  info "Current full_scenario_captures state:"
  ls -la "$CAPTURE_ROOT" || true

  echo
  info "Current processes related to $SCRIPT_NAME:"
  pgrep -af "$SCRIPT_NAME" || true

  echo
}

stop_capture_processes() {
  info "Stopping active $SCRIPT_NAME processes..."

  mapfile -t PIDS < <(pgrep -f "$SCRIPT_NAME" || true)

  if [[ ${#PIDS[@]} -eq 0 ]]; then
    ok "No active $SCRIPT_NAME process found."
    return 0
  fi

  for pid in "${PIDS[@]}"; do
    if [[ "$pid" == "$$" ]]; then
      continue
    fi

    local cmd
    cmd="$(ps -p "$pid" -o args= 2>/dev/null || true)"

    if [[ -z "$cmd" ]]; then
      continue
    fi

    info "Found process: PID=$pid CMD=$cmd"

    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "[DRY-RUN] kill -TERM $pid"
      echo "[DRY-RUN] kill -KILL $pid if still alive"
      continue
    fi

    kill -TERM "$pid" 2>/dev/null || true

    for _ in {1..10}; do
      if ! ps -p "$pid" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done

    if ps -p "$pid" >/dev/null 2>&1; then
      warn "PID=$pid is still alive. Forcing KILL."
      kill -KILL "$pid" 2>/dev/null || true
    fi

    if ! ps -p "$pid" >/dev/null 2>&1; then
      ok "PID=$pid stopped."
    else
      warn "Could not fully stop PID=$pid."
    fi
  done
}

clean_lock_and_pid() {
  info "Cleaning lock and PID file..."

  if [[ -d "$LOCK_DIR" ]]; then
    run_cmd "rm -rf '$LOCK_DIR'"
    ok "Lock removed: $LOCK_DIR"
  else
    ok "Lock does not exist: $LOCK_DIR"
  fi

  if [[ -f "$PID_FILE" ]]; then
    run_cmd "rm -f '$PID_FILE'"
    ok "PID file removed: $PID_FILE"
  else
    ok "PID file does not exist: $PID_FILE"
  fi
}

clean_day_folders() {
  info "Cleaning daily capture folders named YYYYMMDD..."

  mapfile -t DAY_DIRS < <(
    find "$CAPTURE_ROOT" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" \
      | awk '/^[0-9]{8}$/ {print}' \
      | sort
  )

  if [[ ${#DAY_DIRS[@]} -eq 0 ]]; then
    ok "No daily YYYYMMDD folders found."
    return 0
  fi

  for day in "${DAY_DIRS[@]}"; do
    if [[ "$KEEP_TODAY" -eq 1 && "$day" == "$TODAY_UTC" ]]; then
      warn "Keeping today's folder because --keep-today was used: $day"
      continue
    fi

    local dir="$CAPTURE_ROOT/$day"

    info "Removing daily capture folder: $dir"
    run_cmd "rm -rf '$dir'"
  done

  ok "Daily capture folder cleanup completed."
}

clean_logs() {
  if [[ "$CLEAN_LOGS" -ne 1 ]]; then
    info "Logs kept. Use --logs or --all to clean them."
    return 0
  fi

  info "Cleaning log files..."

  if [[ -d "$LOG_DIR" ]]; then
    run_cmd "find '$LOG_DIR' -type f -delete"
    ok "Log files removed inside: $LOG_DIR"
  else
    ok "Log directory does not exist: $LOG_DIR"
  fi
}

show_final_state() {
  echo
  info "Final full_scenario_captures state:"
  ls -la "$CAPTURE_ROOT" || true

  echo
  info "Remaining processes related to $SCRIPT_NAME:"
  pgrep -af "$SCRIPT_NAME" || true

  echo
  ok "Cleanup completed."
}

main() {
  parse_args "$@"
  need_root
  check_paths
  show_current_state
  stop_capture_processes
  clean_lock_and_pid
  clean_day_folders
  clean_logs
  show_final_state
}

main "$@"