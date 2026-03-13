#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS - Full-scenario rolling capture
# - Detects tap* interfaces automatically on the HOST
# - Runs captures in parallel (1 tcpdump per interface)
# - Rotates every INTERVAL seconds (default: 120s)
# - Writes PCAPs under:
#     <OUT_BASE>/<YYYYMMDD>/<iface>/<iface>_<UTC>_<INTERVAL>s.pcap
# - Writes logs under:
#     <OUT_BASE>/logs
#
# Fixes included:
# - Correct REPO_ROOT resolution when script is in repo root:
#     /home/younes/nicscyberlab_v3/nics_scenario_captures.sh
# - Single-instance lock (prevents "saved twice" by multiple loops)
# - PID file and safe cleanup on exit
# - Optional: allow OUT_BASE override via env (recommended from starter)
# ============================================================

# ----------------------------
# Configuration (env overridable)
# ----------------------------
INTERVAL_SEC="${INTERVAL_SEC:-120}"          # seconds
SNAPLEN="${SNAPLEN:-0}"                      # 0 = full
EXTRA_IFACES_CSV="${EXTRA_IFACES_CSV:-}"     # optional, e.g. "br-int,ens33"
LOCK_NAME="${LOCK_NAME:-nics_scenario_captures.lock}"

# ----------------------------
# Path resolution
# ----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Expected layout:
#   REPO_ROOT/nics_scenario_captures.sh
#   REPO_ROOT/app_core/...
REPO_ROOT="$SCRIPT_DIR"

OUT_BASE_DEFAULT="${REPO_ROOT}/app_core/infrastructure/ics_traffic/captures/full_scenario_captures"
OUT_BASE="${OUT_BASE:-$OUT_BASE_DEFAULT}"
LOG_DIR="${OUT_BASE}/logs"
LOCK_DIR="${OUT_BASE}/.${LOCK_NAME}"
PID_FILE="${OUT_BASE}/scenario_captures.pid"

# ----------------------------
# Utils
# ----------------------------
log()  { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
err()  { log "[ERROR] $*"; }
warn() { log "[WARN]  $*"; }
info() { log "[INFO]  $*"; }

require_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || { err "Missing command: $c"; exit 1; }
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run as root (sudo)."
    exit 1
  fi
}

suggest_install_ubuntu() {
  cat <<'TXT'
[HINT] On Ubuntu/Debian install requirements with:
  sudo apt-get update
  sudo apt-get install -y tcpdump iproute2 coreutils gawk util-linux
TXT
}

utc_ts()  { date -u +%Y%m%d_%H%M%SZ; }
utc_day() { date -u +%Y%m%d; }

detect_taps() {
  ip -br link | awk '$1 ~ /^tap/ {print $1}'
}

parse_extra_ifaces() {
  local csv="${1:-}"
  [[ -z "$csv" ]] && return 0
  echo "$csv" | tr ',' '\n' | awk 'NF{print $1}'
}

iface_exists() {
  local ifc="$1"
  [[ -d "/sys/class/net/${ifc}" ]] || return 1
  ip link show "$ifc" >/dev/null 2>&1 || return 1
  return 0
}

make_outdir_for_iface() {
  local day="$1"
  local ifc="$2"
  local dir="${OUT_BASE}/${day}/${ifc}"
  mkdir -p "$dir"
  chmod 0777 "$dir" 2>/dev/null || true
  echo "$dir"
}

ensure_dirs() {
  mkdir -p "$OUT_BASE" "$LOG_DIR"
  chmod 0777 "$OUT_BASE" 2>/dev/null || true
  chmod 0777 "$LOG_DIR" 2>/dev/null || true
}

acquire_lock() {
  # Atomic lock via mkdir. If it exists, another instance is running.
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "${LOCK_DIR}/pid" 2>/dev/null || true
    echo "$$" > "$PID_FILE" 2>/dev/null || true
    return 0
  fi


#--> evitar que múltiples capturadores concurrentes generen PCAP duplicados,
  # If lock exists, check if PID inside is alive; if not, steal lock.
  local old_pid=""
  if [[ -f "${LOCK_DIR}/pid" ]]; then
    old_pid="$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)"
  elif [[ -f "$PID_FILE" ]]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi

  if [[ -n "$old_pid" ]] && ps -p "$old_pid" >/dev/null 2>&1; then
    err "Another instance is already running (PID=$old_pid). Refusing to start."
    exit 1
  fi

  warn "Stale lock detected (old PID=$old_pid). Re-acquiring lock."
  rm -rf "$LOCK_DIR" 2>/dev/null || true
  mkdir "$LOCK_DIR"
  echo "$$" > "${LOCK_DIR}/pid" 2>/dev/null || true
  echo "$$" > "$PID_FILE" 2>/dev/null || true
}

release_lock() {
  rm -rf "$LOCK_DIR" 2>/dev/null || true
  rm -f "$PID_FILE" 2>/dev/null || true
}

# ----------------------------
# Checks
# ----------------------------
require_root

require_cmd ip
require_cmd awk
require_cmd date
require_cmd mkdir
require_cmd timeout
require_cmd tcpdump
require_cmd stat
require_cmd ps

if ! tcpdump --version >/dev/null 2>&1; then
  err "tcpdump not usable."
  suggest_install_ubuntu
  exit 1
fi

# ----------------------------
# Prepare dirs + lock
# ----------------------------
ensure_dirs

if [[ ! -d "$OUT_BASE" ]]; then
  err "OUT_BASE does not exist after mkdir: $OUT_BASE"
  exit 1
fi

if [[ ! -w "$OUT_BASE" ]]; then
  err "OUT_BASE not writable: $OUT_BASE"
  err "Try: sudo chown -R root:root '$OUT_BASE' && sudo chmod -R 0777 '$OUT_BASE'"
  exit 1
fi

acquire_lock

STOP_REQUESTED=0
cleanup() {
  STOP_REQUESTED=1
  info "Stopping... cleaning up lock."
  release_lock
}
trap cleanup INT TERM EXIT

# ----------------------------
# Main loop
# ----------------------------
info "Rolling capture started"
info "repo_root=${REPO_ROOT}"
info "out=${OUT_BASE}"
info "logs=${LOG_DIR}"
info "interval=${INTERVAL_SEC}s snaplen=${SNAPLEN}"
[[ -n "$EXTRA_IFACES_CSV" ]] && info "extra_ifaces=${EXTRA_IFACES_CSV}"

while true; do
  [[ "$STOP_REQUESTED" -eq 1 ]] && break

  day="$(utc_day)"
  start="$(utc_ts)"

  mapfile -t taps  < <(detect_taps)
  mapfile -t extra < <(parse_extra_ifaces "$EXTRA_IFACES_CSV")

  ifaces=()
  for i in "${taps[@]}";  do ifaces+=("$i"); done
  for i in "${extra[@]}"; do ifaces+=("$i"); done

  if [[ ${#ifaces[@]} -eq 0 ]]; then
    warn "No interfaces found (tap*). Sleeping ${INTERVAL_SEC}s..."
    sleep "$INTERVAL_SEC"
    continue
  fi

  final_ifaces=()
  for ifc in "${ifaces[@]}"; do
    if iface_exists "$ifc"; then
      final_ifaces+=("$ifc")
    else
      warn "Skipping iface not present: $ifc"
    fi
  done

  if [[ ${#final_ifaces[@]} -eq 0 ]]; then
    warn "No usable interfaces. Sleeping ${INTERVAL_SEC}s..."
    sleep "$INTERVAL_SEC"
    continue
  fi

  info "Rotation start=${start} ifaces=(${final_ifaces[*]})"

  rot_log="${LOG_DIR}/rotation_${day}_${start}.log"
  {
    echo "[INFO] start_utc=${start} interval=${INTERVAL_SEC} snaplen=${SNAPLEN}"
    echo "[INFO] out_base=${OUT_BASE}"
    echo "[INFO] ifaces=(${final_ifaces[*]})"
  } >> "$rot_log"

  pids=()
  for ifc in "${final_ifaces[@]}"; do
    outdir="$(make_outdir_for_iface "$day" "$ifc")"
    pcap="${outdir}/${ifc}_${start}_${INTERVAL_SEC}s.pcap"
    if_log="${LOG_DIR}/tcpdump_${ifc}_${day}_${start}.log"

    echo "[INFO] tcpdump iface=${ifc} -> ${pcap}" | tee -a "$rot_log" >> "$if_log"

    # timeout ensures tcpdump stops after INTERVAL_SEC
    # IMPORTANT: log stderr/stdout to file so you can see errors
    timeout "${INTERVAL_SEC}" tcpdump -i "$ifc" -s "$SNAPLEN" -nn -U -w "$pcap" >>"$if_log" 2>&1 &
    pids+=("$!")
  done

  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  info "Rotation done start=${start}" | tee -a "$rot_log" >/dev/null

  for ifc in "${final_ifaces[@]}"; do
    pcap="${OUT_BASE}/${day}/${ifc}/${ifc}_${start}_${INTERVAL_SEC}s.pcap"
    if [[ -f "$pcap" ]]; then
      sz="$(stat -c%s "$pcap" 2>/dev/null || echo 0)"
      echo "[INFO] pcap_ok iface=${ifc} size=${sz} file=${pcap}" >> "$rot_log"
    else
      echo "[WARN] pcap_missing iface=${ifc} expected=${pcap}" >> "$rot_log"
    fi
  done

  [[ "$STOP_REQUESTED" -eq 1 ]] && break
done

info "Rolling capture stopped"
exit 0