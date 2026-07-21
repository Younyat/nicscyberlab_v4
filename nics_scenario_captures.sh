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
WAIT_KILL_GRACE_SEC="${WAIT_KILL_GRACE_SEC:-15}"  # 2026-07-17/18: force-kill a tcpdump that ignores the initial signal, see below

# RETENTION_HOURS (2026-07-18): this rolling buffer is a source to select
# FROM for a case's network context window (pre/post context is minutes,
# not hours -- see network_context_importer.py), never something read
# directly. A pcap segment older than this is guaranteed unusable by any
# future case (case windows only ever look backward a few minutes from a
# trigger time) and unusable by any past one (already selected/copied out,
# or never will be). Self-prunes every rotation instead of relying on
# someone remembering to clean up manually -- this is what actually
# answers "hay que quitar el tráfico acumulado siempre", continuously, not
# just at the moment a new repetition happens to start.
RETENTION_HOURS="${RETENTION_HOURS:-4}"

# CAPTURE_SCOPE=roles (default, 2026-07-17): only capture the 3 nodes that
# actually matter for forensic reconstruction of an OT attack (victim, PLC,
# FUXA/SCADA) instead of every tap on the host. Why: this rolling buffer is
# what network_context_importer later reads packet-by-packet in pure-Python
# scapy for OT/Modbus export -- a real, live campaign was observed processing
# 8GB across 35 pcap files from ALL scenario nodes (attacker, monitor, other
# IT nodes included) when only the 3 OT-relevant nodes' traffic is ever used
# for evidence. These 3 nodes also carry far less traffic individually than
# e.g. the attack/monitor nodes, so this cuts volume from both ends at once.
# Set CAPTURE_SCOPE=all to restore the previous behavior (every tap* iface)
# if a future attack profile ever needs broader network context.
CAPTURE_SCOPE="${CAPTURE_SCOPE:-roles}"
CAPTURE_ROLES_CSV="${CAPTURE_ROLES_CSV:-victim,plc,fuxa}"
ROLE_RESOLVE_CACHE_TTL_SEC="${ROLE_RESOLVE_CACHE_TTL_SEC:-60}"
_role_taps_cache=""
_role_taps_cache_ts=0

# This script normally runs as root (sudo), whose secure_path does NOT
# include the venv the `openstack` CLI actually lives in on this host --
# confirmed live 2026-07-17: as root, `command -v openstack` finds nothing
# and role resolution silently fell back to capturing every tap. OPENSTACK_BIN
# lets this be overridden; the default matches this host's actual venv.
OPENSTACK_BIN="${OPENSTACK_BIN:-}"
if [[ -z "$OPENSTACK_BIN" ]]; then
  if command -v openstack >/dev/null 2>&1; then
    OPENSTACK_BIN="$(command -v openstack)"
  elif [[ -x "/home/younes/Desktop/Openstack/myenv/bin/openstack" ]]; then
    OPENSTACK_BIN="/home/younes/Desktop/Openstack/myenv/bin/openstack"
  else
    OPENSTACK_BIN="openstack"  # last resort; role resolution will just fail and fall back to all-taps
  fi
fi

# ----------------------------
# Path resolution
# ----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Expected layout:
#   REPO_ROOT/nics_scenario_captures.sh
#   REPO_ROOT/app_core/...
REPO_ROOT="$SCRIPT_DIR"

# The `openstack` CLI needs OS_* credentials in the environment. This script
# normally runs as root (sudo resets the environment -- env_reset in
# sudoers), so it never inherits whatever a user's own shell has sourced.
# Source the same admin-openrc.sh the rest of the app already uses (see
# level_c_orchestrator.service.ADMIN_OPENRC) so role resolution actually
# works under root, not just when this script happens to be run manually as
# a regular user with credentials already in their shell.
ADMIN_OPENRC="${ADMIN_OPENRC:-${REPO_ROOT}/admin-openrc.sh}"
if [[ -f "$ADMIN_OPENRC" ]]; then
  # shellcheck disable=SC1090
  source "$ADMIN_OPENRC" >/dev/null 2>&1 || true
fi

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

# Resolve the current tap interface for one role (substring match against
# the OpenStack server name, e.g. "plc" matches "PLC_Instance", "victim"
# matches "victim 33") -- same technique already used by
# app_core/infrastructure/ics_traffic/captures/capture_instance_traffic.sh
# (VM_ID -> PORT_ID -> tap${SHORT}/qvo${SHORT}), so a role always maps to
# whatever this repetition's freshly-redeployed instance actually is
# (Level C destroys and redeploys all VMs every repetition, so tap names
# change every time -- this MUST be re-resolved, never hardcoded).
resolve_role_iface() {
  local role="$1"
  local vm_id port_id short iface

  vm_id="$("$OPENSTACK_BIN" server list -f value -c ID -c Name 2>/dev/null \
    | awk -v r="$role" 'tolower($0) ~ r {print $1; exit}')"
  if [[ -z "$vm_id" ]]; then
    return 1
  fi

  port_id="$("$OPENSTACK_BIN" port list --server "$vm_id" -f value -c ID 2>/dev/null | head -n 1 || true)"
  if [[ -z "$port_id" ]]; then
    return 1
  fi

  short="${port_id:0:11}"
  if [[ -d "/sys/class/net/tap${short}" ]]; then
    iface="tap${short}"
  elif [[ -d "/sys/class/net/qvo${short}" ]]; then
    iface="qvo${short}"
  else
    return 1
  fi
  echo "$iface"
  return 0
}

# Interfaces for CAPTURE_ROLES_CSV, cached for ROLE_RESOLVE_CACHE_TTL_SEC so
# every 120s rotation doesn't re-query OpenStack from scratch. Falls back to
# detect_taps() (every tap on the host) if ANY role fails to resolve --
# never silently ends up capturing nothing because one lookup failed.
resolve_role_taps() {
  local now
  now="$(date +%s)"
  if [[ -n "$_role_taps_cache" ]] && (( now - _role_taps_cache_ts < ROLE_RESOLVE_CACHE_TTL_SEC )); then
    echo "$_role_taps_cache"
    return 0
  fi

  local role ifc resolved=()
  local all_ok=1
  IFS=',' read -ra roles <<< "$CAPTURE_ROLES_CSV"
  for role in "${roles[@]}"; do
    role="$(echo "$role" | tr '[:upper:]' '[:lower:]' | xargs)"
    [[ -z "$role" ]] && continue
    if ifc="$(resolve_role_iface "$role")"; then
      resolved+=("$ifc")
    else
      warn "Could not resolve tap interface for role '$role' -- falling back to full-scenario capture (CAPTURE_SCOPE=all) for this rotation."
      all_ok=0
      break
    fi
  done

  if [[ "$all_ok" -eq 1 && ${#resolved[@]} -gt 0 ]]; then
    _role_taps_cache="$(printf '%s\n' "${resolved[@]}")"
    _role_taps_cache_ts="$now"
    echo "$_role_taps_cache"
    return 0
  fi

  detect_taps
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

# Delete pcap segments older than RETENTION_HOURS from the rolling buffer.
# Only ever touches *.pcap under the dated capture dirs (never touches
# case-preserved copies, which live under each case's own
# network/traffic_preserved/ directory, a completely separate tree this
# script has no path to) -- see the retention gotcha above for why this is
# always safe. Also removes any now-empty dated/iface directories left
# behind, and old per-rotation logs (same retention, since they're only
# useful for debugging a rotation that itself no longer exists).
prune_old_captures() {
  local mins=$(( RETENTION_HOURS * 60 ))
  local deleted
  deleted="$(find "$OUT_BASE" -mindepth 3 -maxdepth 3 -type f -name '*.pcap' -mmin "+${mins}" -print -delete 2>/dev/null | wc -l)"
  if [[ "$deleted" -gt 0 ]]; then
    info "Pruned ${deleted} pcap segment(s) older than ${RETENTION_HOURS}h from the rolling buffer."
  fi
  find "$OUT_BASE" -mindepth 2 -maxdepth 2 -type d -empty -delete 2>/dev/null || true
  find "$LOG_DIR" -maxdepth 1 -type f -name 'rotation_*.log' -mmin "+${mins}" -delete 2>/dev/null || true
  find "$LOG_DIR" -maxdepth 1 -type f -name 'tcpdump_*.log' -mmin "+${mins}" -delete 2>/dev/null || true
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
info "capture_scope=${CAPTURE_SCOPE}$( [[ "$CAPTURE_SCOPE" == "roles" ]] && echo " roles=${CAPTURE_ROLES_CSV}")"
[[ -n "$EXTRA_IFACES_CSV" ]] && info "extra_ifaces=${EXTRA_IFACES_CSV}"

while true; do
  [[ "$STOP_REQUESTED" -eq 1 ]] && break

  day="$(utc_day)"
  start="$(utc_ts)"

  if [[ "$CAPTURE_SCOPE" == "roles" ]]; then
    mapfile -t taps < <(resolve_role_taps)
  else
    mapfile -t taps < <(detect_taps)
  fi
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
    # Never let two tcpdump instances capture the SAME interface at once.
    # Confirmed live 2026-07-18: the bounded-wait fix below (added the same
    # day as the -k fix) stops the WHOLE pipeline from hanging when a
    # tcpdump doesn't die quickly -- but it does that by giving up and
    # moving on to the NEXT rotation regardless, and nothing stopped that
    # next rotation from starting ANOTHER tcpdump on the exact same iface
    # while the old, still-not-dead one kept writing. Real result: two
    # pcap files with ~19 minutes of overlapping packet timestamps, both
    # capturing identical live traffic -- not genuinely high traffic
    # volume, just the same packets preserved twice over. A single stuck
    # tcpdump under sustained disk I/O can compound this across several
    # consecutive rotations if each new one gets stuck the same way,
    # producing files many times their nominal 120s size. Skip starting a
    # new capture for this interface if one is already running; it will be
    # picked up again next rotation once the old one finally exits.
    if pgrep -f "tcpdump -i ${ifc} " >/dev/null 2>&1; then
      warn "iface=${ifc}: previous tcpdump for this interface is still running -- skipping this rotation for it instead of starting a duplicate."
      echo "[WARN] iface=${ifc}: previous tcpdump still running, skipped duplicate start" | tee -a "$rot_log" >> "${LOG_DIR}/tcpdump_${ifc}_${day}_${start}.log"
      continue
    fi

    outdir="$(make_outdir_for_iface "$day" "$ifc")"
    pcap="${outdir}/${ifc}_${start}_${INTERVAL_SEC}s.pcap"
    if_log="${LOG_DIR}/tcpdump_${ifc}_${day}_${start}.log"

    echo "[INFO] tcpdump iface=${ifc} -> ${pcap}" | tee -a "$rot_log" >> "$if_log"

    # timeout -k: send SIGTERM at INTERVAL_SEC, force SIGKILL
    # WAIT_KILL_GRACE_SEC later if tcpdump doesn't respond to the first
    # signal. Confirmed live 2026-07-17/18: plain `timeout N cmd` (no -k)
    # left a tcpdump process running for over 22 HOURS past its supposed
    # 120s window -- it silently ignored SIGTERM, the `wait` below blocked
    # on it forever, and every rotation after that one simply never
    # happened. That is the real reason a live case had zero network/OT/
    # alert evidence to analyze -- not the analysis pipeline skipping
    # anything wrongly (see forensics/README.md for the full incident).
    # IMPORTANT: log stderr/stdout to file so you can see errors
    timeout -k "$WAIT_KILL_GRACE_SEC" "${INTERVAL_SEC}" tcpdump -i "$ifc" -s "$SNAPLEN" -nn -U -w "$pcap" >>"$if_log" 2>&1 &
    pids+=("$!")
  done

  # Bounded wait, on top of -k above: even a SIGKILL can (rarely) fail to
  # reap a process immediately (e.g. genuinely stuck in uninterruptible I/O,
  # or -- as seen live -- an AppArmor-confined process an unconfined signal
  # sender can't touch at all). Don't let ANY single stuck child hang this
  # rotation, and therefore every rotation after it, forever. A child still
  # alive past the deadline is left running (already-known, harmless orphan
  # -- see forensics/README.md) and simply excluded going forward; capture
  # on every OTHER interface keeps rotating on schedule regardless.
  wait_deadline=$(( $(date +%s) + INTERVAL_SEC + WAIT_KILL_GRACE_SEC + 15 ))
  for pid in "${pids[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
      if [[ "$(date +%s)" -ge "$wait_deadline" ]]; then
        warn "pid=$pid did not exit within the expected window (interval+kill-grace+15s) -- leaving it running and moving on so the rotation loop itself never hangs."
        break
      fi
      sleep 1
    done
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

  prune_old_captures

  [[ "$STOP_REQUESTED" -eq 1 ]] && break
done

info "Rolling capture stopped"
exit 0