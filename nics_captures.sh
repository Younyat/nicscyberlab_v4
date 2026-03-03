#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS - Full-scenario rolling capture (every 2 minutes)
# - Detects tap* interfaces automatically on the HOST
# - Runs captures in parallel (1 tcpdump per interface)
# - Rotates every INTERVAL seconds (default: 120s)
# - Checks required packages/tools before starting
#
# Usage:
#   sudo ./nics_capture_roll_2min.sh
#
# Stop:
#   Ctrl+C (recommended)
#
# Output:
#   /tmp/nics_captures/full_scenario_rolling/YYYYMMDD/<iface>/<iface>_<startUTC>_<dur>s.pcap
# ============================================================

INTERVAL_SEC="${INTERVAL_SEC:-120}"     # 2 minutes
SNAPLEN="${SNAPLEN:-0}"                 # 0 = full
OUT_BASE="${OUT_BASE:-/tmp/nics_captures/full_scenario_rolling}"
EXTRA_IFACES_CSV="${EXTRA_IFACES_CSV:-}"  # optional, e.g. "uplinkbridge,ens33"

# ----------------------------
# Checks
# ----------------------------
require_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || {
    echo "[ERROR] Missing command: $c"
    exit 1
  }
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[ERROR] Run as root (sudo)."
    exit 1
  fi
}

suggest_install_ubuntu() {
  cat <<'TXT'
[HINT] On Ubuntu/Debian you can install requirements with:
  sudo apt-get update
  sudo apt-get install -y tcpdump iproute2 coreutils gawk
TXT
}

require_root

# Required tools
require_cmd ip
require_cmd awk
require_cmd date
require_cmd mkdir
require_cmd timeout  # coreutils
require_cmd tcpdump

# Quick tcpdump capability check
if ! tcpdump --version >/dev/null 2>&1; then
  echo "[ERROR] tcpdump not usable."
  suggest_install_ubuntu
  exit 1
fi

# ----------------------------
# Helpers
# ----------------------------
utc_ts() { date -u +%Y%m%d_%H%M%SZ; }
utc_day() { date -u +%Y%m%d; }

detect_taps() {
  ip -br link | awk '$1 ~ /^tap/ {print $1}'
}

parse_extra_ifaces() {
  local csv="${1:-}"
  [[ -z "$csv" ]] && return 0
  echo "$csv" | tr ',' '\n' | awk 'NF{print $1}'
}

iface_exists_and_up() {
  local ifc="$1"
  [[ -d "/sys/class/net/${ifc}" ]] || return 1
  # if it's DOWN, tcpdump can still work sometimes, but we keep it simple:
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

# ----------------------------
# Main loop
# ----------------------------
echo "[INFO] Rolling capture started"
echo "[INFO] interval=${INTERVAL_SEC}s out=${OUT_BASE} snaplen=${SNAPLEN}"
[[ -n "$EXTRA_IFACES_CSV" ]] && echo "[INFO] extra_ifaces=${EXTRA_IFACES_CSV}"

# Clean stop on Ctrl+C
STOP_REQUESTED=0
trap 'STOP_REQUESTED=1; echo; echo "[INFO] Stop requested, finishing current rotation...";' INT TERM

while true; do
  day="$(utc_day)"
  start="$(utc_ts)"

  mapfile -t taps < <(detect_taps)
  mapfile -t extra < <(parse_extra_ifaces "$EXTRA_IFACES_CSV")

  ifaces=()
  for i in "${taps[@]}"; do ifaces+=("$i"); done
  for i in "${extra[@]}"; do ifaces+=("$i"); done

  if [[ ${#ifaces[@]} -eq 0 ]]; then
    echo "[WARN] No interfaces found (tap*). Sleeping ${INTERVAL_SEC}s..."
    sleep "$INTERVAL_SEC"
    [[ "$STOP_REQUESTED" -eq 1 ]] && break
    continue
  fi

  # filter non-existent
  final_ifaces=()
  for ifc in "${ifaces[@]}"; do
    if iface_exists_and_up "$ifc"; then
      final_ifaces+=("$ifc")
    else
      echo "[WARN] Skipping iface not present: $ifc"
    fi
  done

  if [[ ${#final_ifaces[@]} -eq 0 ]]; then
    echo "[WARN] No usable interfaces. Sleeping ${INTERVAL_SEC}s..."
    sleep "$INTERVAL_SEC"
    [[ "$STOP_REQUESTED" -eq 1 ]] && break
    continue
  fi

  echo "[INFO] Rotation start=${start} ifaces=(${final_ifaces[*]})"

  pids=()
  for ifc in "${final_ifaces[@]}"; do
    outdir="$(make_outdir_for_iface "$day" "$ifc")"
    pcap="${outdir}/${ifc}_${start}_${INTERVAL_SEC}s.pcap"

    # timeout ensures tcpdump stops after INTERVAL_SEC
    # -U packet-buffered; -nn no name resolution; -s snaplen; -i interface; -w file
    timeout "${INTERVAL_SEC}" tcpdump -i "$ifc" -s "$SNAPLEN" -nn -U -w "$pcap" >/dev/null 2>&1 &
    pids+=("$!")
  done

  # Wait for all parallel captures this rotation
  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  echo "[INFO] Rotation done start=${start}"

  [[ "$STOP_REQUESTED" -eq 1 ]] && break
done

echo "[INFO] Rolling capture stopped"
