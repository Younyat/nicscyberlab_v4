#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS - Full-scenario rolling capture (every 2 minutes)
# - Detects tap* interfaces automatically on the HOST
# - Runs captures in parallel (1 tcpdump per interface)
# - Rotates every INTERVAL seconds (default: 120s)
# - Writes PCAPs under the repo path:
#     <REPO_ROOT>/app_core/infrastructure/ics_traffic/captures/full_scenario_captures
# - Writes logs under:
#     <OUT_BASE>/logs
# ============================================================

INTERVAL_SEC="${INTERVAL_SEC:-120}"     # 2 minutes
SNAPLEN="${SNAPLEN:-0}"                 # 0 = full
EXTRA_IFACES_CSV="${EXTRA_IFACES_CSV:-}"  # optional, e.g. "br-int,ens33"

# Resolve repo root from this script location:
# script dir -> <REPO_ROOT>/app_core/...  (ajusta si tu script no está dentro del repo)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR" && pwd)"

OUT_BASE_DEFAULT="${REPO_ROOT}/app_core/infrastructure/ics_traffic/captures/full_scenario_captures"
OUT_BASE="${OUT_BASE:-$OUT_BASE_DEFAULT}"
LOG_DIR="${OUT_BASE}/logs"

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
[HINT] On Ubuntu/Debian install requirements with:
  sudo apt-get update
  sudo apt-get install -y tcpdump iproute2 coreutils gawk
TXT
}

require_root

require_cmd ip
require_cmd awk
require_cmd date
require_cmd mkdir
require_cmd timeout
require_cmd tcpdump

if ! tcpdump --version >/dev/null 2>&1; then
  echo "[ERROR] tcpdump not usable."
  suggest_install_ubuntu
  exit 1
fi

# ----------------------------
# Helpers
# ----------------------------
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
  mkdir -p "$OUT_BASE"
  mkdir -p "$LOG_DIR"
  chmod 0777 "$OUT_BASE" 2>/dev/null || true
  chmod 0777 "$LOG_DIR" 2>/dev/null || true
}

# ----------------------------
# Sanity paths
# ----------------------------
ensure_dirs

if [[ ! -d "$OUT_BASE" ]]; then
  echo "[ERROR] OUT_BASE does not exist after mkdir: $OUT_BASE"
  exit 1
fi

if [[ ! -w "$OUT_BASE" ]]; then
  echo "[ERROR] OUT_BASE not writable: $OUT_BASE"
  echo "[HINT] Try: sudo chown -R root:root '$OUT_BASE' && sudo chmod -R 0777 '$OUT_BASE'"
  exit 1
fi

# ----------------------------
# Main loop
# ----------------------------
echo "[INFO] Rolling capture started"
echo "[INFO] interval=${INTERVAL_SEC}s out=${OUT_BASE} snaplen=${SNAPLEN}"
echo "[INFO] logs=${LOG_DIR}"
[[ -n "$EXTRA_IFACES_CSV" ]] && echo "[INFO] extra_ifaces=${EXTRA_IFACES_CSV}"

STOP_REQUESTED=0
trap 'STOP_REQUESTED=1; echo; echo "[INFO] Stop requested, finishing current rotation...";' INT TERM

while true; do
  day="$(utc_day)"
  start="$(utc_ts)"

  mapfile -t taps  < <(detect_taps)
  mapfile -t extra < <(parse_extra_ifaces "$EXTRA_IFACES_CSV")

  ifaces=()
  for i in "${taps[@]}";  do ifaces+=("$i"); done
  for i in "${extra[@]}"; do ifaces+=("$i"); done

  if [[ ${#ifaces[@]} -eq 0 ]]; then
    echo "[WARN] No interfaces found (tap*). Sleeping ${INTERVAL_SEC}s..."
    sleep "$INTERVAL_SEC"
    [[ "$STOP_REQUESTED" -eq 1 ]] && break
    continue
  fi

  final_ifaces=()
  for ifc in "${ifaces[@]}"; do
    if iface_exists "$ifc"; then
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

  # rotation log
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

  # quick size summary
  echo "[INFO] Rotation done start=${start}" | tee -a "$rot_log"
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

echo "[INFO] Rolling capture stopped"
