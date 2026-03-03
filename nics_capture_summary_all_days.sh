#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS - Rolling PCAP Summary (ALL DAYS)
# - Entra en full_scenario_captures
# - Detecta carpetas YYYYMMDD
# - Genera 1 resumen TXT + 1 CSV por cada día, por separado
# - Imprime el resumen por pantalla (además de guardarlo)
#
# Uso:
#   sudo bash nics_capture_summary_all_days.sh [ROLLING_ROOT]
#
# Ejemplos:
#   sudo bash nics_capture_summary_all_days.sh
#   sudo bash nics_capture_summary_all_days.sh /tmp/nics_captures/full_scenario_rolling
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"   # <-- CORRECTO si el script está en la raíz del repo
ROLLING_ROOT="${1:-$REPO_ROOT/app_core/infrastructure/ics_traffic/captures/full_scenario_captures}"

# deps mínimos
for c in find awk sort head tail uniq wc stat date tcpdump tee; do
  command -v "$c" >/dev/null 2>&1 || { echo "[ERROR] Missing command: $c"; exit 1; }
done

bytes_h() {
  local b="${1:-0}"
  awk -v b="$b" 'BEGIN{
    split("B KB MB GB TB",u);
    i=1;
    while(b>=1024 && i<5){b/=1024;i++}
    printf "%.2f %s", b, u[i]
  }'
}

pcap_first_ts() {
  local f="$1"
  tcpdump -tt -nn -r "$f" -c 1 2>/dev/null | awk '{print $1; exit}'
}

pcap_last_ts() {
  local f="$1"
  tcpdump -tt -nn -r "$f" 2>/dev/null | tail -n 1 | awk '{print $1}'
}

epoch_to_utc() {
  local e="$1"
  [[ -z "${e:-}" ]] && { echo ""; return; }
  local sec="${e%%.*}"
  [[ -z "${sec:-}" ]] && { echo ""; return; }
  date -u -d "@$sec" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo ""
}

summarize_day_dir() {
  local DAY_DIR="$1"
  local DAY_NAME
  DAY_NAME="$(basename "$DAY_DIR")"

  mapfile -t PCAPS < <(find "$DAY_DIR" -type f -name "*.pcap" | sort)
  if [[ ${#PCAPS[@]} -eq 0 ]]; then
    echo "[WARN] $DAY_NAME: no PCAPs found. Skipping."
    return 0
  fi

  local UTC_TAG OUT_TXT OUT_CSV
  UTC_TAG="$(date -u +%Y%m%d_%H%M%SZ)"
  OUT_TXT="$DAY_DIR/capture_summary_${DAY_NAME}_${UTC_TAG}.txt"
  OUT_CSV="$DAY_DIR/capture_summary_${DAY_NAME}_${UTC_TAG}.csv"

  echo "[INFO] Day=$DAY_NAME -> $OUT_TXT / $OUT_CSV"

  echo "iface,filename,bytes,mtime_utc,first_pkt_epoch,first_pkt_utc,last_pkt_epoch,last_pkt_utc,pkts_estimate" > "$OUT_CSV"

  local TOTAL_BYTES=0 TOTAL_FILES=0

  declare -A IF_BYTES
  declare -A IF_FILES

  for f in "${PCAPS[@]}"; do
    TOTAL_FILES=$((TOTAL_FILES+1))
    local sz
    sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
    TOTAL_BYTES=$((TOTAL_BYTES+sz))

    local rel iface
    rel="${f#$DAY_DIR/}"
    iface="$(echo "$rel" | awk -F/ '{print $1}')"
    if [[ "$iface" == "$rel" ]]; then iface="unknown"; fi

    IF_BYTES["$iface"]=$(( ${IF_BYTES["$iface"]:-0} + sz ))
    IF_FILES["$iface"]=$(( ${IF_FILES["$iface"]:-0} + 1 ))
  done

  local SUMMARY
  SUMMARY="$(
    {
      echo "============================================================"
      echo "NICS Rolling Capture Summary"
      echo "Day folder: $DAY_NAME"
      echo "Generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "Root: $DAY_DIR"
      echo "Files: ${#PCAPS[@]}"
      echo
      echo "Per-interface totals"
      echo "--------------------"

      for iface in "${!IF_BYTES[@]}"; do
        echo "${IF_BYTES[$iface]}|$iface|${IF_FILES[$iface]}"
      done | sort -nr | while IFS="|" read -r b iface n; do
        printf "%-18s  files=%-5s  bytes=%-12s  (%s)\n" \
          "$iface" "$n" "$b" "$(bytes_h "$b")"
      done

      echo
      echo "Global totals"
      echo "-------------"
      echo "Total files:  $TOTAL_FILES"
      echo "Total bytes:  $TOTAL_BYTES ($(bytes_h "$TOTAL_BYTES"))"
      echo
      echo "Per-PCAP details (sorted by mtime)"
      echo "---------------------------------"
    }
  )"

  echo "$SUMMARY" | tee "$OUT_TXT"

  for f in "${PCAPS[@]}"; do
    local rel iface base sz mtime_epoch mtime_utc first_e last_e first_utc last_utc pkts_est

    rel="${f#$DAY_DIR/}"
    iface="$(echo "$rel" | awk -F/ '{print $1}')"
    if [[ "$iface" == "$rel" ]]; then iface="unknown"; fi

    base="$(basename "$f")"
    sz=$(stat -c %s "$f" 2>/dev/null || echo 0)

    mtime_epoch=$(stat -c %Y "$f" 2>/dev/null || echo "")
    mtime_utc=""
    if [[ -n "$mtime_epoch" ]]; then
      mtime_utc="$(date -u -d "@$mtime_epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")"
    fi

    first_e="$(pcap_first_ts "$f" || true)"
    last_e="$(pcap_last_ts "$f" || true)"
    first_utc="$(epoch_to_utc "$first_e")"
    last_utc="$(epoch_to_utc "$last_e")"

    pkts_est=$(( sz / 120 ))
    if [[ "$sz" -lt 200 ]]; then pkts_est=0; fi

    printf "%s  %-18s  %-45s  %12s (%-10s)  first=%-20s  last=%-20s\n" \
      "$mtime_utc" "$iface" "$base" "$sz" "$(bytes_h "$sz")" "${first_utc:-}" "${last_utc:-}" \
      | tee -a "$OUT_TXT"

    echo "$iface,$base,$sz,$mtime_utc,${first_e:-},${first_utc:-},${last_e:-},${last_utc:-},$pkts_est" >> "$OUT_CSV"
  done

  echo "[OK] Day=$DAY_NAME -> summaries written inside $DAY_DIR"
  echo
}

# ---------------- main ----------------
[[ -d "$ROLLING_ROOT" ]] || { echo "[ERROR] Not a directory: $ROLLING_ROOT"; exit 1; }

mapfile -t DAY_DIRS < <(
  find "$ROLLING_ROOT" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" \
    | awk '/^[0-9]{8}$/' \
    | sort
)

if [[ ${#DAY_DIRS[@]} -eq 0 ]]; then
  echo "[ERROR] No day folders (YYYYMMDD) found under: $ROLLING_ROOT"
  exit 1
fi

echo "[INFO] Rolling root: $ROLLING_ROOT"
echo "[INFO] Days found: ${#DAY_DIRS[@]}"
echo

for d in "${DAY_DIRS[@]}"; do
  summarize_day_dir "$ROLLING_ROOT/$d"
done

echo
echo "[DONE] All days summarized."
