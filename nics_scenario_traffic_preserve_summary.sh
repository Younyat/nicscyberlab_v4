#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS - Rolling PCAP Summary (ALL DAYS) + Optional Preserve into Latest CASE
# - Root por defecto: app_core/infrastructure/ics_traffic/captures/full_scenario_captures
# - Detecta carpetas YYYYMMDD
# - Genera 1 resumen TXT + 1 CSV por cada día (en CAPTURES_ROOT/logs)
# - Si existe app_core/infrastructure/forensics/evidence_store/CASE-...:
#     * Busca el último CASE-*
#     * Crea dentro del caso: network/traffic_preserved/full_scenario_captures/
#     * Copia ahí las capturas por día (solo *.pcap preservando estructura iface/)
#
# Uso:
#   bash nics_scenario_traffic_preserve_summary.sh [CAPTURES_ROOT]
#   sudo bash nics_scenario_traffic_preserve_summary.sh [CAPTURES_ROOT]   # recomendado si necesitas copiar al CASE
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repo root: el script está en la raíz del repo
REPO_ROOT="$SCRIPT_DIR"

CAPTURES_ROOT="${1:-$REPO_ROOT/app_core/infrastructure/ics_traffic/captures/full_scenario_captures}"
EVIDENCE_ROOT="$REPO_ROOT/app_core/infrastructure/forensics/evidence_store"

# --- resolve real user/group (no hardcode) ---
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"

# deps mínimos
for c in find awk sort head tail uniq wc stat date tcpdump tee mkdir cp chmod chown id; do
  command -v "$c" >/dev/null 2>&1 || { echo "[ERROR] Missing command: $c"; exit 1; }
done

# rsync es opcional (mejor para copiar dirs grandes)
HAVE_RSYNC=0
if command -v rsync >/dev/null 2>&1; then
  HAVE_RSYNC=1
fi

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

find_latest_case_dir() {
  [[ -d "$EVIDENCE_ROOT" ]] || return 0
  local latest=""
  latest="$(find "$EVIDENCE_ROOT" -maxdepth 1 -mindepth 1 -type d -name "CASE-*" -printf "%f\n" \
    | sort \
    | tail -n 1 || true)"
  [[ -n "$latest" ]] || return 0
  echo "$EVIDENCE_ROOT/$latest"
}

ensure_preserve_dir() {
  local case_dir="$1"
  local preserve_root="$case_dir/network/traffic_preserved/full_scenario_captures"

  mkdir -p "$preserve_root"

  # permisos: mejor "owner real" + grupo, sin hardcode
  chown -R "$REAL_USER:$REAL_GROUP" "$case_dir/network" 2>/dev/null || true
  chmod -R 0775 "$case_dir/network" 2>/dev/null || true

  # README mínimo para trazabilidad
  local readme="$case_dir/network/traffic_preserved/README.txt"
  if [[ ! -f "$readme" ]]; then
    cat > "$readme" <<EOF
NICS CyberLab - Traffic preserved
Generated UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Source captures root: $CAPTURES_ROOT
This folder contains copies of full scenario captures preserved into a forensic CASE.
EOF
    chown "$REAL_USER:$REAL_GROUP" "$readme" 2>/dev/null || true
    chmod 0664 "$readme" 2>/dev/null || true
  fi

  echo "$preserve_root"
}

copy_day_into_case() {
  local day_dir="$1"                 # .../full_scenario_captures/20260219
  local case_preserve_root="$2"      # .../CASE.../network/traffic_preserved/full_scenario_captures

  local day_name dst_day
  day_name="$(basename "$day_dir")"
  dst_day="$case_preserve_root/$day_name"

  mkdir -p "$dst_day"
  chown -R "$REAL_USER:$REAL_GROUP" "$dst_day" 2>/dev/null || true
  chmod -R 0775 "$dst_day" 2>/dev/null || true

  echo "[INFO] Preserving traffic day=$day_name -> $dst_day"

  if [[ "$HAVE_RSYNC" -eq 1 ]]; then
    rsync -a --prune-empty-dirs --include '*/' --include '*.pcap' --exclude '*' \
      "$day_dir/" "$dst_day/" >/dev/null 2>&1 || {
        echo "[WARN] rsync failed, falling back to cp"
        HAVE_RSYNC=0
      }
  fi

  if [[ "$HAVE_RSYNC" -eq 0 ]]; then
    while IFS= read -r -d '' f; do
      local rel dst_dir
      rel="${f#$day_dir/}"
      dst_dir="$dst_day/$(dirname "$rel")"
      mkdir -p "$dst_dir"
      cp -a "$f" "$dst_dir/" 2>/dev/null || true
    done < <(find "$day_dir" -type f -name "*.pcap" -print0)
  fi

  # asegurar ownership al final (por si copió como root)
  chown -R "$REAL_USER:$REAL_GROUP" "$dst_day" 2>/dev/null || true
  chmod -R 0775 "$dst_day" 2>/dev/null || true

  echo "[OK] Preserved: $dst_day"
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

  local UTC_TAG LOGS_DIR OUT_TXT OUT_CSV
  UTC_TAG="$(date -u +%Y%m%d_%H%M%SZ)"

  # Logs: exactamente donde quieres
  LOGS_DIR="$CAPTURES_ROOT/logs"
  mkdir -p "$LOGS_DIR"
  chown -R "$REAL_USER:$REAL_GROUP" "$LOGS_DIR" 2>/dev/null || true
  chmod 0775 "$LOGS_DIR" 2>/dev/null || true

  OUT_TXT="$LOGS_DIR/capture_summary_${DAY_NAME}_${UTC_TAG}.txt"
  OUT_CSV="$LOGS_DIR/capture_summary_${DAY_NAME}_${UTC_TAG}.csv"

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

  # asegurar ownership de los logs (si se ejecutó con sudo)
  chown "$REAL_USER:$REAL_GROUP" "$OUT_TXT" "$OUT_CSV" 2>/dev/null || true
  chmod 0664 "$OUT_TXT" "$OUT_CSV" 2>/dev/null || true

  echo "[OK] Day=$DAY_NAME -> summaries written into $LOGS_DIR"
  echo
}

# ---------------- main ----------------
[[ -d "$CAPTURES_ROOT" ]] || { echo "[ERROR] Not a directory: $CAPTURES_ROOT"; exit 1; }

# Detect latest CASE (optional)
LATEST_CASE_DIR="$(find_latest_case_dir || true)"
PRESERVE_ENABLED=0
PRESERVE_ROOT=""

if [[ -n "${LATEST_CASE_DIR:-}" && -d "$LATEST_CASE_DIR" ]]; then
  PRESERVE_ENABLED=1
  PRESERVE_ROOT="$(ensure_preserve_dir "$LATEST_CASE_DIR")"
  echo "[INFO] Latest CASE detected: $LATEST_CASE_DIR"
  echo "[INFO] Traffic will be preserved into: $PRESERVE_ROOT"
else
  echo "[INFO] No CASE-* detected under: $EVIDENCE_ROOT"
  echo "[INFO] Traffic preservation disabled (summary only)."
fi

mapfile -t DAY_DIRS < <(
  find "$CAPTURES_ROOT" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" \
    | awk '/^[0-9]{8}$/' \
    | sort
)

if [[ ${#DAY_DIRS[@]} -eq 0 ]]; then
  echo "[ERROR] No day folders (YYYYMMDD) found under: $CAPTURES_ROOT"
  exit 1
fi

echo "[INFO] Captures root: $CAPTURES_ROOT"
echo "[INFO] Days found: ${#DAY_DIRS[@]}"
echo "[INFO] Logs dir: $CAPTURES_ROOT/logs (owner=${REAL_USER}:${REAL_GROUP})"
echo

for d in "${DAY_DIRS[@]}"; do
  day_path="$CAPTURES_ROOT/$d"
  summarize_day_dir "$day_path"

  if [[ "$PRESERVE_ENABLED" -eq 1 ]]; then
    copy_day_into_case "$day_path" "$PRESERVE_ROOT"
  fi
done

echo
echo "[DONE] All days summarized."
if [[ "$PRESERVE_ENABLED" -eq 1 ]]; then
  echo "[DONE] Traffic preserved into latest CASE: $LATEST_CASE_DIR"
fi
