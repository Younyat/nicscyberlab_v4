#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Run Volatility 3 analysis for Debian victim memory dump
#
# Target node:
#   ip: 10.0.2.172
#
# Dump:
#   memdump_10.0.2.172_20260610_141234Z.lime
#
# Symbols:
#   /home/younes/nics_volatility_symbols
#
# Output:
#   volatility_results_10.0.2.172
# ============================================================

DUMP="/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260610-140733/memory/memdump_10.0.2.172_20260610_141234Z.lime"
SYMBOLS="/home/younes/nics_volatility_symbols"
OUT="/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260610-140733/memory/volatility_results_10.0.2.172"

VOL="${VOL:-vol}"

echo "[INFO] Starting Volatility 3 analysis"
echo "[INFO] Dump: $DUMP"
echo "[INFO] Symbols: $SYMBOLS"
echo "[INFO] Output: $OUT"

if [ ! -f "$DUMP" ]; then
  echo "[ERROR] Memory dump not found: $DUMP"
  exit 1
fi

if [ ! -d "$SYMBOLS/linux" ]; then
  echo "[ERROR] Volatility symbols directory not found: $SYMBOLS/linux"
  exit 1
fi

if ! command -v "$VOL" >/dev/null 2>&1; then
  echo "[ERROR] Volatility command not found: $VOL"
  echo "[ERROR] Check that Volatility 3 is installed and available as 'vol'."
  exit 1
fi

mkdir -p "$OUT"

run_plugin() {
  local plugin="$1"
  local output_file="$2"

  echo "[RUN] $plugin"

  if "$VOL" -s "$SYMBOLS" -f "$DUMP" "$plugin" > "$OUT/$output_file" 2>&1; then
    echo "[OK] $plugin -> $OUT/$output_file"
  else
    echo "[FAIL] $plugin -> $OUT/$output_file"
    echo "[FAIL] Last lines:"
    tail -80 "$OUT/$output_file" || true
  fi
}

run_plugin banners.Banners banners.txt
run_plugin linux.pslist.PsList pslist.txt
run_plugin linux.lsmod.Lsmod lsmod.txt
run_plugin linux.sockstat.Sockstat sockstat.txt
run_plugin linux.check_syscall.Check_syscall check_syscall.txt
run_plugin linux.bash.Bash bash.txt

echo "[INFO] Results:"
ls -lh "$OUT"

echo "[INFO] Error scan:"
grep -R "Unsatisfied\|Unable to validate\|symbol_table_name\|layer_name\|Traceback\|Error" -n "$OUT" || true

echo "[INFO] Quick preview:"
echo "----- pslist.txt -----"
head -40 "$OUT/pslist.txt" || true

echo "----- lsmod.txt -----"
head -40 "$OUT/lsmod.txt" || true

echo "----- sockstat.txt -----"
head -40 "$OUT/sockstat.txt" || true

echo "----- bash.txt -----"
head -40 "$OUT/bash.txt" || true

echo "[OK] Volatility 3 analysis completed."
