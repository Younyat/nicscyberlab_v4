#!/usr/bin/env bash
# payload: file_tamper_sim.sh (LAB-SCOPE on VICTIM via SSH)
set -euo pipefail




TARGET_IP="${1:-}"
if [[ -z "${TARGET_IP}" ]]; then
  echo "[ERROR] Missing TARGET_IP"
  exit 1
fi

# Usuario en la víctima: preferir arg2 (backend), luego env var, luego debian
VICTIM_USER="${2:-${VICTIM_USER:-debian}}"

LAB_SCOPE="$HOME/nics_lab/sensitive"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

echo "==========================================="
echo "LAB FILE TAMPER (SCOPE CONTROLLED)"
echo "VICTIM: ${VICTIM_USER}@${TARGET_IP}"
echo "SCOPE : ${LAB_SCOPE}"
echo "==========================================="

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
# Fuerza la key que ya usas en el backend
SSH_KEY="$HOME/.ssh/my_key"
if [[ ! -f "${SSH_KEY}" ]]; then
  echo "[ERROR] SSH key not found in attacker: ${SSH_KEY}"
  exit 2
fi
chmod 600 "${SSH_KEY}" 2>/dev/null || true

echo "[TERMINAL] Connecting to victim and applying controlled tamper in ${LAB_SCOPE} ..."

ssh -i "${SSH_KEY}" ${SSH_OPTS} "${VICTIM_USER}@${TARGET_IP}" "bash -s" <<'REMOTE'
set -euo pipefail

LAB_SCOPE="$HOME/nics_lab/sensitive"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "${LAB_SCOPE}"

F1="${LAB_SCOPE}/scada_export.csv"
F2="${LAB_SCOPE}/plc_project.st"
F3="${LAB_SCOPE}/scenario_config.yaml"

echo "[TERMINAL] Creating lab artifacts in ${LAB_SCOPE}"
printf "tag,value,ts\nlevel,42,%s\n" "${TS}" > "${F1}"
printf "PROGRAM main\nVAR\n level : INT;\nEND_VAR\nEND_PROGRAM\n" > "${F2}"
printf "scenario: demo\nrun_id: %s\n" "${TS}" > "${F3}"

echo "[TERMINAL] PRE state:"
ls -l "${LAB_SCOPE}" | while read -r line; do echo "[TERMINAL] $line"; done

echo "[TERMINAL] PRE hashes:"
sha256sum "${F1}" "${F2}" "${F3}" | while read -r line; do echo "[TERMINAL] $line"; done

echo "[TERMINAL] Tamper ops within scope only"
mv "${F3}" "${LAB_SCOPE}/scenario_config_${TS}.yaml"
echo "level,999,${TS}" >> "${F1}"
sed -i 's/level : INT;/level : INT; (* modified *)/' "${F2}"
rm -f "${F1}"   # borrado controlado dentro del lab scope

echo "[TERMINAL] POST state:"
ls -l "${LAB_SCOPE}" | while read -r line; do echo "[TERMINAL] $line"; done

echo "[TERMINAL] POST hashes (existing):"
sha256sum "${F2}" "${LAB_SCOPE}/scenario_config_${TS}.yaml" | while read -r line; do echo "[TERMINAL] $line"; done

echo "[TERMINAL] DONE"
REMOTE

echo "==========================================="
echo "OPERACIÓN FINALIZADA (LAB SCOPE)"