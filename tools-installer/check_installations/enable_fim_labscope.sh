#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Enable File Integrity Monitoring (FIM) for LAB_SCOPE
# - NO toca Suricata
# - NO toca realtime="yes" (no añade ni modifica realtime)
# - NO reenrola (no toca client.keys)
# - Solo añade capacidad de detectar cambios en ficheros (syscheck)
# ============================================================

VICTIM_IP="${1:?IP requerida}"
SSH_USER="${2:-debian}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"

# Carpeta objetivo a monitorizar (tu lab scope)
LAB_SCOPE="${LAB_SCOPE:-/home/debian/nics_lab/sensitive}"

REMOTE_OSSEC="/var/ossec/etc/ossec.conf"

FIM_BEGIN_MARK="<!-- NICS_FIM_LABSCOPE_BEGIN -->"
FIM_END_MARK="<!-- NICS_FIM_LABSCOPE_END -->"

ssh_victim() {
  ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VICTIM_IP}" "$@"
}

echo "[INFO] Conectando a la víctima ${VICTIM_IP} (user=${SSH_USER})"
ssh_victim "true"

echo "[INFO] Verificando wazuh-agent en la víctima"
ssh_victim "systemctl is-active --quiet wazuh-agent" \
  || { echo "[ERROR] wazuh-agent no activo"; exit 1; }
echo "[OK] wazuh-agent activo"

# Crear carpeta objetivo (sin sudo)
echo "[INFO] Asegurando LAB_SCOPE existe: ${LAB_SCOPE}"
ssh_victim "mkdir -p '${LAB_SCOPE}'"

# Construir bloque FIM SIN realtime (solo report_changes)
read -r -d '' FIM_BLOCK <<EOF || true
$FIM_BEGIN_MARK
<ossec_config>
  <syscheck>
    <directories report_changes="yes">${LAB_SCOPE}</directories>
  </syscheck>
</ossec_config>
$FIM_END_MARK
EOF

echo "[INFO] Inyectando bloque FIM (sin realtime) si no existe (idempotente)"

if ssh_victim "sudo grep -qF '$FIM_BEGIN_MARK' '$REMOTE_OSSEC'"; then
  echo "[OK] Bloque FIM ya existe (no se duplica)"
else
  # Si el path ya está declarado en ossec.conf en cualquier sitio, no duplicamos
  if ssh_victim "sudo grep -qF '${LAB_SCOPE}' '$REMOTE_OSSEC'"; then
    echo "[OK] LAB_SCOPE ya aparece en ossec.conf (no se añade bloque)"
  else
    echo "[INFO] Añadiendo bloque FIM para LAB_SCOPE (sin realtime)"
    ssh_victim "sudo bash -c 'printf \"\n%s\n\" \"$FIM_BLOCK\" >> $REMOTE_OSSEC'"
  fi
fi

echo "[INFO] Reiniciando wazuh-agent para aplicar FIM"
ssh_victim "sudo systemctl restart wazuh-agent"
ssh_victim "systemctl is-active --quiet wazuh-agent" \
  || { echo "[ERROR] wazuh-agent no volvió a arrancar"; exit 1; }
echo "[OK] wazuh-agent reiniciado"

# Confirmación básica
if ssh_victim "sudo grep -qF '${LAB_SCOPE}' '$REMOTE_OSSEC'"; then
  echo "[OK] LAB_SCOPE presente en ossec.conf"
else
  echo "[WARN] LAB_SCOPE no aparece en ossec.conf (revisa permisos/edición)"
fi

echo "[OK] FIM (syscheck) habilitado para ${LAB_SCOPE} (sin realtime, sin Suricata)"