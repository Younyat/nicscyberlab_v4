#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab - Wazuh Agent + Suricata (SIN reenrolamiento)
# - Verifica Realtime FIM existente
# - Verifica Suricata instalada
# - Conecta eve.json -> Wazuh
# - NO toca client.keys
# ============================================================

VICTIM_IP="${1:?IP requerida}"
SSH_USER="${2:-debian}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"

REMOTE_OSSEC="/var/ossec/etc/ossec.conf"
REMOTE_LOG="/var/ossec/logs/ossec.log"
SURICATA_EVE="/var/log/suricata/eve.json"

BEGIN_MARK="<!-- NICS_SURICATA_BEGIN -->"
END_MARK="<!-- NICS_SURICATA_END -->"

ssh_victim() {
  ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VICTIM_IP}" "$@"
}

echo "[INFO] Conectando a la víctima $VICTIM_IP"
ssh_victim "true"

# ------------------------------------------------------------
# 1) Verificar wazuh-agent
# ------------------------------------------------------------
ssh_victim "systemctl is-active --quiet wazuh-agent" \
  || { echo "[ERROR] wazuh-agent no activo"; exit 1; }
echo "[OK] wazuh-agent activo"

# ------------------------------------------------------------
# 2) Verificar Realtime FIM (NO modificar)
# ------------------------------------------------------------
if ssh_victim "sudo grep -qE '<directories[^>]*realtime=\"yes\"' '$REMOTE_OSSEC'"; then
  echo "[OK] Realtime FIM ya configurado"
else
  echo "[ERROR] Realtime FIM NO está configurado (imagen base incorrecta)"
  exit 1
fi

# ------------------------------------------------------------
# 3) Verificar Suricata
# ------------------------------------------------------------
if ssh_victim "systemctl is-active --quiet suricata"; then
  echo "[OK] Suricata activa"
else
  echo "[ERROR] Suricata no está activa"
  exit 1
fi

# ------------------------------------------------------------
# 4) Inyectar bloque Suricata -> Wazuh (idempotente)
# ------------------------------------------------------------
read -r -d '' BLOCK <<EOF || true
$BEGIN_MARK
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$SURICATA_EVE</location>
  </localfile>
</ossec_config>
$END_MARK
EOF

if ssh_victim "sudo grep -qF '$BEGIN_MARK' '$REMOTE_OSSEC'"; then
  echo "[INFO] Bloque Suricata ya existe, no se duplica"
else
  echo "[INFO] Añadiendo bloque Suricata -> Wazuh"
  ssh_victim "sudo bash -c 'printf \"\n%s\n\" \"$BLOCK\" >> $REMOTE_OSSEC'"
fi

# ------------------------------------------------------------
# 5) Reiniciar agente
# ------------------------------------------------------------
ssh_victim "sudo systemctl restart wazuh-agent"
ssh_victim "systemctl is-active --quiet wazuh-agent" \
  || { echo "[ERROR] wazuh-agent no volvió a arrancar"; exit 1; }

# ------------------------------------------------------------
# 6) Verificación final
# ------------------------------------------------------------
if ssh_victim "sudo grep -q 'Analyzing JSON file.*suricata/eve.json' '$REMOTE_LOG'"; then
  echo "[OK] Suricata enganchada correctamente a Wazuh"
else
  echo "[INFO] Esperando eventos Suricata (genera tráfico/alertas)"
fi

echo "[OK] Configuración finalizada correctamente"
