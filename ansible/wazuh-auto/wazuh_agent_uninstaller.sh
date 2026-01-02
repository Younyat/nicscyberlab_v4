#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   WAZUH AGENT PROFESSIONAL DESTROYER (Debian/Ubuntu)
# ============================================================

# --- CONFIG ---
MANAGER_IP="10.0.2.160"      # solo informativo (dashboard)
VICTIM_IP="10.0.2.23"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

AGENT_NAME="Victim-3"        # solo informativo (logs)

echo "===================================================="
echo " ⚠️  WAZUH AGENT DESTROYER (PRO)"
echo "===================================================="
echo " Host      : $AGENT_NAME ($VICTIM_IP)"
echo " Dashboard : https://$MANAGER_IP"
echo "===================================================="
echo

# ----------------------------------------------------
# Confirmación explícita
# ----------------------------------------------------
read -rp "⚠️  ¿ELIMINAR COMPLETAMENTE wazuh-agent en $VICTIM_IP? (yes/NO): " CONFIRM
[[ "${CONFIRM}" != "yes" ]] && { echo "Cancelado."; exit 0; }

# ----------------------------------------------------
# SSH preflight
# ----------------------------------------------------
echo
echo "[1/5] Verificando acceso SSH..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VICTIM_IP" "echo SSH_OK"

# ----------------------------------------------------
# Destroy remoto
# ----------------------------------------------------
echo
echo "[2/5] Eliminando wazuh-agent en el nodo..."

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VICTIM_IP" << 'EOF'
set -euo pipefail

echo ">>> Deteniendo y deshabilitando servicio (si existe)..."
sudo systemctl stop wazuh-agent 2>/dev/null || true
sudo systemctl disable wazuh-agent 2>/dev/null || true

echo ">>> Matando procesos residuales..."
sudo pkill -f wazuh-agent 2>/dev/null || true
sudo pkill -f /var/ossec 2>/dev/null || true

echo ">>> Purga del paquete..."
# purge para eliminar /etc también si el paquete lo gestiona
sudo apt-get purge -y wazuh-agent 2>/dev/null || true

echo ">>> Limpieza APT..."
sudo apt-get autoremove -y --purge 2>/dev/null || true
sudo apt-get autoclean -y 2>/dev/null || true

echo ">>> Eliminando restos de filesystem..."
# /var/ossec es la raíz típica del agente (y manager también, pero aquí es agente)
sudo rm -rf \
  /var/ossec \
  /etc/wazuh* \
  /var/log/wazuh* \
  /var/lib/wazuh* \
  /usr/share/wazuh* \
  /etc/systemd/system/wazuh-agent.service \
  /lib/systemd/system/wazuh-agent.service

echo ">>> Eliminando usuario/grupo (si quedaron)..."
sudo userdel -r wazuh 2>/dev/null || true
sudo groupdel wazuh 2>/dev/null || true

echo ">>> Recargando systemd..."
sudo systemctl daemon-reexec 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true

echo ">>> Verificación dpkg (si queda algo)..."
dpkg -l | grep -E 'wazuh-agent|wazuh' || echo "OK: no hay paquetes wazuh"

echo ">>> DONE: host limpio"
EOF

# ----------------------------------------------------
# Verificación final (remota)
# ----------------------------------------------------
echo
echo "[3/5] Verificación final..."

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VICTIM_IP" << 'EOF'
set +e
echo "Servicio:"
systemctl is-active wazuh-agent >/dev/null 2>&1 && echo "❌ Sigue activo" || echo "OK: no activo"
echo
echo "Directorios:"
[ -d /var/ossec ] && echo "❌ /var/ossec existe" || echo "OK: /var/ossec eliminado"
EOF

echo
echo "[4/5] Nota importante (Wazuh Manager)"
echo " - Este script limpia el AGENTE en la víctima."
echo " - Si quieres borrar el agente también del MANAGER (entrada/clave), eso se hace en el panel o con 'manage_agents' en el manager."

echo
echo "===================================================="
echo " ✅ WAZUH AGENT ELIMINADO COMPLETAMENTE"
echo "===================================================="
