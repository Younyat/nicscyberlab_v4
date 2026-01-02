#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   WAZUH PROFESSIONAL DESTROYER (AIO)
# ============================================================

INSTANCE_NAME="Wazuh-Server-Single"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"

BASE_DIR="$HOME/ansible/wazuh-auto"

echo "===================================================="
echo " ⚠️  WAZUH PROFESSIONAL DESTROYER"
echo "===================================================="

# ----------------------------------------------------
# Detectar IP desde OpenStack
# ----------------------------------------------------
echo "[1/6] Detectando instancia OpenStack..."

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | \
  jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "$TARGET_IP" ]]; then
  echo "❌ ERROR: No se pudo resolver la IP de $INSTANCE_NAME"
  exit 1
fi

echo "Instancia  : $INSTANCE_NAME"
echo "IP destino : $TARGET_IP"
echo

# ----------------------------------------------------
# Confirmación explícita
# ----------------------------------------------------
read -rp "⚠️  ¿DESTRUIR COMPLETAMENTE WAZUH en $TARGET_IP? (yes/NO): " CONFIRM
[[ "$CONFIRM" != "yes" ]] && { echo "Cancelado."; exit 0; }

# ----------------------------------------------------
# SSH preflight
# ----------------------------------------------------
echo
echo "[2/6] Verificando acceso SSH..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" "echo SSH_OK"

# ----------------------------------------------------
# Desinstalación remota REAL
# ----------------------------------------------------
echo
echo "[3/6] Eliminando Wazuh en el nodo..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
set -euo pipefail

echo ">>> Deteniendo servicios Wazuh..."
sudo systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
sudo systemctl disable wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true

echo ">>> Matando procesos residuales..."
sudo pkill -f wazuh || true
sudo pkill -f opensearch || true

echo ">>> Purga completa de paquetes..."
sudo apt-get purge -y \
  wazuh-manager \
  wazuh-indexer \
  wazuh-dashboard \
  filebeat \
  opensearch \
  wazuh-agent || true

sudo apt-get autoremove -y --purge
sudo apt-get autoclean -y

echo ">>> Eliminando restos de filesystem..."
sudo rm -rf \
  /var/ossec \
  /etc/wazuh* \
  /var/lib/wazuh* \
  /usr/share/wazuh* \
  /usr/share/opensearch* \
  /var/lib/opensearch \
  /etc/opensearch \
  /etc/filebeat \
  /var/lib/filebeat \
  /var/log/wazuh* \
  /var/log/opensearch \
  /etc/systemd/system/wazuh* \
  /etc/systemd/system/opensearch* \
  /etc/sudoers.d/ansible_nopasswd

echo ">>> Eliminando usuarios y grupos..."
for u in wazuh wazuh-indexer wazuh-dashboard opensearch; do
  sudo userdel -r "$u" 2>/dev/null || true
done

for g in wazuh wazuh-indexer wazuh-dashboard opensearch; do
  sudo groupdel "$g" 2>/dev/null || true
done

echo ">>> Recargando systemd..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

echo ">>> Estado final (dpkg):"
dpkg -l | grep -E 'wazuh|opensearch|filebeat' || echo "OK: limpio"

echo ">>> Nodo completamente limpiado"
EOF

# ----------------------------------------------------
# Limpieza local (Ansible)
# ----------------------------------------------------
echo
echo "[4/6] Limpiando entorno local Ansible..."

if [[ -d "$BASE_DIR" ]]; then
  rm -rf "$BASE_DIR"
  echo "✔ Eliminado $BASE_DIR"
else
  echo "✔ No hay restos locales"
fi

# ----------------------------------------------------
# Verificación final
# ----------------------------------------------------
echo
echo "[5/6] Verificación remota..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
set +e
echo "Servicios:"
systemctl list-units --type=service | grep wazuh || echo "OK"
echo
echo "Directorios:"
ls /var/ossec 2>/dev/null || echo "OK"
EOF

echo
echo "[6/6] DESTROY COMPLETADO"

echo "===================================================="
echo " ✅ WAZUH ELIMINADO COMPLETAMENTE"
echo "===================================================="
