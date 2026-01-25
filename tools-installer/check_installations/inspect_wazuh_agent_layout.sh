#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH AGENT FILESYSTEM & RUNTIME INSPECTOR
#  - Descubre rutas REALES (no asumidas)
# ============================================================

VICTIM_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"

if [[ -z "$VICTIM_IP" ]]; then
    echo " [ERROR] No se proporcionó la IP de la víctima."
    exit 1
fi

echo "===================================================="
echo " [INFO] Inspeccionando layout Wazuh Agent en $VICTIM_IP"
echo "===================================================="

ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$SSH_USER@$VICTIM_IP" "$1"
}

# ------------------------------------------------------------
# 1. Unidad systemd (fuente de verdad)
# ------------------------------------------------------------
echo
echo "=== [1] systemd unit (fuente de verdad) ==="
ssh_exec "systemctl cat wazuh-agent"

# ------------------------------------------------------------
# 2. Proceso real en ejecución
# ------------------------------------------------------------
echo
echo "=== [2] Procesos wazuh en ejecución ==="
ssh_exec "ps aux | grep wazuh | grep -v grep || true"

# ------------------------------------------------------------
# 3. Rutas de configuración EXISTENTES
# ------------------------------------------------------------
echo
echo "=== [3] Configuración detectada ==="
ssh_exec "
for f in \
  /etc/wazuh-agent/ossec.conf \
  /var/ossec/etc/ossec.conf \
  /etc/wazuh-agent/internal_options.conf \
  /var/ossec/etc/internal_options.conf
do
  if [ -f \"\$f\" ]; then
    echo \"[FOUND] \$f\"
  fi
done
"

# ------------------------------------------------------------
# 4. Directorios de logs reales
# ------------------------------------------------------------
echo
echo "=== [4] Logs detectados ==="
ssh_exec "
for d in \
  /var/ossec/logs \
  /var/ossec/logs/archives \
  /var/ossec/logs/alerts \
  /var/log/wazuh-agent
do
  if [ -d \"\$d\" ]; then
    echo \"[FOUND] \$d\"
    ls -lah \"\$d\" | head -n 10
  fi
done
"

# ------------------------------------------------------------
# 5. Colas internas / sockets
# ------------------------------------------------------------
echo
echo "=== [5] Colas internas y sockets ==="
ssh_exec "
find /var/ossec -maxdepth 2 -type d \\( -name queue -o -name queues \\) 2>/dev/null || true
find /var/ossec -type s 2>/dev/null || true
"

# ------------------------------------------------------------
# 6. Archivos usados para comunicación con el Manager
# ------------------------------------------------------------
echo
echo "=== [6] Manager configurado (si existe) ==="
ssh_exec "
grep -R \"<address>\" /etc/wazuh-agent /var/ossec/etc 2>/dev/null || true
"

# ------------------------------------------------------------
# 7. Puertos salientes usados por el agente
# ------------------------------------------------------------
echo
echo "=== [7] Conexiones de red del agente ==="
ssh_exec "ss -tpn | grep wazuh || true"

# ------------------------------------------------------------
# 8. Archivos tocables para tuning / debug
# ------------------------------------------------------------
echo
echo "=== [8] Archivos clave que puedes modificar ==="
ssh_exec "
for f in \
  /etc/wazuh-agent/ossec.conf \
  /etc/wazuh-agent/internal_options.conf \
  /var/ossec/etc/internal_options.conf
do
  if [ -f \"\$f\" ]; then
    echo \"[EDITABLE] \$f\"
  fi
done
"

echo
echo "===================================================="
echo " [DONE] Inspección completada"
echo "===================================================="
exit 0
