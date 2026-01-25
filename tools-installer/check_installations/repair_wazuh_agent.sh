#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH AGENT REPAIR SCRIPT - VERSIÓN FINAL CORREGIDA
# ============================================================

# --- PARAMETROS ---
VICTIM_IP="${1:-}"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
W_PASS="admin"

# ------------------------------------------------------------
# 1. CONFIGURACIÓN DE RUTAS Y AUTO-SOURCE
# ------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
ADMIN_OPENRC="$PROJECT_ROOT/admin-openrc.sh"

echo " [INFO] Comprobando entorno OpenStack..."

if [[ -f "$ADMIN_OPENRC" ]]; then
    echo " [INFO] Cargando credenciales desde $ADMIN_OPENRC"
    # shellcheck disable=SC1090
    source "$ADMIN_OPENRC"
fi

if [[ -z "${OS_AUTH_URL:-}" ]]; then
    echo " [ERROR] No hay credenciales de OpenStack. Abortando."
    exit 1
fi

# ------------------------------------------------------------
# 2. BÚSQUEDA DEL MANAGER (FILTRO JQ CORREGIDO)
# ------------------------------------------------------------
echo " [INFO] Localizando Wazuh Manager (name^=monitor)..."

MONITOR_NAME=$(
    openstack server list -f json | jq -r '.[] | select(.Name | test("^monitor")) | .Name' | head -n 1
)

if [[ -z "$MONITOR_NAME" ]]; then
    echo " [ERROR] No se encontró el Manager."
    exit 1
fi

MANAGER_IP=$(
    openstack server show "$MONITOR_NAME" -f json \
    | jq -r '.addresses' | grep -oP '10\.0\.2\.\d+' | head -n 1 || true
)

echo " [OK] Manager detectado: $MONITOR_NAME ($MANAGER_IP)"

# ------------------------------------------------------------
# 3. REPARACIÓN
# ------------------------------------------------------------
ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$SSH_USER@$VICTIM_IP" "$1"
}

echo "===================================================="
echo " Reparando Agente en: $VICTIM_IP"
echo "===================================================="

# [STEP 1] Validar binarios
echo " [STEP 1] Validando presencia de binarios..."
ssh_exec "sudo test -f /var/ossec/bin/agent-auth"

# [STEP 2] Forzar configuración de ossec.conf
echo " [STEP 2] Configurando ossec.conf..."
ssh_exec "sudo tee /var/ossec/etc/ossec.conf >/dev/null <<EOF
<ossec_config>
  <client>
    <server>
      <address>$MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>
  <logging>
    <logall>yes</logall>
  </logging>
</ossec_config>
EOF"

# [STEP 3] Enrolamiento (Corregido para v4.7.3)
echo " [STEP 3] Enrolando agente..."
ssh_exec "sudo systemctl stop wazuh-agent || true"
ssh_exec "sudo rm -f /var/ossec/etc/client.keys"

# Obtenemos el nombre de la víctima para pasarlo a -A
VICTIM_HOSTNAME=$(ssh_exec "hostname")

# -A $VICTIM_HOSTNAME: Asigna el nombre correctamente (evita error de argumento faltante)
# -i: Permite que el manager asigne la IP (ayuda con duplicados)
# -P: Password admin
if ssh_exec "sudo timeout 20s /var/ossec/bin/agent-auth -m $MANAGER_IP -P $W_PASS -i -A $VICTIM_HOSTNAME"; then
    echo " [OK] Agente enrolado como $VICTIM_HOSTNAME"
else
    echo " [ERROR] Falló el enrolamiento. Si el error es 'Duplicate name', el manager ya tiene un registro activo."
    echo " [HINT] Prueba a borrar el agente en el manager: sudo /var/ossec/bin/manage_agents -r <ID>"
    exit 1
fi

# [STEP 4] Reinicio y Verificación
echo " [STEP 4] Reiniciando servicio..."
ssh_exec "sudo systemctl restart wazuh-agent"
sleep 5

if ssh_exec "systemctl is-active --quiet wazuh-agent"; then
    echo "===================================================="
    echo " [SUCCESS] Agente REPARADO y ACTIVO en $VICTIM_IP"
    echo "===================================================="
else
    echo " [ERROR] El servicio no quedó activo."
    exit 1
fi