#!/usr/bin/env bash
set -euo pipefail

# =========================
# CONFIG
# =========================
VICTIM_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"

# Password de authd (FIJO en el manager)
W_PASS="admin"

# =========================
# VALIDACIÓN
# =========================
if [[ -z "$VICTIM_IP" ]]; then
  echo "Uso: bash $0 <IP_VICTIMA> [SSH_USER] [SSH_KEY]"
  exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "ERROR: No existe la clave SSH: $SSH_KEY"
  exit 1
fi

ssh_victim() {
  ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VICTIM_IP}" "$@"
}

# =========================
# OPENSTACK → MANAGER IP
# =========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
source "$PROJECT_ROOT/admin-openrc.sh"

MONITOR_NAME="$(openstack server list -f json | jq -r '.[] | select(.Name | test("^monitor")) | .Name' | head -n1)"
MANAGER_IP="$(openstack server show "$MONITOR_NAME" -f json | jq -r '.addresses' | grep -oP '10\.0\.2\.\d+' | head -n1)"

echo "Manager: $MANAGER_IP"
echo "Victim : $VICTIM_IP"

# =========================
# STOP + CLEAN
# =========================
ssh_victim "sudo systemctl stop wazuh-agent || true"
ssh_victim "sudo rm -f /var/ossec/etc/client.keys"
ssh_victim "sudo rm -rf /var/ossec/queue/* /var/ossec/var/run/* /var/ossec/var/db/*"

HOSTNAME="$(ssh_victim hostname)"

# =========================
# ENROLL (AQUÍ ESTABA EL PROBLEMA REAL)
# =========================
ssh_victim "sudo /var/ossec/bin/agent-auth -m $MANAGER_IP -P $W_PASS -A $HOSTNAME"

ssh_victim "sudo test -s /var/ossec/etc/client.keys"

# =========================
# ossec.conf
# =========================
ssh_victim "sudo tee /var/ossec/etc/ossec.conf >/dev/null" <<EOF
<ossec_config>
  <client>
    <server>
      <address>$MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <syscheck>
    <disabled>no</disabled>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes">/etc,/bin,/usr/bin,/sbin</directories>
  </syscheck>

  <sca>
    <enabled>yes</enabled>
  </sca>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
EOF

ssh_victim "sudo chown root:wazuh /var/ossec/etc/ossec.conf"
ssh_victim "sudo chmod 640 /var/ossec/etc/ossec.conf"

# =========================
# START
# =========================
ssh_victim "sudo systemctl restart wazuh-agent"

if ssh_victim "sudo systemctl is-active --quiet wazuh-agent"; then
  echo "SUCCESS: wazuh-agent activo en $VICTIM_IP"
else
  echo "ERROR: wazuh-agent no arranca"
  ssh_victim "sudo journalctl -u wazuh-agent -n 50 --no-pager"
  exit 1
fi
