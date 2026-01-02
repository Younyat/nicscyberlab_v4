#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# WAZUH INSTALLER (single-node) - robust + idempotent
# ============================================================

# -----------------------------
# Defaults
# -----------------------------
MANAGER_IP="${1:-}"
DO_PURGE="false"
DO_FORCE="false"
WAZUH_INSTALLER_URL_DEFAULT="https://packages.wazuh.com/4.7/wazuh-install.sh"

# -----------------------------
# Logging
# -----------------------------
ts() { date +"%Y%m%d_%H%M%S"; }

LOG_FILE="/var/log/wazuh-install-$(ts).log"
mkdir -p /var/log
touch "$LOG_FILE" || true

log()  { echo -e "[INFO] $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "\e[32m[OK]\e[0m  $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*" | tee -a "$LOG_FILE" >&2; }
err()  { echo -e "\e[31m[FATAL]\e[0m $*" | tee -a "$LOG_FILE" >&2; exit 1; }

# -----------------------------
# Help
# -----------------------------
usage() {
  cat <<EOF
Usage:
  bash wazuh-install.sh <MANAGER_IP> [--purge] [--force]
EOF
}

# -----------------------------
# Args parsing
# -----------------------------
INSTALLER_URL="$WAZUH_INSTALLER_URL_DEFAULT"

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) DO_PURGE="true"; shift ;;
    --force) DO_FORCE="true"; shift ;;
    *) shift ;;
  esac
done

[[ -z "$MANAGER_IP" ]] && usage && err "Missing MANAGER_IP"

# -----------------------------
# Helpers
# -----------------------------
is_root() { [[ "$(id -u)" -eq 0 ]]; }

sudo_run() {
  if is_root; then
    bash -c "$*"
  else
    sudo bash -c "$*"
  fi
}

service_exists() {
  systemctl list-unit-files | awk '{print $1}' | grep -qx "$1"
}

# -----------------------------
# Step 0: Cleanup
# -----------------------------
clean_preinstall() {
  log "[0/6] Checking dpkg state"
  if [[ "$DO_PURGE" == "true" ]]; then
    sudo_run "dpkg --purge wazuh-dashboard wazuh-manager wazuh-indexer filebeat opensearch || true"
    sudo_run "apt autoremove -y || true"
  fi
}

# -----------------------------
# Step 1: Prepare system
# -----------------------------
prepare_system() {
  log "[1/6] Preparing system"
  sudo_run "apt-get update -y"
  sudo_run "apt-get install -y curl gnupg lsb-release ca-certificates"
}

# -----------------------------
# Step 2: Download installer
# -----------------------------
download_installer() {
  log "[2/6] Downloading Wazuh installer"
  sudo_run "curl -fsSL '$INSTALLER_URL' -o /tmp/wazuh-install.sh"
  sudo_run "chmod +x /tmp/wazuh-install.sh"
}

# -----------------------------
# Step 3: Install Wazuh
# -----------------------------
install_wazuh() {
  log "[3/6] Installing Wazuh"
  sudo bash /tmp/wazuh-install.sh -a
}

# -----------------------------
# Step 4: Check services
# -----------------------------
check_services() {
  log "[4/6] Checking services"
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    systemctl is-active --quiet "$svc" && ok "$svc active" || warn "$svc not active"
  done
}

# ============================================================
# 🔥 AÑADIDO: FORZAR CREDENCIALES admin/admin (SIN TOCAR LO DEMÁS)
# ============================================================
bootstrap_dashboard_credentials() {
  log "[5.5/6] Forzando credenciales admin/admin"

  local SEC_DIR="/etc/wazuh-indexer/opensearch-security"
  local TOOLS="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"

  export JAVA_HOME="/usr/share/wazuh-indexer/jdk"
  export OPENSEARCH_JAVA_HOME="$JAVA_HOME"

  sudo_run "systemctl stop wazuh-dashboard || true"
  sudo_run "systemctl stop wazuh-indexer || true"

  sudo_run "cat > $SEC_DIR/internal_users.yml <<EOF
_meta:
  type: \"internalusers\"
  config_version: 2

admin:
  hash: \"\$(
    echo admin | $TOOLS/hash.sh | tail -n1
  )\"
  backend_roles:
    - \"admin\"
  description: \"Administrator\"
EOF"

  sudo_run "systemctl start wazuh-indexer"
  sleep 30

  sudo_run -E "$TOOLS/securityadmin.sh \
    -cd $SEC_DIR \
    -icl -nhnv \
    -cacert /etc/wazuh-indexer/certs/root-ca.pem \
    -cert /etc/wazuh-indexer/certs/admin.pem \
    -key /etc/wazuh-indexer/certs/admin-key.pem \
    -h localhost"

  sudo_run "systemctl start wazuh-dashboard"

  ok "Credenciales aplicadas: admin / admin"
}

# -----------------------------
# Step 5: Access info
# -----------------------------
print_access_info() {
  log "[6/6] Access info"
  echo
  echo "===================================="
  echo " WAZUH DASHBOARD"
  echo " URL : https://${MANAGER_IP}"
  echo " USER: admin"
  echo " PASS: admin"
  echo "===================================="
}

# -----------------------------
# Run
# -----------------------------
clean_preinstall
prepare_system
download_installer
install_wazuh
check_services
bootstrap_dashboard_credentials
print_access_info
