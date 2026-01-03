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
WAZUH_INSTALLER_URL_DEFAULT="https://packages.wazuh.com/4.9/wazuh-install.sh" # Actualizado a 4.9 como el primer script

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
  bash wazuh-install.sh <MANAGER_IP> [--purge] [--force] [--url <installer_url>]

Examples:
  bash wazuh-install.sh 10.0.2.211
EOF
}

# -----------------------------
# Args parsing
# -----------------------------
INSTALLER_URL="$WAZUH_INSTALLER_URL_DEFAULT"

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --purge) DO_PURGE="true"; shift ;;
    --force) DO_FORCE="true"; shift ;;
    --url)
      shift
      [[ $# -gt 0 ]] || err "Missing value for --url"
      INSTALLER_URL="$1"
      shift
      ;;
    *) shift ;;
  esac
done

if [[ -z "$MANAGER_IP" ]]; then
  usage
  err "Missing MANAGER_IP (example: 10.0.2.211)"
fi

# -----------------------------
# Pre-checks
# -----------------------------
require_cmd() { command -v "$1" >/dev/null 2>&1 || err "Missing command: $1"; }

require_cmd sudo
require_cmd dpkg
require_cmd apt
require_cmd curl
require_cmd grep
require_cmd awk
require_cmd systemctl
require_cmd tar

log "============================================================"
log "Wazuh single-node install starting"
log "  MANAGER_IP = $MANAGER_IP"
log "  LOG        = $LOG_FILE"
log "============================================================"

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
# Step 0: Optional aggressive cleanup
# -----------------------------
clean_preinstall() {
  log "[0/6] Validando estado del sistema APT/DPKG..."
  local RESIDUAL
  RESIDUAL="$(dpkg -l 2>/dev/null | awk '/wazuh|filebeat|opensearch/ {print $2}' || true)"

  if [[ -n "$RESIDUAL" && "$DO_PURGE" == "true" ]]; then
    warn "Aplicando purga agresiva..."
    sudo_run "dpkg --purge wazuh-dashboard wazuh-manager wazuh-indexer filebeat opensearch >/dev/null 2>&1 || true"
  fi
}

# -----------------------------
# Step 1: Prepare system
# -----------------------------
prepare_system() {
  log "[1/6] Preparando sistema"
  sudo_run "apt-get update -y >/dev/null"
  sudo_run "apt-get install -y curl gnupg lsb-release ca-certificates tar >/dev/null"
  ok "Sistema preparado"
}

# -----------------------------
# Step 2: Download official installer
# -----------------------------
download_installer() {
  log "[2/6] Descargando instalador oficial Wazuh"
  local INSTALLER="/tmp/wazuh-install.sh"
  sudo_run "curl -fsSL '$INSTALLER_URL' -o '$INSTALLER'"
  sudo_run "chmod +x '$INSTALLER'"
  ok "Instalador descargado"
}

# -----------------------------
# Step 3: Install Wazuh
# -----------------------------
install_wazuh() {
  log "[3/6] Instalando Wazuh (single-node all-in-one)"
  local INSTALLER="/tmp/wazuh-install.sh"
  
  if service_exists "wazuh-manager.service"; then
    warn "Wazuh ya parece estar instalado. Intentando continuar..."
  fi

  if sudo bash "$INSTALLER" -a 2>&1 | tee -a "$LOG_FILE"; then
    ok "Instalación Wazuh completada"
  else
    err "La instalación falló. Revisa el log: $LOG_FILE"
  fi
}

# -----------------------------
# Step 4: Service checks
# -----------------------------
check_services() {
  log "[4/6] Verificando servicios"
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    systemctl is-active --quiet "$svc" && ok "$svc: active" || warn "$svc: NOT active"
  done
}

# -----------------------------
# Step 5: Access info & Credentials Extraction
# -----------------------------
print_access_info() {
  log "[5/6] Extrayendo credenciales y datos de acceso"
  
  local PASS_FILE="wazuh-install-files.tar"
  local ADMIN_PASS="No detectada"

  # Intentar extraer la contraseña del archivo .tar que genera el script oficial
  if [[ -f "$PASS_FILE" ]]; then
     ADMIN_PASS=$(sudo tar -axf "$PASS_FILE" wazuh-install-files/wazuh-passwords.txt -O \
     | grep -P "'admin'" -A 1 \
     | tail -n 1 \
     | awk -F"'" '{print $2}' || echo "Error al extraer")
  fi

  echo -e "\n------------------------------------------------------------"
  ok "ACCESO AL DASHBOARD"
  echo -e "   URL:      https://${MANAGER_IP}"
  echo -e "   Usuario:  admin"
  echo -e "   Password: ${ADMIN_PASS}"
  echo -e "------------------------------------------------------------\n"
  
  if [[ "$ADMIN_PASS" == "No detectada" ]]; then
    warn "No se encontró el archivo $PASS_FILE. Si ya estaba instalado, busca las claves antiguas."
  fi
}

# -----------------------------
# Step 6: Summary
# -----------------------------
final_summary() {
  log "[6/6] Finalizado"
  ok "Log guardado en: $LOG_FILE"
}

# -----------------------------
# Execution Flow
# -----------------------------
clean_preinstall
prepare_system
download_installer
install_wazuh
check_services
print_access_info
final_summary