#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# WAZUH INSTALLER (single-node) - robust + idempotent
# - Fixes: missing ok/warn/err, empty vars, partial execution
# - Optional aggressive cleanup: --purge
# - Forces overwrite when needed: --force
# - Logs: /var/log/wazuh-install-<timestamp>.log
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
  bash wazuh-install.sh <MANAGER_IP> [--purge] [--force] [--url <installer_url>]

Examples:
  bash wazuh-install.sh 10.0.2.211
  bash wazuh-install.sh 10.0.2.211 --purge
  bash wazuh-install.sh 10.0.2.211 --purge --force
  bash wazuh-install.sh 10.0.2.211 --url https://packages.wazuh.com/4.7/wazuh-install.sh
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

log "============================================================"
log "Wazuh single-node install starting"
log "  MANAGER_IP = $MANAGER_IP"
log "  PURGE      = $DO_PURGE"
log "  FORCE      = $DO_FORCE"
log "  URL        = $INSTALLER_URL"
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

  local RESIDUAL HALF NEW_HALF
  RESIDUAL="$(dpkg -l 2>/dev/null | awk '/wazuh|filebeat|opensearch/ {print $2}' || true)"
  HALF="$(sudo dpkg --audit 2>/dev/null | grep -iE 'wazuh|filebeat|opensearch' || true)"

  if [[ -z "$RESIDUAL" && -z "$HALF" ]]; then
    ok "No hay restos dpkg relevantes"
    return 0
  fi

  warn "Se detectaron paquetes residuales en dpkg:"
  [[ -n "$RESIDUAL" ]] && echo "$RESIDUAL" | tee -a "$LOG_FILE"
  [[ -n "$HALF" ]] && echo "$HALF" | tee -a "$LOG_FILE"

  if [[ "$DO_PURGE" != "true" ]]; then
    warn "No se aplicará purga (usa --purge si quieres limpieza agresiva)"
    return 0
  fi

  warn "Aplicando purga agresiva..."
  sudo_run "dpkg --purge wazuh-dashboard wazuh-manager wazuh-indexer filebeat opensearch >/dev/null 2>&1 || true"

  sudo_run "rm -f /var/lib/dpkg/info/wazuh-* /var/lib/dpkg/info/filebeat* /var/lib/dpkg/info/opensearch* >/dev/null 2>&1 || true"
  sudo_run "dpkg --configure -a >/dev/null 2>&1 || true"
  sudo_run "apt --fix-broken install -y >/dev/null 2>&1 || true"
  sudo_run "apt autoremove -y >/dev/null 2>&1 || true"

  NEW_HALF="$(sudo dpkg --audit 2>/dev/null || true)"
  if echo "$NEW_HALF" | grep -qiE "wazuh|filebeat|opensearch"; then
    warn "Persisten restos dpkg (solo metadatos). Normalmente no bloquean la instalación."
  fi

  ok "Limpieza dpkg finalizada"
}

# -----------------------------
# Step 1: Prepare system
# -----------------------------
prepare_system() {
  log "[1/6] Preparando sistema"
  sudo_run "apt-get update -y >/dev/null"
  sudo_run "apt-get install -y curl gnupg lsb-release ca-certificates >/dev/null"
  ok "Sistema preparado"
}

# -----------------------------
# Step 2: Download official installer
# -----------------------------
download_installer() {
  log "[2/6] Descargando instalador oficial Wazuh"

  local INSTALLER="/tmp/wazuh-install.sh"
  sudo_run "rm -f '$INSTALLER' >/dev/null 2>&1 || true"

  if ! sudo_run "curl -fsSL '$INSTALLER_URL' -o '$INSTALLER'"; then
    err "No se pudo descargar el instalador (curl HTTPS falló): $INSTALLER_URL"
  fi

  sudo_run "test -s '$INSTALLER'" || err "El instalador descargado está vacío"
  sudo_run "chmod +x '$INSTALLER'"

  ok "Instalador descargado: $INSTALLER"
}

# -----------------------------
# Step 3: Install Wazuh
# -----------------------------
install_wazuh() {
  log "[3/6] Instalando Wazuh (single-node all-in-one)"

  if service_exists "wazuh-manager.service" && systemctl is-enabled wazuh-manager >/dev/null 2>&1; then
    warn "Wazuh Manager ya instalado. Saltando instalación."
    return 0
  fi

  local INSTALLER="/tmp/wazuh-install.sh"

  if sudo bash "$INSTALLER" -a 2>&1 | tee -a "$LOG_FILE"; then
    ok "Instalación Wazuh completada"
    return 0
  fi

  if [[ "$DO_FORCE" != "true" ]]; then
    err "Falló la instalación. Repite con --force y revisa el log."
  fi

  warn "Reintentando instalación (--force)"
  sudo_run "dpkg --configure -a >/dev/null 2>&1 || true"
  sudo_run "apt --fix-broken install -y >/dev/null 2>&1 || true"

  if sudo bash "$INSTALLER" -a 2>&1 | tee -a "$LOG_FILE"; then
    ok "Instalación Wazuh completada (reintento)"
    return 0
  fi

  err "Falló incluso con --force"
}

# -----------------------------
# Step 4: Service checks
# -----------------------------
check_services() {
  log "[4/6] Verificando servicios"
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    if service_exists "${svc}.service"; then
      systemctl is-active --quiet "$svc" && ok "$svc: active" || warn "$svc: NOT active"
    else
      warn "Servicio no encontrado: $svc"
    fi
  done
}

# -----------------------------
# Step 5: Access info
# -----------------------------
print_access_info() {
  log "[5/6] Información de acceso"
  ok "Dashboard: https://${MANAGER_IP}"
  warn "Si no abre: https://${MANAGER_IP}:5601 (revisa security groups)"
}

# -----------------------------
# Step 6: Summary
# -----------------------------
final_summary() {
  log "[6/6] Finalizado"
  ok "Instalación terminada"
  ok "Log: $LOG_FILE"
}

# -----------------------------
# Run
# -----------------------------
clean_preinstall
prepare_system
download_installer
install_wazuh
check_services
print_access_info
final_summary
