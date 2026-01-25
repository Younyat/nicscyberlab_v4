#!/usr/bin/env bash
set -uo pipefail

# ============================================================
# MBPOLL INSTALLER — Industrial Forensic Collector (Modbus)
# Compatible con arquitectura forensic-by-design
# ============================================================

# 1. DETECCIÓN DINÁMICA
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"
LOG_FILE="$LOG_DIR/mbpoll_install.log"
SUDOERS_CONF="/etc/sudoers.d/nics_cyberlab_v3"
CURRENT_USER="$(whoami)"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

log_msg() {
    local TYPE="$1"
    local MSG="$2"
    echo "data: [$TYPE] $MSG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [MBPOLL] [$TYPE] $MSG" >> "$LOG_FILE"
}

# ============================================================
# GESTIÓN DE PRIVILEGIOS (mínimos, auditables)
# ============================================================
if [ ! -f "$SUDOERS_CONF" ]; then
    log_msg "AUTH" "Configurando privilegios sudo mínimos para $CURRENT_USER..."
    RULE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt"
    echo "$RULE" | sudo tee "$SUDOERS_CONF" > /dev/null
    sudo chmod 0440 "$SUDOERS_CONF"
fi

# ============================================================
# DETECCIÓN PREVIA
# ============================================================
if command -v mbpoll &> /dev/null; then
    VER="$(mbpoll -h 2>&1 | head -n 1)"
    log_msg "INFO" "mbpoll ya está instalado."
    log_msg "SUCCESS" "$VER"
    echo "data: [FIN]"
    exit 0
fi

# ============================================================
# INSTALACIÓN
# ============================================================
log_msg "START" "Iniciando instalación de mbpoll..."
export DEBIAN_FRONTEND=noninteractive

log_msg "PROG" "Actualizando índices de paquetes..."
if ! sudo apt-get update -qq >> "$LOG_FILE" 2>&1; then
    log_msg "ERROR" "Fallo en apt-get update."
    exit 1
fi

log_msg "PROG" "Instalando paquete mbpoll..."
if sudo apt-get install -y -qq mbpoll >> "$LOG_FILE" 2>&1; then
    log_msg "OK" "mbpoll instalado correctamente."
else
    log_msg "ERROR" "Falló la instalación de mbpoll. Revisa $LOG_FILE"
    exit 1
fi

# ============================================================
# VERIFICACIÓN FINAL
# ============================================================
if command -v mbpoll &> /d
