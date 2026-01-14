#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – SCAPY INSTALLER (HOST)
# ============================================================

# 1. DETECCIÓN DINÁMICA DE RUTAS Y USUARIO
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"
LOG_FILE="$LOG_DIR/host_manage.log"
SUDOERS_CONF="/etc/sudoers.d/nics_cyberlab_v3"
CURRENT_USER=$(whoami)

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

log_msg() {
    local TYPE=$1
    local MSG=$2
    echo "data: [$TYPE] $MSG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SCAPY] [$TYPE] (User: $CURRENT_USER) $MSG" >> "$LOG_FILE"
}

# ============================================================
# 2. GESTIÓN DINÁMICA DE PRIVILEGIOS
# ============================================================

if [ ! -f "$SUDOERS_CONF" ]; then
    log_msg "AUTH" "Configurando privilegios NOPASSWD para $CURRENT_USER..."

    RULE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/pip3, /usr/bin/python3"

    if echo "$RULE" | sudo visudo -cf- &>/dev/null; then
        echo "$RULE" | sudo tee "$SUDOERS_CONF" >/dev/null
        sudo chmod 0440 "$SUDOERS_CONF"
        log_msg "OK" "Permisos sudo configurados correctamente."
    else
        log_msg "ERROR" "Error validando sudoers. Abortando."
        exit 1
    fi
fi

# ============================================================
# 3. COMPROBACIÓN PREVIA
# ============================================================

if python3 - <<EOF &>/dev/null
import scapy
EOF
then
    log_msg "INFO" "Scapy ya está instalado en el sistema."
    echo "data: [FIN]"
    exit 0
fi

# ============================================================
# 4. INSTALACIÓN
# ============================================================

export DEBIAN_FRONTEND=noninteractive

log_msg "START" "Iniciando instalación de Scapy"
log_msg "PROG" "Actualizando repositorios del sistema..."

if ! sudo timeout 60s apt-get update -qq >> "$LOG_FILE" 2>&1; then
    log_msg "ERROR" "Fallo en apt-get update"
    exit 1
fi

log_msg "PROG" "Instalando dependencias base (pip, libpcap)..."

if ! sudo timeout 120s apt-get install -y -qq python3-pip libpcap-dev >> "$LOG_FILE" 2>&1; then
    log_msg "ERROR" "Fallo instalando dependencias del sistema"
    exit 1
fi

log_msg "PROG" "Instalando Scapy vía pip (system-wide)..."

if ! sudo timeout 180s pip3 install --upgrade scapy >> "$LOG_FILE" 2>&1; then
    log_msg "ERROR" "Fallo en pip install scapy"
    exit 1
fi

# ============================================================
# 5. VERIFICACIÓN FINAL
# ============================================================

if python3 - <<EOF &>/dev/null
import scapy
EOF
then
    VER=$(pip3 show scapy | awk '/Version/ {print $2}')
    log_msg "OK" "Scapy instalado correctamente (versión $VER)"
else
    log_msg "ERROR" "Scapy no se pudo importar tras la instalación"
    exit 1
fi

# ============================================================
# 6. FIN
# ============================================================

echo "data: [FIN]"
