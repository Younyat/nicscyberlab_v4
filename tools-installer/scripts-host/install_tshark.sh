#!/usr/bin/env bash
set -uo pipefail

# 1. DETECCIÓN DINÁMICA
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
    # El prefijo "data:" es vital para que el EventSource de JS lo procese
    echo "data: [$TYPE] $MSG"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [TSHARK] [$TYPE] $MSG" >> "$LOG_FILE"
}

# --- GESTIÓN DE PRIVILEGIOS ---
# Si el archivo no existe, intentamos crearlo (requerirá sudo manual la primera vez)
if [ ! -f "$SUDOERS_CONF" ]; then
    log_msg "AUTH" "Configurando privilegios para $CURRENT_USER..."
    RULE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt, /usr/bin/debconf-set-selections"
    echo "$RULE" | sudo tee "$SUDOERS_CONF" > /dev/null
    sudo chmod 0440 "$SUDOERS_CONF"
fi

# --- PROCESO DE INSTALACIÓN ---
if command -v tshark &> /dev/null; then
    log_msg "INFO" "Tshark ya está instalado."
    echo "data: [FIN]"
    exit 0
fi

log_msg "START" "Iniciando despliegue de Tshark..."
export DEBIAN_FRONTEND=noninteractive

# LINEA CRÍTICA: Pre-configura la respuesta para la captura de paquetes sin root
log_msg "PROG" "Configurando debconf para captura no privilegiada..."
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections

log_msg "PROG" "Actualizando índices de paquetes..."
sudo apt-get update -qq

log_msg "PROG" "Instalando binarios de tshark..."
if sudo apt-get install -y -qq tshark >> "$LOG_FILE" 2>&1; then
    # Asegurar que el usuario actual pueda capturar tráfico
    sudo usermod -aG wireshark "$CURRENT_USER"
    log_msg "OK" "Tshark instalado y usuario añadido al grupo wireshark."
else
    log_msg "ERROR" "Fallo en la instalación. Revisa $LOG_FILE"
    exit 1
fi

# --- VERIFICACIÓN ---
if command -v tshark &> /dev/null; then
    VER=$(tshark --version | head -n 1)
    log_msg "SUCCESS" "$VER"
else
    log_msg "ERROR" "Binario no encontrado post-instalación."
    exit 1
fi

echo "data: [FIN]"