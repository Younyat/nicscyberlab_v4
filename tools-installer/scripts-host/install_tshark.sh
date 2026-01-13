#!/usr/bin/env bash
set -uo pipefail

# 1. DETECCIÓN DINÁMICA DE RUTAS Y USUARIO
# Detecta la carpeta donde está este script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Define LOG_DIR un nivel arriba del script, en la carpeta tools-installer/logs
LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"
LOG_FILE="$LOG_DIR/host_manage.log"
SUDOERS_CONF="/etc/sudoers.d/nics_cyberlab_v3"
CURRENT_USER=$(whoami)

# Asegurar que la carpeta de logs existe con los permisos del usuario actual
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

log_msg() {
    local TYPE=$1
    local MSG=$2
    # Salida para capturar en el Frontend (Flask)
    echo "[$TYPE] $MSG"
    # Salida para el registro histórico (Sin sudo para evitar conflictos)
    echo "$(date '+%Y-%m-%d %H:%M:%S') [TSHARK] [$TYPE] (User: $CURRENT_USER) $MSG" >> "$LOG_FILE"
}

# --- GESTIÓN DINÁMICA DE PRIVILEGIOS ---
if [ ! -f "$SUDOERS_CONF" ]; then
    log_msg "AUTH" "Configurando privilegios NOPASSWD para $CURRENT_USER..."
    # Comandos permitidos para el motor de herramientas
    RULE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt, /usr/bin/rm, /usr/local/bin/vol, /usr/local/bin/termshark"
    
    # Validar y escribir la regla
    if echo "$RULE" | sudo visudo -cf- &>/dev/null; then
        echo "$RULE" | sudo tee "$SUDOERS_CONF" > /dev/null
        sudo chmod 0440 "$SUDOERS_CONF"
        log_msg "OK" "Permisos del sistema configurados automáticamente."
    else
        log_msg "ERROR" "Sintaxis de sudoers inválida. No se pudo automatizar."
    fi
fi

# --- PROCESO DE INSTALACIÓN ---
if command -v tshark &> /dev/null; then
    log_msg "INFO" "Tshark ya está instalado."
    echo "data: [FIN]"
    exit 0
fi

log_msg "START" "Iniciando instalación desde: $SCRIPT_DIR"
export DEBIAN_FRONTEND=noninteractive

log_msg "PROG" "Actualizando repositorios del sistema..."
if ! sudo timeout 60s apt-get update -qq >> "$LOG_FILE" 2>&1; then
    log_msg "ERROR" "Fallo en apt update. Revisa el archivo de log en $LOG_FILE"
    exit 1
fi

log_msg "PROG" "Instalando paquetes (esto puede demorar)..."
if ! sudo timeout 180s apt-get install -y -qq tshark >> "$LOG_FILE" 2>&1; then
    log_msg "ERROR" "Fallo en la instalación de paquetes tshark."
    exit 1
fi

# --- VERIFICACIÓN DE ÉXITO ---
if command -v tshark &> /dev/null; then
    VER=$(tshark --version | head -n 1)
    log_msg "OK" "Verificación exitosa: $VER"
else
    log_msg "ERROR" "No se pudo localizar tshark tras la instalación."
    exit 1
fi

echo "data: [FIN]"