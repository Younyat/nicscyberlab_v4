#!/usr/bin/env bash
# =================================================================
# NICS CyberLab – Professional Starter
# Gunicorn + tcpdump (capabilities) + libpcap + Port Management
# =================================================================
# Design principles:
# - Python and Gunicorn run UNPRIVILEGED
# - Network capture delegated ONLY to tcpdump with minimal capabilities
# - Safe & idempotent startup
# - No hard failures if optional components are missing
# =================================================================

set -euo pipefail

# -----------------------------
# CONFIG
# -----------------------------
PORT=5001
TIMEOUT=20000

APP_PATH="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
VENV_PYTHON="/home/younes/Desktop/Openstack/myenv/bin/python3.12"

# -----------------------------
# UTILS
# -----------------------------
section () {
    echo
    echo "============================================="
    echo " $1"
    echo "============================================="
}

ok ()   { echo " [OK]   $1"; }
warn () { echo " [WARN] $1"; }
info () { echo " [INFO] $1"; }
err ()  { echo " [ERR]  $1"; }

# -----------------------------
# [1/6] PREPARATION
# -----------------------------
section "[1/6] Preparando entorno y scripts auxiliares"

if [ -f "$APP_PATH/free_port.sh" ]; then
    chmod +x "$APP_PATH/free_port.sh"
    ok "Script de limpieza de puertos listo."
else
    err "No se encuentra $APP_PATH/free_port.sh"
    exit 1
fi

if [ ! -f "$VENV_PYTHON" ]; then
    err "No se encuentra el Python del venv: $VENV_PYTHON"
    exit 1
else
    ok "VENV Python detectado: $VENV_PYTHON"
fi

# --- Asegurar permisos correctos en SSH (evita Permission denied / bad permissions) ---


section "[2.5/6] Ajustando permisos SSH..."
chmod 700 "$HOME/.ssh" 2>/dev/null || true
chmod 600 "$HOME/.ssh/my_key" 2>/dev/null || true
chmod 644 "$HOME/.ssh/my_key.pub" 2>/dev/null || true



# -----------------------------
# [2/6] SYSTEM DEPENDENCIES
# -----------------------------
section "[2/6] Verificando dependencias del sistema"

if ! dpkg -s libpcap-dev >/dev/null 2>&1; then
    warn "libpcap-dev no detectado."
    info "Instalando libpcap-dev (requiere sudo)..."
    sudo apt-get update && sudo apt-get install -y libpcap-dev
    ok "libpcap-dev instalado."
else
    ok "libpcap-dev ya está instalado."
fi

if ! command -v getcap >/dev/null 2>&1; then
    warn "getcap no disponible (paquete libcap2-bin)."
    info "Instálalo si quieres ver capacidades: sudo apt install libcap2-bin"
else
    ok "getcap disponible."
fi

# -----------------------------
# [3/6] TCPDUMP CAPABILITIES
# -----------------------------
section "[3/6] Configurando capacidades de red (tcpdump)"

TCPDUMP_BIN="$(command -v tcpdump || true)"

if [ -z "$TCPDUMP_BIN" ]; then
    warn "tcpdump no está instalado. La captura de red estará deshabilitada."
else
    ok "tcpdump detectado en: $TCPDUMP_BIN"

    TCPDUMP_CAPS="$(getcap "$TCPDUMP_BIN" 2>/dev/null || true)"

    if echo "$TCPDUMP_CAPS" | grep -q "cap_net_admin,cap_net_raw=eip"; then
        ok "tcpdump ya tiene capacidades de red."
    else
        info "tcpdump sin capacidades. Intentando aplicar (requiere sudo)..."

        if sudo -n true 2>/dev/null; then
            sudo setcap cap_net_raw,cap_net_admin=eip "$TCPDUMP_BIN" || true

            if getcap "$TCPDUMP_BIN" | grep -q "cap_net_admin,cap_net_raw=eip"; then
                ok "Capacidades aplicadas correctamente a tcpdump."
            else
                warn "No se pudieron aplicar capacidades a tcpdump."
                warn "La captura de red fallará si no se ejecuta como root."
            fi
        else
            warn "No hay sudo sin contraseña."
            warn "Ejecuta manualmente:"
            warn "sudo setcap cap_net_raw,cap_net_admin=eip $TCPDUMP_BIN"
        fi
    fi
fi

# -----------------------------
# [4/6] FREE PORT
# -----------------------------
section "[4/6] Liberando el puerto $PORT"

bash "$APP_PATH/free_port.sh" "$PORT"
ok "Puerto $PORT liberado o ya estaba libre."

# -----------------------------
# [5/6] PYTHON RUNTIME
# -----------------------------
section "[5/6] Verificando Gunicorn y Scapy en el VENV"

"$VENV_PYTHON" -m pip install --upgrade pip >/dev/null 2>&1 || true
"$VENV_PYTHON" -m pip install --upgrade gunicorn scapy
ok "Gunicorn y Scapy disponibles en el venv."

# -----------------------------
# [6/6] START SERVER
# -----------------------------
section "[6/6] Lanzando Servidor Forense (Gunicorn)"

cd "$APP_PATH" || exit 1

exec "$VENV_PYTHON" -m gunicorn \
    -w 4 \
    -b "0.0.0.0:$PORT" \
    --timeout "$TIMEOUT" \
    --log-level info \
    app:app
