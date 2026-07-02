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
SCENARIO_CAPTURE_PID=""

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

cleanup() {
    echo
    info "Ejecutando limpieza final..."

    if [[ -n "${SCENARIO_CAPTURE_PID:-}" ]]; then
        if ps -p "$SCENARIO_CAPTURE_PID" > /dev/null 2>&1; then
            info "Deteniendo nics_scenario_captures.sh (PID=$SCENARIO_CAPTURE_PID)..."

            sudo -n kill -TERM "$SCENARIO_CAPTURE_PID" 2>/dev/null || true

            for _ in {1..10}; do
                if ! ps -p "$SCENARIO_CAPTURE_PID" > /dev/null 2>&1; then
                    break
                fi
                sleep 1
            done

            if ps -p "$SCENARIO_CAPTURE_PID" > /dev/null 2>&1; then
                warn "El proceso sigue vivo. Forzando parada..."
                sudo -n kill -KILL "$SCENARIO_CAPTURE_PID" 2>/dev/null || true
            fi

            if ! ps -p "$SCENARIO_CAPTURE_PID" > /dev/null 2>&1; then
                ok "nics_scenario_captures.sh detenido correctamente."
            else
                warn "No se pudo detener completamente nics_scenario_captures.sh."
            fi
        fi
    fi
}

trap cleanup EXIT INT TERM

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

# -----------------------------
# [2.5/6] SSH PERMISSIONS
# -----------------------------
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
# [3.5/6] PYTHON CAPABILITIES
# -----------------------------
section "[3.5/6] Configurando capacidades de red (python)"

REAL_PY="$(readlink -f "$VENV_PYTHON" 2>/dev/null || true)"

if [ -z "$REAL_PY" ] || [ ! -f "$REAL_PY" ]; then
    warn "No se pudo resolver el python real desde el venv: $VENV_PYTHON"
    warn "Saltando setcap para python."
else
    ok "Python real detectado: $REAL_PY"

    PY_CAPS="$(getcap "$REAL_PY" 2>/dev/null || true)"

    if echo "$PY_CAPS" | grep -q "cap_net_admin,cap_net_raw=eip"; then
        ok "Python ya tiene capacidades de captura."
    else
        info "Python sin capacidades. Intentando aplicar (requiere sudo)..."

        if sudo -n true 2>/dev/null; then
            sudo setcap cap_net_raw,cap_net_admin=eip "$REAL_PY" || true

            if getcap "$REAL_PY" | grep -q "cap_net_admin,cap_net_raw=eip"; then
                ok "Capacidades aplicadas correctamente a Python."
            else
                warn "No se pudieron aplicar capacidades a Python."
                warn "Scapy/AsyncSniffer fallará sin sudo/root."
            fi
        else
            warn "No hay sudo sin contraseña."
            warn "Ejecuta manualmente:"
            warn "sudo setcap cap_net_raw,cap_net_admin=eip $REAL_PY"
        fi
    fi

    info "Estado final python caps: $(getcap "$REAL_PY" 2>/dev/null || echo 'none')"
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

echo "============================================="
echo " [5/6] Verificando dependencias Python (en el VENV)"
echo "============================================="

set +e
"$VENV_PYTHON" - <<'PY'
import sys
missing=[]
for m in ("matplotlib",):
    try:
        __import__(m)
    except Exception:
        missing.append(m)
if missing:
    print("FALTAN:", ", ".join(missing))
    sys.exit(2)
print("[OK] matplotlib disponible (venv).")
PY
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "[WARN] matplotlib no está en el venv. Instalando con pip (venv)..."
  "$VENV_PYTHON" -m pip install --upgrade matplotlib
  echo "[OK] matplotlib instalado (pip/venv)."
fi

# -----------------------------
# [5.9/6] START nics_scenario_captures
# -----------------------------
section "[5.9/6] START nics_scenario_captures (background)"

LOG_DIR="$APP_PATH/app_core/infrastructure/ics_traffic/captures/full_scenario_captures/logs"
mkdir -p "$LOG_DIR"

sudo -n bash "$APP_PATH/nics_scenario_captures.sh" > "$LOG_DIR/scenario_captures.log" 2>&1 &
SCENARIO_CAPTURE_PID=$!
ok "nics_scenario_captures lanzado (PID=$SCENARIO_CAPTURE_PID)"

# -----------------------------
# [5.95/6] LOAD OPENSTACK CREDS
# -----------------------------
section "[5.95/6] Cargando credenciales OpenStack (admin-openrc.sh)"

OPENRC="$APP_PATH/admin-openrc.sh"
if [ -f "$OPENRC" ]; then
  set +u
  source "$OPENRC"
  set -u
  ok "OpenStack env cargado desde: $OPENRC"
else
  warn "No existe $OPENRC. Gunicorn arrancará SIN credenciales OS_*."
fi

if [ -z "${OS_AUTH_URL:-}" ]; then
  warn "OS_AUTH_URL está vacío. Revisa admin-openrc.sh o su export."
else
  ok "OS_AUTH_URL detectado."
fi

# -----------------------------
# [6/6] START SERVER
# -----------------------------
section "[6/6] Lanzando Servidor Forense (Gunicorn)"

cd "$APP_PATH" || exit 1

"$VENV_PYTHON" -m gunicorn \
    -w 4 \
    -b "0.0.0.0:$PORT" \
    --timeout "$TIMEOUT" \
    --log-level info \
    app:app

GUNICORN_RC=$?
info "Gunicorn finalizó con código: $GUNICORN_RC"
exit "$GUNICORN_RC"