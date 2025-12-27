#!/usr/bin/env bash
#
# ============================================================
#   MITRE Caldera Installer (Idempotent + Floating IP Check)
#   Versión robusta para producción / auto-deploy
# ============================================================
set -euo pipefail
trap 'echo " ERROR en línea ${LINENO}" >&2' ERR

# IMPORTANTE:
# Este script está pensado para ejecutarse como root
# (por ejemplo: sudo bash install_caldera.sh <IP>).
# Cuando se ejecuta con sudo, HOME suele ser /root.
CALDERA_DIR="/root/caldera"
LOG_FILE="$CALDERA_DIR/caldera.log"
USERS_FILE="$CALDERA_DIR/conf/users.yaml"
PORT="8888"
START_TIME=$(date +%s)

# -------------------------
#  Formatear tiempo
# -------------------------
format_time() {
    local t=$1
    printf "%dm %ds\n" $((t/60)) $((t%60))
}

echo "===================================================="
echo " Instalador de MITRE Caldera"
echo "===================================================="

# -------------------------
#  Floating / Dashboard IP
# -------------------------
FINAL_IP="${1:-}"

if [[ -z "$FINAL_IP" ]]; then
    echo " No se recibió IP como argumento."
    echo "   Detectando IP local..."
    FINAL_IP=$(hostname -I | awk '{print $1}')
fi

echo " IP final para Dashboard: $FINAL_IP"
echo "----------------------------------------------------"


# ============================================================
#  FUNCIÓN: Validar si Caldera está vivo (proceso/puerto/HTTP)
#   Parámetro opcional:
#     1 → verbose (por defecto)
#     0 → silencioso (para loops de espera)
# ============================================================
check_caldera_alive() {
    local verbose="${1:-1}"
    local rc=0

    if [[ "$verbose" == "1" ]]; then
        echo " Validando estado de Caldera..."
        echo "   (Proceso, puerto y respuesta HTTP)"
    fi

    # 1) Proceso
    if pgrep -f "server.py" >/dev/null 2>&1; then
        [[ "$verbose" == "1" ]] && echo " Proceso server.py activo"
    else
        [[ "$verbose" == "1" ]] && echo " Proceso server.py NO activo"
        rc=1
    fi

    # 2) Puerto
    if ss -tunlp | grep -q ":${PORT}"; then
        [[ "$verbose" == "1" ]] && echo " Puerto ${PORT} en escucha"
    else
        [[ "$verbose" == "1" ]] && echo " Puerto ${PORT} no está en escucha"
        rc=1
    fi

    # 3) HTTP básico
    if curl -s --max-time 1 "http://${FINAL_IP}:${PORT}" >/dev/null 2>&1; then
        [[ "$verbose" == "1" ]] && echo " Dashboard responde HTTP"
    else
        [[ "$verbose" == "1" ]] && echo " Dashboard no responde en http://${FINAL_IP}:${PORT}"
        rc=1
    fi

    return "$rc"
}

# ============================================================
#  FUNCIÓN: Esperar a que Caldera levante (máx N segundos)
# ============================================================
wait_for_caldera() {
    local max_secs="${1:-30}"

    echo " Esperando a que Caldera esté disponible (máx ${max_secs}s)..."
    for ((i=1; i<=max_secs; i++)); do
        if check_caldera_alive 0; then
            echo " Caldera activo tras ${i}s"
            return 0
        fi
        sleep 1
    done

    echo " Caldera no respondió dentro de ${max_secs}s"
    return 1
}

# ============================================================
#  FUNCIÓN: Obtener credenciales reales de users.yaml
#    Si no se encuentra nada → admin / admin
# ============================================================
get_caldera_creds() {
    local u p
    if [[ -f "$USERS_FILE" ]]; then
        u=$(grep -oP 'username:\s*"?\K[^"]+' "$USERS_FILE" | head -n1 || true)
        p=$(grep -oP 'password:\s*"?\K[^"]+' "$USERS_FILE" | head -n1 || true)
    fi

    [[ -z "${u:-}" ]] && u="admin"
    [[ -z "${p:-}" ]] && p="admin"

    CALDERA_USER="$u"
    CALDERA_PASS="$p"
}


# ============================================================
#  DETECCIÓN: ¿YA ESTÁ INSTALADO?
# ============================================================
ALREADY=false

if [[ -d "$CALDERA_DIR" ]]; then
    echo " Detectada carpeta existente: $CALDERA_DIR"
    ALREADY=true
fi

if pgrep -f "server.py" >/dev/null 2>&1; then
    echo " Proceso server.py en ejecución"
    ALREADY=true
fi

if ss -tunlp | grep -q ":${PORT}"; then
    echo " Puerto ${PORT} ya está en uso"
    ALREADY=true
fi


# ============================================================
#  SI ESTÁ INSTALADO → VALIDAR Y/O RECUPERAR
# ============================================================
if $ALREADY; then
    echo
    echo " Caldera detectado previamente. Validando estado..."

    if check_caldera_alive 1; then
        echo
        echo "===================================================="
        echo " MITRE Caldera YA ESTÁ INSTALADO Y FUNCIONAL"
        echo "===================================================="
    else
        echo
        echo " Instalación detectada pero NO funcional."
        echo " Intentando levantar servicio de nuevo..."

        cd "$CALDERA_DIR"
        nohup python3 server.py --insecure --build > "$LOG_FILE" 2>&1 &

        # Esperar a que levante
        if ! wait_for_caldera 45; then
            echo " ERROR: Caldera sigue inactivo tras reintento."
            echo "   Revisa logs: $LOG_FILE"
            exit 2
        fi

        echo
        echo "===================================================="
        echo " Caldera restaurado correctamente"
        echo "===================================================="
    fi

    # Credenciales
    get_caldera_creds

    echo " URL      : http://${FINAL_IP}:${PORT}"
    echo " Usuario  : ${CALDERA_USER}"
    echo " Password : ${CALDERA_PASS}"
    echo " Carpeta  : $CALDERA_DIR"
    echo " Log      : $LOG_FILE"
    echo "===================================================="
    exit 0
fi


# ============================================================
#  INSTALACIÓN NUEVA (solo si no había nada)
# ============================================================
echo
echo " No se detecta instalación previa. Iniciando instalación limpia..."
export DEBIAN_FRONTEND=noninteractive

echo "[1/7]  Actualizando sistema..."
sudo apt-get update -y >/dev/null
sudo apt-get upgrade -y >/dev/null

echo "[2/7]  Instalando dependencias base..."
sudo apt-get install -y python3 python3-pip curl git build-essential >/dev/null

echo "[3/7]  Instalando Node.js 20.x (si no existe)..."
if ! command -v node >/dev/null 2>&1; then
    if ! curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null 2>&1; then
        echo " No se pudo añadir el repositorio NodeSource"
        exit 1
    fi

    if ! sudo apt-get install -y nodejs >/dev/null 2>&1; then
        echo " No se pudo instalar nodejs"
        exit 1
    fi
else
    echo " Node.js ya está instalado"
fi

echo "[4/7]  Clonando repositorio Caldera..."
if [[ -d "$CALDERA_DIR" ]]; then
    echo " Carpeta $CALDERA_DIR ya existe inesperadamente."
    echo "   Renombrando a ${CALDERA_DIR}.bak_$(date +%s)"
    mv "$CALDERA_DIR" "${CALDERA_DIR}.bak_$(date +%s)"
fi
git clone https://github.com/mitre/caldera.git --recursive "$CALDERA_DIR" >/dev/null

echo "[5/7]  Instalando dependencias del plugin Magma (si existe)..."
MAGMA_DIR="$CALDERA_DIR/plugins/magma"
if [[ -d "$MAGMA_DIR" ]]; then
    cd "$MAGMA_DIR"
    rm -rf node_modules package-lock.json >/dev/null 2>&1 || true
    if ! npm install \
        vite@2.9.15 \
        @vitejs/plugin-vue@2.3.4 \
        vue@3.2.45 \
        --legacy-peer-deps \
        >/dev/null 2>&1; then
        echo " No se pudieron instalar completamente las dependencias de Magma."
        echo "  Continuando instalación de Caldera igualmente..."
    fi
else
    echo "Info: Plugin Magma no encontrado. Saltando paso de npm."
fi

echo "[6/7]  Instalando requisitos Python..."
cd "$CALDERA_DIR"
sudo pip3 install --break-system-packages -r requirements.txt >/dev/null

echo "[7/7]  Lanzando servidor Caldera..."
mkdir -p "$CALDERA_DIR"
nohup python3 server.py --insecure --build > "$LOG_FILE" 2>&1 &
sleep 3


# ============================================================
#  VALIDACIÓN FINAL (espera + checks)
# ============================================================
if ! wait_for_caldera 45; then
    echo " ERROR: Caldera no responde después de la instalación."
    echo " Revisa el log: $LOG_FILE"
    exit 1
fi

get_caldera_creds

END_TIME=$(date +%s)
TOTAL=$(("$END_TIME" - "$START_TIME"))

echo
echo "===================================================="
echo " Instalación COMPLETA de MITRE Caldera"
echo " Tiempo total: $(format_time "$TOTAL")"
echo "===================================================="
echo " URL      : http://${FINAL_IP}:${PORT}"
echo " Usuario  : ${CALDERA_USER}"
echo " Password : ${CALDERA_PASS}"
echo " Carpeta  : $CALDERA_DIR"
echo " Log      : $LOG_FILE"
echo "===================================================="
