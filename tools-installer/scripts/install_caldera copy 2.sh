#!/usr/bin/env bash
set -euo pipefail
trap 'echo " [FATAL] ERROR en línea ${LINENO}" >&2' ERR

export DEBIAN_FRONTEND=noninteractive

echo "===================================================="
echo " INSTALADOR MAESTRO DE CALDERA (LIMPIEZA TOTAL)"
echo "===================================================="

# --- 1. DESBLOQUEO Y REPARACIÓN DE APT ---
echo "[1/7] Desbloqueando y reparando sistema de paquetes..."
# Matar procesos de apt que puedan estar corriendo en background
killall apt apt-get 2>/dev/null || true
# Eliminar locks
rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock
# Reparar dpkg y dependencias
dpkg --configure -a
apt-get install -f -y
# Limpiar instalaciones rotas de nodejs que suelen causar el 'broken packages'
apt-get purge -y nodejs npm libnode-dev 2>/dev/null || true
apt-get autoremove -y
apt-get update -qq

# --- 2. INSTALACIÓN DE DEPENDENCIAS LIMPIAS ---
echo "[2/7] Instalando dependencias base (Python + Node)..."
# Instalamos Node desde el repo oficial para evitar conflictos de 'broken packages'
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y python3 python3-pip python3-venv curl git build-essential nodejs >/dev/null

# --- 3. PREPARACIÓN DE DIRECTORIO ---
CALDERA_DIR="/opt/caldera"
echo "[3/7] Preparando directorio en $CALDERA_DIR..."
pkill -9 -f "server.py" || true
rm -rf "$CALDERA_DIR"
git clone https://github.com/mitre/caldera.git --recursive "$CALDERA_DIR" >/dev/null

# --- 4. ENTORNO VIRTUAL PYTHON (VENV) ---
echo "[4/7] Configurando entorno virtual Python..."
cd "$CALDERA_DIR"
python3 -m venv venv
./venv/bin/pip install --upgrade pip >/dev/null
./venv/bin/pip install -r requirements.txt >/dev/null

# --- 5. PLUGIN MAGMA (FRONTEND) ---
echo "[5/7] Compilando Plugin Magma..."
if [[ -d "plugins/magma" ]]; then
    cd plugins/magma
    npm install --quiet --legacy-peer-deps >/dev/null 2>&1 || true
    cd "$CALDERA_DIR"
fi

# --- 6. LANZAMIENTO DEL SERVIDOR ---
echo "[6/7] Lanzando Caldera en background..."
# Usamos el venv para evitar el error de 'break-system-packages'
nohup ./venv/bin/python server.py --insecure --build > "$CALDERA_DIR/caldera.log" 2>&1 &

# --- 7. ESPERA ACTIVA (HEALTHCHECK) ---
echo "[7/7] Esperando a que Caldera responda (Puerto 8888)..."
MAX_WAIT=180
SUCCESS=false

for ((i=1; i<=MAX_WAIT; i++)); do
    # Intentamos conectar al puerto
    if curl -s "http://localhost:8888" > /dev/null; then
        echo " [✓] Caldera está ONLINE."
        SUCCESS=true
        break
    fi
    
    # Verificar si el proceso sigue vivo
    if ! pgrep -f "server.py" > /dev/null; then
        echo " [X] El proceso falló al arrancar. Últimas líneas del log:"
        tail -n 20 "$CALDERA_DIR/caldera.log"
        exit 1
    fi
    
    [[ $((i % 10)) -eq 0 ]] && echo "  ... esperando ($i seg) ..."
    sleep 2
done

if [ "$SUCCESS" = false ]; then
    echo " [X] Tiempo de espera agotado. Caldera no responde."
    exit 1
fi

# FINALIZACIÓN
FINAL_IP=$(hostname -I | awk '{print $1}')
echo "===================================================="
echo " INSTALACIÓN COMPLETADA CON ÉXITO"
echo " URL: http://${FINAL_IP}:8888"
echo " Credenciales por defecto en conf/users.yaml"
echo "===================================================="