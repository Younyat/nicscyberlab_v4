#!/usr/bin/env bash
set -uo pipefail

# ============================================================
# 1. CONFIGURACIÓN DINÁMICA (PORTABLE)
# ============================================================
# Detectamos la ubicación del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Subimos un nivel para llegar a la raíz de 'tools-installer'
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Definición de rutas relativas
VOL_DIR="$BASE_DIR/apps/volatility3"
VENV_DIR="$VOL_DIR/venv"
LOG_DIR="$BASE_DIR/logs"
LOG_FILE="$LOG_DIR/host_manage.log"

# Definición de rutas de sistema y usuario
BIN_LINK="/usr/local/bin/vol"
SYMBOLS_DIR="$HOME/.volatility3/symbols"
CURRENT_USER=$(whoami)

# Crear directorios si no existen
mkdir -p "$LOG_DIR"
mkdir -p "$BASE_DIR/apps"
mkdir -p "$SYMBOLS_DIR"

# Función de log dual (Pantalla para SSE y Archivo para persistencia)
log_msg() {
    local TYPE=$1
    local MSG=$2
    # Esto lo lee el frontend
    echo "[$TYPE] $MSG"
    # Esto se guarda en el servidor
    echo "$(date '+%Y-%m-%d %H:%M:%S') [VOL-INSTALL] [$TYPE] $MSG" >> "$LOG_FILE"
}

log_msg "START" "Instalación local de Volatility 3 para usuario: $CURRENT_USER"

# ============================================================
# 2. DEPENDENCIAS DEL SISTEMA
# ============================================================
log_msg "PROG" "[1/7] Instalando dependencias del sistema (apt)..."
export DEBIAN_FRONTEND=noninteractive

# Redirigimos a log para evitar basura ANSI [K en el frontend
sudo apt-get update -qq >> "$LOG_FILE" 2>&1
sudo apt-get install -y -qq python3 python3-venv python3-pip git \
  build-essential libffi-dev libssl-dev >> "$LOG_FILE" 2>&1

# ============================================================
# 3. GESTIONAR REPOSITORIO
# ============================================================
log_msg "PROG" "[2/7] Gestionando repositorio en $VOL_DIR..."
if [[ -d "$VOL_DIR" ]]; then
    log_msg "INFO" "Actualizando repositorio existente..."
    cd "$VOL_DIR" && git pull -q >> "$LOG_FILE" 2>&1
else
    log_msg "INFO" "Clonando repositorio oficial..."
    git clone -q https://github.com/volatilityfoundation/volatility3.git "$VOL_DIR" >> "$LOG_FILE" 2>&1
    cd "$VOL_DIR"
fi

# ============================================================
# 4. ENTORNO VIRTUAL Y DEPENDENCIAS
# ============================================================
log_msg "PROG" "[3/7] Configurando entorno virtual y pip..."
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR" >> "$LOG_FILE" 2>&1
fi

# Usamos la ruta directa al binario del venv para evitar errores de 'activate' en scripts
"$VENV_DIR/bin/pip" install -q --upgrade pip >> "$LOG_FILE" 2>&1
"$VENV_DIR/bin/pip" install -q -e . >> "$LOG_FILE" 2>&1

log_msg "PROG" "Instalando soporte para Yara y extensiones forenses..."
"$VENV_DIR/bin/pip" install -q yara-python pycryptodome pefile >> "$LOG_FILE" 2>&1

# ============================================================
# 5. CREAR WRAPPER GLOBAL
# ============================================================
log_msg "PROG" "[4/7] Creando acceso directo en $BIN_LINK..."
# El wrapper usa las rutas dinámicas detectadas al inicio
sudo tee "$BIN_LINK" >/dev/null <<EOF
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python3 "$VOL_DIR/vol.py" "\$@"
EOF

sudo chmod +x "$BIN_LINK"

# ============================================================
# 6. VERIFICACIÓN
# ============================================================
log_msg "PROG" "[6/7] Test de ejecución..."
if "$BIN_LINK" -h &>/dev/null; then
    log_msg "OK" "Volatility 3 verificado correctamente."
else
    log_msg "ERROR" "Fallo en la verificación. Consulta $LOG_FILE"
    exit 1
fi

# ============================================================
# 7. FINALIZACIÓN
# ============================================================
log_msg "FIN" "Instalación completada con éxito."
echo "data: [FIN]"