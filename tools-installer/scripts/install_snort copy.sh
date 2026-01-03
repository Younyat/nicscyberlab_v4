#!/usr/bin/env bash
set -euo pipefail
trap 'echo " ERROR en línea ${LINENO}" >&2' ERR

echo "===================================================="
echo " Instalador de Snort 3 (Idempotente y Validado)"
echo "===================================================="

INSTALL_PREFIX="/usr/local"
BIN_PATH="$INSTALL_PREFIX/bin/snort"
SRC_DIR="/opt/snort3-src"
CONF_DIR="/etc/snort"
RULES_DIR="/etc/snort/rules"
LOG_DIR="/var/log/snort"

# --------------------------------------------
# 1) Validación real Snort
# --------------------------------------------
is_snort_installed() {
    local bin=""
    if [[ -x "$BIN_PATH" ]]; then
        bin="$BIN_PATH"
    elif command -v snort >/dev/null 2>&1; then
        bin="$(command -v snort)"
    fi

    if [[ -n "$bin" ]] && "$bin" --version | grep -iq "snort"; then
        return 0
    fi

    return 1
}

if is_snort_installed; then
    echo " Snort ya está instalado. Nada que hacer."
    snort --version
    exit 0
fi

echo " Instalando Snort 3..."
export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------
# 2) Dependencias
# --------------------------------------------
sudo apt update -y
sudo apt install -y \
    build-essential cmake make automake autoconf libtool \
    pkg-config flex bison git zlib1g-dev liblzma-dev \
    openssl libssl-dev libpcap-dev libpcre3 libpcre3-dev \
    libdumbnet-dev luajit libluajit-5.1-dev \
    libtirpc-dev libnghttp2-dev libhwloc-dev \
    libhyperscan-dev \
    net-tools

# --------------------------------------------
# 3) Descargar Snort
# --------------------------------------------
sudo rm -rf "$SRC_DIR"
sudo git clone https://github.com/snort3/snort3 "$SRC_DIR"

cd "$SRC_DIR"
mkdir build
cd build

cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
make -j"$(nproc)"
sudo make install

# --------------------------------------------
# 4) Detectar carpeta etc dinámica
# --------------------------------------------
ETC_DIR=$(find "$SRC_DIR" -maxdepth 2 -type d -name etc | head -n1)

if [[ -z "$ETC_DIR" ]]; then
    echo " ERROR CRÍTICO: No se encontró carpeta 'etc' dentro del proyecto"
    exit 1
fi

echo "Configuración fuente detectada: $ETC_DIR"

sudo mkdir -p "$CONF_DIR" "$RULES_DIR" "$LOG_DIR"
sudo cp -r "$ETC_DIR"/* "$CONF_DIR"

# --------------------------------------------
# 5) Regla local ICMP
# --------------------------------------------
echo "alert icmp any any -> any any (msg:\"ICMP detectado\"; sid:10001; rev:1;)" \
  | sudo tee "$RULES_DIR/local.rules" >/dev/null

sudo sed -i "s|# include \$RULE_PATH/local.rules|include \$RULE_PATH/local.rules|g" \
 "$CONF_DIR/snort.lua" || true

# --------------------------------------------
# 6) Validación Snort config
# --------------------------------------------
echo " Validando configuración de Snort..."
sudo snort -T -c "$CONF_DIR/snort.lua"

echo " Test de configuración OK"

# --------------------------------------------
# 7) Validación instalación final
# --------------------------------------------
if is_snort_installed; then
    echo "===================================================="
    echo " Snort 3 instalado correctamente"
    echo "===================================================="
    snort --version
    exit 0
else
    echo " ERROR: Snort NO se instaló correctamente"
    exit 1
fi
