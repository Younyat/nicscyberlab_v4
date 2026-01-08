#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# CONFIGURACIÓN
# ============================================================
VOL_DIR="$HOME/volatility3"
VENV_DIR="$VOL_DIR/venv"
BIN_LINK="/usr/local/bin/vol"
SYMBOLS_DIR="$HOME/.volatility3/symbols"

echo "[*] Instalación local de Volatility 3"
echo "------------------------------------------------------------"

# ============================================================
# 1. DEPENDENCIAS DEL SISTEMA
# ============================================================
echo "[1/7] Instalando dependencias del sistema..."

sudo apt update
sudo apt install -y \
  python3 \
  python3-venv \
  python3-pip \
  git \
  build-essential \
  libffi-dev \
  libssl-dev

# ============================================================
# 2. CLONAR VOLATILITY 3
# ============================================================
echo "[2/7] Clonando Volatility 3 (oficial)..."

if [[ -d "$VOL_DIR" ]]; then
  echo "    -> Directorio existente, actualizando repositorio"
  cd "$VOL_DIR"
  git pull
else
  git clone https://github.com/volatilityfoundation/volatility3.git "$VOL_DIR"
  cd "$VOL_DIR"
fi

# ============================================================
# 3. ENTORNO VIRTUAL PYTHON
# ============================================================
echo "[3/7] Creando entorno virtual Python..."

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

pip install --upgrade pip
pip install -e .

# ============================================================
# 4. COMANDO GLOBAL `vol`
# ============================================================
echo "[4/7] Creando comando global 'vol'..."

sudo tee "$BIN_LINK" >/dev/null <<EOF
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python "$VOL_DIR/vol.py" "\$@"
EOF

sudo chmod +x "$BIN_LINK"

# ============================================================
# 5. DIRECTORIO DE SÍMBOLOS
# ============================================================
echo "[5/7] Preparando directorio de símbolos..."

mkdir -p "$SYMBOLS_DIR"

# ============================================================
# 6. VERIFICACIÓN DE INSTALACIÓN
# ============================================================
echo "[6/7] Verificando instalación..."

vol --help | head -n 20

# ============================================================
# 7. INFORMACIÓN FINAL
# ============================================================
echo "[7/7] Instalación COMPLETADA"
echo "------------------------------------------------------------"
echo " Comando        : vol"
echo " Directorio     : $VOL_DIR"
echo " Entorno virtual: $VENV_DIR"
echo " Símbolos       : $SYMBOLS_DIR"
echo ""
echo " Prueba rápida:"
echo "   vol -f memoria.raw linux.pslist"
echo "------------------------------------------------------------"
