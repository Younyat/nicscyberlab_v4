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
  python3 python3-venv python3-pip git \
  build-essential libffi-dev libssl-dev

# ============================================================
# 2. CLONAR O ACTUALIZAR VOLATILITY 3
# ============================================================
echo "[2/7] Gestionando repositorio..."
if [[ -d "$VOL_DIR" ]]; then
  echo "    -> Actualizando repositorio existente..."
  cd "$VOL_DIR"
  git pull
else
  git clone https://github.com/volatilityfoundation/volatility3.git "$VOL_DIR"
  cd "$VOL_DIR"
fi

# ============================================================
# 3. ENTORNO VIRTUAL Y DEPENDENCIAS CRÍTICAS
# ============================================================
echo "[3/7] Configurando entorno virtual y dependencias..."
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -e .

# --- ADICIÓN IMPORTANTE: Yara y otras extensiones ---
echo "    -> Instalando soporte para Yara (forense avanzado)..."
pip install yara-python pycryptodriver pefile
# ----------------------------------------------------

# ============================================================
# 4. COMANDO GLOBAL `vol` (WRAPPER)
# ============================================================
echo "[4/7] Creando acceso directo en $BIN_LINK..."
# Usamos un wrapper que activa el venv automáticamente
sudo tee "$BIN_LINK" >/dev/null <<EOF
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python3 "$VOL_DIR/vol.py" "\$@"
EOF

sudo chmod +x "$BIN_LINK"

# ============================================================
# 5. DIRECTORIO DE SÍMBOLOS
# ============================================================
echo "[5/7] Configurando directorios de trabajo..."
mkdir -p "$SYMBOLS_DIR"

# ============================================================
# 6. VERIFICACIÓN
# ============================================================
echo "[6/7] Test de ejecución..."
"$BIN_LINK" -v | head -n 5

# ============================================================
# 7. FINALIZACIÓN
# ============================================================
echo "[FIN] Instalación completada."
echo "data: [FIN]" # Enviamos la señal que espera tu frontend para cerrar el overlay