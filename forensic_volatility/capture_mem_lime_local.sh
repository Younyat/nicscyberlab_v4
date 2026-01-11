#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. CONFIGURACIÓN (EDITA ESTOS DOS CAMPOS)
# ============================================================
VM_TARGET="10.0.2.172"   # <--- SUSTITUYE POR LA IP DE VICTIM 3
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key" # <<<<<<<<<<<<<<<-------------copiar al key desde la amuina host y ponerlo en su lugar en la maquina actual
# Verificación de seguridad de la clave
if [[ ! -f "$SSH_KEY" ]]; then
    echo "ERROR: No se encuentra el archivo de clave en $SSH_KEY"
    echo "Prueba a listar tus claves con: ls -l ~/.ssh"
    exit 1
fi
chmod 600 "$SSH_KEY"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_EVIDENCE_DIR="$SCRIPT_DIR/memory_dumps"
mkdir -p "$LOCAL_EVIDENCE_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ============================================================
# 2. NOMBRES DE ARCHIVO
# ============================================================
DUMP_NAME="memdump_victim3_${TIMESTAMP}.lime"
REMOTE_DUMP="/tmp/$DUMP_NAME"
LOCAL_DUMP="$LOCAL_EVIDENCE_DIR/$DUMP_NAME"

echo "[*] Iniciando captura en: $VM_TARGET"

# ============================================================
# 3. CAPTURA LiME VÍA SSH
# ============================================================
# Añadimos -o StrictHostKeyChecking=no para evitar bloqueos por huella digital
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_TARGET" << EOF
set -e

echo "[*] Preparando entorno para LiME en la víctima..."
sudo rmmod lime 2>/dev/null || true
sudo rm -f "$REMOTE_DUMP"

# Instalación de dependencias
sudo apt update
sudo apt install -y linux-headers-\$(uname -r) build-essential git

# Clonar y compilar LiME
rm -rf /tmp/LiME
git clone --depth 1 https://github.com/504ensicsLabs/LiME.git /tmp/LiME
cd /tmp/LiME/src
make

LIME_KO=\$(ls lime-*.ko | head -n1)
echo "[+] Cargando módulo \$LIME_KO"

sudo insmod "\$LIME_KO" "path=$REMOTE_DUMP format=lime"

echo "[+] Capturando memoria en $REMOTE_DUMP..."

# --------- MONITORIZACIÓN ---------
PREV_SIZE=0
STABLE_COUNT=0
MAX_STABLE=3
INTERVAL=10

while true; do
    SIZE=\$(stat -c%s "$REMOTE_DUMP" 2>/dev/null || echo 0)
    echo "[*] Tamaño actual: \$((SIZE / 1024 / 1024)) MB"

    if [[ "\$SIZE" -eq "\$PREV_SIZE" && "\$SIZE" -gt 0 ]]; then
        STABLE_COUNT=\$((STABLE_COUNT + 1))
    else
        STABLE_COUNT=0
    fi

    if [[ "\$STABLE_COUNT" -ge "\$MAX_STABLE" ]]; then
        break
    fi

    PREV_SIZE="\$SIZE"
    sleep "\$INTERVAL"
done

sudo rmmod lime || true
sudo chmod 644 "$REMOTE_DUMP"
EOF

# ============================================================
# 4. EXTRACCIÓN Y VERIFICACIÓN
# ============================================================
echo "[*] Descargando volcado a la estación forense..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_TARGET:$REMOTE_DUMP" "$LOCAL_DUMP"

echo "[*] Generando hash de integridad..."
sha256sum "$LOCAL_DUMP" | tee "$LOCAL_DUMP.sha256"



echo "[OK] Proceso completado."
echo "Archivo local: $LOCAL_DUMP"
