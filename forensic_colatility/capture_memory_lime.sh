#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. CONTEXTO
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENRC_PATH="$SCRIPT_DIR/../admin-openrc.sh"

if [[ ! -f "$OPENRC_PATH" ]]; then
    echo "ERROR: admin-openrc.sh no encontrado en $OPENRC_PATH"
    exit 1
fi

source "$OPENRC_PATH"
echo "[OK] Credenciales OpenStack cargadas"

# ============================================================
# 2. CONFIGURACIÓN
# ============================================================
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

LOCAL_EVIDENCE_DIR="$SCRIPT_DIR/memory_dumps"
mkdir -p "$LOCAL_EVIDENCE_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ============================================================
# 3. RESOLVER VÍCTIMA
# ============================================================
VM_NAME=$(openstack server list -f value -c Name | grep -i '^victim' | head -n1)

if [[ -z "$VM_NAME" ]]; then
    echo "ERROR: no se encontró ninguna VM victim*"
    exit 1
fi

FIXED_IP=$(openstack server show "$VM_NAME" -f value -c addresses \
  | grep -oP '192\.168\.100\.\d+' | head -n1)

FIP=$(openstack floating ip list \
  --fixed-ip-address "$FIXED_IP" \
  -f value -c "Floating IP Address" | head -n1)

if [[ -z "$FIP" ]]; then
    echo "ERROR: la VM no tiene Floating IP"
    exit 1
fi

echo "[OK] Víctima: $VM_NAME ($FIP)"

# ============================================================
# 4. NOMBRES
# ============================================================
DUMP_NAME="memdump_${VM_NAME// /_}_${TIMESTAMP}.lime"
REMOTE_DUMP="/tmp/$DUMP_NAME"
LOCAL_DUMP="$LOCAL_EVIDENCE_DIR/$DUMP_NAME"

# ============================================================
# 5. CAPTURA LiME (ROBUSTA – 4 GB RAM)
# ============================================================
ssh -i "$SSH_KEY" "$SSH_USER@$FIP" << EOF
set -e

echo "[*] Preparando captura LiME"
sudo rmmod lime 2>/dev/null || true
sudo rm -f "$REMOTE_DUMP"

sudo apt update
sudo apt install -y linux-headers-\$(uname -r) build-essential git

rm -rf /tmp/LiME
git clone --depth 1 https://github.com/504ensicsLabs/LiME.git /tmp/LiME
cd /tmp/LiME/src
make

LIME_KO=\$(ls lime-*.ko | head -n1)
echo "[+] Cargando módulo \$LIME_KO"

sudo insmod "\$LIME_KO" "path=$REMOTE_DUMP format=lime"

echo "[+] Dumping memory..."

# --------- CRITERIO CORRECTO DE FINALIZACIÓN ---------
PREV_SIZE=0
STABLE_COUNT=0
MAX_STABLE=3        # 30 s sin crecimiento
INTERVAL=10
MAX_WAIT=480        # 8 min (4 GB RAM)
ELAPSED=0

while true; do
    SIZE=\$(stat -c%s "$REMOTE_DUMP" 2>/dev/null || echo 0)
    echo "[*] Dump size: \$((SIZE / 1024 / 1024)) MB"

    if [[ "\$SIZE" -eq "\$PREV_SIZE" && "\$SIZE" -gt 0 ]]; then
        STABLE_COUNT=\$((STABLE_COUNT + 1))
    else
        STABLE_COUNT=0
    fi

    if [[ "\$STABLE_COUNT" -ge "\$MAX_STABLE" ]]; then
        echo "[+] Dump size stabilized. Finishing capture."
        break
    fi

    PREV_SIZE="\$SIZE"
    sleep "\$INTERVAL"
    ELAPSED=\$((ELAPSED + INTERVAL))

    if [[ "\$ELAPSED" -ge "\$MAX_WAIT" ]]; then
        echo "[!] Timeout alcanzado (\${MAX_WAIT}s). Forzando finalización."
        break
    fi
done
# ----------------------------------------------------

sudo rmmod lime || true
sudo chmod 644 "$REMOTE_DUMP"

echo "[+] Captura finalizada"
ls -lh "$REMOTE_DUMP"
EOF

# ============================================================
# 6. COPIA AL HOST
# ============================================================
scp -i "$SSH_KEY" "$SSH_USER@$FIP:$REMOTE_DUMP" "$LOCAL_DUMP"

# ============================================================
# 7. HASH
# ============================================================
sha256sum "$LOCAL_DUMP" | tee "$LOCAL_DUMP.sha256"

echo "[OK] Captura LiME completada correctamente"
echo "     Archivo: $LOCAL_DUMP"
