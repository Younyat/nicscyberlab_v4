#!/usr/bin/env bash
set -euo pipefail
trap 'echo " ERROR en línea ${LINENO}" >&2' ERR

INSTANCE="$1"
IP_PRIV="$2"
IP_FLOAT="$3"
USER="$4"

IP="${IP_FLOAT:-$IP_PRIV}"

echo " Desinstalando Snort en $INSTANCE"
echo " IP destino: $IP"
echo " Usuario SSH: $USER"
echo "---------------------------------------------------------------"

# =====================================================
#  DETECTAR CLAVE SSH SOLO EN $HOME/.ssh
# =====================================================
SSH_KEY=""

for KEYFILE in "$HOME/.ssh/"*; do
    if [[ -f "$KEYFILE" ]] && grep -q "PRIVATE KEY" "$KEYFILE" 2>/dev/null; then
        SSH_KEY="$KEYFILE"
        break
    fi
done

if [[ -z "$SSH_KEY" ]]; then
    echo " ERROR: No se encontró ninguna clave privada válida en $HOME/.ssh/"
    exit 1
fi

echo " Clave detectada: $SSH_KEY"
chmod 600 "$SSH_KEY"

# =====================================================
#  Ejecutar desinstalación vía SSH
# =====================================================
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" <<EOF
sudo systemctl stop snort || true
sudo systemctl disable snort || true

sudo apt remove -y snort snort3 || true

sudo rm -rf /etc/snort* || true
sudo rm -rf /usr/local/snort* || true
sudo rm -rf /opt/snort* || true
EOF

echo "---------------------------------------------------------------"
echo " Snort desinstalado correctamente de $INSTANCE"
