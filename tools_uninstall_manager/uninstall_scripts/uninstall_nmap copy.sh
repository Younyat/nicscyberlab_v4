#!/usr/bin/env bash
set -euo pipefail

INSTANCE="$1"
IP_PRIV="$2"
IP_FLOAT="$3"
USER="$4"

IP="${IP_FLOAT:-$IP_PRIV}"
echo " Desinstalando NMAP en $INSTANCE ($IP)"

SSH_KEY=""
for K in "$HOME/.ssh/"*; do
    [[ -f "$K" ]] && grep -q "PRIVATE KEY" "$K" && SSH_KEY="$K" && break
done
[[ -z "$SSH_KEY" ]] && echo " ERROR: No key encontrada" && exit 1
chmod 600 "$SSH_KEY"

ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" <<'EOF'
sudo apt remove -y nmap || true
sudo rm -rf /usr/bin/nmap || true
EOF

VALID=$(ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" bash <<'EOF'
which nmap >/dev/null 2>&1 && echo "BIN_PRESENT"
EOF
)

if [[ -z "$VALID" ]]; then
    echo " Nmap eliminado correctamente"
    exit 0
else
    echo " Nmap sigue presente:"
    echo "$VALID"
    exit 3
fi
