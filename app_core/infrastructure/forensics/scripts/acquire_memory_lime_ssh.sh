#!/usr/bin/env bash
set -euo pipefail

# Uso:
#  acquire_memory_lime_ssh.sh <CASE_DIR> <VM_IP> <SSH_USER> <SSH_KEY> [MODE]
#
# MODE:
#  build        = clona + compila LiME en la víctima (como hacías)
#  use_existing = asume que ya existe un lime.ko en /tmp/LiME/src (o ruta definida)

if [[ $# -lt 5 ]]; then
  echo "Uso: $0 <CASE_DIR> <VM_ID> <VM_IP> <SSH_USER> <SSH_KEY> [MODE]"
  exit 1
fi

CASE_DIR="$1"
VM_ID="$2"
VM_TARGET="$3"
SSH_USER="$4"
SSH_KEY="$5"
MODE="${6:-build}"

[[ -f "$SSH_KEY" ]] || { echo "No existe clave: $SSH_KEY"; exit 1; }
chmod 600 "$SSH_KEY" || true

OUT_DIR="${CASE_DIR}/memory"
META_DIR="${CASE_DIR}/metadata"
UTC_TS="$(date -u +%Y%m%d_%H%M%SZ)"

DUMP_NAME="memdump_${VM_TARGET}_${UTC_TS}.lime"
REMOTE_DUMP="/tmp/${DUMP_NAME}"
LOCAL_DUMP="${OUT_DIR}/${DUMP_NAME}"
META="${META_DIR}/${DUMP_NAME}.metadata.json"
SHA_FILE="${META_DIR}/${DUMP_NAME}.sha256"

mkdir -p "$OUT_DIR" "$META_DIR"

echo "[*] Captura LiME en $VM_TARGET (MODE=$MODE)"

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_TARGET" <<EOF
set -e

sudo rmmod lime 2>/dev/null || true
sudo rm -f "$REMOTE_DUMP"

if [[ "$MODE" == "build" ]]; then
  sudo apt-get update -y
  sudo apt-get install -y linux-headers-\$(uname -r) build-essential git

  rm -rf /tmp/LiME
  git clone --depth 1 https://github.com/504ensicsLabs/LiME.git /tmp/LiME
  cd /tmp/LiME/src
  make
fi

cd /tmp/LiME/src
LIME_KO=\$(ls lime-*.ko | head -n1)
if [[ -z "\$LIME_KO" ]]; then
  echo "No se encontró lime-*.ko en /tmp/LiME/src"
  exit 1
fi

echo "[+] insmod \$LIME_KO path=$REMOTE_DUMP format=lime"
sudo insmod "\$LIME_KO" "path=$REMOTE_DUMP format=lime"

# Esperar a estabilización de tamaño
PREV=0
STABLE=0
MAX_STABLE=3
INTERVAL=5

while true; do
  SIZE=\$(stat -c%s "$REMOTE_DUMP" 2>/dev/null || echo 0)
  echo "[*] size=\$SIZE"
  if [[ "\$SIZE" -eq "\$PREV" && "\$SIZE" -gt 0 ]]; then
    STABLE=\$((STABLE+1))
  else
    STABLE=0
  fi
  [[ "\$STABLE" -ge "\$MAX_STABLE" ]] && break
  PREV="\$SIZE"
  sleep "\$INTERVAL"
done

sudo rmmod lime || true
sudo chmod 644 "$REMOTE_DUMP"
EOF

echo "[*] Descargando dump..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_TARGET:$REMOTE_DUMP" "$LOCAL_DUMP"

SHA="$(sha256sum "$LOCAL_DUMP" | awk '{print $1}')"
echo "$SHA" > "$SHA_FILE"

cat > "$META" <<EOF
{
  "vm_ip": "$VM_TARGET",
  "ssh_user": "$SSH_USER",
  "dump_file": "$(basename "$LOCAL_DUMP")",
  "sha256": "$SHA",
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "$MODE"
}
EOF

echo "$LOCAL_DUMP"
