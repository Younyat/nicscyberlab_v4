#!/usr/bin/env bash
set -euo pipefail

# Uso:
#  acquire_memory_lime_ssh.sh <CASE_DIR> <VM_ID> <VM_IP> <SSH_USER> <SSH_KEY> [MODE]
#
# MODE:
#  build        = clona + compila LiME en la víctima
#  use_existing = asume que ya existe un lime.ko en /tmp/LiME/src

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

# -----------------------------
# Helpers
# -----------------------------
has_dns() {
  # DNS OK si resolvemos 1 dominio. No uses ping a IP, eso no valida DNS.
  getent ahosts github.com >/dev/null 2>&1 && return 0
  getent ahosts security.ubuntu.com >/dev/null 2>&1 && return 0
  return 1
}

free_mb_root() {
  df -Pm / | awk 'NR==2 {print \$4}'
}

echo "[SISTEMA] remote hostname=\$(hostname) kernel=\$(uname -r)"
echo "[SISTEMA] remote free_mb_root=\$(free_mb_root) MB"

sudo rmmod lime 2>/dev/null || true
sudo rm -f "$REMOTE_DUMP"

# -----------------------------
# MODE=build: requiere DNS + espacio
# -----------------------------
if [[ "$MODE" == "build" ]]; then
  if ! has_dns; then
    echo "[ERROR] DNS no funcional en la VM. build requiere resolver github/ubuntu repos."
    echo "[ERROR] Solución: arregla DNS o usa MODE=use_existing."
    exit 50
  fi

  # Umbral simple para no reventar el sistema (ajusta si quieres).
  FREE_MB=\$(free_mb_root)
  if [[ "\$FREE_MB" -lt 1200 ]]; then
    echo "[ERROR] Poco espacio en / (free=\${FREE_MB}MB). build puede fallar por apt/git."
    echo "[ERROR] Limpia /var/log o usa MODE=use_existing."
    exit 51
  fi

  # apt update/install: si falla, paramos con mensaje claro.
  echo "[SISTEMA] apt-get update..."
  sudo apt-get update -y || { echo "[ERROR] apt-get update falló (DNS/Repos)."; exit 52; }

  echo "[SISTEMA] apt-get install headers/build-essential/git..."
  sudo apt-get install -y linux-headers-\$(uname -r) build-essential git || { echo "[ERROR] apt-get install falló."; exit 53; }

  rm -rf /tmp/LiME
  echo "[SISTEMA] git clone LiME..."
  git clone --depth 1 https://github.com/504ensicsLabs/LiME.git /tmp/LiME || { echo "[ERROR] git clone falló (DNS/Internet)."; exit 54; }

  cd /tmp/LiME/src
  echo "[SISTEMA] make..."
  make || { echo "[ERROR] make falló."; exit 55; }
fi

# -----------------------------
# MODE=use_existing: debe existir LiME ya preparado
# -----------------------------
if [[ "$MODE" == "use_existing" ]]; then
  if [[ ! -d /tmp/LiME/src ]]; then
    echo "[ERROR] MODE=use_existing pero no existe /tmp/LiME/src"
    echo "[ERROR] Prepara LiME previamente o cambia a MODE=build."
    exit 60
  fi
fi

cd /tmp/LiME/src

LIME_KO=\$(ls lime-*.ko 2>/dev/null | head -n1 || true)
if [[ -z "\$LIME_KO" ]]; then
  echo "[ERROR] No se encontró lime-*.ko en /tmp/LiME/src"
  echo "[ERROR] build: debería compilarlo. use_existing: asegúrate de que existe."
  exit 61
fi

echo "[+] insmod \$LIME_KO path=$REMOTE_DUMP format=lime"
sudo insmod "\$LIME_KO" "path=$REMOTE_DUMP format=lime" || { echo "[ERROR] insmod falló."; exit 62; }

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

# ============================================================
# Cleanup remoto (seguro). NO borrar el dump antes del scp.
# ============================================================
sudo apt-get clean || true
sudo rm -rf /var/lib/apt/lists/* || true
sudo rm -rf /var/cache/apt/archives/* || true

if [[ -d /tmp ]]; then
  sudo find /tmp -mindepth 1 \
    ! -path "/tmp/LiME" ! -path "/tmp/LiME/*" \
    ! -path "$REMOTE_DUMP" \
    -exec rm -rf {} + 2>/dev/null || true
fi

df -h / || true
EOF

echo "[*] Descargando dump..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VM_TARGET:$REMOTE_DUMP" "$LOCAL_DUMP"

SHA="$(sha256sum "$LOCAL_DUMP" | awk '{print $1}')"
echo "$SHA" > "$SHA_FILE"

cat > "$META" <<EOF
{
  "vm_id": "$VM_ID",
  "vm_ip": "$VM_TARGET",
  "ssh_user": "$SSH_USER",
  "dump_file": "$(basename "$LOCAL_DUMP")",
  "sha256": "$SHA",
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "$MODE"
}
EOF

echo "$LOCAL_DUMP"