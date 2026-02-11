#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   generate_vol3_symbols_ssh.sh <CASE_DIR> <VM_ID> <VM_IP> <SSH_USER> <SSH_KEY>
#
# Salida:
#   imprime al final el directorio ABS:  .../symbols/linux
#
# Notas:
# - Detecta KVER con uname -r en la víctima.
# - Detecta repo_type (ubuntu/debian) leyendo /etc/os-release en la víctima.
# - Detecta arquitectura remota (uname -m) para filtrar el paquete correcto (amd64/arm64).
# - Si falla el SSH_USER recibido, prueba usuarios típicos: ubuntu, debian, admin, root.
# - Descarga dwarf2json (binario oficial del host).
# - Descarga el paquete linux-image-<KVER>-dbgsym (Ubuntu) o linux-image-<KVER>-dbg (Debian) del pool
#   y extrae vmlinux-<KVER> para generar <KVER>.json.
# - Cache root configurable por env: VOL3_SYMBOLS_CACHE_ROOT (por defecto: $HOME/vol3_symbols_cache)

if [[ $# -lt 5 ]]; then
  echo "Uso: $0 <CASE_DIR> <VM_ID> <VM_IP> <SSH_USER> <SSH_KEY>"
  exit 1
fi

CASE_DIR="$1"
VM_ID="$2"
VM_IP="$3"
SSH_USER="$4"
SSH_KEY="$5"

[[ -f "$SSH_KEY" ]] || { echo "No existe clave: $SSH_KEY"; exit 1; }
chmod 600 "$SSH_KEY" || true

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Falta comando: $1"; exit 1; }; }
need_cmd ssh
need_cmd curl
need_cmd ar
need_cmd tar
need_cmd wget

SSH_OPTS=(
  -i "$SSH_KEY"
  -o StrictHostKeyChecking=no
  -o BatchMode=yes
  -o ConnectTimeout=8
  -o ConnectionAttempts=1
)

try_ssh() {
  local user="$1"
  local cmd="$2"
  ssh "${SSH_OPTS[@]}" "$user@$VM_IP" "$cmd" 2>/dev/null || true
}

# Cache global (host) - NO hardcodea /home/<user>
CACHE_ROOT="${VOL3_SYMBOLS_CACHE_ROOT:-$HOME/vol3_symbols_cache}"
SYMBOLS_DIR="$CACHE_ROOT/symbols/linux"
mkdir -p "$SYMBOLS_DIR"

# ------------------------------------------------------------
# 1) Descubrir usuario válido + KVER + ARCH remota
# ------------------------------------------------------------
echo "[*] Detectando KVER (uname -r) y ARCH (uname -m) en $VM_IP ..."

CAND_USERS=()
if [[ -n "${SSH_USER:-}" ]]; then
  CAND_USERS+=("$SSH_USER")
fi
CAND_USERS+=("ubuntu" "debian" "admin" "root")

KVER=""
ARCH_RAW=""
GOOD_USER=""

for u in "${CAND_USERS[@]}"; do
  k="$(try_ssh "$u" "uname -r" | tr -d '\r')"
  if [[ -n "$k" ]]; then
    KVER="$k"
    ARCH_RAW="$(try_ssh "$u" "uname -m" | tr -d '\r')"
    GOOD_USER="$u"
    break
  fi
done

if [[ -z "$KVER" || -z "$GOOD_USER" ]]; then
  echo "ERROR: No se pudo conectar por SSH con usuarios: ${CAND_USERS[*]}"
  echo "       Verifica: keypair correcto en la VM, SG permite 22, floating IP, y usuario."
  exit 1
fi

SSH_USER="$GOOD_USER"
echo "[+] ssh_user_used=$SSH_USER"
echo "[+] KVER=$KVER"
echo "[+] arch_raw=$ARCH_RAW"

# Normalizar arch a nombres de paquete .deb
ARCH_DEB=""
case "$ARCH_RAW" in
  x86_64|amd64)  ARCH_DEB="amd64" ;;
  aarch64|arm64) ARCH_DEB="arm64" ;;
  *)
    echo "ERROR: arquitectura remota no soportada: $ARCH_RAW (esperado x86_64/amd64 o aarch64/arm64)"
    exit 1
    ;;
esac
echo "[+] arch_deb=$ARCH_DEB"

# ------------------------------------------------------------
# 2) Detectar OS remoto
# ------------------------------------------------------------
echo "[*] Detectando OS remoto (/etc/os-release) ..."
REMOTE_OS="$(try_ssh "$SSH_USER" 'source /etc/os-release 2>/dev/null; echo "${ID:-unknown}"' | tr -d "\r")"
REMOTE_OS_LIKE="$(try_ssh "$SSH_USER" 'source /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}"' | tr -d "\r")"

REPO_TYPE="unknown"
if echo "$REMOTE_OS" | grep -qi "ubuntu"; then
  REPO_TYPE="ubuntu"
elif echo "$REMOTE_OS" | grep -Eqi "debian|kali"; then
  REPO_TYPE="debian"
elif echo "$REMOTE_OS_LIKE" | grep -qi "ubuntu"; then
  REPO_TYPE="ubuntu"
elif echo "$REMOTE_OS_LIKE" | grep -qi "debian"; then
  REPO_TYPE="debian"
fi

if [[ "$REPO_TYPE" == "unknown" ]]; then
  echo "ERROR: OS remoto no soportado: ID=$REMOTE_OS ID_LIKE=$REMOTE_OS_LIKE"
  exit 1
fi
echo "[+] repo_type=$REPO_TYPE"

# ------------------------------------------------------------
# 3) Cache de símbolos
# ------------------------------------------------------------
OUT_JSON="$SYMBOLS_DIR/${KVER}.json"
if [[ -f "$OUT_JSON" ]]; then
  echo "[+] Ya existe: $OUT_JSON"
  echo "$SYMBOLS_DIR"
  exit 0
fi

# ------------------------------------------------------------
# 4) Instalar dwarf2json (host) si no existe
# ------------------------------------------------------------
if ! command -v dwarf2json >/dev/null 2>&1; then
  echo "[*] Instalando dwarf2json en /usr/local/bin ..."
  # Nota: este binario es para el host (asumido amd64). Si tu host es arm64, cámbialo.
  sudo wget -N \
    https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-amd64 \
    -O /usr/local/bin/dwarf2json
  sudo chmod +x /usr/local/bin/dwarf2json
fi

TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

cd "$TMPDIR"

# ------------------------------------------------------------
# 5) Resolver URL del paquete debug desde pool (filtrando arquitectura)
# ------------------------------------------------------------
if [[ "$REPO_TYPE" == "debian" ]]; then
  # Debian: los símbolos suelen estar en debian-debug como -dbgsym.
  # Algunos casos antiguos usan -dbg. Y el kernel puede estar en debian (no en security).
  BASES=(
    "https://deb.debian.org/debian-debug/pool/main/l/linux/"
    "https://deb.debian.org/debian/pool/main/l/linux/"
    "https://security.debian.org/debian-security/pool/updates/main/l/linux/"
  )

  URL=""
  for BASE in "${BASES[@]}"; do
    echo "[*] Buscando paquete debug en: $BASE (arch=$ARCH_DEB)"

    # 1) intentar dbgsym
    PKG="$(curl -fsSL "$BASE" | grep -oP "linux-image-${KVER}-dbgsym_[^\" ]+_${ARCH_DEB}\\.deb" | head -1 || true)"
    if [[ -n "$PKG" ]]; then
      URL="${BASE}${PKG}"
      break
    fi

    # 2) fallback dbg
    PKG="$(curl -fsSL "$BASE" | grep -oP "linux-image-${KVER}-dbg_[^\" ]+_${ARCH_DEB}\\.deb" | head -1 || true)"
    if [[ -n "$PKG" ]]; then
      URL="${BASE}${PKG}"
      break
    fi
  done

  [[ -n "$URL" ]] || {
    echo "ERROR: No encontré paquete debug para linux-image-${KVER} (arch=${ARCH_DEB}) en debian-debug/debian/security pools"
    exit 1
  }

else
  BASE="https://ddebs.ubuntu.com/pool/main/l/linux/"
  echo "[*] Buscando paquete dbgsym en: $BASE (arch=$ARCH_DEB)"
  PKG="$(curl -fsSL "$BASE" | grep -oP "linux-image-${KVER}-dbgsym_[^\" ]+_${ARCH_DEB}\\.deb" | head -1 || true)"
  [[ -n "$PKG" ]] || { echo "ERROR: No encontré linux-image-${KVER}-dbgsym_..._${ARCH_DEB}.deb en el pool"; exit 1; }
  URL="${BASE}${PKG}"
fi


echo "[*] Descargando: $URL"
wget -N "$URL"

DEB_FILE="$(basename "$URL")"
echo "[*] Extrayendo .deb: $DEB_FILE"
ar x "$DEB_FILE"

DATA_TAR=""
for f in data.tar.xz data.tar.zst data.tar.gz data.tar.bz2 data.tar; do
  if [[ -f "$f" ]]; then
    DATA_TAR="$f"
    break
  fi
done
[[ -n "$DATA_TAR" ]] || { echo "ERROR: no encuentro data.tar.* dentro del .deb"; exit 1; }

VMLINUX_IN_PKG="./usr/lib/debug/boot/vmlinux-${KVER}"
echo "[*] Extrayendo vmlinux: $VMLINUX_IN_PKG desde $DATA_TAR"
tar -xf "$DATA_TAR" "$VMLINUX_IN_PKG"

VMLINUX_LOCAL="$TMPDIR/$VMLINUX_IN_PKG"
[[ -f "$VMLINUX_LOCAL" ]] || { echo "ERROR: vmlinux no extraído: $VMLINUX_LOCAL"; exit 1; }

echo "[*] Generando symbols JSON: $OUT_JSON"
dwarf2json linux --elf "$VMLINUX_LOCAL" > "$OUT_JSON"

echo "[+] OK: $OUT_JSON"
echo "$SYMBOLS_DIR"
