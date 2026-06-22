#!/usr/bin/env bash
set -Eeuo pipefail

SSH_KEY="/home/younes/.ssh/my_key"
SSH_USER="ubuntu"

TARGET_IP="10.0.2.9"
TARGET_REMOTE="${SSH_USER}@${TARGET_IP}"

BUILDER_IP="10.0.2.136"
BUILDER_REMOTE="${SSH_USER}@${BUILDER_IP}"

LOCAL_SYMBOL_ROOT="/home/younes/nics_volatility_symbols"
LOCAL_SYMBOL_DIR="${LOCAL_SYMBOL_ROOT}/linux"
LOCAL_META_DIR="${LOCAL_SYMBOL_ROOT}/metadata"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-target-${TARGET_IP//./_}-builder-${BUILDER_IP//./_}-$$"

HOST_TMP_DIR="/tmp/nics-vol3-symbol-${RUN_ID}"
BUILDER_WORK="/home/ubuntu/nics-vol3-symbol-${RUN_ID}"
BUILDER_RESULT="/tmp/nics-vol3-symbol-${RUN_ID}.env"
BUILDER_TEMP_REPO="/etc/apt/sources.list.d/nics-ddebs-${RUN_ID}.sources"

SSH_OPTS=(
  -i "$SSH_KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=4
)

mkdir -p "$LOCAL_SYMBOL_DIR" "$LOCAL_META_DIR" "$HOST_TMP_DIR"

cleanup_host_tmp() {
  rm -rf "$HOST_TMP_DIR" || true
}

cleanup_builder() {
  echo "[HOST] Cleaning builder node ${BUILDER_REMOTE}..."

  ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" 'bash -s' -- "$BUILDER_WORK" "$BUILDER_RESULT" "$BUILDER_TEMP_REPO" <<'REMOTE_CLEAN' || true
set +e

BUILDER_WORK="$1"
BUILDER_RESULT="$2"
BUILDER_TEMP_REPO="$3"

echo "[BUILDER] Cleanup started."

sudo rm -f "$BUILDER_TEMP_REPO" || true
sudo rm -f /etc/apt/sources.list.d/ddebs.list || true
sudo rm -f /etc/apt/sources.list.d/ddebs.sources || true

rm -rf "$BUILDER_WORK" || true
rm -f "$BUILDER_RESULT" || true

sudo apt-get clean || true
sudo rm -rf /var/cache/apt/archives/* || true
sudo rm -rf /var/cache/apt/archives/partial/* || true

echo "[BUILDER] Disk status after cleanup:"
df -h /

echo "[BUILDER] Cleanup completed."
REMOTE_CLEAN
}

trap 'cleanup_builder; cleanup_host_tmp' EXIT

echo "[HOST] Phase 1: reading target kernel information from ${TARGET_REMOTE}..."

TARGET_ENV="$(ssh "${SSH_OPTS[@]}" "$TARGET_REMOTE" 'bash -s' <<'TARGET_INFO'
set -Eeuo pipefail

KERNEL="$(uname -r)"
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
ARCH="$(dpkg --print-architecture)"
HOSTNAME_VALUE="$(hostname)"

printf 'TARGET_KERNEL=%q\n' "$KERNEL"
printf 'TARGET_CODENAME=%q\n' "$CODENAME"
printf 'TARGET_ARCH=%q\n' "$ARCH"
printf 'TARGET_HOSTNAME_REAL=%q\n' "$HOSTNAME_VALUE"
TARGET_INFO
)"

eval "$TARGET_ENV"

echo "[INFO] Target node: ${TARGET_REMOTE}"
echo "[INFO] Target hostname: ${TARGET_HOSTNAME_REAL}"
echo "[INFO] Target kernel: ${TARGET_KERNEL}"
echo "[INFO] Target Ubuntu codename: ${TARGET_CODENAME}"
echo "[INFO] Target architecture: ${TARGET_ARCH}"

echo "[HOST] Phase 2: checking builder node ${BUILDER_REMOTE}..."

ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" 'bash -s' <<'BUILDER_CHECK'
set -Eeuo pipefail

echo "[BUILDER] Hostname: $(hostname)"
echo "[BUILDER] Kernel: $(uname -r)"
echo "[BUILDER] OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "[BUILDER] Disk status:"
df -h /

sudo -n true
BUILDER_CHECK

echo "[HOST] Phase 3: copying System.map from target if available..."

LOCAL_SYSTEM_MAP="${HOST_TMP_DIR}/System.map-${TARGET_KERNEL}"

scp "${SSH_OPTS[@]}" "${TARGET_REMOTE}:/boot/System.map-${TARGET_KERNEL}" "$LOCAL_SYSTEM_MAP" >/dev/null 2>&1 || true

if [ -f "$LOCAL_SYSTEM_MAP" ]; then
  echo "[INFO] System.map copied from target."
else
  echo "[WARN] System.map not found on target. Continuing with vmlinux only."
fi

echo "[HOST] Phase 4: creating builder work directory..."

ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" "mkdir -p '$BUILDER_WORK/input' '$BUILDER_WORK/output' '$BUILDER_WORK/extract' '$BUILDER_WORK/build'"

if [ -f "$LOCAL_SYSTEM_MAP" ]; then
  scp "${SSH_OPTS[@]}" "$LOCAL_SYSTEM_MAP" "${BUILDER_REMOTE}:${BUILDER_WORK}/input/System.map-${TARGET_KERNEL}"
fi

echo "[HOST] Phase 5: generating symbol on builder node ${BUILDER_REMOTE}..."

ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" 'bash -s' -- \
  "$BUILDER_WORK" \
  "$BUILDER_RESULT" \
  "$BUILDER_TEMP_REPO" \
  "$TARGET_KERNEL" \
  "$TARGET_CODENAME" \
  "$TARGET_ARCH" \
  "$TARGET_IP" \
  "$TARGET_HOSTNAME_REAL" <<'BUILDER_GEN'
set -Eeuo pipefail

BUILDER_WORK="$1"
BUILDER_RESULT="$2"
BUILDER_TEMP_REPO="$3"
TARGET_KERNEL="$4"
TARGET_CODENAME="$5"
TARGET_ARCH="$6"
TARGET_IP="$7"
TARGET_HOSTNAME_REAL="$8"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

mkdir -p "$BUILDER_WORK/input" "$BUILDER_WORK/output" "$BUILDER_WORK/extract" "$BUILDER_WORK/build"

echo "[BUILDER] Builder hostname: $(hostname)"
echo "[BUILDER] Builder kernel: $(uname -r)"
echo "[BUILDER] Target IP: ${TARGET_IP}"
echo "[BUILDER] Target hostname: ${TARGET_HOSTNAME_REAL}"
echo "[BUILDER] Target kernel: ${TARGET_KERNEL}"
echo "[BUILDER] Target codename: ${TARGET_CODENAME}"
echo "[BUILDER] Work directory: ${BUILDER_WORK}"

echo "[BUILDER] Checking disk space on builder..."

AVAILABLE_KB="$(df --output=avail /home | tail -n 1 | tr -d ' ')"
REQUIRED_KB="$((10 * 1024 * 1024))"

if [ "$AVAILABLE_KB" -lt "$REQUIRED_KB" ]; then
  echo "[ERROR] Builder does not have enough free space under /home."
  echo "[ERROR] Required: about 10 GB free."
  df -h /home
  exit 1
fi

df -h /home

echo "[BUILDER] Stopping package auto-updaters temporarily if active..."

sudo systemctl stop unattended-upgrades.service 2>/dev/null || true
sudo systemctl stop apt-daily.service 2>/dev/null || true
sudo systemctl stop apt-daily-upgrade.service 2>/dev/null || true
sudo systemctl stop packagekit.service 2>/dev/null || true

echo "[BUILDER] Repairing package database if needed..."
sudo dpkg --configure -a || true

echo "[BUILDER] Installing build dependencies on builder only..."

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  ubuntu-dbgsym-keyring \
  ca-certificates \
  git \
  golang-go \
  xz-utils \
  dpkg-dev \
  pkg-config \
  gcc \
  libc6-dev \

echo "[BUILDER] Creating temporary ddebs repository for target codename only..."

sudo rm -f /etc/apt/sources.list.d/ddebs.list || true
sudo rm -f /etc/apt/sources.list.d/ddebs.sources || true

sudo tee "$BUILDER_TEMP_REPO" >/dev/null <<EOF
Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: ${TARGET_CODENAME} ${TARGET_CODENAME}-updates ${TARGET_CODENAME}-proposed
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg
EOF

sudo apt-get update

echo "[BUILDER] Selecting matching dbgsym package for target kernel..."

DBGSYM_PKG=""

if apt-cache show "linux-image-unsigned-${TARGET_KERNEL}-dbgsym" >/dev/null 2>&1; then
  DBGSYM_PKG="linux-image-unsigned-${TARGET_KERNEL}-dbgsym"
elif apt-cache show "linux-image-${TARGET_KERNEL}-dbgsym" >/dev/null 2>&1; then
  DBGSYM_PKG="linux-image-${TARGET_KERNEL}-dbgsym"
else
  echo "[ERROR] No matching dbgsym package found for target kernel: ${TARGET_KERNEL}"
  exit 1
fi

echo "[BUILDER] Selected dbgsym package: ${DBGSYM_PKG}"

echo "[BUILDER] Downloading dbgsym package on builder only..."

cd "$BUILDER_WORK"
rm -f ./*.deb ./*.ddeb || true

apt-get download "$DBGSYM_PKG"

DEB_FILE="$(find "$BUILDER_WORK" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.ddeb' \) | head -n 1)"

if [ -z "$DEB_FILE" ] || [ ! -f "$DEB_FILE" ]; then
  echo "[ERROR] dbgsym package was downloaded by apt-get, but no .deb/.ddeb file was found in:"
  echo "$BUILDER_WORK"
  echo "[DEBUG] Files currently present:"
  find "$BUILDER_WORK" -maxdepth 2 -type f -printf "%s %p\n" | sort -nr | head -30 || true
  exit 1
fi

echo "[BUILDER] Downloaded package:"
ls -lh "$DEB_FILE"

echo "[BUILDER] Extracting dbgsym package on builder only..."

dpkg-deb -x "$DEB_FILE" "$BUILDER_WORK/extract"

VMLINUX="${BUILDER_WORK}/extract/usr/lib/debug/boot/vmlinux-${TARGET_KERNEL}"

if [ ! -f "$VMLINUX" ]; then
  VMLINUX="${BUILDER_WORK}/extract/usr/lib/debug/lib/modules/${TARGET_KERNEL}/vmlinux"
fi

if [ ! -f "$VMLINUX" ]; then
  echo "[ERROR] vmlinux not found inside extracted dbgsym package."
  find "$BUILDER_WORK/extract" -type f -name "vmlinux*" | sort || true
  exit 1
fi

echo "[BUILDER] Using vmlinux: ${VMLINUX}"

SYSTEM_MAP="${BUILDER_WORK}/input/System.map-${TARGET_KERNEL}"

if [ -f "$SYSTEM_MAP" ]; then
  echo "[BUILDER] Using System.map copied from target: ${SYSTEM_MAP}"
else
  echo "[BUILDER] System.map not available. Continuing with vmlinux only."
fi

echo "[BUILDER] Building dwarf2json on builder..."

BUILD_DIR="${BUILDER_WORK}/build/dwarf2json"
rm -rf "$BUILD_DIR"

git clone --depth 1 https://github.com/volatilityfoundation/dwarf2json.git "$BUILD_DIR"

cd "$BUILD_DIR"
go build -trimpath

OUT_JSON="${BUILDER_WORK}/output/ubuntu-${TARGET_CODENAME}-${TARGET_KERNEL}.json"
OUT_XZ="${OUT_JSON}.xz"

echo "[BUILDER] Generating Volatility 3 Linux ISF symbol..."

if [ -f "$SYSTEM_MAP" ]; then
  ./dwarf2json linux --elf "$VMLINUX" --system-map "$SYSTEM_MAP" > "$OUT_JSON"
else
  ./dwarf2json linux --elf "$VMLINUX" > "$OUT_JSON"
fi

xz -f -9 "$OUT_JSON"

SHA256="$(sha256sum "$OUT_XZ" | awk '{print $1}')"
SIZE_BYTES="$(stat -c '%s' "$OUT_XZ")"

cat > "$BUILDER_RESULT" <<EOF
TARGET_IP=${TARGET_IP}
TARGET_HOSTNAME_REAL=${TARGET_HOSTNAME_REAL}
TARGET_KERNEL=${TARGET_KERNEL}
TARGET_CODENAME=${TARGET_CODENAME}
TARGET_ARCH=${TARGET_ARCH}
BUILDER_HOSTNAME=$(hostname)
BUILDER_IP=10.0.2.136
DBGSYM_PKG=${DBGSYM_PKG}
VMLINUX=${VMLINUX}
SYMBOL_PATH=${OUT_XZ}
SYMBOL_SHA256=${SHA256}
SYMBOL_SIZE_BYTES=${SIZE_BYTES}
GENERATION_MODE=builder_monitor_node
EOF

echo "[BUILDER] Symbol generated:"
ls -lh "$OUT_XZ"

echo "[BUILDER] SHA256:"
sha256sum "$OUT_XZ"
BUILDER_GEN

echo "[HOST] Phase 6: copying generated symbol from builder to host..."

LOCAL_RESULT="${HOST_TMP_DIR}/builder-result.env"

scp "${SSH_OPTS[@]}" "${BUILDER_REMOTE}:${BUILDER_RESULT}" "$LOCAL_RESULT"

# shellcheck disable=SC1090
source "$LOCAL_RESULT"

LOCAL_SYMBOL_PATH="${LOCAL_SYMBOL_DIR}/$(basename "$SYMBOL_PATH")"

scp "${SSH_OPTS[@]}" "${BUILDER_REMOTE}:${SYMBOL_PATH}" "$LOCAL_SYMBOL_PATH"

echo "${SYMBOL_SHA256}  ${LOCAL_SYMBOL_PATH}" | sha256sum -c -

chmod 0644 "$LOCAL_SYMBOL_PATH"

cat > "${LOCAL_META_DIR}/$(basename "$LOCAL_SYMBOL_PATH").metadata.txt" <<EOF
target_node=${TARGET_REMOTE}
target_ip=${TARGET_IP}
target_hostname=${TARGET_HOSTNAME_REAL}
target_kernel=${TARGET_KERNEL}
target_ubuntu_codename=${TARGET_CODENAME}
target_architecture=${TARGET_ARCH}
builder_node=${BUILDER_REMOTE}
builder_ip=${BUILDER_IP}
builder_hostname=${BUILDER_HOSTNAME}
dbgsym_package=${DBGSYM_PKG}
remote_vmlinux=${VMLINUX}
local_symbol=${LOCAL_SYMBOL_PATH}
sha256=${SYMBOL_SHA256}
size_bytes=${SYMBOL_SIZE_BYTES}
generation_mode=${GENERATION_MODE}
generated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
target_node_dbgsym_installed=no
builder_large_temp_files_cleaned=yes
EOF

echo "[HOST] Phase 7: cleaning builder node..."
cleanup_builder
trap - EXIT
cleanup_host_tmp

echo "[OK] Symbol copied to host:"
ls -lh "$LOCAL_SYMBOL_PATH"

echo "[OK] Metadata:"
cat "${LOCAL_META_DIR}/$(basename "$LOCAL_SYMBOL_PATH").metadata.txt"

echo "[NEXT] Test with:"
echo "vol -s ${LOCAL_SYMBOL_ROOT} -f /ruta/al/dump_10.0.2.9.lime linux.pslist.PsList"
