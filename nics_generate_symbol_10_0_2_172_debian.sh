#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Generate Volatility 3 Linux symbol for Debian victim node
#
# Target node:
#   user: debian
#   ip:   10.0.2.172
#
# Builder node:
#   user: ubuntu
#   ip:   10.0.2.136
#
# Output on host:
#   /home/younes/nics_volatility_symbols/linux/
#
# Important:
# - The target victim is Debian, not Ubuntu.
# - This script does NOT use Ubuntu ddebs.
# - This script does NOT add Debian repositories to the monitor.
# - This script does NOT run apt-get update.
# - This script does NOT touch Wazuh.
# - This script does NOT install debug packages on the victim.
# - Heavy extraction/build work is done on the monitor node.
# ============================================================

SSH_KEY="/home/younes/.ssh/my_key"

TARGET_USER="debian"
TARGET_IP="10.0.2.172"
TARGET_NAME="victim-debian"
TARGET_REMOTE="${TARGET_USER}@${TARGET_IP}"

BUILDER_USER="ubuntu"
BUILDER_IP="10.0.2.136"
BUILDER_REMOTE="${BUILDER_USER}@${BUILDER_IP}"

LOCAL_SYMBOL_ROOT="/home/younes/nics_volatility_symbols"
LOCAL_SYMBOL_DIR="${LOCAL_SYMBOL_ROOT}/linux"
LOCAL_META_DIR="${LOCAL_SYMBOL_ROOT}/metadata"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-target-${TARGET_IP//./_}-builder-${BUILDER_IP//./_}-debian-$$"

HOST_TMP_DIR="/tmp/nics-vol3-symbol-${RUN_ID}"
BUILDER_WORK="/home/ubuntu/nics-vol3-symbol-${RUN_ID}"
BUILDER_RESULT="/tmp/nics-vol3-symbol-${RUN_ID}.env"

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

  ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" 'bash -s' -- "$BUILDER_WORK" "$BUILDER_RESULT" <<'REMOTE_CLEAN' || true
set +e

BUILDER_WORK="$1"
BUILDER_RESULT="$2"

echo "[BUILDER] Cleanup started."

rm -rf "$BUILDER_WORK" || true
rm -f "$BUILDER_RESULT" || true

# Remove only old temporary repositories created by previous NICS attempts.
# This does not touch Wazuh.
sudo rm -f /etc/apt/sources.list.d/nics-debian-debug-*.list 2>/dev/null || true

echo "[BUILDER] Disk status after cleanup:"
df -h /

echo "[BUILDER] Cleanup completed."
REMOTE_CLEAN
}

trap 'cleanup_builder; cleanup_host_tmp' EXIT

echo "[HOST] Phase 1: reading Debian target kernel information from ${TARGET_REMOTE}..."

TARGET_ENV="$(ssh "${SSH_OPTS[@]}" "$TARGET_REMOTE" 'bash -s' <<'TARGET_INFO'
set -Eeuo pipefail

KERNEL="$(uname -r)"
ARCH="$(dpkg --print-architecture)"
HOSTNAME_VALUE="$(hostname)"

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  CODENAME="${VERSION_CODENAME:-}"
  PRETTY="${PRETTY_NAME:-unknown}"
else
  OS_ID="unknown"
  CODENAME=""
  PRETTY="unknown"
fi

if [ -z "$CODENAME" ] && command -v lsb_release >/dev/null 2>&1; then
  CODENAME="$(lsb_release -sc)"
fi

KERNEL_PACKAGE="linux-image-${KERNEL}"
KERNEL_PACKAGE_VERSION=""

if command -v dpkg-query >/dev/null 2>&1; then
  KERNEL_PACKAGE_VERSION="$(dpkg-query -W -f='${Version}' "$KERNEL_PACKAGE" 2>/dev/null || true)"
fi

printf 'TARGET_KERNEL=%q\n' "$KERNEL"
printf 'TARGET_ARCH=%q\n' "$ARCH"
printf 'TARGET_HOSTNAME_REAL=%q\n' "$HOSTNAME_VALUE"
printf 'TARGET_OS_ID=%q\n' "$OS_ID"
printf 'TARGET_CODENAME=%q\n' "$CODENAME"
printf 'TARGET_PRETTY=%q\n' "$PRETTY"
printf 'TARGET_KERNEL_PACKAGE=%q\n' "$KERNEL_PACKAGE"
printf 'TARGET_KERNEL_PACKAGE_VERSION=%q\n' "$KERNEL_PACKAGE_VERSION"
TARGET_INFO
)"

eval "$TARGET_ENV"

echo "[INFO] Target logical name: ${TARGET_NAME}"
echo "[INFO] Target node: ${TARGET_REMOTE}"
echo "[INFO] Target hostname: ${TARGET_HOSTNAME_REAL}"
echo "[INFO] Target OS: ${TARGET_PRETTY}"
echo "[INFO] Target OS ID: ${TARGET_OS_ID}"
echo "[INFO] Target codename: ${TARGET_CODENAME}"
echo "[INFO] Target kernel: ${TARGET_KERNEL}"
echo "[INFO] Target architecture: ${TARGET_ARCH}"
echo "[INFO] Target kernel package: ${TARGET_KERNEL_PACKAGE}"
echo "[INFO] Target kernel package version: ${TARGET_KERNEL_PACKAGE_VERSION}"

if [ "$TARGET_OS_ID" != "debian" ]; then
  echo "[ERROR] Target is not detected as Debian. Detected OS ID: ${TARGET_OS_ID}"
  echo "[ERROR] This script is Debian-specific."
  exit 1
fi

if [ -z "$TARGET_CODENAME" ]; then
  echo "[ERROR] Debian codename could not be detected."
  exit 1
fi

if [ -z "$TARGET_KERNEL_PACKAGE_VERSION" ]; then
  echo "[ERROR] Could not read installed kernel package version from target."
  echo "[ERROR] Expected installed package: ${TARGET_KERNEL_PACKAGE}"
  exit 1
fi

echo "[HOST] Phase 2: checking builder node ${BUILDER_REMOTE}..."

ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" 'bash -s' <<'BUILDER_CHECK'
set -Eeuo pipefail

echo "[BUILDER] Hostname: $(hostname)"
echo "[BUILDER] Kernel: $(uname -r)"
echo "[BUILDER] OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "[BUILDER] Disk status:"
df -h /

echo "[BUILDER] Checking required commands without modifying repositories..."

MISSING=""

for cmd in wget curl dpkg-deb git go gcc make xz sha256sum stat find; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING="$MISSING $cmd"
  fi
done

if [ -n "$MISSING" ]; then
  echo "[ERROR] Missing required commands on builder:$MISSING"
  echo "[ERROR] This script will not install packages, will not modify APT, and will not touch Wazuh."
  exit 1
fi

sudo -n true

echo "[BUILDER] Removing only old NICS temporary Debian debug repo files, if any."
sudo rm -f /etc/apt/sources.list.d/nics-debian-debug-*.list 2>/dev/null || true
BUILDER_CHECK

echo "[HOST] Phase 3: copying System.map from Debian target if available..."

LOCAL_SYSTEM_MAP="${HOST_TMP_DIR}/System.map-${TARGET_KERNEL}"

scp "${SSH_OPTS[@]}" "${TARGET_REMOTE}:/boot/System.map-${TARGET_KERNEL}" "$LOCAL_SYSTEM_MAP" >/dev/null 2>&1 || true

if [ -f "$LOCAL_SYSTEM_MAP" ]; then
  echo "[INFO] System.map copied from target."
else
  echo "[WARN] System.map not found on target. Continuing with vmlinux only."
fi

echo "[HOST] Phase 4: creating builder work directory..."

ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" "mkdir -p '$BUILDER_WORK/input' '$BUILDER_WORK/output' '$BUILDER_WORK/extract' '$BUILDER_WORK/build' '$BUILDER_WORK/download'"

if [ -f "$LOCAL_SYSTEM_MAP" ]; then
  scp "${SSH_OPTS[@]}" "$LOCAL_SYSTEM_MAP" "${BUILDER_REMOTE}:${BUILDER_WORK}/input/System.map-${TARGET_KERNEL}"
fi

echo "[HOST] Phase 5: generating Debian symbol on builder node ${BUILDER_REMOTE}..."

TARGET_PRETTY_B64="$(printf '%s' "$TARGET_PRETTY" | base64 -w0)"

ssh "${SSH_OPTS[@]}" "$BUILDER_REMOTE" 'bash -s' -- \
  "$BUILDER_WORK" \
  "$BUILDER_RESULT" \
  "$TARGET_KERNEL" \
  "$TARGET_CODENAME" \
  "$TARGET_ARCH" \
  "$TARGET_IP" \
  "$TARGET_NAME" \
  "$TARGET_HOSTNAME_REAL" \
  "$TARGET_PRETTY_B64" \
  "$TARGET_KERNEL_PACKAGE_VERSION" <<'BUILDER_GEN'
set -Eeuo pipefail

BUILDER_WORK="$1"
BUILDER_RESULT="$2"
TARGET_KERNEL="$3"
TARGET_CODENAME="$4"
TARGET_ARCH="$5"
TARGET_IP="$6"
TARGET_NAME="$7"
TARGET_HOSTNAME_REAL="$8"
TARGET_PRETTY_B64="$9"
TARGET_KERNEL_PACKAGE_VERSION="${10}"
TARGET_PRETTY="$(printf '%s' "$TARGET_PRETTY_B64" | base64 -d)"

mkdir -p "$BUILDER_WORK/input" "$BUILDER_WORK/output" "$BUILDER_WORK/extract" "$BUILDER_WORK/build" "$BUILDER_WORK/download"

echo "[BUILDER] Builder hostname: $(hostname)"
echo "[BUILDER] Builder kernel: $(uname -r)"
echo "[BUILDER] Target logical name: ${TARGET_NAME}"
echo "[BUILDER] Target IP: ${TARGET_IP}"
echo "[BUILDER] Target hostname: ${TARGET_HOSTNAME_REAL}"
echo "[BUILDER] Target OS: ${TARGET_PRETTY}"
echo "[BUILDER] Target kernel: ${TARGET_KERNEL}"
echo "[BUILDER] Target codename: ${TARGET_CODENAME}"
echo "[BUILDER] Target package version: ${TARGET_KERNEL_PACKAGE_VERSION}"
echo "[BUILDER] Work directory: ${BUILDER_WORK}"

echo "[BUILDER] Checking disk space on builder..."

AVAILABLE_KB="$(df --output=avail /home | tail -n 1 | tr -d ' ')"
REQUIRED_KB="$((6 * 1024 * 1024))"

if [ "$AVAILABLE_KB" -lt "$REQUIRED_KB" ]; then
  echo "[ERROR] Builder does not have enough free space under /home."
  echo "[ERROR] Required: about 6 GB free."
  df -h /home
  exit 1
fi

df -h /home

echo "[BUILDER] Checking required commands..."

for cmd in wget curl dpkg-deb git go gcc make xz sha256sum stat find; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERROR] Missing required command on builder: $cmd"
    echo "[ERROR] This script will not install packages, will not modify APT, and will not touch Wazuh."
    exit 1
  fi
done

echo "[BUILDER] Ensuring no old NICS temporary Debian repo remains."
sudo rm -f /etc/apt/sources.list.d/nics-debian-debug-*.list 2>/dev/null || true

DBG_PKG="linux-image-${TARGET_KERNEL}-dbg"
DBG_FILE="${DBG_PKG}_${TARGET_KERNEL_PACKAGE_VERSION}_${TARGET_ARCH}.deb"

echo "[BUILDER] Expected Debian debug package:"
echo "[BUILDER]   ${DBG_FILE}"

DOWNLOAD_DIR="${BUILDER_WORK}/download"
DEB_FILE="${DOWNLOAD_DIR}/${DBG_FILE}"

URLS=(
  "https://deb.dsi.ist.utl.pt/debian-security/pool/main/l/linux/${DBG_FILE}"
  "http://deb.dsi.ist.utl.pt/debian-security/pool/main/l/linux/${DBG_FILE}"
  "https://the.earth.li/debian/pool/main/l/linux/${DBG_FILE}"
  "http://the.earth.li/debian/pool/main/l/linux/${DBG_FILE}"
  "https://security.debian.org/debian-security/pool/main/l/linux/${DBG_FILE}"
  "http://security.debian.org/debian-security/pool/main/l/linux/${DBG_FILE}"
  "https://deb.debian.org/debian-security/pool/main/l/linux/${DBG_FILE}"
  "http://deb.debian.org/debian-security/pool/main/l/linux/${DBG_FILE}"
  "https://ftp.debian.org/debian/pool/main/l/linux/${DBG_FILE}"
  "http://ftp.debian.org/debian/pool/main/l/linux/${DBG_FILE}"
  "https://snapshot.debian.org/archive/debian-security/20260208T000000Z/pool/main/l/linux/${DBG_FILE}"
  "https://snapshot.debian.org/archive/debian/20260208T000000Z/pool/main/l/linux/${DBG_FILE}"
)

echo "[BUILDER] Downloading Debian debug package directly."
echo "[BUILDER] No Debian repository is added."
echo "[BUILDER] No apt-get update is executed."
echo "[BUILDER] Wazuh is not touched."

rm -f "$DEB_FILE"

DOWNLOAD_OK="no"
USED_URL=""

for url in "${URLS[@]}"; do
  echo "[BUILDER] Trying: $url"

  if wget --timeout=30 --tries=2 -q --show-progress --progress=bar:force:noscroll -O "$DEB_FILE" "$url"; then
    if [ -s "$DEB_FILE" ]; then
      DOWNLOAD_OK="yes"
      USED_URL="$url"
      break
    fi
  fi

  rm -f "$DEB_FILE"
done

if [ "$DOWNLOAD_OK" != "yes" ]; then
  echo "[ERROR] Could not download Debian debug package directly."
  echo "[ERROR] Tried URLs:"
  for url in "${URLS[@]}"; do
    echo "  - $url"
  done
  echo "[ERROR] The package may require another mirror or a different snapshot timestamp."
  exit 1
fi

echo "[BUILDER] Downloaded package:"
ls -lh "$DEB_FILE"

echo "[BUILDER] Download source:"
echo "$USED_URL"

echo "[BUILDER] Extracting Debian debug package on builder only..."

dpkg-deb -x "$DEB_FILE" "$BUILDER_WORK/extract"

VMLINUX=""

for candidate in \
  "$BUILDER_WORK/extract/usr/lib/debug/boot/vmlinux-${TARGET_KERNEL}" \
  "$BUILDER_WORK/extract/usr/lib/debug/lib/modules/${TARGET_KERNEL}/vmlinux" \
  "$BUILDER_WORK/extract/usr/lib/debug/vmlinux-${TARGET_KERNEL}"
do
  if [ -f "$candidate" ]; then
    VMLINUX="$candidate"
    break
  fi
done

if [ -z "$VMLINUX" ]; then
  echo "[ERROR] vmlinux not found inside extracted Debian debug package."
  echo "[DEBUG] Searching extracted package:"
  find "$BUILDER_WORK/extract" -type f \( -name "vmlinux*" -o -name "vmlinux" \) | sort || true
  exit 1
fi

echo "[BUILDER] Using vmlinux: ${VMLINUX}"

SYSTEM_MAP="${BUILDER_WORK}/input/System.map-${TARGET_KERNEL}"

if [ -f "$SYSTEM_MAP" ]; then
  SYSTEM_MAP_SIZE="$(wc -c < "$SYSTEM_MAP")"

  if [ "$SYSTEM_MAP_SIZE" -lt 1024 ]; then
    echo "[WARN] System.map exists but is too small: ${SYSTEM_MAP_SIZE} bytes."
    echo "[WARN] Ignoring System.map and using vmlinux only."
    SYSTEM_MAP=""
  else
    echo "[BUILDER] Using System.map copied from target: ${SYSTEM_MAP}"
  fi
else
  echo "[BUILDER] System.map not available. Continuing with vmlinux only."
  SYSTEM_MAP=""
fi

echo "[BUILDER] Building dwarf2json on builder..."

BUILD_DIR="${BUILDER_WORK}/build/dwarf2json"
rm -rf "$BUILD_DIR"

git clone --depth 1 https://github.com/volatilityfoundation/dwarf2json.git "$BUILD_DIR"

cd "$BUILD_DIR"
go build -trimpath

SAFE_CODENAME="$(echo "$TARGET_CODENAME" | tr -c 'A-Za-z0-9._-' '_')"
OUT_JSON="${BUILDER_WORK}/output/debian-${SAFE_CODENAME}-${TARGET_KERNEL}.json"
OUT_XZ="${OUT_JSON}.xz"

echo "[BUILDER] Generating Volatility 3 Linux ISF symbol..."

if [ -n "$SYSTEM_MAP" ] && [ -f "$SYSTEM_MAP" ]; then
  ./dwarf2json linux --elf "$VMLINUX" --system-map "$SYSTEM_MAP" > "$OUT_JSON"
else
  ./dwarf2json linux --elf "$VMLINUX" > "$OUT_JSON"
fi

xz -f -9 "$OUT_JSON"

SHA256="$(sha256sum "$OUT_XZ" | awk '{print $1}')"
SIZE_BYTES="$(stat -c '%s' "$OUT_XZ")"

{
  printf 'TARGET_NAME=%q\n' "$TARGET_NAME"
  printf 'TARGET_IP=%q\n' "$TARGET_IP"
  printf 'TARGET_HOSTNAME_REAL=%q\n' "$TARGET_HOSTNAME_REAL"
  printf 'TARGET_KERNEL=%q\n' "$TARGET_KERNEL"
  printf 'TARGET_CODENAME=%q\n' "$TARGET_CODENAME"
  printf 'TARGET_ARCH=%q\n' "$TARGET_ARCH"
  printf 'TARGET_PRETTY=%q\n' "$TARGET_PRETTY"
  printf 'TARGET_KERNEL_PACKAGE_VERSION=%q\n' "$TARGET_KERNEL_PACKAGE_VERSION"
  printf 'BUILDER_HOSTNAME=%q\n' "$(hostname)"
  printf 'BUILDER_IP=%q\n' "10.0.2.136"
  printf 'DEBUG_PACKAGE=%q\n' "$DBG_PKG"
  printf 'DEBUG_PACKAGE_URL=%q\n' "$USED_URL"
  printf 'VMLINUX=%q\n' "$VMLINUX"
  printf 'SYMBOL_PATH=%q\n' "$OUT_XZ"
  printf 'SYMBOL_SHA256=%q\n' "$SHA256"
  printf 'SYMBOL_SIZE_BYTES=%q\n' "$SIZE_BYTES"
  printf 'GENERATION_MODE=%q\n' "builder_monitor_node_debian_direct_download_no_repo_no_wazuh"
} > "$BUILDER_RESULT"

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
target_name=${TARGET_NAME}
target_node=${TARGET_REMOTE}
target_ip=${TARGET_IP}
target_hostname=${TARGET_HOSTNAME_REAL}
target_os=${TARGET_PRETTY}
target_kernel=${TARGET_KERNEL}
target_debian_codename=${TARGET_CODENAME}
target_architecture=${TARGET_ARCH}
target_kernel_package_version=${TARGET_KERNEL_PACKAGE_VERSION}
builder_node=${BUILDER_REMOTE}
builder_ip=${BUILDER_IP}
builder_hostname=${BUILDER_HOSTNAME}
debug_package=${DEBUG_PACKAGE}
debug_package_url=${DEBUG_PACKAGE_URL}
remote_vmlinux=${VMLINUX}
local_symbol=${LOCAL_SYMBOL_PATH}
sha256=${SYMBOL_SHA256}
size_bytes=${SYMBOL_SIZE_BYTES}
generation_mode=${GENERATION_MODE}
generated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
target_node_debug_package_installed=no
builder_debian_repository_added=no
apt_get_update_executed=no
wazuh_touched=no
builder_large_temp_files_cleaned=yes
EOF

echo "[HOST] Phase 7: cleaning builder node..."
cleanup_builder
trap - EXIT
cleanup_host_tmp

echo "[OK] Debian symbol copied to host:"
ls -lh "$LOCAL_SYMBOL_PATH"

echo "[OK] Metadata:"
cat "${LOCAL_META_DIR}/$(basename "$LOCAL_SYMBOL_PATH").metadata.txt"

echo "[NEXT] Test with:"
echo "DUMP=\"/ruta/al/dump_del_victim_10.0.2.172.lime\""
echo "SYMBOLS=\"${LOCAL_SYMBOL_ROOT}\""
echo "vol -s \"\$SYMBOLS\" -f \"\$DUMP\" banners.Banners"
echo "vol -s \"\$SYMBOLS\" -f \"\$DUMP\" linux.pslist.PsList"
