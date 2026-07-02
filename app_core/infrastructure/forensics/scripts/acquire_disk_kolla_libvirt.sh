#!/usr/bin/env bash
set -euo pipefail

# Debe ejecutarse como root para evitar prompts de sudo en mitad del proceso.
# Si NICS_DFIR_SUDO_NONINTERACTIVE=1, la auto-elevación se hace con sudo -n
# para que los orquestadores en background fallen rápido en vez de quedarse
# esperando una contraseña en el terminal.
# Probe sentinel: when called as root with __nics_probe__ the script exits 0
# immediately. This gives a clean exit-code=0 signal that sudo worked and the
# script body was reached, without running any actual acquisition logic.
# Must come BEFORE the privilege-escalation block so it also catches the case
# where the non-root probe re-exec reaches this point as root.
if [[ "${1:-}" == "__nics_probe__" ]]; then
  exit 0
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if [[ "${NICS_DFIR_SUDO_NONINTERACTIVE:-0}" == "1" ]]; then
    # Use /bin/bash explicitly so that the probe and the re-exec both match
    # the Cmnd_Alias rule in /etc/sudoers.d/nicscyberlab-acquire-disk:
    #   Cmnd_Alias NICS_DFIR_DISK_HELPER = /bin/bash <this_script> *
    # "sudo -n true" or "sudo -n <script>" would fail even with that rule.
    # The probe exits 0 on success (see top of script) so exit-code is reliable.
    sudo -n /bin/bash "$0" __nics_probe__ >/dev/null 2>&1 || {
      echo "[ERROR] Disk acquisition requires non-interactive sudo/root privileges for background execution."
      echo "[ERROR] Configure NOPASSWD for the disk acquisition helper or run the service as root."
      exit 77
    }
    exec sudo -n /bin/bash "$0" "$@"
  fi
  exec sudo /bin/bash "$0" "$@"
fi

# Uso:
#  acquire_disk_kolla_libvirt.sh <CASE_DIR> <INSTANCE_UUID> [CONTAINER_NAME]
#
# Notas:
# - Requiere estar en el nodo compute donde vive la instancia.
# - Requiere docker y acceso al contenedor de nova/libvirt.

if [[ $# -lt 2 ]]; then
  echo "Uso: $0 <CASE_DIR> <INSTANCE_UUID> [CONTAINER_NAME]"
  exit 1
fi

CASE_DIR="$1"
INSTANCE_UUID="$2"
CONTAINER_NAME="${3:-nova_libvirt}"

# Usuario real que invocó sudo (para devolver ownership del RAW)
OWNER_USER="${SUDO_USER:-root}"
OWNER_GROUP="$(id -gn "$OWNER_USER" 2>/dev/null || echo root)"

OUT_DIR="${CASE_DIR}/disk"
META_DIR="${CASE_DIR}/metadata"
UTC_TS="$(date -u +%Y%m%d_%H%M%SZ)"

ORIG_QCOW="${OUT_DIR}/${INSTANCE_UUID}_${UTC_TS}.disk.qcow2"
BACKING_LOCAL="${OUT_DIR}/${INSTANCE_UUID}_${UTC_TS}.backing_base.raw"
FINAL_RAW="${OUT_DIR}/${INSTANCE_UUID}_${UTC_TS}.disk.final.raw"

META="${META_DIR}/${INSTANCE_UUID}_${UTC_TS}.disk.metadata.json"
SHA_FILE="${META_DIR}/${INSTANCE_UUID}_${UTC_TS}.disk.sha256"

mkdir -p "$OUT_DIR" "$META_DIR"

cleanup_partial_on_failure() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    rm -f "$ORIG_QCOW" "$BACKING_LOCAL" "$FINAL_RAW" 2>/dev/null || true
  fi
  exit "$rc"
}
trap cleanup_partial_on_failure EXIT

human_bytes() {
  local bytes="${1:-0}"
  local units=("B" "KB" "MB" "GB" "TB")
  local idx=0
  local value="$bytes"
  while [[ "$value" -ge 1024 && "$idx" -lt 4 ]]; do
    value=$(( value / 1024 ))
    idx=$(( idx + 1 ))
  done
  echo "${value}${units[$idx]}"
}

echo "[1/6] docker cp qcow2 (overlay) desde nova/libvirt..."
docker cp \
  "$CONTAINER_NAME:/var/lib/nova/instances/$INSTANCE_UUID/disk" \
  "$ORIG_QCOW"

echo "[2/6] Detectando backing file..."
BACKING_FILE_INFO="$(qemu-img info "$ORIG_QCOW" | awk -F': ' '/^backing file:/{print $2}' | xargs || true)"

if [[ -z "$BACKING_FILE_INFO" ]]; then
  echo "[ERROR] No se detectó backing file. ¿La VM usa Ceph/rbd o ruta distinta?"
  echo "qemu-img info:"
  qemu-img info "$ORIG_QCOW" || true
  exit 1
fi

BACKING_FILE_PATH="${BACKING_FILE_INFO%% (actual path:*}"
BACKING_FILE_PATH="${BACKING_FILE_PATH%% (actual path =*}"
BACKING_FILE_PATH="$(echo "$BACKING_FILE_PATH" | xargs)"
VIRTUAL_SIZE_BYTES="$(qemu-img info --output=json "$ORIG_QCOW" | python3 -c 'import json,sys; print(int(json.load(sys.stdin).get("virtual-size") or 0))' 2>/dev/null || echo 0)"
BACKING_SIZE_BYTES="$(docker exec "$CONTAINER_NAME" stat -c %s "$BACKING_FILE_PATH" 2>/dev/null || echo 0)"
FREE_BYTES="$(df -PB1 "$OUT_DIR" | awk 'NR==2 {print $4}')"
SAFETY_MARGIN_BYTES=$((2 * 1024 * 1024 * 1024))
REQUIRED_FREE_BYTES=$((BACKING_SIZE_BYTES + VIRTUAL_SIZE_BYTES + SAFETY_MARGIN_BYTES))

if [[ "$FREE_BYTES" -lt "$REQUIRED_FREE_BYTES" ]]; then
  echo "[ERROR] Insufficient free space for transient disk conversion."
  echo "[ERROR] free_bytes=${FREE_BYTES} ($(human_bytes "$FREE_BYTES"))"
  echo "[ERROR] required_additional_bytes=${REQUIRED_FREE_BYTES} ($(human_bytes "$REQUIRED_FREE_BYTES"))"
  echo "[ERROR] overlay_local_bytes=$(stat -c %s "$ORIG_QCOW" 2>/dev/null || echo 0)"
  echo "[ERROR] backing_source_bytes=${BACKING_SIZE_BYTES}"
  echo "[ERROR] final_raw_estimated_bytes=${VIRTUAL_SIZE_BYTES}"
  echo "[ERROR] The helper currently needs space for backing_raw + final_raw while the overlay qcow2 is already local."
  exit 28
fi

echo "[3/6] docker cp backing file..."
docker cp \
  "$CONTAINER_NAME:$BACKING_FILE_PATH" \
  "$BACKING_LOCAL"

echo "[4/6] Rebase + convert a RAW (independiente)..."
pushd "$OUT_DIR" >/dev/null

qemu-img rebase -u -f qcow2 -b "$(basename "$BACKING_LOCAL")" -F raw "$(basename "$ORIG_QCOW")"
qemu-img convert -f qcow2 -O raw "$(basename "$ORIG_QCOW")" "$(basename "$FINAL_RAW")"

popd >/dev/null

echo "[5/6] Ajustando permisos..."
chown "$OWNER_USER:$OWNER_GROUP" "$FINAL_RAW"

echo "[6/6] Hash + metadata..."
SHA="$(sha256sum "$FINAL_RAW" | awk '{print $1}')"
echo "$SHA" > "$SHA_FILE"

cat > "$META" <<EOF
{
  "instance_uuid": "$INSTANCE_UUID",
  "container": "$CONTAINER_NAME",
  "qcow2_overlay": "$(basename "$ORIG_QCOW")",
  "backing_file_in_container": "$(echo "$BACKING_FILE_INFO" | sed 's/"/\\"/g')",
  "backing_local_raw": "$(basename "$BACKING_LOCAL")",
  "final_raw": "$(basename "$FINAL_RAW")",
  "sha256": "$SHA",
  "intermediate_overlay_deleted": true,
  "intermediate_backing_deleted": true,
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

rm -f "$ORIG_QCOW" "$BACKING_LOCAL"
trap - EXIT

echo "$FINAL_RAW"
