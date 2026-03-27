#!/usr/bin/env bash
set -euo pipefail

# Debe ejecutarse como root para evitar prompts de sudo en mitad del proceso
# Auto-elevación: si no soy root, relanzo el script con sudo -E
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E "$0" "$@"
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

# Usuario real que invocó sudo
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

cleanup() {
  rm -f "$ORIG_QCOW" "$BACKING_LOCAL" 2>/dev/null || true
  chown -R "$OWNER_USER:$OWNER_GROUP" "$OUT_DIR" "$META_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "[INFO] OWNER_USER=$OWNER_USER OWNER_GROUP=$OWNER_GROUP"
echo "[INFO] CASE_DIR=$CASE_DIR"
echo "[INFO] OUT_DIR=$OUT_DIR"
echo "[INFO] META_DIR=$META_DIR"

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

echo "[3/6] docker cp backing file..."
docker cp \
  "$CONTAINER_NAME:$BACKING_FILE_INFO" \
  "$BACKING_LOCAL"

echo "[4/6] Rebase + convert a RAW (independiente)..."
pushd "$OUT_DIR" >/dev/null

qemu-img rebase -u -f qcow2 -b "$(basename "$BACKING_LOCAL")" -F raw "$(basename "$ORIG_QCOW")"
qemu-img convert -f qcow2 -O raw "$(basename "$ORIG_QCOW")" "$(basename "$FINAL_RAW")"

popd >/dev/null

echo "[5/6] Hash + metadata..."
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
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "[6/6] Ajustando permisos finales..."
chown -R "$OWNER_USER:$OWNER_GROUP" "$OUT_DIR" "$META_DIR"
chmod 644 "$FINAL_RAW" "$SHA_FILE" "$META" 2>/dev/null || true

echo "$FINAL_RAW"