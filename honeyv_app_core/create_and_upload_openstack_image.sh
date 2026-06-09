#!/usr/bin/env bash
set -euo pipefail

trap 'echo "[ERROR] Failed at line ${LINENO}" >&2' ERR

# ============================================================
# create_and_upload_openstack_image.sh
#
# Qué hace:
#   - carga credenciales desde admin-openrc.sh
#   - valida el fichero de imagen local
#   - convierte a qcow2 si hace falta
#   - sube la imagen a OpenStack
#
# Uso:
#   bash create_and_upload_openstack_image.sh <image_file> <image_name>
#
# Ejemplo:
#   bash create_and_upload_openstack_image.sh /opt/images/windows-server-2019.qcow2 windows-server-2019
#
# Requisitos:
#   - admin-openrc.sh en el directorio actual o ruta conocida
#   - openstack CLI
#   - qemu-img
#
# ============================================================

IMAGE_FILE="${1:-}"
IMAGE_NAME="${2:-}"

OPENRC_FILE="${OPENRC_FILE:-./admin-openrc.sh}"
VISIBILITY="${VISIBILITY:-private}"          # public | private | shared | community
OS_TYPE="${OS_TYPE:-windows}"                # windows | linux
DISK_FORMAT="${DISK_FORMAT:-qcow2}"          # destino final
CONTAINER_FORMAT="${CONTAINER_FORMAT:-bare}"
MIN_DISK_GB="${MIN_DISK_GB:-40}"
MIN_RAM_MB="${MIN_RAM_MB:-4096}"
FORCE_REUPLOAD="${FORCE_REUPLOAD:-no}"       # yes | no

if [[ -z "$IMAGE_FILE" || -z "$IMAGE_NAME" ]]; then
    echo "Usage: $0 <image_file> <image_name>"
    echo
    echo "Example:"
    echo "  bash $0 /opt/images/windows-server-2019.qcow2 windows-server-2019"
    exit 1
fi

if [[ ! -f "$IMAGE_FILE" ]]; then
    echo "[ERROR] Image file not found: $IMAGE_FILE"
    exit 1
fi

if [[ ! -f "$OPENRC_FILE" ]]; then
    echo "[ERROR] OpenRC file not found: $OPENRC_FILE"
    exit 1
fi

command -v openstack >/dev/null 2>&1 || {
    echo "[ERROR] openstack CLI not found"
    exit 1
}

command -v qemu-img >/dev/null 2>&1 || {
    echo "[ERROR] qemu-img not found"
    exit 1
}

echo "[INFO] Loading OpenStack credentials from: $OPENRC_FILE"
# shellcheck disable=SC1090
source "$OPENRC_FILE"

echo "[INFO] Checking OpenStack authentication..."
openstack token issue >/dev/null 2>&1 || {
    echo "[ERROR] OpenStack authentication failed"
    exit 1
}

ABS_IMAGE_FILE="$(realpath "$IMAGE_FILE")"
INPUT_BASENAME="$(basename "$ABS_IMAGE_FILE")"
INPUT_EXT="${INPUT_BASENAME##*.}"
WORK_DIR="$(dirname "$ABS_IMAGE_FILE")"
QCOW2_FILE="$ABS_IMAGE_FILE"

case "${INPUT_EXT,,}" in
    qcow2)
        echo "[INFO] Input image already in qcow2 format"
        ;;
    img|raw|vmdk|vdi|vhd|vhdx)
        QCOW2_FILE="${WORK_DIR}/${IMAGE_NAME}.qcow2"
        echo "[INFO] Converting image to qcow2..."
        echo "[INFO] Source: $ABS_IMAGE_FILE"
        echo "[INFO] Target: $QCOW2_FILE"
        qemu-img convert -O qcow2 "$ABS_IMAGE_FILE" "$QCOW2_FILE"
        ;;
    iso)
        echo "[ERROR] ISO detected: $ABS_IMAGE_FILE"
        echo "[ERROR] This script does not create a bootable OpenStack image from a Windows ISO."
        echo "[ERROR] You need a prepared disk image, for example qcow2."
        exit 1
        ;;
    *)
        echo "[WARN] Unknown extension .$INPUT_EXT"
        echo "[INFO] Trying to convert to qcow2 anyway..."
        QCOW2_FILE="${WORK_DIR}/${IMAGE_NAME}.qcow2"
        qemu-img convert -O qcow2 "$ABS_IMAGE_FILE" "$QCOW2_FILE"
        ;;
esac

if [[ ! -f "$QCOW2_FILE" ]]; then
    echo "[ERROR] qcow2 image not found after conversion: $QCOW2_FILE"
    exit 1
fi

echo "[INFO] Inspecting qcow2 image..."
qemu-img info "$QCOW2_FILE"

if openstack image show "$IMAGE_NAME" >/dev/null 2>&1; then
    if [[ "$FORCE_REUPLOAD" == "yes" ]]; then
        echo "[WARN] Image already exists. Deleting because FORCE_REUPLOAD=yes"
        openstack image delete "$IMAGE_NAME"
    else
        echo "[ERROR] OpenStack image already exists: $IMAGE_NAME"
        echo "[ERROR] Use another image name or export FORCE_REUPLOAD=yes"
        exit 1
    fi
fi

echo "[INFO] Uploading image to OpenStack..."
openstack image create "$IMAGE_NAME" \
    --file "$QCOW2_FILE" \
    --disk-format "$DISK_FORMAT" \
    --container-format "$CONTAINER_FORMAT" \
    --"$VISIBILITY" \
    --min-disk "$MIN_DISK_GB" \
    --min-ram "$MIN_RAM_MB" \
    --property os_type="$OS_TYPE" \
    --property hw_disk_bus=virtio \
    --property hw_vif_model=virtio \
    --property img_format="$DISK_FORMAT"

echo "[INFO] Image uploaded successfully"
echo
openstack image show "$IMAGE_NAME"

echo
echo "[INFO] Done"
echo "[INFO] Image name: $IMAGE_NAME"
echo "[INFO] Source file: $QCOW2_FILE"