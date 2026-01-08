#!/usr/bin/env bash
set -euo pipefail

INSTANCE_UUID="16583180-627d-4c40-bd65-aa9db704d75c"
CONTAINER_NAME="nova_libvirt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="$SCRIPT_DIR/evidencias_forenses"
ORIG_QCOW="$DEST_DIR/temp_disk.qcow2"
FINAL_RAW="$DEST_DIR/victim3_final.raw"

echo "-------------------------------------------------------"
echo "EXTRACCIÓN FORENSE (OPENSTACK + CEPH / KOLLA)"
echo "-------------------------------------------------------"

mkdir -p "$DEST_DIR"

echo "[1/5] Extrayendo disco de la instancia..."
sudo docker cp \
  "$CONTAINER_NAME:/var/lib/nova/instances/$INSTANCE_UUID/disk" \
  "$ORIG_QCOW"

echo "[2/5] Verificando información del disco..."
BACKING_FILE_INFO=$(sudo qemu-img info "$ORIG_QCOW" | grep "^backing file:" | cut -d: -f2- | xargs)
echo "Backing file detectado: $BACKING_FILE_INFO"

echo "[3/5] Extrayendo backing file desde el contenedor..."
BACKING_LOCAL="$DEST_DIR/backing_base.raw"
sudo docker cp \
  "$CONTAINER_NAME:$BACKING_FILE_INFO" \
  "$BACKING_LOCAL" || {
    echo "⚠ No se pudo extraer el backing file, intentando método sin backing..."
    BACKING_LOCAL=""
  }

echo "[4/5] Convirtiendo a imagen independiente..."
if [ -n "$BACKING_LOCAL" ] && [ -f "$BACKING_LOCAL" ]; then
    # Tenemos el backing file, hacemos rebase
    echo "→ Rebase con backing file local..."
    sudo qemu-img rebase \
      -u \
      -b "$BACKING_LOCAL" \
      "$ORIG_QCOW"
    
    # Commitear cambios para unir backing + overlay
    TEMP_MERGED="$DEST_DIR/temp_merged.qcow2"
    sudo qemu-img convert \
      -f qcow2 \
      -O qcow2 \
      "$ORIG_QCOW" \
      "$TEMP_MERGED"
    
    sudo qemu-img convert \
      -f qcow2 \
      -O raw \
      "$TEMP_MERGED" \
      "$FINAL_RAW"
    
    sudo rm -f "$TEMP_MERGED" "$BACKING_LOCAL"
else
    # Intentar extracción directa desde el contenedor
    echo "→ Extrayendo disco directamente desde contenedor en ejecución..."
    sudo docker exec "$CONTAINER_NAME" \
      qemu-img convert \
        -f qcow2 \
        -O raw \
        "/var/lib/nova/instances/$INSTANCE_UUID/disk" \
        "/tmp/disk_forensic.raw"
    
    sudo docker cp \
      "$CONTAINER_NAME:/tmp/disk_forensic.raw" \
      "$FINAL_RAW"
    
    sudo docker exec "$CONTAINER_NAME" rm -f /tmp/disk_forensic.raw
fi

echo "[5/5] Limpieza y verificación..."
sudo rm -f "$ORIG_QCOW"
sudo chown "$USER:$USER" "$FINAL_RAW"

# Verificar la imagen final
echo ""
echo "Información de la imagen forense:"
file "$FINAL_RAW"
ls -lh "$FINAL_RAW"

echo ""
echo "-------------------------------------------------------"
echo "✓ ÉXITO: Imagen forense válida generada en:"
echo "$FINAL_RAW"
echo "-------------------------------------------------------"
echo ""
echo "Para montar la imagen (solo lectura):"
echo "  sudo losetup -fP --show -r \"$FINAL_RAW\""
echo "  sudo mount -o ro /dev/loopXp1 /mnt/forensic"
echo "-------------------------------------------------------"