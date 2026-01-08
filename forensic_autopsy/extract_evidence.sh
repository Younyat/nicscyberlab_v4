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
    echo "⚠ No se pudo extraer el backing file."
    exit 1
  }

echo "[4/5] Convirtiendo a imagen independiente..."
# Usando los comandos validados por el usuario
cd "$DEST_DIR"

echo "→ Realizando rebase (Backing: RAW)..."
sudo qemu-img rebase -u -f qcow2 -b backing_base.raw -F raw temp_disk.qcow2

echo "→ Fusionando capas y convirtiendo a RAW..."
sudo qemu-img convert -f qcow2 -O raw temp_disk.qcow2 victim3_final.raw

echo "→ Ajustando permisos..."
sudo chown "$USER:$USER" victim3_final.raw

echo "[5/5] Limpieza y verificación..."
sudo rm -f temp_disk.qcow2
# Nota: backing_base.raw se mantiene si deseas conservarlo, o puedes añadir rm si prefieres borrarlo.

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
echo "  sudo mount -o ro,noload /dev/loopXp1 /mnt/forensic"
echo "-------------------------------------------------------"