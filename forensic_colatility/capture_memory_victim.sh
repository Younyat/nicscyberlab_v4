#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. CONTEXTO Y OPENSTACK CREDENTIALS
# ============================================================
# En la Workstation, buscamos el archivo en el HOME o nivel superior
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENRC_PATH="$(realpath "$SCRIPT_DIR/../admin-openrc.sh" 2>/dev/null || echo "$HOME/admin-openrc.sh")"

if [[ ! -f "$OPENRC_PATH" ]]; then
    echo "ERROR: admin-openrc.sh no encontrado en $OPENRC_PATH"
    exit 1
fi

source "$OPENRC_PATH"
echo "Credenciales OpenStack cargadas"

# ============================================================
# 2. CONFIGURACIÓN SSH
# ============================================================
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

LOCAL_EVIDENCE_DIR="$HOME/forensics/memory_dumps"
mkdir -p "$LOCAL_EVIDENCE_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ============================================================
# 3. BUSCAR VM VÍCTIMA (victim*)
# ============================================================
echo "🔍 Buscando máquina víctima (nombre empieza por 'victim')..."

VM_NAME=$(openstack server list -f value -c Name | grep -i '^victim' | head -n 1)

if [[ -z "$VM_NAME" ]]; then
    echo "ERROR: no se encontró ninguna VM victim*"
    exit 1
fi

echo "VM encontrada: $VM_NAME"

# ============================================================
# 4. RESOLVER IP (FIXED IP → FLOATING IP)
# ============================================================
FIXED_IP=$(openstack server show "$VM_NAME" -f value -c addresses \
  | grep -oP '192\.168\.100\.\d+' | head -n1)

if [[ -z "$FIXED_IP" ]]; then
    echo "ERROR: no se pudo obtener IP privada"
    exit 1
fi

FIP=$(openstack floating ip list \
  --fixed-ip-address "$FIXED_IP" \
  -f value -c "Floating IP Address" | head -n1)

if [[ -z "$FIP" ]]; then
    echo "ERROR: la VM no tiene IP flotante asociada"
    exit 1
fi

VICTIM_IP="$FIP"
echo "IP flotante seleccionada: $VICTIM_IP"

# ============================================================
# 5. PREPARAR CAPTURA
# ============================================================
DUMP_NAME="memdump_${VM_NAME// /_}_${TIMESTAMP}.raw"
REMOTE_DUMP="/tmp/$DUMP_NAME"

echo "====================================================="
echo " LIVE MEMORY ACQUISITION (IN-BAND)"
echo "====================================================="
echo " VM      : $VM_NAME"
echo " IP      : $VICTIM_IP"
echo " Dump    : $DUMP_NAME"
echo " Destino : $LOCAL_EVIDENCE_DIR"
echo "====================================================="



# ============================================================
# 6. CAPTURA DE MEMORIA (SSH /proc/kcore)
# ============================================================
echo "[1/3] Capturando memoria en la víctima..."

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no \
  "$SSH_USER@$VICTIM_IP" << EOF
sudo dd if=/proc/kcore of=$REMOTE_DUMP bs=1M status=progress
sudo chmod 644 $REMOTE_DUMP
EOF

# ============================================================
# 7. DESCARGAR AL HOST (WORKSTATION)
# ============================================================
echo "[2/3] Descargando volcado a Ubuntu_Forensics_Workstation..."

scp -i "$SSH_KEY" \
  "$SSH_USER@$VICTIM_IP:$REMOTE_DUMP" \
  "$LOCAL_EVIDENCE_DIR/"

# ============================================================
# 8. LIMPIEZA REMOTA
# ============================================================
echo "[3/3] Limpieza remota en la víctima..."

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no \
  "$SSH_USER@$VICTIM_IP" "sudo rm -f $REMOTE_DUMP"

# ============================================================
# 9. HASH DE INTEGRIDAD
# ============================================================
echo "Calculando hash SHA-256..."

sha256sum "$LOCAL_EVIDENCE_DIR/$DUMP_NAME" \
  | tee "$LOCAL_EVIDENCE_DIR/$DUMP_NAME.sha256"
echo "====================================================="
echo " CAPTURA COMPLETADA"
echo " Archivo : $LOCAL_EVIDENCE_DIR/$DUMP_NAME"
echo "====================================================="