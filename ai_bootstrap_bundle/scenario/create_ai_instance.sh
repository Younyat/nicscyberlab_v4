#!/usr/bin/env bash
set -e

VM_NAME="${1}"

IMAGE="ubuntu-22.04"
FLAVOR="M_4CPU_8GB"          # con 8GB RAM ok, si tienes uno más pequeño, ponlo aquí
PRIVATE_NET="private-net"
KEYPAIR="cyberlab-key"
SG_AI="ai_sg"
SG_ACCESS="allow-ssh-icmp"  # opcional; si no existe, quítalo o créalo

echo "[+] Ensuring AI instance: $VM_NAME"

openstack keypair show "$KEYPAIR" >/dev/null 2>&1 || { echo "[✗] Keypair $KEYPAIR not found"; exit 1; }

# Si existe, verificar key_name; si es distinta, borrar y recrear (única forma de “arreglar” key)
if openstack server show "$VM_NAME" >/dev/null 2>&1; then
  CURRENT_KEY=$(openstack server show "$VM_NAME" -f value -c key_name || true)

  if [[ "$CURRENT_KEY" != "$KEYPAIR" ]]; then
    echo "[!] VM exists but wrong key ($CURRENT_KEY). Deleting and recreating..."
    openstack server delete "$VM_NAME"
    while openstack server show "$VM_NAME" >/dev/null 2>&1; do
      sleep 2
    done
  else
    echo "[✓] VM exists with correct keypair"
    exit 0
  fi
fi

# Crear VM en PRIVATE_NET (modelo OpenStack correcto)
openstack server create \
  --image "$IMAGE" \
  --flavor "$FLAVOR" \
  --key-name "$KEYPAIR" \
  --network "$PRIVATE_NET" \
  --security-group "$SG_AI" \
  --security-group "$SG_ACCESS" \
  --property role=ai \
  --property type=llm \
  "$VM_NAME"

echo "[✓] AI instance creation requested"
