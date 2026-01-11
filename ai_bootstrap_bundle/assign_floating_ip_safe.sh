#!/usr/bin/env bash
set -e

VM_NAME="$1"
EXT_NET="net_external_01"

if [[ -z "${VM_NAME:-}" ]]; then
  echo "[✗] Usage: $0 <vm-name>"
  exit 1
fi

echo "[+] Ensuring Floating IP for $VM_NAME"

SERVER_ID=$(openstack server show "$VM_NAME" -f value -c id)

PORT_ID=$(openstack port list --server "$SERVER_ID" -f value -c ID | head -n 1)
if [[ -z "${PORT_ID:-}" ]]; then
  echo "[✗] Could not find a port for $VM_NAME"
  exit 1
fi

# Si ya tiene FIP, no tocar nada
EXISTING_FIP=$(openstack floating ip list --port "$PORT_ID" -f value -c "Floating IP Address" || true)
if [[ -n "${EXISTING_FIP:-}" ]]; then
  echo "[✓] Floating IP already assigned: $EXISTING_FIP"
  echo "$EXISTING_FIP"
  exit 0
fi

# Crear uno nuevo (no reutiliza los de otros)
NEW_FIP=$(openstack floating ip create "$EXT_NET" -f value -c floating_ip_address)
openstack floating ip set --port "$PORT_ID" "$NEW_FIP"

echo "[✓] Floating IP assigned: $NEW_FIP"
echo "$NEW_FIP"
