#!/usr/bin/env bash
set -e

VM_NAME="${1}"

IMAGE="ubuntu-22.04"
FLAVOR="AI_FLAVOR"
PRIVATE_NET="net_private_01"
KEYPAIR="my_key"
SG_AI="ai_sg"
SG_ACCESS="allow-ssh-icmp"
TCP_PORTS=(22 3000 8000 8080)

[[ -z "$VM_NAME" ]] && { echo "Usage: $0 <vm-name>"; exit 1; }

echo "[+] Ensuring AI instance: $VM_NAME"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*"; }

# ------------------------------------------------------------
# Flavor
# ------------------------------------------------------------
openstack flavor show "$FLAVOR" >/dev/null 2>&1 || \
openstack flavor create "$FLAVOR" --vcpus 4 --ram 8192 --disk 20 --public

# ------------------------------------------------------------
# Security Group ai_sg
# ------------------------------------------------------------
ensure_sg_exists() {
  if openstack security group show "$SG_AI" >/dev/null 2>&1; then
    ok "Security group exists: $SG_AI"
  else
    log "Creating security group: $SG_AI"
    openstack security group create "$SG_AI" >/dev/null
    ok "Security group created"
  fi
}

create_rule_ignore_conflict() {
  set +e
  openstack security group rule create "$@" >/dev/null 2>&1
  rc=$?
  set -e
  [[ $rc -eq 0 ]] && ok "Rule created" || warn "Rule already exists (ignored)"
}

ensure_ingress_icmp() {
  create_rule_ignore_conflict \
    --ingress \
    --proto icmp \
    --remote-ip 0.0.0.0/0 \
    "$SG_AI"
}

ensure_ingress_tcp_port() {
  local port="$1"
  create_rule_ignore_conflict \
    --ingress \
    --proto tcp \
    --dst-port "$port" \
    --remote-ip 0.0.0.0/0 \
    "$SG_AI"
}

ensure_sg_exists
ensure_ingress_icmp
for port in "${TCP_PORTS[@]}"; do
  ensure_ingress_tcp_port "$port"
done

# ------------------------------------------------------------
# Keypair
# ------------------------------------------------------------
openstack keypair show "$KEYPAIR" >/dev/null 2>&1 || {
  echo "[✗] Keypair $KEYPAIR not found"
  exit 1
}

# ------------------------------------------------------------
# Optional SG_ACCESS handling (FIX)
# ------------------------------------------------------------
EXTRA_SG_ARGS=()
if openstack security group show "$SG_ACCESS" >/dev/null 2>&1; then
  EXTRA_SG_ARGS+=(--security-group "$SG_ACCESS")
fi

# ------------------------------------------------------------
# VM existence / recreate if wrong key
# ------------------------------------------------------------
if openstack server show "$VM_NAME" >/dev/null 2>&1; then
  CURRENT_KEY=$(openstack server show "$VM_NAME" -f value -c key_name || true)
  if [[ "$CURRENT_KEY" != "$KEYPAIR" ]]; then
    openstack server delete "$VM_NAME"
    while openstack server show "$VM_NAME" >/dev/null 2>&1; do sleep 2; done
  else
    exit 0
  fi
fi

# ------------------------------------------------------------
# Create VM
# ------------------------------------------------------------
openstack server create \
  --image "$IMAGE" \
  --flavor "$FLAVOR" \
  --key-name "$KEYPAIR" \
  --network "$PRIVATE_NET" \
  --security-group "$SG_AI" \
  "${EXTRA_SG_ARGS[@]}" \
  --property role=ai \
  --property type=llm \
  "$VM_NAME"

echo "[✓] AI instance creation requested"
