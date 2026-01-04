#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================
# CONFIGURACIÓN
# ============================================================
VM_NAME="PLC_Instance"

IMAGE="ubuntu-22.04"
FLAVOR="PLC_FLAVOR"

PRIVATE_NET="net_private_01"
EXTERNAL_NET="net_external_01"

KEYPAIR="my_key"
KEY_PATH="$HOME/.ssh/my_key"

SG_PLC="plc-sg"
CLOUD_INIT="$SCRIPT_DIR/cloud_init_plc.yaml"


TCP_PORTS=(22 502 8080 8443)

# ============================================================
# UTILIDADES
# ============================================================
log()  { echo -e "[+] $*"; }
ok()   { echo -e "[✓] $*"; }
warn() { echo -e "[!] $*"; }
fail() { echo -e "[✗] $*"; exit 1; }

# ============================================================
# SSH USER
# ============================================================
detect_ssh_user() {
  case "$IMAGE" in
    *ubuntu*) echo "ubuntu" ;;
    *debian*) echo "debian" ;;
    *kali*) echo "kali" ;;
    *centos*) echo "centos" ;;
    *rocky*) echo "rocky" ;;
    *alma*) echo "almalinux" ;;
    *) echo "ubuntu" ;;
  esac
}

# ============================================================
# ESPERAS
# ============================================================
wait_for_active() {
  log "Waiting for VM to become ACTIVE..."
  while true; do
    STATUS="$(openstack server show "$VM_NAME" -f value -c status 2>/dev/null || echo UNKNOWN)"
    case "$STATUS" in
      ACTIVE) ok "VM is ACTIVE"; return ;;
      ERROR)  fail "VM entered ERROR state" ;;
      *) sleep 5 ;;
    esac
  done
}

wait_for_ssh() {
  local user="$1" ip="$2"
  log "Waiting for SSH on $ip..."
  until ssh -o BatchMode=yes \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            -i "$KEY_PATH" \
            "${user}@${ip}" "echo OK" >/dev/null 2>&1; do
    sleep 5
  done
  ok "SSH ready"
}

stream_cloud_init_logs() {
  local user="$1" ip="$2"

  wait_for_ssh "$user" "$ip"

  ssh -o StrictHostKeyChecking=no \
      -o ServerAliveInterval=10 \
      -i "$KEY_PATH" \
      "${user}@${ip}" \
      "sudo -n tail -f /var/log/cloud-init-output.log" &

  STREAM_PID=$!

  until ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            -i "$KEY_PATH" \
            "${user}@${ip}" \
            "test -f /opt/PLC_READY" >/dev/null 2>&1; do
    sleep 5
  done

  kill "$STREAM_PID" >/dev/null 2>&1 || true
  wait "$STREAM_PID" 2>/dev/null || true
  ok "PLC_READY detected"
}

# ============================================================
# SECURITY GROUP (ROBUSTO REAL)
# ============================================================
ensure_sg_exists() {
  if openstack security group show "$SG_PLC" >/dev/null 2>&1; then
    ok "Security group exists: $SG_PLC"
  else
    log "Creating security group: $SG_PLC"
    openstack security group create "$SG_PLC" >/dev/null
    ok "Security group created"
  fi
}

create_rule_ignore_conflict() {
  set +e
  openstack security group rule create "$@" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    ok "Rule created"
  else
    warn "Rule already exists (ignored)"
  fi
}

ensure_ingress_icmp() {
  log "Ensuring ICMP ingress"
  create_rule_ignore_conflict \
    --ingress \
    --proto icmp \
    --remote-ip 0.0.0.0/0 \
    "$SG_PLC"
}

ensure_ingress_tcp_port() {
  local port="$1"
  log "Ensuring TCP $port ingress"
  create_rule_ignore_conflict \
    --ingress \
    --proto tcp \
    --dst-port "$port" \
    --remote-ip 0.0.0.0/0 \
    "$SG_PLC"
}

# ============================================================
# VALIDACIONES
# ============================================================
[[ -f "$KEY_PATH" ]] || fail "SSH key not found"
openstack keypair show "$KEYPAIR" >/dev/null 2>&1 || fail "Keypair not found"
[[ -f "$CLOUD_INIT" ]] || fail "cloud-init file not found"

# ============================================================
# FLAVOR
# ============================================================
# ============================================================
# FLAVOR (IDEMPOTENTE REAL)
# ============================================================
ensure_flavor_exists() {
  if openstack flavor show "$FLAVOR" >/dev/null 2>&1; then
    ok "Flavor exists: $FLAVOR"
    return
  fi

  log "Creating flavor: $FLAVOR"
  set +e
  openstack flavor create "$FLAVOR" \
    --vcpus 1 \
    --ram 1024 \
    --disk 10 >/dev/null 2>&1
  rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    ok "Flavor created: $FLAVOR"
  else
    warn "Flavor already exists (409 ignored)"
  fi
}

ensure_flavor_exists


# ============================================================
# SECURITY GROUP
# ============================================================
ensure_sg_exists
ensure_ingress_icmp
for port in "${TCP_PORTS[@]}"; do
  ensure_ingress_tcp_port "$port"
done

# ============================================================
# VM
# ============================================================
if ! openstack server show "$VM_NAME" >/dev/null 2>&1; then
  log "Creating VM: $VM_NAME"
  openstack server create \
    --image "$IMAGE" \
    --flavor "$FLAVOR" \
    --key-name "$KEYPAIR" \
    --network "$PRIVATE_NET" \
    --security-group "$SG_PLC" \
    --user-data "$CLOUD_INIT" \
    "$VM_NAME" >/dev/null
fi

wait_for_active

# ============================================================
# FLOATING IP
# ============================================================
SERVER_ID="$(openstack server show "$VM_NAME" -f value -c id)"
PORT_ID="$(openstack port list --server "$SERVER_ID" --network "$PRIVATE_NET" -f value -c ID | head -n1)"

FIP="$(openstack floating ip list --port "$PORT_ID" -f value -c "Floating IP Address" || true)"
if [[ -z "${FIP:-}" ]]; then
  FIP="$(openstack floating ip create "$EXTERNAL_NET" -f value -c floating_ip_address)"
  openstack floating ip set --port "$PORT_ID" "$FIP" >/dev/null
fi

SSH_USER="$(detect_ssh_user)"
stream_cloud_init_logs "$SSH_USER" "$FIP"

# ============================================================
# FINAL
# ============================================================
echo
echo "========================================"
echo " 🚀 DEPLOYMENT COMPLETED"
echo "========================================"
echo "Instance : $VM_NAME"
echo "Floating : $FIP"
echo "SSH      : ssh -i $KEY_PATH ${SSH_USER}@${FIP}"
echo "Web      : http://${FIP}:8080"
echo "Web TLS  : https://${FIP}:8443"
echo "========================================"
