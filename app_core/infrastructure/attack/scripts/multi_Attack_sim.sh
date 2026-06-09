#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${1:?Usage: $0 <VICTIM_IP> <SSH_USER>}"
SSH_USER="${2:?Usage: $0 <VICTIM_IP> <SSH_USER>}"
SSH_KEY="$HOME/.ssh/my_key"

ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        -o BatchMode=yes \
        "$SSH_USER@$VICTIM_IP" "$1"
}

echo "===================================================="
echo " [INFO] Generating security events on $VICTIM_IP"
echo " [INFO] SSH user: $SSH_USER"
echo "===================================================="

echo "[1/3] Modifying critical files..."
ssh_exec "sudo touch /etc/shadow_backup && sudo chmod 777 /etc/shadow_backup"
echo " [OK] Integrity event generated in /etc"

echo "[2/3] Generating failed access attempts..."
ssh_exec "for i in {1..3}; do ssh -o ConnectTimeout=1 no-existe@localhost 2>/dev/null || true; done"
echo " [OK] Authentication events generated"

echo "[3/3] Executing suspicious requests..."
ssh_exec "curl -s -A 'SQLMAP' http://google.com > /dev/null || true"
ssh_exec "curl -s http://testmyids.com > /dev/null || true"
echo " [OK] Suspicious network activity generated"

echo "===================================================="
echo " [SUCCESS] Events sent. Check your remote monitor."
echo "===================================================="
