#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VM_NAME="${1:-AI_Server}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/cyberlab-key}"
SSH_USER="ubuntu"

echo "[+] Step 1: Security groups"
bash "$SCRIPT_DIR/create_ai_secgroup.sh"

echo "[+] Step 2: Create / validate AI instance: $VM_NAME"
bash "$SCRIPT_DIR/create_ai_instance.sh" "$VM_NAME"

echo "[+] Step 3: Waiting for VM to become ACTIVE"
while true; do
  STATUS=$(openstack server show "$VM_NAME" -f value -c status)
  echo "    VM status: $STATUS"
  [[ "$STATUS" == "ACTIVE" ]] && break
  sleep 5
done

echo "[+] Step 4: Assign Floating IP (safe)"
FIP=$(bash "$SCRIPT_DIR/assign_floating_ip_safe.sh" "$VM_NAME" | tail -n 1)
echo "[+] Floating IP: $FIP"

echo "[+] Step 5: Waiting for SSH"
for i in {1..40}; do
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=4 \
        -i "$SSH_KEY" "$SSH_USER@$FIP" "echo ok" >/dev/null 2>&1; then
    echo "[✓] SSH reachable"
    break
  fi
  echo "    SSH not ready yet ($i/40)"
  sleep 5
done

echo "[+] Step 6: Bootstrap AI stack remotely"
# Subimos el bootstrap por stdin para no depender de scp/permiso exec
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$SSH_USER@$FIP" "bash -s" < "$SCRIPT_DIR/bootstrap_ai_stack.sh"

echo
echo "[✓] DONE"
echo "[✓] Web UI: http://$FIP:3000"
echo "[✓] API:    http://$FIP:8000/v1/chat/completions"
echo "[✓] SSH:    ssh -i $SSH_KEY $SSH_USER@$FIP"
