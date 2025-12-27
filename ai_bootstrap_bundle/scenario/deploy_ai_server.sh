#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VM_NAME="AI_Server_Qwen2_5_7B"
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
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$SSH_USER@$FIP" "bash -s" < "$SCRIPT_DIR/bootstrap_ai_stack_Qwen2_5_7B.sh"

# =====================================================
# MODIFICACIÓN: Crear el archivo de cliente local
# =====================================================
echo "[+] Step 7: Creating local CLI client (preguntar.sh)"
cat << EOF > "$SCRIPT_DIR/preguntar.sh"
#!/bin/bash
# Cliente rápido para hablar con Qwen en la instancia $VM_NAME
URL="http://$FIP:8000/v1/chat/completions"

if [ -z "\$1" ]; then
    echo "Uso: ./preguntar.sh \"Tu mensaje aquí\""
    exit 1
fi

curl -s -X POST "\$URL" \\
     -H "Content-Type: application/json" \\
     -d "{\"model\": \"qwen\", \"messages\": [{\"role\": \"user\", \"content\": \"\$1\"}]}" \\
     | python3 -c "import sys, json; print(json.load(sys.stdin)['choices'][0]['message']['content'])"
EOF

chmod +x "$SCRIPT_DIR/preguntar.sh"

echo
echo "[✓] DONE"
echo "[✓] Web UI: http://$FIP:3000"
echo "[✓] API:    http://$FIP:8000/v1/chat/completions"
echo "[✓] SSH:    ssh -i $SSH_KEY $SSH_USER@$FIP"
echo "[✓] CLI:    ./preguntar.sh \"Tu pregunta\""