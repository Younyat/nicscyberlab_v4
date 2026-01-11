#!/usr/bin/env bash
set -e

# ============================================================
# PATHS (FIJOS)
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

STATE_DIR="$SCRIPT_DIR/ai"
STATE_FILE="$STATE_DIR/ai_module_state.json"

LOG_DIR="$STATE_DIR/logs"
LOG_FILE="$LOG_DIR/deploy_ai.log"

mkdir -p "$STATE_DIR" "$LOG_DIR"

# Log completo (stdout + stderr)
exec > >(tee -a "$LOG_FILE") 2>&1

# ============================================================
# CONFIG
# ============================================================
VM_NAME="AI"
SSH_USER="ubuntu"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/my_key}"

timestamp() { date -Iseconds; }

# ============================================================
# INIT STATE (bloquea frontend desde el inicio)
# ============================================================
cat <<EOF > "$STATE_FILE"
{
  "module": "ai",
  "deployment": {
    "phase": "init",
    "progress": 1,
    "message": "Inicializando despliegue del módulo IA"
  },
  "instance": {
    "name": "$VM_NAME",
    "exists": false,
    "id": null,
    "status": null
  },
  "network": {
    "ip_floating": null,
    "ip_private": null
  },
  "gui": {
    "installed": false,
    "status": "not_installed",
    "port": 3000,
    "url": null
  },
  "api": {
    "port": 8000,
    "url": null
  },
  "timestamps": {
    "created": "$(timestamp)",
    "last_update": "$(timestamp)"
  }
}
EOF

update_state() {
  local PHASE="$1"
  local PROGRESS="$2"
  local MESSAGE="$3"
  local NOW
  NOW="$(date -Iseconds)"

  jq \
    --arg phase "$PHASE" \
    --arg msg "$MESSAGE" \
    --argjson progress "$PROGRESS" \
    --arg now "$NOW" \
    '.deployment.phase=$phase
     | .deployment.progress=$progress
     | .deployment.message=$msg
     | .timestamps.last_update=$now' \
    "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
}

# ============================================================
# DEPLOY FLOW
# ============================================================

update_state "security-groups" 5 "Configurando security groups"
bash "$SCRIPT_DIR/create_ai_secgroup.sh"

update_state "instance-create" 15 "Creando instancia IA"
bash "$SCRIPT_DIR/create_ai_instance.sh" "$VM_NAME"

# ------------------------------------------------------------
# ESPERAR A ACTIVE (OBLIGATORIO)
# ------------------------------------------------------------
update_state "instance-wait" 25 "Esperando instancia ACTIVE"

while true; do
  STATUS=$(openstack server show "$VM_NAME" -f value -c status)

  if [[ "$STATUS" == "ACTIVE" ]]; then
    break
  fi

  if [[ "$STATUS" == "ERROR" ]]; then
    echo "[ERROR] La instancia entró en estado ERROR"
    openstack server show "$VM_NAME"
    exit 1
  fi

  sleep 5
done

VM_ID=$(openstack server show "$VM_NAME" -f value -c id)

jq \
  --arg id "$VM_ID" \
  '.instance.exists=true
   | .instance.id=$id
   | .instance.status="ACTIVE"' \
  "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"

# ------------------------------------------------------------
# NETWORK
# ------------------------------------------------------------
update_state "network" 40 "Asignando Floating IP"
FIP=$(bash "$SCRIPT_DIR/assign_floating_ip_safe.sh" "$VM_NAME" | tail -n 1)

jq --arg fip "$FIP" '.network.ip_floating=$fip' \
  "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"

# ------------------------------------------------------------
# ESPERAR SSH (CRÍTICO)
# ------------------------------------------------------------
update_state "ssh-wait" 55 "Esperando servicio SSH"

for i in {1..40}; do
  if ssh -o BatchMode=yes \
         -o StrictHostKeyChecking=no \
         -o ConnectTimeout=5 \
         -i "$SSH_KEY" "$SSH_USER@$FIP" "echo SSH_READY" \
         >/dev/null 2>&1; then
    break
  fi

  sleep 5
done

# ------------------------------------------------------------
# BOOTSTRAP IA
# ------------------------------------------------------------
update_state "bootstrap" 70 "Instalando stack IA (GUI + API)"

ssh -o StrictHostKeyChecking=no \
    -i "$SSH_KEY" "$SSH_USER@$FIP" \
    "bash -s" < "$SCRIPT_DIR/bootstrap_ai_stack_Qwen2_5_7B.sh"

# ------------------------------------------------------------
# FINALIZAR
# ------------------------------------------------------------
update_state "finalizing" 90 "Finalizando despliegue"

jq \
  --arg gui "http://$FIP:3000" \
  --arg api "http://$FIP:8000/v1/chat/completions" \
  '.gui.installed=true
   | .gui.status="running"
   | .gui.url=$gui
   | .api.url=$api' \
  "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"

update_state "done" 100 "Módulo IA desplegado correctamente"

echo
echo "[✓] DESPLIEGUE COMPLETADO"
echo "[✓] GUI → http://$FIP:3000"
echo "[✓] API → http://$FIP:8000/v1/chat/completions"
