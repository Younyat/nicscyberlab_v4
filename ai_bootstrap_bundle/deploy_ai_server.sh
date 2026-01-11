#!/usr/bin/env bash
set -euo pipefail

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
VM_NAME="${1:-AI}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/my_key}"

timestamp() { date -Iseconds; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] Falta comando: $1"; exit 1; }
}

need_cmd openstack
need_cmd jq
need_cmd ssh

# ============================================================
# INIT STATE (bloquea frontend desde el inicio)
# ============================================================
cat > "$STATE_FILE" <<EOF
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
  NOW="$(timestamp)"

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

set_instance_active() {
  local VM_ID="$1"
  jq \
    --arg id "$VM_ID" \
    '.instance.exists=true
     | .instance.id=$id
     | .instance.status="ACTIVE"' \
    "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
}

set_fip() {
  local FIP="$1"
  jq --arg fip "$FIP" '.network.ip_floating=$fip' \
    "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
}

set_endpoints() {
  local FIP="$1"
  jq \
    --arg gui "http://$FIP:3000" \
    --arg api "http://$FIP:8000/v1/chat/completions" \
    '.gui.installed=true
     | .gui.status="running"
     | .gui.url=$gui
     | .api.url=$api' \
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
  STATUS="$(openstack server show "$VM_NAME" -f value -c status 2>/dev/null || true)"

  if [[ "$STATUS" == "ACTIVE" ]]; then
    break
  fi

  if [[ "$STATUS" == "ERROR" ]]; then
    echo "[ERROR] La instancia entró en estado ERROR"
    openstack server show "$VM_NAME" || true
    exit 1
  fi

  sleep 5
done

VM_ID="$(openstack server show "$VM_NAME" -f value -c id)"
set_instance_active "$VM_ID"

# ------------------------------------------------------------
# NETWORK
# ------------------------------------------------------------
update_state "network" 40 "Asignando Floating IP"

# Espera que el script imprima SOLO la IP en su última línea
FIP="$(bash "$SCRIPT_DIR/assign_floating_ip_safe.sh" "$VM_NAME" | tail -n 1 | tr -d '[:space:]')"

if [[ ! "$FIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "[ERROR] Floating IP inválida detectada: '$FIP'"
  exit 1
fi

set_fip "$FIP"

# ------------------------------------------------------------
# ESPERAR SSH (CRÍTICO) -> si no levanta, FAIL
# ------------------------------------------------------------
update_state "ssh-wait" 55 "Esperando servicio SSH"

SSH_OK="false"
for i in {1..40}; do
  if ssh -o BatchMode=yes \
         -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=5 \
         -i "$SSH_KEY" "$SSH_USER@$FIP" "echo SSH_READY" \
         >/dev/null 2>&1; then
    SSH_OK="true"
    break
  fi
  sleep 5
done

if [[ "$SSH_OK" != "true" ]]; then
  echo "[ERROR] SSH no disponible en $FIP tras 40 intentos"
  exit 1
fi

# ------------------------------------------------------------
# BOOTSTRAP IA
#  - HF_TOKEN se pasa como env var si existe localmente
# ------------------------------------------------------------
update_state "bootstrap" 70 "Instalando stack IA (GUI + API)"

if [[ -n "${HF_TOKEN:-}" ]]; then
  echo "[+] HF_TOKEN detectado en entorno local: se pasará a la VM (no se guarda en logs si no lo imprimes)."
  ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -i "$SSH_KEY" "$SSH_USER@$FIP" \
      "HF_TOKEN='${HF_TOKEN}' bash -s" < "$SCRIPT_DIR/bootstrap_ai_stack_Qwen2_5_7B.sh"
else
  ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -i "$SSH_KEY" "$SSH_USER@$FIP" \
      "bash -s" < "$SCRIPT_DIR/bootstrap_ai_stack_Qwen2_5_7B.sh"
fi

# ------------------------------------------------------------
# FINALIZAR
# ------------------------------------------------------------
update_state "finalizing" 90 "Finalizando despliegue"

set_endpoints "$FIP"
update_state "done" 100 "Módulo IA desplegado correctamente"

echo
echo "[OK] DESPLIEGUE COMPLETADO"
echo "[OK] GUI -> http://$FIP:3000"
echo "[OK] API -> http://$FIP:8000/v1/chat/completions"
