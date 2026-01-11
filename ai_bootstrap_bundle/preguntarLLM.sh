#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# AI COPILOT – OPENSTACK FLOATING IP + QWEN API (FINAL REAL)
# ============================================================

# ----------------------------
# PATHS
# ----------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENRC="$PROJECT_ROOT/admin-openrc.sh"

LOG_DIR="$SCRIPT_DIR/ai/logs"
LOG_FILE="$LOG_DIR/ai.log"

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "---- AI QUERY START ----"

# ----------------------------
# INPUT
# ----------------------------
PROMPT="${1:-}"
if [[ -z "$PROMPT" ]]; then
    log "ERROR: Prompt vacío"
    echo "IA_OCUPADA"
    exit 0
fi



# ----------------------------
# LOAD OPENSTACK CREDS
# ----------------------------
if [[ ! -f "$OPENRC" ]]; then
    log "ERROR: admin-openrc.sh no encontrado"
    echo "IA_NO_DISPONIBLE"
    exit 0
fi

# shellcheck disable=SC1090
source "$OPENRC"
log "OpenStack credentials loaded"

# ----------------------------
# CONFIG
# ----------------------------
VM_NAME="AI"
EXTERNAL_NET="external-net"

# ----------------------------
# GET SERVER ID
# ----------------------------
SERVER_ID="$(openstack server show "$VM_NAME" -f value -c id 2>/dev/null || true)"
if [[ -z "$SERVER_ID" ]]; then
    log "ERROR: Instancia AI no existe"
    echo "IA_NO_DISPONIBLE"
    exit 0
fi
log "AI Server ID: $SERVER_ID"

# ----------------------------
# GET ALL PORTS OF SERVER
# ----------------------------
PORT_IDS="$(openstack port list --server "$SERVER_ID" -f value -c ID || true)"
if [[ -z "$PORT_IDS" ]]; then
    log "ERROR: La instancia no tiene puertos"
    echo "IA_NO_DISPONIBLE"
    exit 0
fi

# ----------------------------
# SEARCH EXISTING FLOATING IP
# ----------------------------
FIP=""
FIP_PORT=""

for PORT in $PORT_IDS; do
    FOUND_FIP="$(openstack floating ip list --port "$PORT" -f value -c 'Floating IP Address' | head -n1 || true)"
    if [[ -n "$FOUND_FIP" ]]; then
        FIP="$FOUND_FIP"
        FIP_PORT="$PORT"
        break
    fi
done

if [[ -n "$FIP" ]]; then
    log "Existing floating IP found: $FIP (port $FIP_PORT)"
else
    log "No floating IP associated to any port, creating new one"

    # ----------------------------
    # CREATE FLOATING IP
    # ----------------------------
    FIP="$(openstack floating ip create "$EXTERNAL_NET" -f value -c floating_ip_address)"
    if [[ -z "$FIP" ]]; then
        log "ERROR: No se pudo crear floating IP"
        echo "IA_NO_DISPONIBLE"
        exit 0
    fi

    # Associate to FIRST port
    FIRST_PORT="$(echo "$PORT_IDS" | head -n1)"
    openstack floating ip set --port "$FIRST_PORT" "$FIP" >/dev/null

    log "Floating IP created and associated: $FIP (port $FIRST_PORT)"
fi

# ----------------------------
# CALL AI API
# ----------------------------
API_URL="http://$FIP:8000/v1/chat/completions"
log "Calling AI API at $API_URL"

JSON_PAYLOAD="$(jq -n \
  --arg prompt "$PROMPT" \
  '{
    model: "qwen",
    messages: [
      { role: "system", content: "Eres un asistente forense experto." },
      { role: "user", content: $prompt }
    ]
  }'
)"

RESPONSE="$(curl -s --max-time 80 -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD" || true)"


if [[ -z "$RESPONSE" ]]; then
    log "TIMEOUT: AI did not respond in time"
    echo "IA_OCUPADA"
    exit 0
fi

log "RAW RESPONSE: $RESPONSE"

ANSWER="$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"

if [[ -z "$ANSWER" ]]; then
    log "ERROR: Respuesta vacía del modelo"
    echo "IA_OCUPADA"
    exit 0
fi


# ----------------------------
# LOG & OUTPUT
# ----------------------------
log "PROMPT: $PROMPT"
log "RESPONSE: $ANSWER"
log "---- AI QUERY END ----"

echo "$ANSWER"
exit 0
