#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Remote Wazuh Alert Monitor (JSON + UI)
# ============================================================

MANAGER_IP="${1:-10.0.2.136}"
SSH_USER="${2:-ubuntu}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"
ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"

RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

[[ -n "$MANAGER_IP" ]] || die "Uso: $0 <IP_MANAGER_WAZUH> [SSH_USER] [SSH_KEY]"
[[ -f "$SSH_KEY" ]] || die "No existe la clave SSH en $SSH_KEY"

info "Validando entorno en el Manager ($MANAGER_IP)..."

# ── Asegurar que jq está disponible en el manager ───────────────────────────
# jq es necesario para parsear alerts.json. Si no está instalado, el stream
# falla silenciosamente con "jq: command not found".
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 "${SSH_USER}@${MANAGER_IP}" \
    "command -v jq >/dev/null 2>&1 || sudo apt-get install -y jq >/dev/null 2>&1" \
    || info "Advertencia: no se pudo verificar/instalar jq en el manager."

# ── Localizar alerts.json (puede tardar si Wazuh acaba de arrancar) ─────────
REMOTE_PATH=""
WAIT_ALERTS=0
WAIT_ALERTS_MAX=120  # esperar hasta 2 min si alerts.json no existe aún
while [[ -z "$REMOTE_PATH" ]]; do
    REMOTE_PATH=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 "${SSH_USER}@${MANAGER_IP}" \
        "if sudo test -f $ALERTS_JSON 2>/dev/null; then echo $ALERTS_JSON;
         else sudo find /var/ossec/logs/alerts -name 'alerts.json' 2>/dev/null | head -n 1; fi" \
        2>/dev/null || true)
    if [[ -z "$REMOTE_PATH" ]]; then
        if [[ $WAIT_ALERTS -ge $WAIT_ALERTS_MAX ]]; then
            die "No se encontró alerts.json en $MANAGER_IP tras ${WAIT_ALERTS_MAX}s. ¿Está Wazuh Manager activo?"
        fi
        info "alerts.json no encontrado aún (${WAIT_ALERTS}s/${WAIT_ALERTS_MAX}s) — esperando..."
        sleep 15
        WAIT_ALERTS=$((WAIT_ALERTS + 15))
    fi
done

echo -e "${YELLOW}==========================================================${NC}"
echo -e "${YELLOW}    MONITOR REMOTO MULTI-VECTOR - NICS CYBERLAB${NC}"
echo -e "${YELLOW}==========================================================${NC}"
info "Escuchando alertas en: $REMOTE_PATH"

trap "echo -e '\n${YELLOW}[INFO]${NC} Cerrando monitor...'; exit" SIGINT SIGTERM

# Keepalive (para SSE)
( while true; do echo "[SYSTEM] WAZUH STREAM ACTIVE"; sleep 2; done ) &
KEEPALIVE_PID=$!
trap "kill $KEEPALIVE_PID 2>/dev/null" EXIT

# ------------------------------------------------------------
# REMOTE COMMAND:
#  - tail recent alerts first, then follow new ones
#  - jq filtra grupos y emite 1 JSON por evento (compacto)
# ------------------------------------------------------------
REMOTE_COMMAND=$(cat <<'EOF'
# We intentionally keep a short backlog here because Level B launches the
# attack before opening the monitor session. A pure "-n 0 -F" can miss the
# detection if Wazuh writes the alert during the attack itself. The Level B
# matcher still enforces a tight temporal window around the executed attack,
# so a small recent backlog is safe and avoids losing the relevant alert.
sudo stdbuf -oL tail -n 200 -F __REMOTE_PATH__ | jq --unbuffered -c '
  # filtrar solo lo que interesa
  select(.rule.groups[]? | . == "suricata" or . == "syscheck" or . == "authentication_failed") |

  # clasificar tipo
  (if (.rule.groups[]? == "suricata") then "[IDS/SURICATA]"
   elif (.rule.groups[]? == "syscheck") then "[FIM/INTEGRIDAD]"
   else "[AUTH/ATAQUE]" end) as $atype |

  {
    "__tag":"NICS_ALERT_JSON",

    "ts_utc": (.timestamp // ""),
    "source": "wazuh",
    "alert_type": $atype,

    "rule_id": (.rule.id // null),
    "rule_level": (.rule.level // null),
    "description": (.rule.description // null),

    "signature": (.data.alert.signature // .syscheck.path // .full_log // "Evento detectado"),

    "src": {
      "ip": (.data.src_ip // "Interno"),
      "port": (.data.src_port // 0)
    },
    "dst": {
      "ip": (.data.dest_ip // "Interno"),
      "port": (.data.dest_port // 0)
    },

    "protocol": (.data.proto // .data.protocol // "unknown"),

    "agent": {
      "name": (.agent.name // null),
      "ip": (.agent.ip // null)
    },

    "raw": .
  }'
EOF
)

REMOTE_COMMAND="${REMOTE_COMMAND/__REMOTE_PATH__/$REMOTE_PATH}"

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o BatchMode=yes "${SSH_USER}@${MANAGER_IP}" "$REMOTE_COMMAND"
