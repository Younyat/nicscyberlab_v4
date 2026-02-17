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

REMOTE_PATH=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${MANAGER_IP}" "
    if [ -f $ALERTS_JSON ]; then
        echo $ALERTS_JSON
    else
        sudo find /var/ossec/logs/alerts -name 'alerts.json' | head -n 1
    fi
")

if [[ -z "$REMOTE_PATH" ]]; then
    die "No se encontró el archivo de alertas en $MANAGER_IP. ¿Es la IP del Manager?"
fi

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
#  - tail alerts.json
#  - jq filtra grupos y emite 1 JSON por evento (compacto)
# ------------------------------------------------------------
REMOTE_COMMAND=$(cat <<'EOF'
sudo stdbuf -oL tail -f __REMOTE_PATH__ | jq --unbuffered -c '
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
