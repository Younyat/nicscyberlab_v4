#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Remote Wazuh Alert Monitor (FULL REPAIR)
# ============================================================

# INPUTS: Personaliza estos valores según tu entorno
MANAGER_IP="${1:-}"
SSH_USER="${2:-ubuntu}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"
ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"

# Colores locales
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

[[ -n "$MANAGER_IP" ]] || die "Uso: $0 <IP_MANAGER_WAZUH> [SSH_USER] [SSH_KEY]"
[[ -f "$SSH_KEY" ]] || die "No existe la clave SSH en $SSH_KEY"

# 1. Preparación y Validación del Manager
info "Validando entorno en el Manager ($MANAGER_IP)..."

# Verificamos si el archivo existe. Si no, lo buscamos.
REMOTE_PATH=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${MANAGER_IP}" "
    if [ -f $ALERTS_JSON ]; then
        echo $ALERTS_JSON
    else
        sudo find /var/ossec/logs/alerts -name 'alerts.json' | head -n 1
    fi
")

if [[ -z "$REMOTE_PATH" ]]; then
    die "No se encontró el archivo de alertas en $MANAGER_IP. ¿Es esta la IP del Manager o de la Víctima?"
fi

# 2. Comando Remoto (Optimizado para NICS CyberLab)
REMOTE_COMMAND="sudo stdbuf -oL tail -f $REMOTE_PATH | jq --unbuffered -r '
  select(.rule.groups[]? | . == \"suricata\" or . == \"syscheck\" or . == \"authentication_failed\") |
  \"----------------------------------------------------------
  TIPO:       \" + (if .rule.groups[]? == \"suricata\" then \"[IDS/SURICATA]\" 
                    elif .rule.groups[]? == \"syscheck\" then \"[FIM/INTEGRIDAD]\" 
                    else \"[AUTH/ATAQUE]\" end) + \"
  NIVEL:      \(.rule.level) - \(.rule.description)
  TIEMPO:     \(.timestamp)
  AGENTE:     \(.agent.name) (\(.agent.ip))
  DETALLE:    \(.data.alert.signature // .syscheck.path // \"Evento detectado\")
  ORIGEN:     \(.data.src_ip // \"Interno\"):\(.data.src_port // \"0\")
  DESTINO:    \(.data.dest_ip // \"Interno\"):\(.data.dest_port // \"0\")
  ----------------------------------------------------------\"'"

echo -e "${YELLOW}==========================================================${NC}"
echo -e "${YELLOW}    MONITOR REMOTO MULTI-VECTOR - NICS CYBERLAB${NC}"
echo -e "${YELLOW}==========================================================${NC}"
info "Escuchando alertas en: $REMOTE_PATH"

trap "echo -e '\n${YELLOW}[INFO]${NC} Cerrando monitor...'; exit" SIGINT SIGTERM

# 3. Ejecución y Coloreado local con sed
ssh -t -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${MANAGER_IP}" "$REMOTE_COMMAND" | sed \
    -e "s/TIPO:/$(echo -e $BLUE)TIPO:$(echo -e $NC)/" \
    -e "s/NIVEL:/$(echo -e $RED)NIVEL:$(echo -e $NC)/" \
    -e "s/TIEMPO:/$(echo -e $GREEN)TIEMPO:$(echo -e $NC)/" \
    -e "s/AGENTE:/$(echo -e $GREEN)AGENTE:$(echo -e $NC)/" \
    -e "s/DETALLE:/$(echo -e $CYAN)DETALLE:$(echo -e $NC)/" \
    -e "s/ORIGEN:/$(echo -e $YELLOW)ORIGEN:$(echo -e $NC)/" \
    -e "s/DESTINO:/$(echo -e $YELLOW)DESTINO:$(echo -e $NC)/" \
    -e "s/---/$(echo -e $BLUE)---$(echo -e $NC)/g"