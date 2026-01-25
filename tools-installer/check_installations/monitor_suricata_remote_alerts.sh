#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Remote Wazuh/Suricata Alert Monitor (FIXED)
# ============================================================

MANAGER_IP="${1:-}"
SSH_USER="${2:-ubuntu}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"
ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"

# Colores locales
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

[[ -n "$MANAGER_IP" ]] || die "Uso: $0 <IP_MANAGER_WAZUH> [SSH_USER] [SSH_KEY]"
[[ -f "$SSH_KEY" ]] || die "No existe la clave SSH en $SSH_KEY"

# 1. Verificar dependencias (jq ya debería estar instalado por el intento anterior)
info "Verificando jq en el Manager..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${MANAGER_IP}" \
    "command -v jq >/dev/null 2>&1 || sudo apt update && sudo apt install -y jq"

# 2. Comando Remoto (Sin colores internos para evitar errores de escape)
REMOTE_COMMAND="sudo stdbuf -oL tail -f $ALERTS_JSON | jq --unbuffered -r '
  select(.rule.groups[]? == \"suricata\") | 
  \"----------------------------------------------------------
  TIEMPO:     \(.timestamp)
  NIVEL:      \(.rule.level) (ID: \(.rule.id))
  AGENTE:     \(.agent.name) (\(.agent.ip))
  MENSAJE:    \(.data.alert.signature // \"Sin firma\")
  ID REGLA:   \(.data.alert.signature_id // \"N/A\")
  PROTOCOLO:  \(.data.proto)
  ORIGEN:     \(.data.src_ip):\(.data.src_port // \"0\")
  DESTINO:    \(.data.dest_ip):\(.data.dest_port // \"0\")
  ----------------------------------------------------------\"'"

echo -e "${YELLOW}==========================================================${NC}"
echo -e "${YELLOW}      MONITOR REMOTO SURICATA - NICS CYBERLAB${NC}"
echo -e "${YELLOW}==========================================================${NC}"
info "Escuchando alertas en $MANAGER_IP..."

# 3. Ejecutar y aplicar colores localmente con sed
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${SSH_USER}@${MANAGER_IP}" "$REMOTE_COMMAND" | sed \
    -e "s/TIEMPO:/$(echo -e $GREEN)TIEMPO:$(echo -e $NC)/" \
    -e "s/NIVEL:/$(echo -e $GREEN)NIVEL:$(echo -e $NC)/" \
    -e "s/AGENTE:/$(echo -e $GREEN)AGENTE:$(echo -e $NC)/" \
    -e "s/MENSAJE:/$(echo -e $CYAN)MENSAJE:$(echo -e $NC)/" \
    -e "s/ID REGLA:/$(echo -e $CYAN)ID REGLA:$(echo -e $NC)/" \
    -e "s/---/$(echo -e $YELLOW)---$(echo -e $NC)/g"