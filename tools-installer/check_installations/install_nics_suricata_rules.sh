#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Suricata Ping Detection (ICMP)
# ============================================================

VICTIM_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="${3:-$HOME/.ssh/my_key}"

# RUTAS
RULES_DIR="/var/lib/suricata/rules"
RULE_FILE="$RULES_DIR/nics-ping.rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"

info() { echo "[INFO] $*"; }
ok()   { echo "[OK]   $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

ssh_victim() {
  ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${SSH_USER}@${VICTIM_IP}" "$@"
}

# ------------------------------------------------------------
# Validación inicial
# ------------------------------------------------------------
[[ -n "$VICTIM_IP" ]] || die "Uso: $0 <IP_VICTIMA> [SSH_USER] [SSH_KEY]"
[[ -f "$SSH_KEY" ]] || die "No existe la clave SSH en $SSH_KEY"

ssh_victim "echo connected" >/dev/null || die "No puedo conectar a la víctima en $VICTIM_IP"
info "Conectado a $VICTIM_IP"

# ------------------------------------------------------------
# Verificar Suricata
# ------------------------------------------------------------
ssh_victim "command -v suricata >/dev/null" || die "Suricata no está instalada en el destino"
ssh_victim "test -f '$SURICATA_YAML'" || die "suricata.yaml no encontrado en $SURICATA_YAML"

ok "Suricata detectada"

# ------------------------------------------------------------
# Configurar Directorio y Regla
# ------------------------------------------------------------
ssh_victim "sudo mkdir -p '$RULES_DIR'"

# Escribimos la regla en una sola línea limpia para evitar errores de parseo
RULE_CONTENT='alert icmp any any -> any any (msg:"NICS ICMP Ping Detected"; itype:8; classtype:network-scan; sid:9200001; rev:1;)'

if ssh_victim "grep -q 'sid:9200001' '$RULE_FILE' 2>/dev/null"; then
  ok "Regla ICMP ya existe en $RULE_FILE"
else
  info "Creando regla ICMP (ping)"
  ssh_victim "echo '$RULE_CONTENT' | sudo tee '$RULE_FILE' >/dev/null"
  ssh_victim "sudo chown root:root '$RULE_FILE' && sudo chmod 640 '$RULE_FILE'"
  ok "Regla ICMP creada correctamente"
fi

# ------------------------------------------------------------
# Registrar regla en suricata.yaml
# ------------------------------------------------------------
if ssh_victim "grep -q 'nics-ping.rules' '$SURICATA_YAML'"; then
  ok "Regla ya estaba registrada en suricata.yaml"
else
  info "Registrando nics-ping.rules en suricata.yaml"
  # Insertamos la regla bajo la sección rule-files
  ssh_victim "sudo sed -i '/rule-files:/a \  - nics-ping.rules' '$SURICATA_YAML'"
  ok "Regla registrada"
fi

# ------------------------------------------------------------
# Validación y Reinicio
# ------------------------------------------------------------
info "Validando configuración de Suricata..."
# Capturamos la salida para ver errores si falla
if ssh_victim "sudo suricata -T -c '$SURICATA_YAML'"; then
  ok "Configuración válida"
else
  die "La validación de Suricata falló. Revisa nics-ping.rules"
fi

info "Reiniciando servicio Suricata..."
ssh_victim "sudo systemctl restart suricata"
sleep 3

if ssh_victim "systemctl is-active --quiet suricata"; then
  ok "Suricata está activa y funcionando"
else
  die "Suricata falló al arrancar tras el reinicio"
fi

# ------------------------------------------------------------
# Instrucciones de prueba
# ------------------------------------------------------------
echo "------------------------------------------------------------"
ok "Instalación finalizada con éxito"
info "Para probar la detección:"
info "  1. Desde otra máquina ejecuta: ping -c 4 $VICTIM_IP"
info "  2. En la víctima, verifica el log: sudo grep 9200001 /var/log/suricata/eve.json"
echo "------------------------------------------------------------"