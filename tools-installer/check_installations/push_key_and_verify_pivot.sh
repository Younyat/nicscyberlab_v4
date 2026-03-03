#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Push my_key to attacker + verify pivot to victim
# - Copia ~/.ssh/my_key y ~/.ssh/my_key.pub al attacker:/home/debian/.ssh/
# - Ajusta permisos en attacker
# - Verifica:
#     1) existe /home/debian/.ssh/my_key en attacker
#     2) desde attacker, SSH a victim con esa key (host key check desactivado)
# ============================================================

ATTACKER_IP="${ATTACKER_IP:-${1:-}}"
VICTIM_IP="${VICTIM_IP:-${2:-}}"

LOCAL_KEY="${LOCAL_KEY:-$HOME/.ssh/my_key}"
LOCAL_PUB="${LOCAL_PUB:-$HOME/.ssh/my_key.pub}"

ATTACKER_USER="${ATTACKER_USER:-debian}"
ATTACKER_SSH_DIR="/home/${ATTACKER_USER}/.ssh"
REMOTE_KEY="${ATTACKER_SSH_DIR}/my_key"
REMOTE_PUB="${ATTACKER_SSH_DIR}/my_key.pub"

# Victim user (por defecto debian; si quieres ubuntu, exporta VICTIM_USER=ubuntu)
VICTIM_USER="${VICTIM_USER:-debian}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"

die(){ echo "[ERROR] $*" >&2; exit 1; }
ok(){ echo "[OK] $*"; }
info(){ echo "[INFO] $*"; }

[[ -n "${ATTACKER_IP}" ]] || die "Uso: $0 <ATTACKER_IP> <VICTIM_IP>  (o exporta ATTACKER_IP / VICTIM_IP)"
[[ -n "${VICTIM_IP}"   ]] || die "Uso: $0 <ATTACKER_IP> <VICTIM_IP>  (o exporta ATTACKER_IP / VICTIM_IP)"

[[ -f "${LOCAL_KEY}" ]] || die "No existe ${LOCAL_KEY}"
[[ -f "${LOCAL_PUB}" ]] || die "No existe ${LOCAL_PUB}"

info "1) Asegurando .ssh existe en attacker (${ATTACKER_USER}@${ATTACKER_IP})"
ssh -i "${LOCAL_KEY}" ${SSH_OPTS} "${ATTACKER_USER}@${ATTACKER_IP}" "mkdir -p '${ATTACKER_SSH_DIR}'"

info "2) Copiando my_key y my_key.pub al attacker:${ATTACKER_SSH_DIR}/"
scp -i "${LOCAL_KEY}" ${SSH_OPTS} \
  "${LOCAL_KEY}" "${LOCAL_PUB}" \
  "${ATTACKER_USER}@${ATTACKER_IP}:${ATTACKER_SSH_DIR}/"

info "3) Ajustando permisos en attacker"
ssh -i "${LOCAL_KEY}" ${SSH_OPTS} "${ATTACKER_USER}@${ATTACKER_IP}" \
  "chmod 700 '${ATTACKER_SSH_DIR}' && chmod 600 '${REMOTE_KEY}' && chmod 644 '${REMOTE_PUB}'"

info "4) Verificando que existe ${REMOTE_KEY} en attacker"
ssh -i "${LOCAL_KEY}" ${SSH_OPTS} "${ATTACKER_USER}@${ATTACKER_IP}" \
  "test -f '${REMOTE_KEY}' && ls -l '${REMOTE_KEY}'" \
  && ok "Key presente en attacker: ${REMOTE_KEY}"

info "5) Verificando pivot: attacker -> victim (${VICTIM_USER}@${VICTIM_IP}) usando ${REMOTE_KEY}"
ssh -i "${LOCAL_KEY}" ${SSH_OPTS} "${ATTACKER_USER}@${ATTACKER_IP}" \
  "ssh -i '${REMOTE_KEY}' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 '${VICTIM_USER}@${VICTIM_IP}' 'echo OK_FROM_VICTIM'" \
  && ok "Pivot OK: attacker puede acceder a victim con la key"

ok "Todo correcto."