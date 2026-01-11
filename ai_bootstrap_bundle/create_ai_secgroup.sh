#!/usr/bin/env bash
set -e

SG_NAME="ai_sg"

echo "[+] Ensuring security group: $SG_NAME"

if ! openstack security group show "$SG_NAME" >/dev/null 2>&1; then
  openstack security group create "$SG_NAME"
  echo "[✓] Security group $SG_NAME created"
else
  echo "[✓] Security group $SG_NAME already exists"
fi

create_rule_safe() {
  local proto="$1"
  local port="$2"

  if [[ -z "${port:-}" ]]; then
    if openstack security group rule create --proto "$proto" "$SG_NAME" >/dev/null 2>&1; then
      echo "[+] Rule added: $proto any"
    else
      echo "[✓] Rule already exists: $proto any"
    fi
  else
    if openstack security group rule create --proto "$proto" --dst-port "$port" "$SG_NAME" >/dev/null 2>&1; then
      echo "[+] Rule added: $proto $port"
    else
      echo "[✓] Rule already exists: $proto $port"
    fi
  fi
}

# Entrada (ingress)
create_rule_safe icmp
create_rule_safe tcp 22     # SSH
create_rule_safe tcp 8000   # llama.cpp API
create_rule_safe tcp 3000   # Open WebUI
