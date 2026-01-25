#!/bin/bash
# ping_target_detecter.sh
# ICMP passive detector – Victim node
# Sends detection events to MONITOR node

set -e

MONITOR_IP="$1"
MONITOR_PORT=9999

echo "[DETECTOR] Host: $(hostname)"
echo "[DETECTOR] Start: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[DETECTOR] Monitor: ${MONITOR_IP}:${MONITOR_PORT}"

# ============================================================
# 1. Checks
# ============================================================
if [ -z "$MONITOR_IP" ]; then
    echo "[ERROR] MONITOR_IP not provided"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Must run as root"
    exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "[INFO] Installing tcpdump..."
    apt-get update -qq && apt-get install -y tcpdump
fi

if ! command -v nc >/dev/null 2>&1; then
    echo "[ERROR] netcat (nc) not installed"
    exit 1
fi

echo "[DETECTOR] ICMP monitoring active"

# ============================================================
# 2. Detection loop (BPF FILTER – CORRECTO)
# ============================================================
tcpdump -l -n -i any 'icmp and icmp[icmptype] = icmp-echo' 2>/dev/null |
while read -r line; do
    TS=$(date '+%Y-%m-%d %H:%M:%S')

    SRC_IP=$(echo "$line" | sed -n 's/^IP \([0-9.]*\) > .*/\1/p')
    DST_IP=$(echo "$line" | sed -n 's/^IP [0-9.]* > \([0-9.]*\):.*/\1/p')

    EVENT=$(printf '{"ts":"%s","src":"%s","dst":"%s","host":"%s","type":"icmp_echo"}' \
        "$TS" "$SRC_IP" "$DST_IP" "$(hostname)")

    echo "[ICMP-DETECTED] $EVENT"

    # Envío TCP delimitado (OBLIGATORIO)
    printf "%s\n" "$EVENT" | nc "$MONITOR_IP" "$MONITOR_PORT" || true
done
