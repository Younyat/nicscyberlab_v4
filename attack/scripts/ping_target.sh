#!/usr/bin/env bash
# payload: ping_target.sh
TARGET_IP=$1

echo "==========================================="
echo "INICIANDO SONDA ICMP HACIA: $TARGET_IP"
echo "==========================================="

# Lanzamos 5 pings con salida inmediata
ping -c 5 "$TARGET_IP" | while read -r line; do
    echo "[TERMINAL] $line"
done

echo "==========================================="
echo "OPERACIÓN FINALIZADA"