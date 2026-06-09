#!/usr/bin/env bash
# payload: ping_target.sh
TARGET_IP=$1

echo "==========================================="
echo "STARTING ICMP PROBE TO: $TARGET_IP"
echo "==========================================="

# Emit 5 pings with immediate output
ping -c 5 "$TARGET_IP" | while read -r line; do
    echo "[TERMINAL] $line"
done

echo "==========================================="
echo "OPERATION COMPLETED"
