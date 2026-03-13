#!/usr/bin/env bash

TARGET_IP=$1

echo "==========================================="
echo "RECONNAISSANCE PHASE - PORT SCAN"
echo "==========================================="

echo "[INFO] Target: $TARGET_IP"
echo "[INFO] Starting Nmap scan..."

if ! command -v nmap >/dev/null 2>&1; then
    echo "[ERROR] nmap not installed on attacker node"
    exit 1
fi

nmap -sS -p 1-1024 "$TARGET_IP" | while read line
do
    echo "[NMAP] $line"
done

echo "==========================================="
echo "PORT SCAN COMPLETED"
echo "==========================================="