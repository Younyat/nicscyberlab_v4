#!/usr/bin/env bash

TARGET_IP="${1:-}"

if [[ -z "$TARGET_IP" ]]; then
    echo "[ERROR] Usage: $0 <TARGET_IP>"
    exit 1
fi

echo "==========================================="
echo "RECONNAISSANCE PHASE - NOISY PORT SCAN"
echo "==========================================="

echo "[INFO] Target: $TARGET_IP"
echo "[INFO] Starting noisy Nmap scan..."

if ! command -v nmap >/dev/null 2>&1; then
    echo "[ERROR] nmap not installed on attacker node"
    exit 1
fi

if ! nmap -sT -Pn -n --max-retries 0 --min-rate 1000 -T4 -p 1-65535 "$TARGET_IP" | while IFS= read -r line
do
    echo "[NMAP] $line"
done
then
    echo "[ERROR] Nmap scan failed"
    exit 1
fi

echo "==========================================="
echo "NOISY PORT SCAN COMPLETED"
echo "==========================================="