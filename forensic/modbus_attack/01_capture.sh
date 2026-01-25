#!/usr/bin/env bash
set -e

PCAP="modbus_write_attack.pcap"
IFACE="any"

echo "[CAPTURE] Starting tcpdump (20s)..."

sudo timeout 20 tcpdump \
  -i "$IFACE" \
  -nn \
  -s 0 \
  -w "$PCAP" \
  tcp port 502

echo "[CAPTURE] Saved to $PCAP"
