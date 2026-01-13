#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Uso: $0 <NOMBRE_INSTANCIA> <DURACION_SEGUNDOS>"
  exit 1
fi

INSTANCE_NAME="$1"
DURATION="$2"
OUT_DIR="./captures"
mkdir -p "$OUT_DIR"

# Obtener IP de la instancia
INSTANCE_IP=$(openstack server show "$INSTANCE_NAME" -f value -c addresses | awk -F= '{print $2}')

if [[ -z "$INSTANCE_IP" ]]; then
  echo "No se pudo obtener IP de la instancia"
  exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
PCAP="$OUT_DIR/${INSTANCE_NAME}_${TS}.pcap"

echo "[+] Capturando tráfico de $INSTANCE_NAME ($INSTANCE_IP) durante $DURATION s"

sudo timeout "$DURATION" tcpdump -i any host "$INSTANCE_IP" -w "$PCAP"

echo "[OK] Captura guardada en $PCAP"
echo "$PCAP"
