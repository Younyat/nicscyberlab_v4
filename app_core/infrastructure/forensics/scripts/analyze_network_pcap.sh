#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   analyze_network_pcap.sh <CASE_DIR> <PCAP_ABS_PATH>
#
# Salidas:
#   <CASE_DIR>/analysis/network/...

if [[ $# -lt 2 ]]; then
  echo "Uso: $0 <CASE_DIR> <PCAP_ABS_PATH>"
  exit 1
fi

CASE_DIR="$1"
PCAP="$2"

[[ -d "$CASE_DIR" ]] || { echo "No existe CASE_DIR: $CASE_DIR"; exit 1; }
[[ -f "$PCAP" ]] || { echo "No existe PCAP: $PCAP"; exit 1; }

OUT="$CASE_DIR/analysis/network"
mkdir -p "$OUT"

echo "[*] Network analysis => $OUT"
echo "[*] pcap=$PCAP"

# Requisitos: tshark
if ! command -v tshark >/dev/null 2>&1; then
  echo "[ERROR] Falta tshark en el host"
  exit 1
fi

# 1) Top conversaciones
tshark -r "$PCAP" -q -z conv,tcp > "$OUT/conv_tcp.txt" 2> "$OUT/conv_tcp.err" || true
tshark -r "$PCAP" -q -z conv,udp > "$OUT/conv_udp.txt" 2> "$OUT/conv_udp.err" || true
tshark -r "$PCAP" -q -z io,stat,10 > "$OUT/iostat_10s.txt" 2> "$OUT/iostat_10s.err" || true

# 2) Flujos (5-tuple) rápidos
tshark -r "$PCAP" -T fields \
  -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags \
  -E header=y -E separator=, \
  "tcp" > "$OUT/tcp_flows.csv" 2> "$OUT/tcp_flows.err" || true

# 3) Modbus/TCP: listar function codes si wireshark lo decodifica
# (Si no, este fichero quedará vacío y no pasa nada)
tshark -r "$PCAP" -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e modbus.func_code -e modbus.reference_num -e modbus.word_cnt \
  -E header=y -E separator=, \
  "tcp.port==502 && modbus" > "$OUT/modbus_summary.csv" 2> "$OUT/modbus_summary.err" || true

echo "$OUT"
