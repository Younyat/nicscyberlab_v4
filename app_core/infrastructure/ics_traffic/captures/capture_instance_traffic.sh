#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Uso: $0 <NOMBRE_INSTANCIA_O_ID> <DURACION_SEGUNDOS>"
  exit 1
fi

INSTANCE="$1"
DURATION="$2"

OUT_DIR="./captures"
mkdir -p "$OUT_DIR"

BPF_EXTRA="${BPF_EXTRA:-}"               # ejemplo: 'and (tcp port 502)'
UTC_TS="$(date -u +%Y%m%d_%H%M%SZ)"
PCAP="$OUT_DIR/${INSTANCE}_${UTC_TS}.pcap"
META="$OUT_DIR/${INSTANCE}_${UTC_TS}.metadata.json"
SHA_FILE="$OUT_DIR/${INSTANCE}_${UTC_TS}.sha256"

# 1) Resolver VM_ID (si pasas nombre, esto te lo convierte)
VM_ID="$(openstack server show "$INSTANCE" -f value -c id 2>/dev/null || true)"
if [[ -z "$VM_ID" ]]; then
  echo "No se pudo resolver VM_ID para '$INSTANCE'"
  exit 1
fi

# 2) Obtener IPs (pueden venir múltiples)
ADDRS_RAW="$(openstack server show "$VM_ID" -f value -c addresses || true)"
INSTANCE_IPS="$(echo "$ADDRS_RAW" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | tr '\n' ' ')"

if [[ -z "${INSTANCE_IPS// }" ]]; then
  echo "No se pudo obtener IPv4 de la instancia. addresses='$ADDRS_RAW'"
  exit 1
fi

# 3) Obtener PORT_ID y derivar iface tap{short}
PORT_ID="$(openstack port list --server "$VM_ID" -f value -c ID | head -n 1 || true)"
IFACE="${IFACE:-}"

if [[ -z "$IFACE" ]]; then
  if [[ -n "$PORT_ID" ]]; then
    SHORT="${PORT_ID:0:11}"
    if [[ -d "/sys/class/net/tap${SHORT}" ]]; then
      IFACE="tap${SHORT}"
    elif [[ -d "/sys/class/net/qvo${SHORT}" ]]; then
      IFACE="qvo${SHORT}"
    else
      # último recurso
      IFACE="any"
    fi
  else
    IFACE="any"
  fi
fi

# 4) Construir filtro BPF: (host ip1 or host ip2 ...) [and extra]
HOST_FILTER=""
for ip in $INSTANCE_IPS; do
  if [[ -z "$HOST_FILTER" ]]; then
    HOST_FILTER="host $ip"
  else
    HOST_FILTER="$HOST_FILTER or host $ip"
  fi
done

BPF="($HOST_FILTER)"
if [[ -n "$BPF_EXTRA" ]]; then
  BPF="$BPF $BPF_EXTRA"
fi

echo "[+] Capturando tráfico de $INSTANCE (vm_id=$VM_ID, port_id=${PORT_ID:-N/A}) durante $DURATION s"
echo "    IFACE=$IFACE"
echo "    BPF =$BPF"
echo "    OUT =$PCAP"

# 5) Guardar metadatos (mínimo DFIR)
cat > "$META" <<EOF
{
  "instance": "$INSTANCE",
  "vm_id": "$VM_ID",
  "port_id": "${PORT_ID:-}",
  "addresses_raw": $(python3 - <<PY
import json
print(json.dumps("""$ADDRS_RAW"""))
PY
),
  "instance_ipv4": $(python3 - <<PY
import json
print(json.dumps("""$INSTANCE_IPS""".strip()))
PY
),
  "iface": "$IFACE",
  "bpf": $(python3 - <<PY
import json
print(json.dumps("""$BPF"""))
PY
),
  "start_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_s": $DURATION
}
EOF

# 6) Captura limpia: SIGINT para que tcpdump cierre PCAP correctamente
timeout -s INT "$DURATION" tcpdump -U -i "$IFACE" -n "$BPF" -w "$PCAP" >/dev/null 2>&1 || true

END_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 7) Hash de integridad (primario)
sha256sum "$PCAP" | tee "$SHA_FILE" >/dev/null

# 8) Completar metadatos finales
tmp_meta="${META}.tmp"
jq --arg end "$END_UTC" --arg sha "$(cut -d' ' -f1 "$SHA_FILE")" \
  '. + { "end_utc": $end, "sha256": $sha, "pcap_file": "'"$(basename "$PCAP")"'" }' \
  "$META" > "$tmp_meta" && mv "$tmp_meta" "$META" 2>/dev/null || true

echo "[OK] Captura guardada en $PCAP"
echo "[OK] Metadata: $META"
echo "[OK] SHA-256 : $(cut -d' ' -f1 "$SHA_FILE")"
echo "$PCAP"
