#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# install_tools_from_json_via_backend.sh
#
# Uso:
#   ./install_tools_from_json_via_backend.sh /ruta/al/archivo_tools.json [BACKEND_URL]
#
# Ejemplo:
#   ./install_tools_from_json_via_backend.sh tools-installer-tmp/attack_2_tools.json
#   ./install_tools_from_json_via_backend.sh tools-installer-tmp/attack_2_tools.json http://127.0.0.1:5000
#
# Qué hace:
#   1. Lee el JSON pasado por parámetro
#   2. Verifica que tenga id, name y tools
#   3. Consulta al backend si existe una instancia con ESE id y ESE name
#   4. Registra el JSON en /api/add_tool_to_instance
#   5. Lanza la instalación con /api/install_tools
#   6. Muestra el stream SSE en consola
#
# Requisitos:
#   - bash
#   - jq
#   - curl
# ============================================================

JSON_FILE="${1:-}"
BACKEND_URL="${2:-http://127.0.0.1:5001}"

if [[ -z "$JSON_FILE" ]]; then
    echo "Uso: $0 <archivo_tools.json> [BACKEND_URL]"
    exit 1
fi

if [[ ! -f "$JSON_FILE" ]]; then
    echo "ERROR: No existe el archivo JSON: $JSON_FILE"
    exit 1
fi

for bin in jq curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "ERROR: Falta dependencia requerida: $bin"
        exit 1
    fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

INSTANCES_JSON="$TMP_DIR/instances.json"
REGISTER_RESP="$TMP_DIR/register_response.json"
INSTALL_STREAM="$TMP_DIR/install_stream.log"

echo "===================================================="
echo " INSTALL TOOLS FROM JSON VIA BACKEND"
echo "===================================================="
echo "JSON_FILE    : $JSON_FILE"
echo "BACKEND_URL  : $BACKEND_URL"
echo

# ------------------------------------------------------------
# 1. Leer y validar JSON de entrada
# ------------------------------------------------------------
INSTANCE_ID="$(jq -r '.id // empty' "$JSON_FILE")"
INSTANCE_NAME="$(jq -r '.name // empty' "$JSON_FILE")"
TOOLS_COUNT="$(jq -r '(.tools // {}) | keys | length' "$JSON_FILE")"

if [[ -z "$INSTANCE_ID" ]]; then
    echo "ERROR: El JSON no contiene '.id'"
    exit 1
fi

if [[ -z "$INSTANCE_NAME" ]]; then
    echo "ERROR: El JSON no contiene '.name'"
    exit 1
fi

if [[ "$TOOLS_COUNT" -eq 0 ]]; then
    echo "ERROR: El JSON no contiene herramientas en '.tools'"
    exit 1
fi

echo "[OK] JSON válido"
echo "  - instance_id   : $INSTANCE_ID"
echo "  - instance_name : $INSTANCE_NAME"
echo "  - tools_count   : $TOOLS_COUNT"
echo

# ------------------------------------------------------------
# 2. Consultar instancias en backend y validar name + id
# ------------------------------------------------------------
echo "[INFO] Consultando instancias en backend..."
HTTP_CODE="$(
    curl -sS -o "$INSTANCES_JSON" -w "%{http_code}" \
        "$BACKEND_URL/api/openstack/instances"
)"

if [[ "$HTTP_CODE" != "200" ]]; then
    echo "ERROR: Falló GET /api/openstack/instances (HTTP $HTTP_CODE)"
    echo "Respuesta:"
    cat "$INSTANCES_JSON" || true
    exit 1
fi

MATCH_COUNT="$(
    jq --arg iid "$INSTANCE_ID" --arg iname "$INSTANCE_NAME" '
        [
            .instances[]
            | select((.id == $iid) and (.name == $iname))
        ] | length
    ' "$INSTANCES_JSON"
)"

if [[ "$MATCH_COUNT" -eq 0 ]]; then
    echo "ERROR: No existe en OpenStack una instancia que coincida con:"
    echo "  - id   : $INSTANCE_ID"
    echo "  - name : $INSTANCE_NAME"
    echo
    echo "Instancias encontradas actualmente:"
    jq -r '.instances[] | "  - \(.id) | \(.name) | \(.status) | \(.ip // "N/A")"' "$INSTANCES_JSON"
    exit 1
fi

INSTANCE_STATUS="$(
    jq --arg iid "$INSTANCE_ID" --arg iname "$INSTANCE_NAME" -r '
        .instances[]
        | select((.id == $iid) and (.name == $iname))
        | .status
    ' "$INSTANCES_JSON" | head -n1
)"

INSTANCE_IP="$(
    jq --arg iid "$INSTANCE_ID" --arg iname "$INSTANCE_NAME" -r '
        .instances[]
        | select((.id == $iid) and (.name == $iname))
        | (.ip // .ip_floating // .ip_private // "N/A")
    ' "$INSTANCES_JSON" | head -n1
)"

echo "[OK] Instancia validada en backend"
echo "  - status : $INSTANCE_STATUS"
echo "  - ip     : $INSTANCE_IP"
echo

if [[ "$INSTANCE_STATUS" != "ACTIVE" ]]; then
    echo "ERROR: La instancia existe pero no está ACTIVE. Estado actual: $INSTANCE_STATUS"
    exit 1
fi

# ------------------------------------------------------------
# 3. Registrar JSON en backend
# ------------------------------------------------------------
echo "[INFO] Registrando definición en /api/add_tool_to_instance ..."

HTTP_CODE="$(
    curl -sS -o "$REGISTER_RESP" -w "%{http_code}" \
        -X POST "$BACKEND_URL/api/add_tool_to_instance" \
        -H "Content-Type: application/json" \
        --data @"$JSON_FILE"
)"

if [[ "$HTTP_CODE" != "200" ]]; then
    echo "ERROR: Falló POST /api/add_tool_to_instance (HTTP $HTTP_CODE)"
    echo "Respuesta:"
    cat "$REGISTER_RESP" || true
    exit 1
fi

REGISTER_STATUS="$(jq -r '.status // empty' "$REGISTER_RESP")"
if [[ "$REGISTER_STATUS" != "success" ]]; then
    echo "ERROR: El backend no aceptó el JSON"
    cat "$REGISTER_RESP"
    exit 1
fi

echo "[OK] JSON registrado correctamente en tools-installer-tmp"
echo

# ------------------------------------------------------------
# 4. Preparar payload para /api/install_tools
#    Importante: este endpoint espera lista de nombres de tools
# ------------------------------------------------------------
INSTALL_PAYLOAD="$TMP_DIR/install_payload.json"

jq '{
    instance: .name,
    instance_id: .id,
    tools: (.tools | keys)
}' "$JSON_FILE" > "$INSTALL_PAYLOAD"

echo "[INFO] Payload de instalación:"
cat "$INSTALL_PAYLOAD"
echo
echo "[INFO] Lanzando instalación vía /api/install_tools ..."
echo "----------------------------------------------------"

# ------------------------------------------------------------
# 5. Consumir el stream SSE de instalación
# ------------------------------------------------------------
# -N para no bufferizar
# Mostramos solo las líneas que vienen con "data:"
# y quitamos el prefijo para que se vea limpio.
curl -sS -N \
    -X POST "$BACKEND_URL/api/install_tools" \
    -H "Content-Type: application/json" \
    --data @"$INSTALL_PAYLOAD" | tee "$INSTALL_STREAM" | while IFS= read -r line; do
        if [[ "$line" == data:* ]]; then
            echo "${line#data: }"
        fi
    done

echo "----------------------------------------------------"

# ------------------------------------------------------------
# 6. Verificación básica final
# ------------------------------------------------------------
if grep -q "\[FIN\] Exit Code: 0" "$INSTALL_STREAM"; then
    echo "[OK] Instalación completada correctamente."
    exit 0
fi

echo "[ERROR] La instalación terminó con error o no devolvió éxito limpio."
echo "Revisa también los logs del backend y tools-installer/logs/"
exit 1