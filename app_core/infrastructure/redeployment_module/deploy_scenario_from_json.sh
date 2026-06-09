#!/usr/bin/env bash
set -euo pipefail

trap 'echo "[ERROR] Fallo en línea ${LINENO}" >&2' ERR

# ============================================================
# deploy_scenario_from_json.sh
#
# Qué hace:
#   1. Lee un scenario JSON
#   2. Ignora properties.ip de todos los nodos
#   3. Ejecuta el despliegue usando el generador actual
#   4. Consulta OpenStack al final
#   5. Muestra resumen con IP privada y flotante por instancia
#
# Uso:
#   bash deploy_scenario_from_json.sh scenario_file.json
#   bash deploy_scenario_from_json.sh /ruta/completa/scenario_file.json
# ============================================================

SCENARIO_JSON_INPUT="${1:-}"

if [[ -z "$SCENARIO_JSON_INPUT" ]]; then
    echo "Uso: $0 <scenario_json>"
    exit 1
fi

for bin in jq openstack; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[ERROR] Falta dependencia requerida: $bin"
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_repo_root() {
    local dir="$1"

    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/admin-openrc.sh" && -f "$dir/scenario/main_generator_inicial_openstack.sh" ]]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done

    return 1
}

REPO_ROOT="$(find_repo_root "$SCRIPT_DIR")" || {
    echo "[ERROR] No se pudo localizar automáticamente la raíz del proyecto"
    exit 1
}

ADMIN_OPENRC="$REPO_ROOT/admin-openrc.sh"
GENERATOR_SCRIPT="$REPO_ROOT/scenario/main_generator_inicial_openstack.sh"
TF_OUT_DIR="$REPO_ROOT/tf_out"

resolve_json_path() {
    local input="$1"

    if [[ -f "$input" ]]; then
        cd "$(dirname "$input")" && pwd
        return 0
    fi

    if [[ -f "$SCRIPT_DIR/$input" ]]; then
        cd "$SCRIPT_DIR/$(dirname "$input")" && pwd
        return 0
    fi

    if [[ -f "$REPO_ROOT/scenario/$input" ]]; then
        cd "$REPO_ROOT/scenario/$(dirname "$input")" && pwd
        return 0
    fi

    return 1
}

if [[ -f "$SCENARIO_JSON_INPUT" ]]; then
    SCENARIO_JSON="$(cd "$(dirname "$SCENARIO_JSON_INPUT")" && pwd)/$(basename "$SCENARIO_JSON_INPUT")"
elif [[ -f "$SCRIPT_DIR/$SCENARIO_JSON_INPUT" ]]; then
    SCENARIO_JSON="$SCRIPT_DIR/$SCENARIO_JSON_INPUT"
elif [[ -f "$REPO_ROOT/scenario/$SCENARIO_JSON_INPUT" ]]; then
    SCENARIO_JSON="$REPO_ROOT/scenario/$SCENARIO_JSON_INPUT"
else
    echo "[ERROR] No existe el archivo JSON: $SCENARIO_JSON_INPUT"
    exit 1
fi

if [[ ! -f "$ADMIN_OPENRC" ]]; then
    echo "[ERROR] No se encontró: $ADMIN_OPENRC"
    exit 1
fi

if [[ ! -f "$GENERATOR_SCRIPT" ]]; then
    echo "[ERROR] No se encontró: $GENERATOR_SCRIPT"
    exit 1
fi

mkdir -p "$TF_OUT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CLEAN_JSON="$TMP_DIR/scenario_clean.json"
NODES_FILE="$TMP_DIR/nodes.txt"

echo "===================================================="
echo " DEPLOY SCENARIO FROM JSON"
echo "===================================================="
echo "SCRIPT_DIR    : $SCRIPT_DIR"
echo "REPO_ROOT     : $REPO_ROOT"
echo "SCENARIO_JSON : $SCENARIO_JSON"
echo

NODE_COUNT="$(jq -r '.nodes | length' "$SCENARIO_JSON" 2>/dev/null || echo 0)"

if [[ "$NODE_COUNT" -eq 0 ]]; then
    echo "[ERROR] El JSON no contiene nodos válidos."
    exit 1
fi

jq -r '.nodes[].name' "$SCENARIO_JSON" > "$NODES_FILE"

echo "[OK] JSON válido"
echo "Nodos detectados: $NODE_COUNT"
echo

jq '
  .nodes |= map(
    if has("properties") and (.properties | type == "object")
    then .properties |= del(.ip)
    else .
    end
  )
' "$SCENARIO_JSON" > "$CLEAN_JSON"

echo "[OK] Se generó copia temporal sin properties.ip"
echo "Archivo temporal: $CLEAN_JSON"
echo

# shellcheck disable=SC1090
source "$ADMIN_OPENRC"
echo "[OK] Credenciales OpenStack cargadas"
echo

chmod +x "$GENERATOR_SCRIPT"

echo "===================================================="
echo " INICIANDO DESPLIEGUE"
echo "===================================================="
echo

bash "$GENERATOR_SCRIPT" "$CLEAN_JSON" "$TF_OUT_DIR"

echo
echo "===================================================="
echo " DESPLIEGUE FINALIZADO"
echo "===================================================="
echo

sleep 5

echo "===================================================="
echo " RESUMEN DE INSTANCIAS DESPLEGADAS"
echo "===================================================="
echo

while IFS= read -r INSTANCE_NAME; do
    [[ -n "$INSTANCE_NAME" ]] || continue

    echo ">>> $INSTANCE_NAME"

    RAW_INFO="$(openstack server show "$INSTANCE_NAME" -f json 2>/dev/null || true)"

    if [[ -z "$RAW_INFO" ]]; then
        echo "    [ERROR] No se pudo consultar esta instancia en OpenStack"
        echo
        continue
    fi

    INSTANCE_ID="$(echo "$RAW_INFO" | jq -r '.id // "N/A"')"
    STATUS="$(echo "$RAW_INFO" | jq -r '.status // "N/A"')"
    FLAVOR="$(echo "$RAW_INFO" | jq -r '.flavor // .flavor_name // "N/A"')"
    IMAGE="$(echo "$RAW_INFO" | jq -r '.image // .image_name // "N/A"')"

    IP_PRIVATE="N/A"
    IP_FLOATING="N/A"

    ADDRESSES_STR="$(echo "$RAW_INFO" | jq -r '.addresses // empty')"

    if [[ -n "$ADDRESSES_STR" ]]; then
        mapfile -t IPS < <(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$ADDRESSES_STR" || true)

        if [[ "${#IPS[@]}" -ge 1 ]]; then
            IP_PRIVATE="${IPS[0]}"
        fi
        if [[ "${#IPS[@]}" -ge 2 ]]; then
            IP_FLOATING="${IPS[1]}"
        fi
    fi

    echo "    id          : $INSTANCE_ID"
    echo "    status      : $STATUS"
    echo "    image       : $IMAGE"
    echo "    flavor      : $FLAVOR"
    echo "    ip_private  : $IP_PRIVATE"
    echo "    ip_floating : $IP_FLOATING"
    echo
done < "$NODES_FILE"

echo "===================================================="
echo " FIN"
echo "===================================================="