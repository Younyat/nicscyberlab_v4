#!/usr/bin/env bash
set -euo pipefail
trap 'echo " ERROR en línea ${LINENO}" >&2' ERR

echo "===================================================="
echo " TOOLS INSTALLER MASTER (State-Aware Orchestrator)"
echo "===================================================="

# --- Rutas de Trabajo ---
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_JSON_DIR="$BASE_DIR/tools-installer-tmp"
TOOLS_SCRIPTS_DIR="$BASE_DIR/tools-installer/scripts"
LOGS_DIR="$BASE_DIR/tools-installer/logs"
ADMIN_OPENRC="$BASE_DIR/admin-openrc.sh"

mkdir -p "$LOGS_DIR"

# --- Cargar Entorno OpenStack ---
if [[ -f "$ADMIN_OPENRC" ]]; then 
    source "$ADMIN_OPENRC"
    echo " [OK] Credenciales OpenStack cargadas."
else 
    echo "ERROR: No se encontró admin-openrc.sh"; exit 1
fi

cd "$TOOLS_JSON_DIR"

# --- Bucle Principal ---
for FILE in *_tools.json; do
    [[ -f "$FILE" ]] || continue

    INSTANCE=$(jq -r '.name' "$FILE")
    TOOLS=$(jq -r '.tools | keys[]' "$FILE")
    IP=$(jq -r '.ip_floating // .ip_private' "$FILE")

    echo ">>> Analizando Instancia: $INSTANCE ($IP)"

    # 1. Detección Segura de Usuario SSH
    # Evitamos error de jq si openstack falla
    RAW_INFO=$(openstack server show "$INSTANCE" -f json 2>/dev/null || echo "ERROR")
    
    if [[ "$RAW_INFO" == "ERROR" ]]; then
        echo " [WARN] No se pudo obtener info de OpenStack para $INSTANCE. Usando debian."
        USER_SSH="debian"
    else
        IMAGE_NAME=$(echo "$RAW_INFO" | jq -r '.image // .image_name // "unknown"')
        if echo "$IMAGE_NAME" | grep -qi "ubuntu"; then
            USER_SSH="ubuntu"
        else
            USER_SSH="debian"
        fi
    fi
    echo " [INFO] Usuario para conexión: $USER_SSH"

    # 2. Bucle de Herramientas
    for TOOL in $TOOLS; do
        CURRENT_STATUS=$(jq -r ".tools.\"$TOOL\"" "$FILE")

        if [[ "$CURRENT_STATUS" == "installed" ]]; then
            echo "    [SKIPPED] $TOOL ya instalada."
            continue
        fi

        SCRIPT_PATH="$TOOLS_SCRIPTS_DIR/install_${TOOL}.sh"
        LOG_FILE="$LOGS_DIR/${INSTANCE}_${TOOL}.log"

        if [[ -f "$SCRIPT_PATH" ]]; then
            chmod +x "$SCRIPT_PATH"
            echo "    [INSTALLING] Orquestando $TOOL localmente..."
            
            # Ejecución local: Pasamos IP y Usuario al script
            if bash "$SCRIPT_PATH" "$IP" "$USER_SSH" >"$LOG_FILE" 2>&1; then
                NEW_STATUS="installed"
                echo "    [SUCCESS] $TOOL completado."
            else
                NEW_STATUS="error"
                echo "    [ERROR] Ver log en: $LOG_FILE"
            fi

            # 3. Actualización JSON
            jq ".tools.\"$TOOL\" = \"$NEW_STATUS\"" "$FILE" > "${FILE}.tmp" && mv "${FILE}.tmp" "$FILE"
        else
            echo "    [ERROR] No existe: $SCRIPT_PATH"
        fi
    done
    echo "----------------------------------------------------"
done

echo "===================================================="
echo " PROCESO FINALIZADO"
echo "===================================================="