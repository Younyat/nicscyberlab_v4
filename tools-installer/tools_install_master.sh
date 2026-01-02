#!/usr/bin/env bash
set -euo pipefail
trap 'echo " ERROR en línea ${LINENO}" >&2' ERR

echo "===================================================="
echo " TOOLS INSTALLER MASTER INIT (State-Aware Version)"
echo "===================================================="

# ====================================================
#  Obtener directorio raíz (donde está la app)
# ====================================================
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_JSON_DIR="$BASE_DIR/tools-installer-tmp"
TOOLS_SCRIPTS_DIR="$BASE_DIR/tools-installer/scripts"
LOGS_DIR="$BASE_DIR/tools-installer/logs"

mkdir -p "$LOGS_DIR"

echo " BASE_DIR:              $BASE_DIR"
echo " JSON Tools Directory: $TOOLS_JSON_DIR"
echo " Scripts Directory:    $TOOLS_SCRIPTS_DIR"
echo " Logs Directory:       $LOGS_DIR"
echo "----------------------------------------------------"

# ====================================================
#  Validar carpeta JSON
# ====================================================
if [[ ! -d "$TOOLS_JSON_DIR" ]]; then
    echo " ERROR: No existe $TOOLS_JSON_DIR"
    exit 1
fi

cd "$TOOLS_JSON_DIR"


# ====================================================
#  Verificar dependencias básicas
# ====================================================
echo " Comprobando dependencias..."

REQUIRED_PKGS=("jq" "ssh" "scp" "openstack")

for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        echo " ERROR: Falta '$pkg'"
        echo " Instala con: sudo apt install -y $pkg"
        exit 1
    fi
done

echo " Dependencias OK"
echo "----------------------------------------------------"


# ====================================================
#  Cargar admin-openrc antes de usar openstack
# ====================================================
ADMIN_OPENRC="$BASE_DIR/admin-openrc.sh"

if [[ -f "$ADMIN_OPENRC" ]]; then
    source "$ADMIN_OPENRC"
    echo " Credenciales OpenStack cargadas."
else
    echo " ERROR: No existe $ADMIN_OPENRC"
    exit 1
fi

# ====================================================
#  Validar variables OpenStack
# ====================================================
REQUIRED_VARS=(
    OS_AUTH_URL OS_USERNAME OS_PASSWORD
    OS_PROJECT_NAME OS_USER_DOMAIN_NAME OS_PROJECT_DOMAIN_NAME
)

for v in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!v:-}" ]]; then
        echo " ERROR: Falta variable de entorno '$v'."
        echo " Asegúrate de ejecutar correctamente admin-openrc.sh"
        exit 1
    fi
done

echo " Variables OpenStack OK"
echo "----------------------------------------------------"


# ====================================================
#  Buscar SSH key
# ====================================================
echo " Buscando clave SSH disponible..."

SSH_KEY=""

# Buscar ficheros privados válidos
for CANDIDATE in \
    "$HOME/.ssh/my_key" \
; do
    if [[ -f "$CANDIDATE" ]] && grep -q "PRIVATE KEY" "$CANDIDATE" 2>/dev/null; then
        SSH_KEY="$CANDIDATE"
        break
    fi
done

if [[ -z "$SSH_KEY" ]]; then
    echo " ERROR: No se encontró ninguna clave privada válida en ~/.ssh"
    exit 1
fi

echo " Clave detectada: $SSH_KEY"
chmod 600 "$SSH_KEY"

echo " Usando llave SSH: $SSH_KEY"
echo "----------------------------------------------------"


# ====================================================
#  PROCESADO DE JSONS
# ====================================================
echo " Buscando JSON de herramientas..."
echo ""

FILES_FOUND=false

for FILE in *_tools.json; do
    [[ -f "$FILE" ]] || continue
    FILES_FOUND=true

    echo "===================================================="
    echo " Detectado archivo: $FILE"

    # -------------------------------------------
    # Validación mínima JSON
    # -------------------------------------------
    for field in name tools; do
        if ! jq -e ".${field}" "$FILE" >/dev/null 2>&1; then
            echo " ERROR: $FILE no tiene '$field'"
            continue 2
        fi
    done

    INSTANCE=$(jq -r '.name' "$FILE")
    
    # --- CAMBIO AQUÍ: Obtenemos las llaves del objeto 'tools' ---
    TOOLS=$(jq -r '.tools | keys[]' "$FILE")


    echo " Instancia: $INSTANCE"

    FLOATING_IP=$(jq -r '.ip_floating // empty' "$FILE")
    PRIVATE_IP=$(jq -r '.ip_private // empty' "$FILE")

    [[ -n "$FLOATING_IP" ]] && IP="$FLOATING_IP" || IP="$PRIVATE_IP"

    if [[ -z "$IP" ]]; then
        echo " ERROR: No IP válida encontrada en $FILE"
        continue
    fi

    echo " IP usada para conexión: $IP"


    # ====================================================
    #  Detectar imagen y usuario correcto
    # ====================================================
    RAW_IMAGE=$(openstack server show "$INSTANCE" -f json | jq -r '.image')

    if echo "$RAW_IMAGE" | jq empty 2>/dev/null; then
        IMAGE_NAME=$(echo "$RAW_IMAGE" | jq -r '.name')
    else
        IMAGE_NAME="$RAW_IMAGE"
    fi

    echo " Imagen detectada: $IMAGE_NAME"

    if echo "$IMAGE_NAME" | grep -qi "ubuntu"; then
        POSSIBLE_USERS=("ubuntu" "debian")
    elif echo "$IMAGE_NAME" | grep -qi "debian"; then
        POSSIBLE_USERS=("debian" "ubuntu")
    else
        POSSIBLE_USERS=("ubuntu" "debian")
    fi

    USER=""
    for u in "${POSSIBLE_USERS[@]}"; do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$SSH_KEY" "$u@$IP" "echo ok" >/dev/null 2>&1; then
            USER="$u"
            break
        fi
    done

    if [[ -z "$USER" ]]; then
        echo " ERROR: No fue posible conectar vía SSH a $IP."
        continue
    fi

    echo " Usuario SSH detectado: $USER"
    echo "----------------------------------------------------"


    # ====================================================
    #  Instalación por herramienta
    # ====================================================
    for TOOL in $TOOLS; do
        
        # --- CAMBIO AQUÍ: Leer estado actual ---
        CURRENT_STATUS=$(jq -r ".tools.\"$TOOL\"" "$FILE")
        
        echo " Revisando herramienta: $TOOL (Estado actual: $CURRENT_STATUS)"

        if [[ "$CURRENT_STATUS" == "installed" ]]; then
            echo " [AVISO] $TOOL ya está instalada. Saltando..."
            continue
        fi

        INSTALL_SCRIPT_LOCAL="$TOOLS_SCRIPTS_DIR/install_${TOOL}.sh"
        TOOL_DIR_LOCAL="$BASE_DIR/tools-installer/${TOOL}"
        TOOL_DIR_REMOTE="/opt/tools/${TOOL}"

        LOG_FILE="$LOGS_DIR/${INSTANCE}_${TOOL}_install.log"
        echo " Log → $LOG_FILE"

        if [[ ! -f "$INSTALL_SCRIPT_LOCAL" ]]; then
            echo " ERROR: Falta script de instalación: $INSTALL_SCRIPT_LOCAL"
            continue
        fi

        if [[ ! -x "$INSTALL_SCRIPT_LOCAL" ]]; then
            chmod +x "$INSTALL_SCRIPT_LOCAL"
        fi

        echo " Preparando entorno remoto para $TOOL..."
        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" "sudo mkdir -p $TOOL_DIR_REMOTE"

        if [[ -d "$TOOL_DIR_LOCAL" ]]; then
            scp -o StrictHostKeyChecking=no -i "$SSH_KEY" -r "$TOOL_DIR_LOCAL/" "$USER@$IP:$TOOL_DIR_REMOTE/"
        fi

        scp -o StrictHostKeyChecking=no -i "$SSH_KEY" "$INSTALL_SCRIPT_LOCAL" "$USER@$IP:/tmp/"

        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" "
            sudo chmod -R 755 $TOOL_DIR_REMOTE || true
            sudo chmod +x /tmp/install_${TOOL}.sh || true
            sudo chmod +x $TOOL_DIR_REMOTE/installer.sh 2>/dev/null || true
        "

        # Ejecución
        INSTALL_SUCCESS=true
        if ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" "[ -f $TOOL_DIR_REMOTE/installer.sh ]"; then
            echo " Ejecutando installer.sh..."
            ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" "cd $TOOL_DIR_REMOTE && sudo bash ./installer.sh \"$IP\"" >"$LOG_FILE" 2>&1 || INSTALL_SUCCESS=false
        else
            echo " Ejecutando install_${TOOL}.sh..."
            ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" "sudo bash /tmp/install_${TOOL}.sh \"$IP\"" >"$LOG_FILE" 2>&1 || INSTALL_SUCCESS=false
        fi

        # Validación
        case "$TOOL" in
            suricata) CHECK_CMD="suricata -V" ;;
            snort)    CHECK_CMD="snort -V" ;;
            wazuh)    CHECK_CMD="systemctl is-active wazuh-manager" ;;
            caldera)  CHECK_CMD="ss -tunlp | grep -q ':8888'" ;;
            *)        CHECK_CMD="which $TOOL" ;;
        esac

        if [[ "$INSTALL_SUCCESS" == true ]] && ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" "$CHECK_CMD" >/dev/null 2>&1; then
            echo " Instalación CONFIRMADA: $TOOL"
            NEW_STATUS="installed"
        else
            echo " ERROR DE INSTALACIÓN: $TOOL"
            NEW_STATUS="error"
        fi

        # --- CAMBIO AQUÍ: Actualización del JSON ---
        jq ".tools.\"$TOOL\" = \"$NEW_STATUS\"" "$FILE" > "${FILE}.tmp" && mv "${FILE}.tmp" "$FILE"
        echo " Estado actualizado en $FILE a: $NEW_STATUS"
        echo "----------------------------------------------------"

    done  # <-- CIERRA for TOOL

done  # <-- CIERRA for FILE


if [[ "$FILES_FOUND" == false ]]; then
    echo " No se encontraron JSONs en $TOOLS_JSON_DIR"
fi

echo ""
echo "===================================================="
echo " PROCESO COMPLETO FINALIZADO"
echo "===================================================="