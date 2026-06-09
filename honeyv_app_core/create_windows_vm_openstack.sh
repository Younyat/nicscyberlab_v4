#!/usr/bin/env bash
set -euo pipefail

trap 'echo "[ERROR] Fallo en la línea ${LINENO}" >&2' ERR

# ============================================================
# create_windows_vm_openstack.sh
#
# Crea una máquina virtual Windows en OpenStack.
#
# Requisitos:
#   - CLI de OpenStack instalada
#   - Credenciales cargadas previamente:
#       source admin-openrc.sh
#     o
#       source openrc.sh
#
# Uso:
#   bash create_windows_vm_openstack.sh
#
# Opcional:
#   puedes exportar variables antes de ejecutarlo, por ejemplo:
#
#   export VM_NAME="win-analysis-01"
#   export IMAGE_NAME="Windows-Server-2019"
#   export FLAVOR_NAME="m1.large"
#   export NETWORK_NAME="private-net"
#   export KEY_NAME="my_key"
#   export SECURITY_GROUP="default"
#   export BOOT_VOLUME_SIZE="60"
#   export FLOATING_NETWORK="public"
#   export ASSIGN_FLOATING_IP="yes"
#
# ============================================================

# -----------------------------
# CONFIGURACIÓN
# -----------------------------
VM_NAME="${VM_NAME:-windows-analysis-01}"
IMAGE_NAME="${IMAGE_NAME:-Windows-Server-2019}"
FLAVOR_NAME="${FLAVOR_NAME:-m1.large}"
NETWORK_NAME="${NETWORK_NAME:-private-net}"
KEY_NAME="${KEY_NAME:-my_key}"
SECURITY_GROUP="${SECURITY_GROUP:-default}"

# Tamaño del volumen de arranque en GB
BOOT_VOLUME_SIZE="${BOOT_VOLUME_SIZE:-60}"

# Red externa para floating IP
FLOATING_NETWORK="${FLOATING_NETWORK:-public}"

# yes / no
ASSIGN_FLOATING_IP="${ASSIGN_FLOATING_IP:-yes}"

# Espera máxima en segundos
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-600}"
SLEEP_INTERVAL="${SLEEP_INTERVAL:-5}"

# Nombre del volumen bootable
BOOT_VOLUME_NAME="${BOOT_VOLUME_NAME:-${VM_NAME}-boot}"

# -----------------------------
# FUNCIONES
# -----------------------------
log() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "No se encontró el comando requerido: $1"
}

resource_exists() {
    local cmd="$1"
    if eval "$cmd" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

wait_for_server_status() {
    local server_name="$1"
    local desired_status="$2"
    local waited=0
    local current_status=""

    while (( waited < MAX_WAIT_SECONDS )); do
        current_status="$(openstack server show "$server_name" -f value -c status 2>/dev/null || true)"

        if [[ "$current_status" == "$desired_status" ]]; then
            log "La instancia '$server_name' alcanzó el estado '$desired_status'."
            return 0
        fi

        if [[ "$current_status" == "ERROR" ]]; then
            die "La instancia '$server_name' entró en estado ERROR."
        fi

        sleep "$SLEEP_INTERVAL"
        waited=$((waited + SLEEP_INTERVAL))
        log "Esperando estado '$desired_status' para '$server_name'. Estado actual: '${current_status:-desconocido}' (${waited}s/${MAX_WAIT_SECONDS}s)"
    done

    die "Timeout esperando a que '$server_name' llegue a estado '$desired_status'."
}

# -----------------------------
# VALIDACIONES INICIALES
# -----------------------------
require_cmd openstack

log "Comprobando autenticación OpenStack..."
openstack token issue >/dev/null 2>&1 || die "No hay sesión válida de OpenStack. Carga primero el openrc."

log "Comprobando que no exista ya una instancia con ese nombre..."
if resource_exists "openstack server show \"$VM_NAME\""; then
    die "Ya existe una instancia llamada '$VM_NAME'."
fi

log "Comprobando imagen..."
resource_exists "openstack image show \"$IMAGE_NAME\"" || die "No existe la imagen '$IMAGE_NAME'."

log "Comprobando flavor..."
resource_exists "openstack flavor show \"$FLAVOR_NAME\"" || die "No existe el flavor '$FLAVOR_NAME'."

log "Comprobando red..."
resource_exists "openstack network show \"$NETWORK_NAME\"" || die "No existe la red '$NETWORK_NAME'."

log "Comprobando keypair..."
resource_exists "openstack keypair show \"$KEY_NAME\"" || die "No existe el keypair '$KEY_NAME'."

log "Comprobando security group..."
resource_exists "openstack security group show \"$SECURITY_GROUP\"" || die "No existe el security group '$SECURITY_GROUP'."

if [[ "$ASSIGN_FLOATING_IP" == "yes" ]]; then
    log "Comprobando red externa para floating IP..."
    resource_exists "openstack network show \"$FLOATING_NETWORK\"" || die "No existe la red externa '$FLOATING_NETWORK'."
fi

# -----------------------------
# CREAR VOLUMEN DE ARRANQUE
# -----------------------------
log "Creando volumen bootable '$BOOT_VOLUME_NAME' desde imagen '$IMAGE_NAME'..."
openstack volume create \
    --image "$IMAGE_NAME" \
    --size "$BOOT_VOLUME_SIZE" \
    "$BOOT_VOLUME_NAME" >/dev/null

log "Esperando a que el volumen esté disponible..."
openstack volume wait --available "$BOOT_VOLUME_NAME"

# -----------------------------
# CREAR INSTANCIA
# -----------------------------
log "Creando instancia '$VM_NAME'..."
openstack server create \
    --flavor "$FLAVOR_NAME" \
    --volume "$BOOT_VOLUME_NAME" \
    --network "$NETWORK_NAME" \
    --key-name "$KEY_NAME" \
    --security-group "$SECURITY_GROUP" \
    "$VM_NAME" >/dev/null

wait_for_server_status "$VM_NAME" "ACTIVE"

# -----------------------------
# ASIGNAR FLOATING IP
# -----------------------------
FLOATING_IP=""
if [[ "$ASSIGN_FLOATING_IP" == "yes" ]]; then
    log "Reservando floating IP de la red '$FLOATING_NETWORK'..."
    FLOATING_IP="$(openstack floating ip create "$FLOATING_NETWORK" -f value -c floating_ip_address)"

    [[ -n "$FLOATING_IP" ]] || die "No se pudo reservar una floating IP."

    log "Asociando floating IP '$FLOATING_IP' a '$VM_NAME'..."
    openstack server add floating ip "$VM_NAME" "$FLOATING_IP"
fi

# -----------------------------
# RESUMEN FINAL
# -----------------------------
SERVER_STATUS="$(openstack server show "$VM_NAME" -f value -c status)"
SERVER_ID="$(openstack server show "$VM_NAME" -f value -c id)"
SERVER_NETWORKS="$(openstack server show "$VM_NAME" -f value -c addresses)"

echo
echo "============================================================"
echo "VM Windows creada correctamente"
echo "============================================================"
echo "Nombre VM:        $VM_NAME"
echo "ID VM:            $SERVER_ID"
echo "Estado:           $SERVER_STATUS"
echo "Imagen base:      $IMAGE_NAME"
echo "Flavor:           $FLAVOR_NAME"
echo "Red:              $NETWORK_NAME"
echo "Volumen boot:     $BOOT_VOLUME_NAME"
echo "Tamaño volumen:   ${BOOT_VOLUME_SIZE} GB"
echo "Keypair:          $KEY_NAME"
echo "Security group:   $SECURITY_GROUP"
echo "Direcciones:      $SERVER_NETWORKS"
if [[ -n "$FLOATING_IP" ]]; then
    echo "Floating IP:      $FLOATING_IP"
fi
echo "============================================================"
