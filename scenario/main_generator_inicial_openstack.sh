#!/usr/bin/env bash
set -euo pipefail

# === 0. Resolver rutas RELATIVAS al repositorio =======================

# Ruta absoluta donde está este script (*.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Raíz del repositorio (directorio superior)
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Archivo admin-openrc.sh generado por app.py
ADMIN_OPENRC="$REPO_ROOT/admin-openrc.sh"

DEFAULT_KEYPAIR="my_key"
LOCAL_KEYFILE="$HOME/.ssh/my_key"
DEFAULT_EXTERNAL_NET="net_external_01"

echo " SCRIPT_DIR: $SCRIPT_DIR"
echo " REPO_ROOT : $REPO_ROOT"
echo " ADMIN_OPENRC : $ADMIN_OPENRC"

# ======================================================================
# === 1. Cargar credenciales ===========================================
# ======================================================================

if [ ! -f "$ADMIN_OPENRC" ]; then
    echo " ERROR: No se encontró admin-openrc.sh en el root del repositorio."
    echo "Ruta esperada: $ADMIN_OPENRC"
    echo " app.py debería haberlo generado automáticamente."
    exit 1
fi

# shellcheck disable=SC1090
source "$ADMIN_OPENRC"
echo " Credenciales OpenStack cargadas desde: $ADMIN_OPENRC"

# Validar que hay token
if openstack token issue >/dev/null 2>&1; then
    echo " Token OpenStack válido"
else
    echo " ERROR: Credenciales inválidas (falló 'openstack token issue')."
    exit 1
fi


# ======================================================================
# === 2. Validar entorno del script ===================================
# ======================================================================

if ! command -v jq >/dev/null 2>&1; then
  echo " Error: jq no está instalado."
  exit 1
fi

if [ "$#" -lt 1 ]; then
  echo "Uso: $0 escenario.json [output_dir]"
  exit 1
fi

SCENARIO_JSON="$1"
OUTDIR="${2:-./os_out}"

mkdir -p "$OUTDIR"
rm -f "$OUTDIR"/*.json

echo " Escenario JSON: $SCENARIO_JSON"
echo " Output: $OUTDIR"
echo " Keypair objetivo: $DEFAULT_KEYPAIR"
echo " Floating desde: $DEFAULT_EXTERNAL_NET"


# ======================================================================
# === 3. Verificar todos los recursos ANTES de crear nada ==============
# ======================================================================

echo " Verificando recursos del escenario..."

while read -r node; do
  name=$(echo "$node" | jq -r '.name')
  image=$(echo "$node" | jq -r '.properties.image')
  flavor=$(echo "$node" | jq -r '.properties.flavor')
  network=$(echo "$node" | jq -r '.properties.network')
  subnet=$(echo "$node" | jq -r '.properties.subnet')
  secgroup=$(echo "$node" | jq -r '.properties.security_group')

  echo "   → Nodo: $name"

  openstack image show "$image" >/dev/null
  openstack flavor show "$flavor" >/dev/null
  openstack network show "$network" >/dev/null
  openstack subnet show "$subnet" >/dev/null
  openstack security group show "$secgroup" >/dev/null

done < <(jq -c '.nodes[]' "$SCENARIO_JSON")

openstack network show "$DEFAULT_EXTERNAL_NET" >/dev/null

echo " Verificación completada."
echo "------------------------------------------------------------"


# ======================================================================
# === 4. Verificar / crear keypair =====================================
# ======================================================================

echo " Verificando keypair '$DEFAULT_KEYPAIR'..."

if openstack keypair show "$DEFAULT_KEYPAIR" >/dev/null 2>&1; then
    echo " La keypair existe en OpenStack."
else
    echo " La keypair NO existe. Creándola…"

    mkdir -p "$HOME/.ssh"

    if [ ! -f "$LOCAL_KEYFILE" ]; then
        echo " Generando clave local $LOCAL_KEYFILE..."
        ssh-keygen -t rsa -b 4096 -f "$LOCAL_KEYFILE" -N ""
    else
        echo " Usando clave local existente: $LOCAL_KEYFILE"
    fi

    openstack keypair create "$DEFAULT_KEYPAIR" \
        --public-key "${LOCAL_KEYFILE}.pub"

    echo " Keypair '$DEFAULT_KEYPAIR' creada."
fi

echo "------------------------------------------------------------"


# ======================================================================
# === 5. CREAR INSTANCIAS ==============================================
# ======================================================================

SUMMARY="[]"

while read -r node; do

  id=$(echo "$node" | jq -r '.id')
  name=$(echo "$node" | jq -r '.name')
  os=$(echo "$node" | jq -r '.properties.os')

  image=$(echo "$node" | jq -r '.properties.image')
  flavor=$(echo "$node" | jq -r '.properties.flavor')
  network=$(echo "$node" | jq -r '.properties.network')
  subnet=$(echo "$node" | jq -r '.properties.subnet')
  secgroup=$(echo "$node" | jq -r '.properties.security_group')

  safe=$(echo "$id" | tr -c '[:alnum:]' '_')

  echo ""
  echo " CREANDO NODO → $name"
  echo "------------------------------------------------------------"

  # === Crear puerto ====================================================

  PORT_ID=$(openstack port create "${safe}-port" \
        --network "$network" \
        --security-group "$secgroup" \
        -f value -c id)

  echo "    Puerto creado: $PORT_ID"

  # === Crear instancia =================================================

  SERVER_ID=$(openstack server create "$name" \
        --image "$image" \
        --flavor "$flavor" \
        --key-name "$DEFAULT_KEYPAIR" \
        --nic port-id="$PORT_ID" \
        -f value -c id)

  echo "    Instancia creada, ID: $SERVER_ID"
  echo "    Esperando a ACTIVE..."

  # === Polling manual ==================================================

  MAX_ATTEMPTS=60
  attempt=0

  while true; do
      STATUS=$(openstack server show "$SERVER_ID" -f value -c status)

      if [[ "$STATUS" == "ACTIVE" ]]; then
          echo "    Estado ACTIVE."
          break
      fi

      if [[ "$STATUS" == "ERROR" ]]; then
          echo " ERROR: La instancia $name entró en estado ERROR."
          exit 1
      fi

      if (( attempt >= MAX_ATTEMPTS )); then
          echo " TIMEOUT esperando a que $name esté ACTIVE"
          exit 1
      fi

      attempt=$((attempt+1))
      sleep 2
  done

  # === Asignar Floating IP ============================================

  FIP=$(openstack floating ip create "$DEFAULT_EXTERNAL_NET" \
        -f value -c floating_ip_address)

  echo "    Floating IP creada: $FIP"

  openstack server add floating ip "$SERVER_ID" "$FIP"

  echo "    Floating IP asociada."

  # === Determinar usuario ==============================================

  case "$os" in
    ubuntu*) ssh_user="ubuntu" ;;
    debian*) ssh_user="debian" ;;
    kali*) ssh_user="kali" ;;
    centos*) ssh_user="centos" ;;
    fedora*) ssh_user="fedora" ;;
    *) ssh_user="ubuntu" ;;
  esac

  # === Añadir al summary ===============================================

  SUMMARY=$(echo "$SUMMARY" | jq \
      --arg id "$id" \
      --arg name "$name" \
      --arg fip "$FIP" \
      --arg ssh_user "$ssh_user" \
      '. += [{
        id:$id,
        name:$name,
        floating_ip:$fip,
        ssh_user:$ssh_user
      }]')

  echo " Nodo $name creado correctamente."
  echo "------------------------------------------------------------"

done < <(jq -c '.nodes[]' "$SCENARIO_JSON")


# ======================================================================
# === 6. Guardar summary.json ==========================================
# ======================================================================

SUMMARY_PATH="$OUTDIR/summary.json"
echo "$SUMMARY" | jq '.' > "$SUMMARY_PATH"

echo ""
echo "============================================================"
echo " ESCENARIO CREADO CORRECTAMENTE"
echo " summary.json → $SUMMARY_PATH"
echo "============================================================"
