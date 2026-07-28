#!/usr/bin/env bash
set -euo pipefail

#opcion1 : 
###############################################
#  Configuración de Credenciales de OpenStack
# =============================================
# Reemplaza las siguientes variables con la información
# obtenida del archivo `app-cred-app-openrc.sh`
# descargado desde el Dashboard de OpenStack.
###############################################

# URL de autenticación del servicio Keystone
# export OS_AUTH_URL=http://192.168.0.10:5000

# Nombre del proyecto o tenant asociado
# export OS_PROJECT_NAME=admin

# Dominio del proyecto (por defecto: Default)
# export OS_PROJECT_DOMAIN_NAME=Default

# Nombre de usuario administrador
# export OS_USERNAME=admin

# Dominio del usuario (por defecto: Default)
# export OS_USER_DOMAIN_NAME=Default

# Contraseña asociada al usuario o credencial
# export OS_PASSWORD=JE6663lP1THXJqP8zVCWz3OQxqyXzu74b7Cd0Z7s

# Interfaz de acceso (public, internal o admin)
# export OS_INTERFACE=public

# Versión de la API de identidad (normalmente 3)
# export OS_IDENTITY_API_VERSION=3

###############################################

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq no está instalado. Instálalo (ej. apt install jq) y vuelve a probar."
  exit 1
fi

if [ "$#" -lt 1 ]; then
  echo "Uso: $0 escenario.json [outdir]"
  exit 1
fi

SCENARIO_JSON="$1"
OUTDIR="${2:-./tf_out}"

mkdir -p "$OUTDIR"
rm -f "$OUTDIR"/*.tf "$OUTDIR"/inventory.* "$OUTDIR"/config.yml "$OUTDIR"/summary.json

BASE_DIR=$(pwd)

# DIRECTORIO DONDE DEBE IR LA CLAVE
KEY_OUTPUT_DIR=$BASE_DIR/tf_out 

# ASEGURAR QUE EL DIRECTORIO EXISTA ANTES DE ESCRIBIR
mkdir -p "$KEY_OUTPUT_DIR"

# Ahora, genera la clave:
KEY_PATH=$KEY_OUTPUT_DIR/nueva_clave_wazuh

echo "=== 2. Generando clave SSH si no existe ==="
if [ ! -f "$KEY_PATH" ]; then
  ssh-keygen -t rsa -b 4096 -f $KEY_PATH -N ""
  echo "Clave SSH creada en $KEY_PATH"
else
  echo "Clave SSH ya existe en $KEY_PATH"
fi

PROVIDER_FILE="$OUTDIR/provider.tf"
GEN_PROVIDER_SCRIPT="$BASE_DIR/scenario/generate_provider_from_clouds.sh"

echo "==============================================="
echo " Iniciando generador principal de Terraform"
echo "==============================================="

# ------------------------------------------------------
# 1⃣ Comprobar si existe clouds.yaml y script generador
# ------------------------------------------------------
if [[ -f "/etc/kolla/clouds.yaml" && -f "$GEN_PROVIDER_SCRIPT" ]]; then
    echo " Detectado clouds.yaml en /etc/kolla y script generador."
    echo " Ejecutando $GEN_PROVIDER_SCRIPT ..."
    bash "$GEN_PROVIDER_SCRIPT" "$OUTDIR"
else
    echo " No se encontró /etc/kolla/clouds.yaml o el script $GEN_PROVIDER_SCRIPT."
    echo " No se generará provider.tf hasta que existan ambos archivos."
    echo "    Asegúrate de tener:"
    echo "     - /etc/kolla/clouds.yaml"
    echo "     - generate_provider_from_clouds.sh"
    echo ""
    echo "   Luego vuelve a ejecutar:"
    echo "     bash main_generator_inicial.sh"
    echo ""
    exit 1
fi

echo " Archivo provider.tf generado en $PROVIDER_FILE"

# Plantilla inventory.tmpl
cat > "$OUTDIR/inventory.tmpl" <<'TEMPLATE'
[aio]
server ansible_host=${server_ip} ansible_user=ubuntu ansible_ssh_private_key_file=./nueva_clave_wazuh
TEMPLATE

# Inicia config.yml
cat > "$OUTDIR/config.yml" <<'EOF'
nodes:
EOF

# Array JSON temporal
SUMMARY="[]"

count=0
#  Cambiado: el bucle se ejecuta en la misma shell, evitando el problema del subshell
while read -r node; do
  id=$(echo "$node" | jq -r '.id')
  name=$(echo "$node" | jq -r '.name')
  ntype=$(echo "$node" | jq -r '.type')
  os=$(echo "$node" | jq -r '.properties.os // empty')
  ip=$(echo "$node" | jq -r '.properties.ip // empty')
  network=$(echo "$node" | jq -r '.properties.network // empty')
  subnetwork=$(echo "$node" | jq -r '.properties.subnetwork // empty')
  flavor=$(echo "$node" | jq -r '.properties.flavor // empty')
  image=$(echo "$node" | jq -r '.properties.image // empty')
  secgroup=$(echo "$node" | jq -r '.properties.securityGroup // empty')
  sshkey=$(echo "$node" | jq -r '.properties.sshKey // empty')

  safe_id=$(echo "$id" | tr -c '[:alnum:]_' '_' | tr '[:upper:]' '[:lower:]')
  count=$((count+1))

   # Usuario SSH y contraseña por defecto según OS
  case "$os" in
    ubuntu*|Ubuntu*) ssh_user="ubuntu"; default_pass="ubuntu123" ;;
    debian*|Debian*) ssh_user="debian"; default_pass="debian123" ;;
    centos*|CentOS*) ssh_user="centos"; default_pass="centos123" ;;
    fedora*|Fedora*) ssh_user="fedora"; default_pass="fedora123" ;;
    kali*|Kali*) ssh_user="kali"; default_pass="kali123" ;;
    *) ssh_user="ubuntu"; default_pass="ubuntu123" ;;
  esac

  tf_file="$OUTDIR/node_${safe_id}.tf"
  echo "Generando $tf_file para nodo $id ($name, OS=$os)"




CLOUD_INIT="#cloud-config
ssh_pwauth: True
chpasswd:
  list: |
    ${ssh_user}:${default_pass}
  expire: False"





  cat > "$tf_file" <<EOF
# Terraform auto-generado para nodo ${name} (id: ${id})
data "openstack_networking_network_v2" "${safe_id}_network" {
  name = "${network}"
}

data "openstack_networking_subnet_v2" "${safe_id}_subnet" {
  name       = "${subnetwork}"
  network_id = data.openstack_networking_network_v2.${safe_id}_network.id
}

data "openstack_networking_secgroup_v2" "${safe_id}_secgroup" {
  name = "${secgroup}"
}

data "openstack_images_image_v2" "${safe_id}_image" {
  name = "${image}"
}

data "openstack_compute_flavor_v2" "${safe_id}_flavor" {
  name = "${flavor}"
}

resource "openstack_compute_keypair_v2" "${safe_id}_keypair" {
  name       = "${sshkey}_${safe_id}"
  public_key = file("\${path.module}/${sshkey}.pub")
}

resource "openstack_networking_floatingip_v2" "${safe_id}_fip" {
  pool = "red_externa"
}

resource "openstack_networking_port_v2" "${safe_id}_port" {
  name               = "${safe_id}-port"
  network_id         = data.openstack_networking_network_v2.${safe_id}_network.id
  security_group_ids = [data.openstack_networking_secgroup_v2.${safe_id}_secgroup.id]
  fixed_ip {
    subnet_id = data.openstack_networking_subnet_v2.${safe_id}_subnet.id
  }
}

resource "openstack_compute_instance_v2" "${safe_id}_instance" {
  name         = "${name}"
  image_id     = data.openstack_images_image_v2.${safe_id}_image.id
  flavor_id    = data.openstack_compute_flavor_v2.${safe_id}_flavor.id
  key_pair     = openstack_compute_keypair_v2.${safe_id}_keypair.name
  config_drive = true

  network {
    port = openstack_networking_port_v2.${safe_id}_port.id
  }

  user_data = <<CLOUDCONF
${CLOUD_INIT}
CLOUDCONF
}

#  Asociar Floating IP después de que la instancia esté lista
resource "openstack_networking_floatingip_associate_v2" "${safe_id}_fip_associate" {
  floating_ip = openstack_networking_floatingip_v2.${safe_id}_fip.address
  port_id     = openstack_networking_port_v2.${safe_id}_port.id

  depends_on = [
    openstack_compute_instance_v2.${safe_id}_instance
  ]
}

output "${safe_id}_floating_ip" {
  value = openstack_networking_floatingip_v2.${safe_id}_fip.address
}
EOF

  # Añadir al JSON resumen
  SUMMARY=$(echo "$SUMMARY" | jq \
    --arg id "$id" \
    --arg name "$name" \
    --arg os "$os" \
    --arg ssh_user "$ssh_user" \
    --arg flavor "$flavor" \
    --arg image "$image" \
    --arg network "$network" \
    --arg subnetwork "$subnetwork" \
    --arg secgroup "$secgroup" \
    --arg sshkey "$sshkey" \
    --arg safe_id "$safe_id" \
    --arg floating_ip_ref "${safe_id}_floating_ip"\
    '. += [{
      id: $id,
      name: $name,
      os: $os,
      ssh_user: $ssh_user,
      flavor: $flavor,
      image: $image,
      network: $network,
      subnetwork: $subnetwork,
      security_group: $secgroup,
      ssh_key: $sshkey,
      floating_ip_value: $floating_ip_ref
    }]')

done < <(jq -c '.nodes[]' "$SCENARIO_JSON")  
# Guardar resumen en JSON
echo "$SUMMARY" | jq '.' > "$OUTDIR/summary.json"

echo "Generados $(ls -1 "$OUTDIR"/*.tf 2>/dev/null | wc -l) archivos .tf en $OUTDIR"
echo "También generado: $OUTDIR/config.yml, $OUTDIR/inventory.tmpl, $OUTDIR/summary.json"
echo "Pausando 10 segundos antes de Lanzar Terraform"
echo "=== 4. Lanzando Terraform ==="
sleep 10
cd $BASE_DIR/tf_out/
terraform init
echo "Pausando 10 segundos antes de 'init'..."
sleep 10
terraform plan
echo "Pausando 30 segundos antes de 'plan'..."
sleep 30
terraform apply -auto-approve -parallelism=4























# === 5. Fusionar terraform_outputs.json con summary.json (IPs reales) ===
echo "=== 5. Fusionando IPs reales en summary.json ==="
cd "$OUTDIR"

# Exportar outputs de Terraform (si no existen)
terraform output -json > terraform_outputs.json

# Crear un archivo temporal para modificaciones
tmpfile=$(mktemp)
cp "$OUTDIR/summary.json" "$tmpfile"

# Recorre cada output (por ejemplo, node1__floating_ip)
for key in $(jq -r 'keys[]' terraform_outputs.json); do
  ip=$(jq -r ".\"$key\".value" terraform_outputs.json)
  # limpiar el nombre (node1__floating_ip → node1)
  safe_id=$(echo "$key" | sed 's/__floating_ip$//')

  echo "   ↳ Actualizando ${safe_id} → ${ip}"

  # Actualiza el campo floating_ip_value en el summary.json
  jq --arg sid "$safe_id" --arg ip "$ip" \
    'map(if .id == $sid or .safe_id == $sid then .floating_ip_value = $ip else . end)' \
    "$tmpfile" > "${tmpfile}.new" && mv "${tmpfile}.new" "$tmpfile"
done

# Sobrescribe summary.json final
mv "$tmpfile" "$OUTDIR/summary.json"

# (opcional) eliminar terraform_outputs.json si no lo quieres conservar
rm -f "$OUTDIR/terraform_outputs.json"

echo " summary.json actualizado con IPs flotantes reales "

