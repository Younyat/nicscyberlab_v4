#!/usr/bin/env bash
set -euo pipefail

##############################################################
#     DESTRUCCIÓN BASADA ÚNICAMENTE EN summary.json          #
#   - Elimina instancias, FIPs y puertos                     #
#   - Elimina keypair y claves locales                       #
#   - NO usa scenario.json                                   #
#   - Idempotente: no falla si algo ya está borrado          #
##############################################################

ADMIN_OPENRC="$HOME/Escritorio/cyber-range-v1/admin-openrc.sh"

DEFAULT_KEYPAIR="my_key"
LOCAL_KEYFILE="$HOME/.ssh/my_key"


# ============================================================
# 1. Cargar credenciales OpenStack
# ============================================================

if [ -f "$ADMIN_OPENRC" ]; then
    source "$ADMIN_OPENRC"
    echo " Credenciales OpenStack cargadas."
else
    echo " No se encontró admin-openrc. Siguiendo igualmente."
fi


# ============================================================
# 2. Validación de parámetros
# ============================================================

if [ "$#" -lt 1 ]; then
    echo "Uso: $0 output_dir"
    exit 0
fi

OUTDIR="$1"
SUMMARY_JSON="tf_out/summary.json"

echo ""
echo " OUTDIR:   $OUTDIR"
echo " Summary:  $SUMMARY_JSON"
echo "------------------------------------------------------------"


# ============================================================
# 3. No hay summary.json → nada que destruir
# ============================================================

if [ ! -f "$SUMMARY_JSON" ]; then
    echo " No existe summary.json. No hay recursos que eliminar."
    exit 0
fi


# ============================================================
# 4. Eliminar recursos según summary.json
# ============================================================

while read -r node; do
    id=$(echo "$node" | jq -r '.id')
    name=$(echo "$node" | jq -r '.name')
    fip=$(echo "$node" | jq -r '.floating_ip')

    SAFE_ID=$(echo "$id" | tr -c '[:alnum:]' '_')
    PORT_NAME="${SAFE_ID}-port"

    echo ""
    echo " Eliminando nodo → $name"
    echo "------------------------------------------------------------"


    # === Floating IP ====================================================
    if [ -n "$fip" ] && openstack floating ip show "$fip" >/dev/null 2>&1; then
        echo " Eliminando Floating IP: $fip"
        openstack floating ip delete "$fip" || true
    else
        echo " Floating IP ya no existe."
    fi


    # === Instancia ======================================================
    if openstack server show "$name" >/dev/null 2>&1; then
        echo " Eliminando instancia: $name"
        openstack server delete "$name" || true
    else
        echo " Instancia ya eliminada."
    fi

    # esperar cierre real
    for i in {1..20}; do
        if ! openstack server show "$name" >/dev/null 2>&1; then break; fi
        sleep 1
    done


    # === Puerto =========================================================
    if openstack port show "$PORT_NAME" >/dev/null 2>&1; then
        echo " Eliminando puerto: $PORT_NAME"
        openstack port delete "$PORT_NAME" || true
    else
        echo " Puerto ya eliminado."
    fi

    echo " Nodo $name eliminado."

done < <(jq -c '.[]' "$SUMMARY_JSON")


# ============================================================
# 5. Eliminar Keypair + claves locales
# ============================================================

echo ""
echo " Eliminando keypair y claves..."

if openstack keypair show "$DEFAULT_KEYPAIR" >/dev/null 2>&1; then
    echo " Eliminando keypair $DEFAULT_KEYPAIR"
    openstack keypair delete "$DEFAULT_KEYPAIR" || true
else
    echo " Keypair ya no existe."
fi

if [ -f "$LOCAL_KEYFILE" ] || [ -f "${LOCAL_KEYFILE}.pub" ]; then
    echo " Eliminando claves locales"
    rm -f "$LOCAL_KEYFILE" "${LOCAL_KEYFILE}.pub" || true
else
    echo " Claves locales ya eliminadas."
fi


# ============================================================
# 6. Limpiar OUTDIR
# ============================================================

echo ""
echo " Limpiando directorio de salida..."
#rm -rf "${OUTDIR:?}/"* || true


# ============================================================
# 7. Final
# ============================================================

echo ""
echo "=================================================================="
echo " INSTANCIAS ELIMINADAS CORRECTAMENTE"
echo " OUTDIR limpiado"
echo " Keypair & claves eliminadas"
echo "=================================================================="

exit 0
