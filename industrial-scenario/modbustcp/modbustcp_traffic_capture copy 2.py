#!/bin/bash
# Uso: ./forensic_manager.sh <check|install> <tool_id>

ACTION=$1
TOOL_ID=$2

# Mapeo de IDs a paquetes reales
case $TOOL_ID in
    "tsk")        PKG="sleuthkit" ;;
    "tcpdump")    PKG="tcpdump" ;;
    "tshark")     PKG="tshark" ;;
    "termshark")   PKG="termshark" ;;
    "volatility") PKG="volatility3" ;; # Asumiendo repo debian/ubuntu moderno
    *) echo "UNKNOWN"; exit 1 ;;
esac

if [ "$ACTION" == "check" ]; then
    if dpkg -l | grep -q "^ii  $PKG "; then
        echo "INSTALLED"
    else
        echo "ABSENT"
    fi
elif [ "$ACTION" == "install" ]; then
    sudo apt-get update > /dev/null
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$PKG" 2>&1
fi