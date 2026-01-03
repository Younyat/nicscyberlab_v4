#!/usr/bin/env bash
set -euo pipefail

echo "----------------------------------------------------------"
echo "🔥 MODO ELIMINACIÓN TOTAL: WAZUH / INDEXER / DASHBOARD"
echo "----------------------------------------------------------"

# 1. Parada forzosa
echo "[1/8] Matando procesos residuales (pkill)..."
for proc in wazuh-manager wazuh-db wazuh-modulesd wazuh-authd filebeat opensearch dashboard; do
    # Usamos || true para que el script no se detenga si no encuentra el proceso
    sudo pkill -9 -f "$proc" >/dev/null 2>&1 || true
done
sleep 1

# 2. Servicios systemd
echo "[2/8] Deteniendo y deshabilitando servicios systemd..."
sudo systemctl stop wazuh-manager wazuh-dashboard wazuh-indexer filebeat 2>/dev/null || true
sudo systemctl disable wazuh-manager wazuh-dashboard wazuh-indexer filebeat 2>/dev/null || true

# 3. Archivos de unidad
echo "[3/8] Eliminando archivos de configuración de servicios..."
sudo rm -f /etc/systemd/system/wazuh* /lib/systemd/system/wazuh* /etc/systemd/system/filebeat*
sudo systemctl daemon-reload

# 4. Purga de paquetes
echo "[4/8] Purgando paquetes (apt purge)..."
sudo apt-get purge -y wazuh-manager wazuh-dashboard wazuh-indexer filebeat opensearch* >/dev/null 2>&1 || true
sudo apt-get autoremove -y >/dev/null 2>&1 || true

# 5. Directorios y Datos
echo "[5/8] Eliminando directorios de datos y configuraciones..."
sudo rm -rf /var/ossec /etc/ossec* /usr/share/wazuh* /etc/wazuh* /var/lib/wazuh* /opt/wazuh*
sudo rm -rf /etc/filebeat /etc/opensearch* /var/lib/opensearch* /usr/share/opensearch*

# 6. Logs y Registros
echo "[6/8] Limpiando archivos de log y temporales..."
sudo rm -rf /var/log/wazuh* /var/log/filebeat* /var/log/opensearch* /tmp/wazuh-*

# 7. Usuarios y Grupos
echo "[7/8] Eliminando usuarios y grupos del sistema..."
for u in wazuh wazuh-indexer wazuh-dashboard filebeat; do
    sudo userdel -f "$u" >/dev/null 2>&1 || true
    sudo groupdel "$u" >/dev/null 2>&1 || true
done

# 8. Validación Final
echo "[8/8] Validación de seguridad (Puertos y Procesos)..."
FAILED=false
MY_PID=$$

# BUSQUEDA ULTRA-FILTRADA: 
# Buscamos procesos que tengan wazuh/filebeat/opensearch 
# PERO ignoramos: el PID del script ($MY_PID), el proceso 'sudo', el propio 'grep' y el nombre del script 'uninstall'
PROCESOS_VIVOS=$(pgrep -a -f "wazuh|filebeat|opensearch" | grep -v "$MY_PID" | grep -v "uninstall" | grep -v "grep" | grep -v "sudo" || true)

if [[ -n "$PROCESOS_VIVOS" ]]; then
    echo "⚠️ ATENCIÓN: Se detectaron estos procesos activos:"
    echo "$PROCESOS_VIVOS"
    FAILED=true
fi

# Revisar puertos
PUERTOS_VIVOS=$(ss -tunlp | grep -E ":1515|:1514|:55000|:5601|:9200" || true)
if [[ -n "$PUERTOS_VIVOS" ]]; then
    echo "⚠️ ATENCIÓN: Hay puertos todavía ocupados:"
    echo "$PUERTOS_VIVOS"
    FAILED=true
fi

if [[ "$FAILED" == false ]]; then
    echo "--------------------------------------------------"
    echo "✅ [SUCCESS] LIMPIEZA 8/8 COMPLETADA"
    echo "--------------------------------------------------"
    exit 0
else
    echo "--------------------------------------------------"
    echo "❌ [ERROR] EL SISTEMA NO ESTÁ LIMPIO"
    echo "--------------------------------------------------"
    exit 1
fi