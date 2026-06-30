#!/bin/bash

echo "Iniciando reinicio de servicios de OpenStack..."

# 1. Infraestructura Base
echo "Reiniciando base de datos y mensajería..."
sudo docker restart mariadb rabbitmq memcached proxysql haproxy
sleep 10

# 2. Identidad (Keystone)
echo "Reiniciando Keystone..."
sudo docker restart keystone keystone_fernet keystone_ssh
sleep 5

# 3. Almacenamiento e Imágenes (Glance)
echo "Reiniciando Glance..."
sudo docker restart glance_api
sleep 5

# 4. Computación (Nova) y Placement
echo "Reiniciando Placement y Nova..."
sudo docker restart placement_api
sudo docker restart nova_api nova_conductor nova_scheduler nova_novncproxy nova_compute nova_libvirt nova_ssh
sleep 5

# 5. Red (Neutron) y Open vSwitch
echo "Reiniciando Networking..."
sudo docker restart openvswitch_db openvswitch_vswitchd
sudo docker restart neutron_server neutron_openvswitch_agent neutron_dhcp_agent neutron_l3_agent neutron_metadata_agent
sleep 5

# 6. Orquestación y Dashboard
echo "Reiniciando Heat y Horizon..."
sudo docker restart heat_api heat_api_cfn heat_engine
sudo docker restart horizon

# 7. Servicios auxiliares
echo "Reiniciando servicios de soporte..."
sudo docker restart fluentd cron kolla_toolbox

echo "Todos los servicios han sido reiniciados."
echo "Verificando estado de los contenedores..."
sudo docker ps --format "table {{.Names}}\t{{.Status}}"
