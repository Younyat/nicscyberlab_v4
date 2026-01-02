
openstack server create   --flavor M_4CPU_8GB   --image ubuntu-22.04   --nic net-id=net_private_01   --security-group sg_basic   --key-name my_key   --wait   Wazuh-Server-Single

FLOATING_IP=$(openstack floating ip create net_external_01 -f value -c floating_ip_address)

openstack server add floating ip Wazuh-Server-Single $FLOATING_IP
