# Guía de Despliegue Automatizado — OpenStack all-in-one & Dashboard NICS | CyberLab

Este documento describe cómo desplegar de forma completamente automatizada un entorno OpenStack all-in-one mediante Kolla-Ansible, incluyendo la creación automática y persistente de la red virtual requerida, así como el despliegue del backend Flask del Dashboard NICS | CyberLab.  
Además, se detallan las funcionalidades del Dashboard NICS | CyberLab (GUI) que permiten gestionar la infraestructura, los escenarios y la instalación de herramientas de forma visual y centralizada.

---

## Índice

- [Introducción](#0-introducción)  
- [Requisitos previos](#requisitos-previos)  
- [Ejecución automática — openstack-installer.sh](#1-ejecución-automática--openstack-installersh)  
- [Red virtual persistente (topología creada)](#2-red-virtual-persistente--topología-creada)  
- [Instalación y flujo de despliegue](#3-instalación-y-flujo-de-despliegue)  
- [Credenciales de acceso](#4-credenciales-de-acceso)  
- [Verificación del entorno](#5-verificación-del-entorno)  
- [Gestión desde el Dashboard NICS | CyberLab (GUI)](#6-gestión-desde-el-dashboard-nics--cyberlab-gui)  
  - [Etapa 1 — Inicialización del entorno](#etapa-1--inicialización-del-entorno)  
  - [Etapa 2 — Creación de escenarios](#etapa-2--creación-de-escenarios)  
  - [Etapa 3 — Instalación de herramientas en nodos](#etapa-3--instalación-de-herramientas-en-nodos)  
- [Lanzamiento del backend del Dashboard NICS | CyberLab](#7-lanzamiento-del-backend-del-dashboard-nics--cyberlab)  
- [Acceso al Dashboard NICS | CyberLab](#8-acceso-al-dashboard-nics--cyberlab)  
- [Notas y buenas prácticas](#9-notas-y-buenas-prácticas)

---

## 0. Introducción

El script principal `openstack-installer.sh` automatiza todo el proceso de despliegue:

- Instalación de dependencias del sistema y Python.  
- Configuración de Docker y Terraform.  
- Creación del entorno virtual `openstack_venv`.  
- Instalación de Kolla-Ansible y OpenStackClient.  
- Creación automática de la topología de red virtual (`uplinkbridge`, `veth0`, `veth1`) con persistencia mediante systemd.  
- Despliegue completo de OpenStack y configuración final.  
- Generación automática de credenciales (`admin-openrc.sh`, `clouds.yaml`).

---

## Requisitos previos

- Sistema operativo: Ubuntu/Debian (probado en Ubuntu LTS).  
- CPU: mínimo 4 vCPU.  
- RAM: 16 GB (recomendado 24 GB o más).  
- Almacenamiento: al menos 80 GB libres.  
- Conectividad a Internet.  
- Privilegios de superusuario (sudo).  

---

## 1. Ejecución automática — openstack-installer.sh

Ejecuta el instalador principal para desplegar el entorno completo:

```bash
sudo bash openstack-installer.sh 2>&1 | tee nombre_del_log.log
```

El script configura los servicios necesarios y garantiza la persistencia de la red mediante systemd.

---

## 2. Red virtual persistente — topología creada

Durante la instalación se configura una red virtual persistente utilizada por OpenStack como red de gestión y red externa.

```
                          
                   ens33       Internet   
                          
                        
                  [ NAT / iptables ]
                        
                
                     uplinkbridge     
                
                        
                   
                            
               
               veth0    veth1  
               
```

- `ens33`: interfaz física principal.  
- `uplinkbridge`: puente virtual para comunicación externa.  
- `veth0 / veth1`: par de interfaces virtuales persistentes.  

En cada reinicio, systemd ejecuta automáticamente `setup-veth.sh` para restaurar la topología.

---

## 3. Instalación y flujo de despliegue

Durante la ejecución del script:

1. Creación de la red virtual persistente.  
2. Instalación de Docker, Ansible, Kolla-Ansible y Terraform.  
3. Inicialización y despliegue de los contenedores de OpenStack.  
4. Desactivación de servicios no requeridos (masakari, venus, skyline).  
5. Generación automática de credenciales y archivos de configuración finales.

---

## 4. Credenciales de acceso

El Dashboard NICS | CyberLab incluye un módulo de generación automática de credenciales (integrado en `app.py`).  
Al iniciar el backend mediante `start_dashboard.sh`, el sistema intenta crear y desplegar las credenciales necesarias a partir de `clouds.yaml`.

En condiciones normales, las credenciales se generan sin intervención manual.  
Si la generación automática falla, pueden utilizarse los archivos creados por Kolla-Ansible:

```
/etc/kolla/admin-openrc.sh
/etc/kolla/clouds.yaml
```

Cargar las credenciales manualmente:

```bash
source /etc/kolla/admin-openrc.sh
```

Si has exportado Application Credentials desde Horizon (Dashboard de OpenStack):

```bash
source app-cred-admin-openrc.sh
```

Para depuración, revisa el archivo `dashboard_log.log` o los registros del backend para detectar errores relacionados con la generación de credenciales.

---

## 5. Verificación del entorno

Comprueba el estado general del despliegue:

```bash
openstack service list
openstack network list
openstack image list
openstack flavor list
```

Verifica los contenedores activos:

```bash
sudo docker ps --format "table {{.Names}}	{{.Status}}"
```

Si los servicios aparecen en estado *healthy*, el entorno está operativo.

---

## 6. Gestión del entorno e infraestructura desde el Dashboard NICS | CyberLab (GUI)

El Dashboard NICS | CyberLab permite realizar de forma gráfica y automatizada las principales tareas de configuración y despliegue, sin necesidad de ejecutar scripts manualmente.

### Etapa 1 — Inicialización del entorno

Corresponde a la configuración inicial del entorno OpenStack y NICS | CyberLab.  
Desde la sección *Infraestructura Inicial* se pueden crear o modificar:

- Redes internas y externas.  
- Subredes y routers.  
- Grupos y reglas de seguridad.  
- Imágenes base (Ubuntu, Debian, etc.).  
- Sabores (flavors) predefinidos (CPU, RAM, disco).  
- Claves SSH para acceso remoto.

---

### Etapa 2 — Creación de escenarios

En el *Gestor de Escenarios* los usuarios pueden definir y administrar entornos de simulación o formación:

- Crear y nombrar escenarios personalizados.  
- Añadir nodos con roles (ataque, víctima, monitor, servicio).  
- Conectar nodos mediante redes internas o externas.  
- Asignar recursos (flavor, imagen, clave SSH) y metadatos por nodo.

---

### Etapa 3 — Instalación de herramientas en nodos

Desde la sección *Herramientas y Servicios* el usuario puede instalar o actualizar software en cada tipo de nodo:

- Nodos de ataque → herramientas de pentesting y red-teaming.  
- Nodos de monitorización → Wazuh, Suricata, Caldera, etc.  
- Nodos de servicio / víctimas → aplicaciones industriales o IoT simuladas.

Cada instalación se gestiona desde el GUI, con control de versiones y despliegue por nodo.

---

## 7. Lanzamiento del backend del Dashboard NICS | CyberLab

El backend está desarrollado en Flask + Gunicorn.

### Opción 1 — Ejecución directa

```bash
gunicorn -w 4 -b localhost:5001 app:app
```

### Opción 2 — Ejecución recomendada

```bash
chmod +x start_dashboard.sh
(openstack_venv)$ bash start_dashboard.sh 2>&1 | tee dashboard_log.log
```

El script `start_dashboard.sh` valida el puerto, instala Gunicorn si es necesario y lanza el servidor automáticamente.

---

## 8. Acceso al Dashboard NICS | CyberLab

Una vez iniciado el backend, abre en tu navegador:

```
http://localhost:5001
```

Desde ahí podrás acceder a los módulos:
- Infraestructura Inicial  
- Gestor de Escenarios  
- Herramientas y Servicios  

Todo el flujo de trabajo del entorno NICS | CyberLab puede gestionarse desde este panel centralizado.

---

## 9. Notas y buenas prácticas

- Guarda copias de seguridad de `/etc/kolla/` y de los archivos `*.openrc.sh`.  
- Revisa el archivo `nombre_del_log.log` para depurar la instalación.  
- Comprueba el servicio persistente de red con:  
  ```bash
  sudo systemctl status setup-veth.service
  ```  
- Ajusta los recursos de hardware si planeas ejecutar varios escenarios simultáneamente.  
- Mantén el Dashboard y sus scripts actualizados para asegurar compatibilidad con nuevas versiones de OpenStack.

---

NICS LAB — NICS | CyberLab
