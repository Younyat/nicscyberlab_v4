# Windows Lab Exchange

`Windows Lab Exchange` es un módulo integrado en NICS CyberLab diseñado para intercambiar archivos sospechosos con una máquina remota de análisis que ya dispone de FLARE-VM y del repositorio original `HoneyV`.

Repositorio original integrado en el flujo de análisis:  
https://github.com/nicslabdev/HoneyV

La finalidad de este módulo es servir como puente controlado entre NICS CyberLab y la máquina de análisis. Desde esta interfaz, el usuario puede seleccionar archivos locales, empaquetarlos, enviarlos a la máquina Windows remota, ejecutar acciones remotas si es necesario y recuperar después el reporte generado por el entorno de análisis. El repositorio `HoneyV` aporta el marco original de análisis y organización de muestras, mientras que este panel proporciona la capa práctica de intercambio, control y recuperación dentro de NICS CyberLab. :contentReference[oaicite:1]{index=1}




![Interface](../Images_readme/LAB_EXCHANGE_DASHBOARD.png)

## Flujo general de uso

El flujo funcional del módulo es sencillo:

1. El usuario navega por directorios locales autorizados y selecciona uno o varios archivos sospechosos.
2. Puede empaquetarlos en ZIP o subir directamente un archivo al workspace.
3. Configura la máquina Windows remota por SSH.
4. Envía el archivo o el ZIP a la máquina de análisis.
5. Verifica que el archivo remoto existe.
6. Si lo necesita, ejecuta un comando o script remoto para lanzar el análisis.
7. Cuando el entorno remoto genera un reporte JSON, el usuario indica su ruta y lo carga desde la propia interfaz.
8. El reporte se visualiza en la parte inferior como un visor JSON estructurado y navegable.

En resumen, este módulo no sustituye a HoneyV ni a FLARE-VM. Lo que hace es conectar ambos con NICS CyberLab para que el intercambio y la recuperación del análisis se puedan hacer desde una única pantalla. :contentReference[oaicite:2]{index=2}

## Qué papel tiene HoneyV en este módulo

HoneyV es el repositorio original sobre el que se apoya la máquina de análisis. En el repositorio se observan carpetas de muestras organizadas por familias como `Adwares`, `Botnet`, `Ransomwares`, `Rootkits`, `Spywares`, `Trojans`, `Virus` y `Worms`, además de scripts como `Analyzer.ps1` y los orquestadores para VirtualBox y VMware. Esto refuerza que el papel de la máquina remota es ejecutar o apoyar un proceso de análisis de malware ya definido por ese proyecto. :contentReference[oaicite:3]{index=3}

Dentro de `Windows Lab Exchange`, HoneyV no se expone como una aplicación independiente con su propia interfaz. En su lugar, el módulo permite enviar artefactos sospechosos a la máquina remota donde HoneyV ya está clonado y preparado, y después recuperar el resultado del análisis en formato JSON.

## Descripción funcional de la interfaz

### Estado superior

La franja superior muestra cuatro elementos clave:

- **Backend**: indica si el backend del módulo está operativo.
- **SSH target**: muestra el estado de conectividad con la máquina remota.
- **Current path**: refleja la ruta local actual que se está navegando.
- **Selected**: indica cuántos elementos locales han sido seleccionados.

El botón **Refresh** actualiza el estado general del módulo y recarga la información visible.  
El botón **Clear Console** limpia el registro visual de actividad de la interfaz.

### Directory Browser

Esta sección permite navegar por rutas locales autorizadas del host donde corre NICS CyberLab.

Sus funciones principales son:

- elegir una raíz permitida
- abrir una ruta concreta
- volver al directorio padre
- listar directorios y archivos
- seleccionar elementos
- marcar un archivo concreto para su envío posterior

Esta zona sirve para localizar los artefactos sospechosos que se quieren remitir a la máquina de análisis.

### Workspace Actions

Esta sección agrupa las acciones locales previas al envío.

#### Create ZIP from selected
Permite crear un archivo ZIP a partir de los elementos seleccionados en el navegador local. Es útil cuando se quiere enviar un conjunto de muestras o conservar una estructura compacta antes de transferirla.

#### Upload to workspace
Permite subir un archivo desde el equipo local al workspace del módulo. Esto resulta útil cuando el archivo sospechoso no se encuentra aún en una de las rutas navegables o se quiere incorporarlo rápidamente al flujo del módulo.

#### Send via SSH SFTP
Envía el archivo indicado a la máquina Windows remota mediante SFTP sobre SSH. Esta es la acción principal para transferir la muestra o el ZIP al sistema de análisis.

### SSH Target Configuration

Esta sección define la conexión con la máquina Windows remota.

Permite configurar:

- host
- puerto
- usuario
- timeout
- autenticación por contraseña o por clave
- directorio remoto de destino

#### Save SSH Config
Guarda la configuración SSH actual.

#### Reload SSH Config
Recarga la configuración ya almacenada.

#### Test SSH Connection
Comprueba si la máquina remota es accesible con los datos actuales. Esta acción es importante antes de intentar enviar muestras o ejecutar comandos remotos.

### Remote Verification

Esta sección se usa para comprobar si un archivo ya existe en la máquina remota.

#### Use last sent remote path
Reutiliza automáticamente la última ruta remota enviada.

#### Verify remote file
Comprueba que el archivo remoto existe y que la transferencia se ha completado correctamente.

Esta parte es importante porque introduce una validación explícita antes de pasar al análisis remoto.

### Remote JSON Report Reader

Esta es una de las secciones más importantes del módulo, porque permite recuperar y visualizar el resultado del análisis.

#### Remote JSON file path
El usuario introduce aquí la ruta del reporte JSON generado en la máquina de análisis.

#### Use last remote path
Reutiliza la última ruta remota conocida, lo que puede ser útil si el análisis genera el reporte en la misma ubicación del archivo enviado o en una ubicación derivada.

#### Read remote JSON
Lee el fichero JSON remoto y lo carga en la interfaz.

Una vez cargado, el reporte se presenta en un visor estructurado que permite:

- ver la ruta del reporte
- ver el tamaño
- ver la fecha de modificación
- navegar por el contenido JSON
- expandir todo
- colapsar todo
- copiar el JSON en bruto
- buscar términos dentro del reporte

Funcionalmente, esta sección convierte el módulo en una interfaz de recuperación y lectura de resultados, no solo de transferencia.

### Remote Execution

Esta sección permite lanzar acciones remotas en la máquina Windows.

Puede usarse para:

- ejecutar un comando
- ejecutar un script de PowerShell
- definir un directorio de trabajo remoto
- fijar un timeout de ejecución
- indicar un archivo objetivo esperado
- lanzar una verificación posterior opcional

#### Run on remote host
Ejecuta el comando o script remoto definido por el usuario.

Esta opción es útil cuando el análisis no se lanza de forma automática tras recibir la muestra y es necesario invocar manualmente el flujo de HoneyV o cualquier otro script de análisis presente en la máquina remota.

### Console

La consola muestra el historial de eventos de la interfaz. Aquí se reflejan acciones como:

- recargas
- selecciones
- transferencias
- verificaciones
- ejecuciones remotas
- lectura de reportes

Su función es ayudar al usuario a seguir el flujo operativo.

### Selected Artifact

Esta tarjeta resume el artefacto actualmente seleccionado:

- nombre
- ruta
- tipo
- tamaño
- fecha de modificación

También ofrece acciones para reutilizar esa ruta en el envío o copiarla.

### Remote Status

Muestra un resumen de la configuración remota actualmente activa:

- host
- usuario
- directorio remoto
- última ruta remota conocida
- última comprobación de conexión

### Last Result

Muestra la última respuesta estructurada del backend, normalmente en formato JSON técnico. Es útil para revisar lo que devolvió exactamente la última acción realizada.

## Modo de uso recomendado

Un uso típico del módulo sería el siguiente:

1. Navegar por el directorio local y seleccionar el archivo sospechoso.
2. Crear un ZIP si se desea enviar un conjunto o encapsular la muestra.
3. Confirmar la configuración SSH.
4. Probar la conexión con la máquina remota.
5. Enviar el archivo o ZIP mediante SFTP.
6. Verificar que el archivo remoto existe.
7. Ejecutar, si hace falta, el script remoto que lanza el análisis en la máquina con FLARE-VM y HoneyV.
8. Leer el JSON generado por el análisis remoto.
9. Revisar el reporte desde el visor integrado.

## Qué aporta este módulo dentro de NICS CyberLab

Este módulo aporta una capacidad de intercambio y recuperación de análisis que une tres elementos:

- NICS CyberLab como plataforma de control
- una máquina Windows de análisis con FLARE-VM
- el repositorio original HoneyV como base del flujo de análisis remoto

La aportación principal no es crear un nuevo sistema de análisis, sino integrar operativamente el intercambio de muestras y la recuperación del resultado en una interfaz única, clara y trazable. Esto hace posible gestionar el envío de artefactos sospechosos, su verificación y la lectura posterior del reporte desde el entorno general de NICS CyberLab, mientras el análisis profundo sigue realizándose en la máquina remota preparada para ello. :contentReference[oaicite:4]{index=4}