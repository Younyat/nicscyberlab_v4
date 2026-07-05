# Obstaculos Cientificos y Resoluciones

Este documento registra los principales obstaculos encontrados durante la validacion cientifica de `Level A`, `Level B` y los paquetes `paper evidence`, junto con la correccion aplicada y la razon metodologica para esa correccion.

El objetivo no es maquillar fallos en reporting, sino dejar trazabilidad de:

- que se rompio
- en que capa se rompio
- como se corrigio
- que sigue exigiendo rerun o reacquisicion para mantener rigor cientifico

## 1. Nivel de rigor adoptado

Se adopto un criterio `preserve-first` estricto:

- la evidencia critica debe preservarse antes de cleanup o bundle ligero
- los reportes no pueden presentar como `final claim` lo que solo existe como marcador `not available`
- cuando falta evidencia critica, el caso pasa a `diagnostic/audit only`
- si la correccion cambia adquisicion o preservacion, los resultados anteriores no se mezclan con los nuevos

## 2. Obstaculos principales

### 2.1. Denominadores cientificos mezclados

Problema:

- se mezclaban `Level A standalone`, `nested Level A over Level B` y `accepted Level B`
- eso inflaba interpretaciones y confundia comparabilidad

Causa raiz:

- la capa de reporting agregaba resultados heterogeneos bajo un mismo denominador

Correccion:

- separacion explicita de denominadores
- exclusion explicita de ejecuciones `failed`
- separacion entre `Option B` y `Option C`

Estado:

- corregido en reporting y evaluacion

### 2.2. Alias mapping ambiguo entre case_id y preserved heavy-case directory

Problema:

- la relacion entre `case-7b45e0d8` y `CASE-20260702-202841` podia leerse como inconsistencia

Causa raiz:

- el retained lightweight bundle y el heavy-case preservado usaban identificadores distintos sin nota interpretativa suficiente

Correccion:

- alias mapping explicito en tablas y gap reports

Estado:

- corregido en reporting

### 2.3. Packet-level Modbus no preservado

Problema:

- existia `network_context_manifest`, pero no PCAP defendible para confirmar Modbus a nivel paquete

Causa raiz:

- se preservaba contexto de red sin garantizar `PCAP/PCAPNG` o segmentos suficientes

Correccion:

- el reporting ya no lo presenta como recuperable desde artefactos actuales
- `critical evidence gate` exige evidencia packet-level real
- el retained bundle debe conservar PCAP/segmentos cientificamente utiles

Estado:

- diagnosticado y endurecido en pipeline
- sigue requiriendo evidencia real preservada para claims finales

### 2.4. OT export ausente o no disponible para analisis

Problema:

- `analysis/06_ot/ot_findings.json` podia quedar en `skipped_no_ot_export`

Causa raiz:

- la adquisicion/preservacion/retencion OT no garantizaba la presencia del export como input util para el analisis

Correccion:

- inspeccion de causa raiz mas precisa en gap reports
- exigencia de `industrial/*` en manifest y retained bundle
- eventos explicitos de pipeline para `ot_export_started/completed/preserved/manifested`

Estado:

- diagnosticado y endurecido en reporting/pipeline
- sigue exigiendo preservacion OT real para cerrar el gap

### 2.5. Raw Wazuh alert-to-case binding ausente

Problema:

- habia alert summaries, pero no siempre un binding defendible alerta -> caso

Causa raiz:

- el trigger util para intervencion no se persistia como artefacto cientifico explicito

Correccion:

- `metadata/trigger_alert_binding.json`
- inclusion en manifest, custody y retained bundle

Estado:

- corregido en pipeline de preservacion

### 2.6. forensic_intervention no persistido como artefacto causal

Problema:

- faltaban relaciones `alert -> forensic_case` y `forensic_case -> preserved_evidence`

Causa raiz:

- la intervencion existia operacionalmente, pero no como artefacto o provenance cientificamente citable

Correccion:

- `metadata/forensic_intervention.json`
- inclusion en manifest, custody y retained bundle

Estado:

- corregido en pipeline de preservacion

### 2.7. Relaciones degraded por timestamps no resolubles

Problema:

- algunas aristas quedaban `degraded` por no poder ordenar temporalmente eventos criticos

Causa raiz:

- faltaban timestamps UTC normalizados o no estaban expuestos en artefactos citable

Correccion:

- `metadata/normalized_causal_timestamps.json`
- diagnostico explicito de que timestamp existe, cual falta y que archivo deberia contenerlo

Estado:

- corregido en pipeline y reporting

### 2.8. Manifest/custody interpretado de forma demasiado fuerte

Problema:

- `custody valid` podia leerse como verificacion integral completa

Causa raiz:

- large-artifact skip y verificacion parcial no estaban siempre interpretados con lenguaje suficientemente conservador

Correccion:

- frase fija: `Integrity verification is partial because large artifacts were skipped; custody-chain validity does not imply full byte-level rehash of every artifact.`
- separacion entre `verified`, `skipped_large`, `failed_hash`, `missing`, `not_checked`

Estado:

- corregido en reporting

### 2.9. Adopcion de background cases/placeholders no validos

Problema:

- directorios `CASE-*` vacios o placeholders podian bloquear o contaminar una nueva repeticion

Causa raiz:

- el guard de preservacion y el runner aceptaban demasiado pronto ciertos casos recientes

Correccion:

- pruning de placeholders huerfanos
- validacion minima para que un case pueda adoptarse

Estado:

- corregido en pipeline

### 2.12. La campana seguia tras un `failed` y mezclaba recuperacion con repeticion nueva

Problema:

- una repeticion `Level B` podia fallar de forma terminal y, aun asi, la campana continuaba lanzando ataques o intentando recuperar flujo
- tras reinicios del frontend/plataforma, el comportamiento podia parecer aun menos profesional porque la ejecucion ya figuraba como terminada mientras el backend seguia intentando avanzar

Causa raiz:

- el runner generaba el reporte final correctamente, pero no cerraba la campana en el primer `execution_status=failed`

Correccion:

- cierre temprano de campana en el primer `failed`
- conservacion de la evidencia ya generada
- generacion de reportes/conclusiones solo con las repeticiones realmente ejecutadas
- registro explicito de `early stop reason`

Estado:

- corregido en pipeline

### 2.13. Los casos limpiados quedaban sin una forma profesional de auditoria ligera

Problema:

- algunos `CASE-*` terminaban con restos minimos o con una semantica ambigua despues del cleanup
- eso no dejaba claro si la evidencia pesada habia sido borrada por politica de retencion o si simplemente faltaba

Causa raiz:

- el cleanup preservaba memoria cientifica en el workspace de ejecucion, pero no reconstruia el propio `CASE-*` como objeto ligero/auditable

Correccion:

- el cleanup de `Level B` ahora reconstruye el `CASE-*` como `lightweight audit shell`
- se preservan manifest/custody, artefactos criticos, analisis, hashes, causal outputs y trazas de retencion
- se sella `metadata/lightweight_retention_audit.json` con la explicacion de que la evidencia pesada fue eliminada por la plataforma para liberar espacio y no por manipulacion
- el shell ligero se mantiene por politica por debajo de `500 MB`

Estado:

- corregido en pipeline

### 2.10. Trigger de alerta desalineado temporalmente con el ataque

Problema:

- un ataque podia terminar en una ventana y el trigger quedar ligado a una alerta mucho mas tardia
- eso rompia la ventana de red y acababa en `selected_segments=0`

Causa raiz:

- matcher/fallback demasiado permisivo con alertas tardias

Correccion:

- ventana temporal acotada alrededor del ataque
- fallback OT-aware con coherencia temporal
- backlog corto en monitor para no perder la alerta del propio ataque

Estado:

- corregido en pipeline

### 2.11. Limpieza de espacio no verificada cientificamente

Problema:

- podia ejecutarse cleanup en nodos y aun asi llegar a memoria con espacio insuficiente

Causa raiz:

- se trataba `cleanup ejecutado` como exito, pero no se verificaba si `free_mb_root` quedaba realmente por encima del umbral requerido por LiME build
- ademas, `Level B` y `DFIR AUTO` no reutilizaban exactamente la misma ruta de acceso remoto que el boton de `Node Health`

Correccion:

- helper compartido de cleanup remoto basado en la misma resolucion de nodo que `Node Health`
- medicion `free_mb_before/free_mb_after`
- umbral minimo verificado (`MEMORY_BUILD_MIN_FREE_MB`)
- limpieza preventiva antes de memoria build
- reintento tras `low-space`
- cleanup entre repeticiones `Level B` como gate real, no solo como accion cosmetica

Estado:

- corregido en pipeline

## 3. Caso operativo que motivo la correccion de espacio

Contexto:

- se estaba ejecutando una campana de `Level B` con `10` repeticiones
- cada repeticion `Level B` debia lanzar `2` repeticiones anidadas de `Level A`
- en fases avanzadas aparecio fallo de memoria LiME sobre `fuxa` por `free=730MB`

Leccion metodologica:

- no basta con invocar cleanup
- hay que verificar que el cleanup deja el nodo por encima del umbral cientifico/operacional requerido

## 4. Que quedo corregido solo en reporting y que quedo corregido en pipeline real

Corregido en reporting:

- separacion de denominadores
- exclusion de casos fallidos
- wording conservador de claims
- trazabilidad de alias mapping
- interpretacion parcial de manifest/custody

Corregido en pipeline real:

- trigger binding explicito
- forensic intervention explicito
- normalized timestamps
- critical evidence gate
- pruning de placeholders
- coherencia temporal del matcher
- backlog corto del monitor para no perder alertas del ataque
- cleanup remoto compartido y verificado por espacio libre
- cierre temprano de campana tras `failed`
- reconstruccion del `CASE-*` como shell ligero/auditable

## 5. Que sigue requiriendo rerun

Un rerun de `Level B` sigue siendo obligatorio cuando:

- cambie la adquisicion o preservacion efectiva
- cambie el retained bundle de artefactos criticos
- se corrija captura de PCAP/OT export/binding causal de forma que el nuevo resultado no sea comparable con la campana antigua

## 6. Principio final

Cuando una limitacion afecta la suficiencia empirica de la evidencia:

- no se compensa con narrativa
- no se suaviza con tablas
- se corrige en adquisicion, preservacion, analisis o retencion
- y, si hace falta, se repite la campana con las nuevas guardrails
