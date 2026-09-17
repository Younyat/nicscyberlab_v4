# Estudio de viabilidad — Campañas experimentales controladas y política de retención de casos

**Naturaleza de este documento:** estudio de viabilidad técnico, read-only. No se ha modificado ningún fichero de código ni de configuración de la plataforma para producir este informe. Toda afirmación cita archivo:línea real. Donde la evidencia no permite una conclusión limpia, se dice explícitamente en vez de asumir.

**No se ha implementado nada.** Este documento responde a la petición explícita de "quiero un informe de viabilidad... no implementar nada hasta revisar ese análisis."

---

## 0. Método

Se lanzaron 4 investigaciones de código independientes y en paralelo, cada una acotada a un subsistema real:

1. Ciclo de vida de sellado/retención/cleanup (`retention_service.py`, `level_b_repetition_runner.py`, `level_c_orchestrator/service.py`, `global_cleanup_service.py`).
2. Configuración de campañas en el dashboard (formulario, endpoints, persistencia de config).
3. Pipelines de generación de evidencia OT/temporal/missing-evidence relevantes para fault injection (`network_context_importer.py`, `foc_causal_reconstruction/service.py`, `edge_evaluator.py`).
4. Prior art de archivado ZIP y huella real en disco de casos sellados.

Todas las citas de archivo:línea de este informe provienen de esas cuatro investigaciones, verificadas contra el árbol de trabajo actual.

---

## 1. Resumen ejecutivo

**El hallazgo más importante de todo el estudio:** la plataforma **ya tiene hoy** una política de retención — pero es una regla booleana hardcodeada ("conservar solo la última repetición"), nunca expuesta al usuario, y con dos huecos reales de integridad forense (manifest y custody no se actualizan cuando se borra evidencia). Además, existen **dos mecanismos de cleanup independientes** (uno en `level_b_repetition_runner.py`, otro en Level C vía `global_cleanup_service.py`) que no se coordinan entre sí — cualquier política nueva de retención debe parchear ambos, o Level C la anulará silenciosamente.

**Segundo hallazgo importante:** el evaluador OT (`plc_state_observation`) usa una compuerta binaria muy tosca (`total_ot_records > 0`) sin ningún chequeo semántico fino. Esto significa que la variante "degradación semántica parcial" (registros parciales pero no vacíos) **no dispararía `degraded` de forma fiable** con el evaluador actual — solo la variante "export preservado pero vacío" lo hace de forma determinista, porque replica exactamente el mecanismo real ya observado en la ejecución degradada de la campaña real.

**Tercer hallazgo importante:** `acquisition_profile_id` existe como campo en toda la plataforma pero **nunca ha determinado comportamiento real** — es una etiqueta cosmética/de trazabilidad. Introducir condiciones experimentales que sí cambien comportamiento sería el primer caso real de "un ID de perfil cambia lo que se adquiere" en esta plataforma — no es una extensión de un patrón existente, es un patrón nuevo.

**Cuarto hallazgo importante:** ZIP64 ya está probado empíricamente en este stack exacto — existe un ZIP manual de 9.7 GiB / 2050 entradas / 3 entradas >4GiB que Python 3.12.3 (versión real de este entorno) lee y verifica correctamente. La tecnología no es el riesgo; el riesgo real es el **espacio en disco** (137G libres de 589G en el momento de la comprobación) y la **naturaleza sparse** de las imágenes de disco (un caso real mide 27G reales / 79G aparentes — una copia/extracción ingenua ya demostró materializar los huecos y casi triplicar el uso real a 79G).

Recomendación de alto nivel por bloque (detalle en §6): **GO WITH CHANGES** en casi todo; **NO-GO** explícito solo en "retención All sin compresión inmediata" y en "degradación OT semántica fina sin antes mejorar el evaluador".

---

## 2. Parte A — Condiciones experimentales de evidencia

### 2.1 Línea base actual

No existe ningún mecanismo de fault injection hoy. Lo confirma el propio código: `app_core/infrastructure/foc_paper_evidence/tables.py:135` y `service.py:1019` declaran explícitamente que los estados degraded/missing/ambiguous observados hasta ahora son orgánicos ("this package reflects observed degradation in real outputs... does not claim a controlled fault-injection campaign"). Es decir, los autores ya eran conscientes de este hueco.

No existe tampoco ningún registro de "perfiles de adquisición" (`acquisition_profile_id` es una cadena descriptiva hardcodeada como fallback en 8 ficheros distintos — `campaign_service.py:285,386`, `execution_service.py:334`, `scientific_memory.py:215,313,390`, `scientific_memory_sync.py:138`, `comparison_registry.py:140`, `level_b_repetition_runner.py:3610` — nunca resuelta contra un diccionario/registro). Los pasos de adquisición reales (`_run_single_repetition` en `level_b_repetition_runner.py`) son llamadas Python incondicionales y fijas, no derivadas de ningún perfil.

### 2.2 Selector Baseline / Experimental mode

**Viable, riesgo bajo.** El patrón de UI para mostrar/ocultar controles según el Level ya existe y funciona: `syncAttackProfileField()` (`foc_repetition_manager.js:2906-2912`, oculta un bloque completo con `classList.toggle("hidden", level === "A")`) y `syncNestedLevelAField()` (`foc_repetition_manager.js:1247-1267`, oculta + limpia el valor si no aplica). Un nuevo `syncExperimentalConditionField()` seguiría exactamente el mismo patrón.

La configuración de campaña ya se persiste en un único punto (`campaign_service.py:248-299`, escrito a `campaign_config.json` vía `_write_json` en la línea 300-301) y se lee de vuelta en los mismos puntos donde hoy se lee `acquisition_profile_id` (`execution_service.py:41`, `level_b_repetition_runner.py:1234`, `level_c_orchestrator/service.py:528` vía `campaign_service.get_campaign()`). Un nuevo campo `experimental_condition_id` (ver §2.7 sobre por qué no reutilizar `acquisition_profile_id`) encaja en el mismo dict sin tocar la forma de persistencia.

### 2.3 OT semantic degradation

**El evaluador real** (`app_core/infrastructure/foc_causal_reconstruction/service.py:521-531`, requisito `plc_state_observation`) es así de tosco:

```python
if int(network_ot_context.get("total_ot_records") or 0) > 0:
    return {"status": "recovered", ...}
limitations.append("The OT export analysis exists but recorded no PLC/SCADA state entries for this case.")
return {"status": "degraded", ...}
```

Es un **todo-o-nada**: cualquier recuento > 0 (incluso 1 registro sin relación con la correlación real) se marca `recovered`. No hay ningún chequeo de "¿el registro/valor concreto declarado en ground truth (registro=4, valor=30) está presente?", ni de "¿existe un readback que confirme el cambio de estado?". El propio evaluador lo reconoce en su texto de limitaciones (líneas 524-526).

**Comparación de las 5 variantes propuestas:**

| Variante | Dispara `degraded` de forma fiable HOY | Requiere cambios en el evaluador | Riesgo de alterar retrospectivamente evidencia |
|---|---|---|---|
| (a) Export con soporte semántico parcial | **NO** — cualquier registro>0 es `recovered` | Sí (chequeo semántico fino nuevo) | Bajo si es a nivel de adquisición |
| (b) Exclusión selectiva de campos/registros | **NO**, mismo motivo que (a) | Sí | Bajo si es a nivel de adquisición |
| (c) Ventana OT incompleta | Depende — si la ventana no solapa la escritura, records=0 → SÍ dispara degraded; si solapa parcialmente pero captura ≥1 registro, NO | No, si se logra records=0 | Ninguno — usa el mecanismo real ya existente (`pre_context_seconds`/`post_context_seconds`, `network_context_importer.py:20-21`, hoy sin variar por el llamador) |
| (d) Procesamiento protocol-aware incompleto | **NO** de forma fiable — depende de qué se "incompleta"; si sigue contando registros >0, sigue siendo `recovered` | Probablemente sí | Medio — toca el parser scapy (`_decode_modbus_adu`, líneas 272-356) |
| (e) Export preservado pero semánticamente vacío | **SÍ, determinista** — replica exactamente `total_ot_records == 0`, el mecanismo real ya observado en EXEC-0006 de la campaña real | **No** — cero cambios de evaluador | Ninguno — es honesto: el fichero existe, está vacío, y así se declara |

**Recomendación:** la variante **(e)**, implementada como una variante controlada de **(c)** — es decir, una condición experimental que fuerza deliberadamente que la ventana de captura preservada no solape la escritura OT (reproduciendo con control el mismo hueco de rotación de ~22-26s entre segmentos de 120s ya documentado como estructural en la auditoría de la campaña real) — es la opción **metodológicamente más limpia**: no toca el evaluador, no toca el parser, y reproduce fielmente el único mecanismo de degradación OT que la plataforma ya ha demostrado producir de forma real y auditada.

Las variantes (a)/(b)/(d) — degradación semántica *fina* (parcial-pero-no-vacía) — requieren primero ampliar el evaluador con un chequeo semántico real (p.ej. contar escrituras que coincidan con el registro/valor objetivo, o exigir un readback pareado). **Esto está directamente acoplado a la Decisión de Autor pendiente de la auditoría anterior** (`FINAL_CAMPAIGN_AUDIT.md`, Sección 6, bloqueo #3: C3 pasa bajo la regla actual de "presencia" pero no bajo la prosa literal de dos cláusulas del paper para EXEC-0006). Recomiendo tratarlas como una **fase 2 explícitamente posterior**, no simultánea: primero decidir la definición de C3, después ampliar el evaluador, y solo entonces construir las variantes finas.

### 2.4 Temporal uncertainty

**Hallazgo clave (corrige una asunción previa):** `max_clock_offset_ms` **no es solo descriptivo** — es una entrada real en la decisión `ambiguous`/`contradicted`. La función `_evaluate_temporal()` (`foc_causal_reconstruction/service.py:537-564`) calcula:

```python
uncertainty_seconds = (max_offset_ms + timestamp_resolution_ms + acquisition_jitter_ms) / 1000.0
delta = dst_value - src_value
if delta > uncertainty_seconds: return "supported"
if abs(delta) <= uncertainty_seconds: return "ambiguous"
return "contradicted"
```

Esto abre **dos palancas legítimas y ya existentes** en la arquitectura, ninguna de las cuales corrompe evidencia:

1. **Omitir deliberadamente la corrección de reloj** para una ejecución experimental declarada, usando el mecanismo `_time_sync_policy()` ya existente (`node_health_api.py:1669-1710`, con su flag `maintenance_override`). Esto produce un `max_clock_offset_ms` real y honesto más grande (exactamente el mismo mecanismo que causó el offset real de 0.247s de la campaña ya auditada — aquí se haría a propósito y de forma controlada en vez de por bug).
2. **Variar `timestamp_resolution_ms` / `acquisition_jitter_ms`** declarados en el ground truth del escenario (`case_context["ground_truth"]`, con default 1000ms cada uno) — esto es una declaración honesta de "qué precisión de instrumentación reclama esta ejecución", hecha *antes* de correr, no una alteración posterior.

**Advertencia importante, específica de esta plataforma:** la arista e5 (`edge_detection_surface_to_alert_observation`) está **arquitectónicamente fijada a delta=0 siempre** (`detection_surface_hit_at_utc` se copia literalmente del mismo valor que `alert_observed_at_utc`, `level_b_repetition_runner.py:406-410`, ya documentado con comentario explícito en el código). Esto significa que e5 será `ambiguous` bajo **cualquier** condición, incluida baseline — no sirve como arista de demostración para "temporal uncertainty", porque no puede moverse a `supported` bajo ninguna condición actual. Una campaña de "temporal uncertainty" con fines demostrativos debe apuntar a **otra arista** con `source_timestamp_ref`/`target_timestamp_ref` reales declarados en el ground truth del escenario — y esto es **dependiente del escenario**: se confirmó que el ground truth de `industrial_file` ni siquiera declara esos campos para e5 (da `"not_required"`), mientras que `scn-b83dbbfb` sí los declara. Antes de construir esta condición hay que validar, escenario por escenario, qué arista es candidata real.

### 2.5 Evidence suppression

**La más limpia de las tres, sin ambigüedad.** El mecanismo `missing_evidence` (`edge_evaluator.py:34`) ya está pensado para esto exactamente: si un artefacto requerido nunca se registra en `manifest.json["artifacts"]` (porque el paso de adquisición correspondiente se omite honestamente), el evaluador ya produce `missing` de forma correcta y trazable, sin ningún cambio de código en el evaluador. El propio `network_context_importer.py` ya tiene un estado orgánico de esto (`"skipped_no_preserved_segments"`, líneas 364-370) — solo falta una etiqueta explícita de "esto se omitió porque es una condición experimental declarada X", en vez de que ocurra de forma incidental.

**No requiere alterar evidencia después del hecho** — es una decisión tomada *antes* de adquirir, honestamente reflejada porque el artefacto simplemente nunca se genera ni se declara.

### 2.6 Nomenclatura de interfaz (sin `e4`/`e5`)

Mapeo recomendado interfaz ↔ interno (el interno permanece en backend/logs, nunca en el dashboard principal):

| Nombre en UI | Descripción en UI | Arista interna afectada | Estado esperado |
|---|---|---|---|
| Baseline | Normal evidence conditions | — (ninguna) | mixed, mayoría `recovered` |
| OT semantic degradation | OT action to PLC/SCADA state correlation | `edge_ot_write_to_plc_state_observation` (e4) | `degraded` |
| Temporal uncertainty | Detection-to-alert temporal ordering *(nota: renombrar la descripción de cara al usuario a la arista realmente afectada, ver advertencia §2.4 — no necesariamente e5)* | arista candidata validada por escenario | `ambiguous` |
| Evidence suppression | Required evidence availability | edge cuyo `required_evidence` se omite deliberadamente | `missing` |

Esto ya es coherente con el patrón ya usado en el dashboard científico (`forge_vi_dashboard/endpoints.py`, constantes `_C_INVARIANTS`/`_E_CRITERIA`/`_IR_GATE` con nombres descriptivos, e4/e5 solo en comentarios/backend) — no hace falta inventar un patrón nuevo, solo extenderlo.

### 2.7 Garantizar que baseline nunca active una condición por accidente

Recomendaciones concretas:

1. **Campo nuevo y propio**, `experimental_condition_id`, en vez de sobrecargar `acquisition_profile_id`. Motivo: `acquisition_profile_id` nunca ha determinado comportamiento real (§2.1) — reutilizarlo implicaría retroactivamente que campañas antiguas "eligieron" un comportamiento que nunca existió. Mejor un campo nuevo, semánticamente honesto.
2. **Default explícito y estricto**: ausencia del campo, cadena vacía, o el literal `"baseline"` deben tratarse de forma idéntica — código de comportamiento real, no solo UI.
3. **Lista blanca, no lista negra**: el registro de condiciones (que hay que construir desde cero, §2.1) debe rechazar/fallar ruidosamente ante un `experimental_condition_id` desconocido, nunca ignorarlo silenciosamente (un typo no debe producir un estado híbrido no declarado).
4. **Punto único de decisión, antes de cualquier rama**: la comprobación `if experimental_condition_id not in (None, "", "baseline")` debe vivir en un solo lugar (el punto de entrada de `_run_single_repetition`), con la ruta baseline como *default* explícito, nunca como fallback implícito de un error.
5. **Visibilidad forzada en metadata**: si una condición está activa, debe quedar grabada de forma prominente e irreversible en `forensic_intervention.json` y `campaign_manifest.json` — cualquier activación accidental sería inmediatamente auditable, no solo prevenida.

---

## 3. Parte B — Retención y archivado de casos sellados

### 3.1 Línea base actual — más compleja de lo que parece

**Ya existe una política "Last 1" hoy, hardcodeada:**

```python
# level_b_repetition_runner.py:4145
preserve_as_final_sample = (preserve_final_case and repetition_number == requested_repetitions)
```

Si es `True`, el caso se mueve intacto (con bytes crudos) a `campaign_dir/final_sample_case/` (`retention_service.py:651`, `shutil.move`, **no comprime**). Si es `False` (todas las demás repeticiones), se construye un "lightweight bundle" (solo manifests + análisis derivado, nunca memoria/disco/red crudos — lista blanca exacta en `retention_service.py:16-58`) y **el directorio original se borra con `shutil.rmtree`** (línea 653).

`preserve_final_case` es un booleano simple, sin parámetro numérico "N" en ningún sitio. Y **el endpoint HTTP público que lanza campañas Level B reales nunca lo expone en absoluto** (`foc_experimentation_api.py:717-747`) — siempre se aplica el default `True`, sin forma de desactivarlo ni de pedir un N distinto desde la UI/API hoy.

**Dos huecos reales de integridad forense, independientes de cualquier feature nueva:**

- El borrado de memoria/disco/red **no se registra en `chain_of_custody.log`** — `retention_service.py` nunca llama a `_append_custody_entry` (`forensics_api.py:1260-1298`). Solo escribe una nota JSON separada, no encadenada (`metadata/lightweight_retention_audit.json`), que se autodeclara `"heavy_artifacts_deleted_is_not_tampering": True` — una afirmación, no una prueba criptográfica.
- **`manifest.json` no se reescribe tras el borrado** — sigue listando los artefactos de memoria/disco/red con sus hashes originales, aunque los ficheros ya no existan. Nadie llama a `_write_manifest`/`_add_artifact_fast` para reflejar la eliminación.

**Un segundo mecanismo de cleanup, completamente independiente, existe en Level C:** la fase `CLEANING` (`level_c_orchestrator/service.py:834-865`) llama a `global_cleanup_service.execute_cleanup()`, que hace un `shutil.rmtree` **incondicional** sobre cualquier directorio de caso marcado `deletable=True` (`global_cleanup_service.py:431-484`) — incluidos los remanentes ya reducidos a "lightweight" por el mecanismo anterior. No preserva ningún bundle, no escribe ninguna nota de auditoría, no toca custody. **Esto es lo más importante de todo el estudio de retención**: cualquier política nueva (Last N / All) debe parchear *ambos* mecanismos, o Level C anulará silenciosamente lo que la política pida.

**Secuenciación confirmada — buena noticia:** el agregado final de la campaña (`_store_level_b_report`, línea 4214) se construye **una sola vez, al final, tras todas las repeticiones**, leyendo exclusivamente de la lista `results` en memoria / `per_repetition_results` ya escrito incrementalmente al JSON del job (línea 4162) — **nunca vuelve a leer los directorios de caso**. Esto confirma que el cleanup por repetición, tal y como ya sucede hoy, no pone en riesgo el agregado final: el diseño ya asume que cada `result` se captura *antes* de limpiar.

**Campo `retention_policy` ya existe pero es solo descriptivo:** dos strings fijos (`"original_case_retained"` para A, `"profiles_only_after_archive"` para B/C, `campaign_service.py:289`) — **nunca se leen para condicionar comportamiento real**. La decisión real es la aritmética `repetition_number == requested_repetitions`, no este campo.

**Nota para el equipo, no resuelta por este estudio:** se encontró un campo `heavy_case_policy` en el mismo payload de creación de campaña (`campaign_service.py:290`) que no se ha caracterizado en profundidad en esta investigación — antes de implementar, revisar si ya solapa parcial o totalmente con la política de retención propuesta, para no duplicar mecanismos.

### 3.2 Last 1 / Last N / All

**Last 1** ya está implementado (aunque no expuesto). **Generalizar a Last N** es una extensión aritmética directa:

```python
# hoy:
preserve_as_final_sample = (preserve_final_case and repetition_number == requested_repetitions)
# generalización propuesta:
preserve_as_final_sample = (repetition_number > requested_repetitions - retain_count)
```

con `retain_count` clamped a `[0, requested_repetitions]`, y "All" como caso `retain_count >= requested_repetitions` (o, más explícito, un valor centinela que desactive el cleanup por completo para esa campaña).

**Cambios reales necesarios:**
1. Nuevo campo entero (`sealed_case_retention_count`, o el enum `Last 1 / Last N / All` + N) en `campaign_config.json`.
2. Exponerlo realmente en el cuerpo de la petición de `/api/foc/repetitions/level-b/run` — hoy ni siquiera `preserve_final_case` se lee del body (`foc_experimentation_api.py:717-747`), así que esto es, además de la feature nueva, **la corrección de un hueco ya existente**.
3. **Parchear `global_cleanup_service.execute_cleanup()`** para que respete la ventana de retención vigente (no marcar `deletable=True` un caso todavía dentro de las últimas N repeticiones) — sin esto, Level C rompe la política silenciosamente (§3.1).
4. Threading del mismo parámetro a través de `launch_level_c` → `start_level_b_repetitions_job` por cada repetición de Level C.

### 3.3 Archivado ZIP/ZIP64 + verificación antes del cleanup

**Viable, tecnología ya probada en este stack exacto.** Existe ya un ZIP manual de 9.7 GiB, 2050 entradas, 3 entradas >4GiB, `extract_version=45` (marcador ZIP64) — Python 3.12.3 (versión real confirmada de este entorno) lo lee y verifica sin problema. `zipfile` ya está importado en el codebase para otros fines (`foc_paper_evidence/service.py:6`, `windows_lab_exchange_service.py:10`) — no hay dependencia nueva.

**Riesgo real, medido, no teórico — ficheros sparse:** un caso real sellado mide **27G reales / 79G aparentes** en disco (`disk/` concretamente: 18G reales / 70G aparentes — imágenes raw muy sparse). Un `zipfile`/`tarfile` estándar lee el **stream lógico** (79G), no el mapa sparse — el coste de CPU/I-O escala con 79G, no con 27G. Peor aún: **ya se demostró empíricamente** que una copia/extracción ingenua de este mismo caso materializa los huecos sparse y **casi triplica el uso real de disco** (27G→79G). Recomendación dura: el archivado debe leer directamente del origen sparse en su sitio, sin ningún paso previo de copia/extracción a un directorio temporal.

**Secuencia recomendada** (exactamente la que pide el usuario, con primitivas ya existentes):

```
run → preserve → seal → analyze → reconstruct
   → aggregate campaign results
   → final report
   → apply retention policy (¿este caso cae dentro de la ventana N?)
   → si NO está dentro de la ventana Y archive está activado:
        1. zipfile.ZipFile(dest, "w", compression=ZIP_DEFLATED, allowZip64=True)  [lee del origen sparse, sin copiar antes]
        2. sha256 del zip resultante — reutilizar _sha256_path (level_b_orchestrator.py:94-99), ya streaming y tolerante a ficheros grandes
        3. verificación: zip.testzip() (valida CRC32 de cada entrada) — cero infraestructura nueva
        4. si (2)+(3) OK → _append_custody_entry(action="case_archived_verified", details={sha256, size, zip64:true, entries})  [reutilizar forensics_api.py:1260-1298 tal cual]
        5. solo entonces → delete_generated_case_artifacts(...)  [el borrado ya existente]
   → si archive está desactivado, o el caso SÍ está dentro de la ventana N: no se toca
```

Esto **cierra, como efecto colateral, los dos huecos de integridad ya descritos en §3.1** (hoy el borrado no deja rastro en custody ni actualiza el manifest) — recomiendo aplicar el mismo patrón de custody-entry al borrado normal (sin archivo) también, no solo al camino con ZIP, ya que las primitivas (`_append_custody_entry`) son las mismas y el coste es marginal.

**Metadata por archivo, tal como se pidió**, todo derivable de datos que ya existen o de las primitivas ya presentes:

| Campo | Fuente |
|---|---|
| campaign ID / execution ID / case ID | ya disponibles en el contexto de la llamada |
| original case sealed status | `case_result_card` (ya existe) |
| archive creation timestamp | `datetime.now(timezone.utc)` en el momento de crear el zip |
| archive format | literal `"zip64"` vs `"zip"` según si se activó `allowZip64` / si algún entry superó 4GiB |
| archive size | `zip_path.stat().st_size` |
| integrity hash | `_sha256_path(zip_path)` — reutilizable sin cambios |
| verification status | resultado de `zip.testzip()` |

**Alternativas a ZIP/ZIP64 evaluadas:** no se recomienda cambiar de formato sin justificación explícita, tal como pidió el usuario. `tar` sin compresión (ya hay un `.tar` manual de 78.24 GiB en disco) evita la sobrecarga de compresión pero no aporta verificación de integridad por entrada como `zipfile.testzip()`; formatos con soporte sparse nativo (p.ej. `tar --sparse`) preservarían el ahorro de espacio del origen pero no están usados hoy en ningún sitio del código — introducirlos sería una dependencia/patrón nuevo, no una reutilización. **Recomendación: mantener ZIP64**, ya probado, ya sin dependencias nuevas, con la salvedad del coste de leer el stream lógico completo en vez del sparse.

### 3.4 Coste aproximado por política

No se ha cronometrado ningún archivado real en esta investigación (solo lectura, sin ejecutar procesos largos) — cualquier cifra de tiempo sería inventada. Lo que sí es medible con los datos ya recogidos:

- **Retain Last 1** (ya en producción): coste marginal ≈ 0, ya corre así hoy.
- **Retain Last N**: coste de disco dominante ≈ N × ~79G aparentes por caso completo retenido en crudo (el resto de repeticiones siempre conservan su lightweight bundle de ~692KB, coste despreciable). Recomendación: N pequeño (1–3) por defecto, dado que cada unidad son decenas de GB.
- **Retain All**: ≈ 10 × ~79G aparentes ≈ 790G para una campaña de 10 ejecuciones — **no cabe** en los 137G libres medidos hoy (589G totales, 76% usado) sin compresión inmediata o almacenamiento externo. Con ZIP inmediato por caso (ratio real medido ≈ 8.8:1 sobre la muestra real, 9.04G comprimidos de 79G aparentes) el total bajaría a ≈ 90G — todavía ajustado contra 137G libres, y sin margen para campañas concurrentes.
- **CPU/I-O de ZIP**: dominado por leer el stream lógico completo (~79G) en compresión DEFLATE por caso — coste real no cronometrado; recomiendo una prueba piloto cronometrada sobre un caso real antes de comprometer un presupuesto de tiempo por campaña.
- **Espacio**: ya existe un hook para redirigir el destino del archivo fuera del `EVIDENCE_STORE_ROOT` compartido (`archive_destination`, añadido 2026-09-01, `retention_service.py:641-644`) — señal de que esta preocupación ya estaba sobre la mesa; recomiendo usarlo para todo archivado "All"/"Last N>1" en vez de asumir espacio local suficiente.

### 3.5 Riesgos de integridad, custody, manifests y reconstruction

- **Ya existen hoy**, independientemente de cualquier feature nueva: manifest no actualizado tras borrado, custody no registra el borrado (§3.1). Cualquier trabajo de retención/archivado toca exactamente este código — recomiendo corregirlo como parte del mismo cambio, no como tarea aparte.
- **Reconstruction no se ve afectado por el momento del cleanup** — confirmado que el agregado final nunca relee directorios de caso (§3.1), así que borrar/archivar antes del agregado es seguro por diseño ya hoy.
- **El mecanismo dual de cleanup (Level B vs Level C `global_cleanup_service`) es el riesgo estructural más alto** — si no se coordina, cualquier promesa de "Last N" o "All" hecha por el dashboard puede ser falsa en la práctica para campañas Level C.
- El archivo ZIP en sí, una vez verificado con `testzip()` + hash + custody entry, se vuelve una **prueba de integridad más fuerte** que la que existe hoy para el borrado sin archivar — no introduce nuevo riesgo neto si se sigue la secuencia de §3.3.

### 3.6 Alcance por niveles

Confirmado viable dejar Level A completamente intacto: su ruta de lanzamiento (`level_a_scientific_report_service.py`) es un servicio separado que no comparte el bucle de cleanup de `level_b_repetition_runner.py`. El patrón de ocultar controles de UI por nivel (§2.2) ya cubre exactamente este caso — los controles de retención/archivado se ocultarían con la misma técnica cuando `level === "A"`.

---

## 4. Respuestas directas a los puntos de la petición

1. **Componentes a modificar:** `campaign_service.py` (nuevos campos de config), `level_b_repetition_runner.py` (generalizar `preserve_as_final_sample` a N, leer `experimental_condition_id`), `retention_service.py` (nuevo `action_type` con ZIP+verify+custody), `global_cleanup_service.py` (respetar ventana de retención), `foc_experimentation_api.py` (exponer los campos que hoy faltan en el body), `level_c_orchestrator/service.py` y `api.py` (threading de los mismos parámetros), `foc_repetition_manager.html`/`.js` (nuevos selectores), y un módulo **nuevo** de registro de condiciones experimentales (no existe hoy nada análogo a extender).
2. **¿Sin romper el flujo existente?** Sí, siempre que todos los campos nuevos sean opcionales con default = comportamiento actual exacto (ver §2.7 y §6).
3. **Backend que controla el sellado:** `forensics_api.py` (`dfir_orchestration_done`, manifest, custody, digest).
4. **Backend que controla el cleanup en B/C:** dos sitios, no uno — `retention_service.py`/`level_b_repetition_runner.py` (por repetición) y `global_cleanup_service.py` vía Level C `CLEANING` (§3.1).
5. **¿Deben permanecer accesibles todos los runs hasta el agregado final?** No hace falta cambiarlo — ya está garantizado por diseño: el agregado lee de `per_repetition_results` en memoria/JSON, nunca de los directorios de caso (§3.1).
6. **Cambios de dashboard:** dos nuevos `<select>` (Experimental mode, Evidence condition profile) + controles de retención/archivado, todos ocultables por nivel con el patrón ya existente (§2.2, §3.6).
7. **Cambios de modelo/config/API:** nuevos campos en `campaign_config.json` (`experimental_condition_id`, `sealed_case_retention_count`, `archive_before_cleanup`); exponer en el body de `/api/foc/repetitions/level-b/run` lo que hoy falta; nuevo `action_type` en `retention_service.py`.
8. **Riesgos de integridad/custody/manifest/reconstruction:** ver §3.5 — los dos huecos ya existentes, más el riesgo de coordinación entre los dos cleanups.
9. **Fault injection sin alterar retrospectivamente evidencia:** por diseño de adquisición, no por borrado posterior — ver §2.3/§2.4/§2.5, las tres condiciones tienen una vía honesta "decidida antes de adquirir".
10. **Variante OT más adecuada:** (e) export preservado pero vacío, vía control de ventana de captura — ver §2.3.
11. **Garantizar que baseline nunca activa una condición por accidente:** ver §2.7, 5 medidas concretas.
12. **Implementar Last 1/N/All:** generalización aritmética directa + parche obligatorio del segundo cleanup de Level C — ver §3.2.
13. **Implementar y verificar ZIP/ZIP64:** ver §3.3, secuencia completa con primitivas ya existentes.
14. **Coste aproximado:** ver §3.4 — cifras de espacio medidas reales; tiempo/CPU no cronometrado, requiere piloto.
15. **Tests a añadir:** aritmética de retención (límites N=0, N>ejecuciones, N=ejecuciones); validación de `experimental_condition_id` (ID desconocido rechazado, ausente→baseline); integración archive→verify→cleanup con fallo de verificación forzado (el original NO debe borrarse); interacción Level C `CLEANING` vs ventana de retención; regresión de campañas baseline existentes (comportamiento byte-idéntico); test de que manifest/custody reflejan honestamente cualquier borrado; test end-to-end por cada condición experimental confirmando el estado de relación esperado (especialmente OT, dado el hallazgo de §2.3).
16. **Rollback:** todos los campos nuevos opcionales con default = comportamiento actual; registro de condiciones como módulo aditivo nuevo (no reescritura de las llamadas de adquisición existentes); archivado con default `Off`; recomendable además un flag de config independiente del despliegue de código para poder desactivar todo el bloque nuevo al instante.
17. **Conflictos con la arquitectura actual:** el más serio es el cleanup dual (§3.1); el segundo es que `experimental_condition_id` sería el primer campo tipo-perfil que realmente cambia comportamiento (`acquisition_profile_id` nunca lo ha hecho) — mantenerlo como campo propio, no reutilizar el existente.

---

## 5. Tabla final de viabilidad

| Feature | Feasible | Risk | Notes |
|---|---|---|---|
| Baseline / experimental mode selector | YES | Low | Patrón de UI y persistencia de config ya existen; solo campos nuevos opcionales |
| OT semantic degradation campaign | YES (variante gruesa) | Medium | Evaluador solo chequea `records>0`; solo la variante "export vacío" es determinista hoy; variantes finas requieren mejorar el evaluador primero (acoplado al bloqueo C3 pendiente) |
| Temporal uncertainty campaign | YES | Low-Medium | Dos palancas honestas ya existen (offset real, resolución/jitter declarados); e5 está fijado a `ambiguous` siempre — validar arista objetivo por escenario |
| Evidence suppression campaign | YES | Low | Usa el mecanismo `missing_evidence` sin ningún cambio de evaluador; la más limpia de las tres |
| Retention: Last 1 | YES (ya existe) | None | Ya implementado hoy, hardcodeado; solo falta exponerlo y documentarlo como política real |
| Retention: Last N | YES | Medium | Generalización aritmética directa; requiere parchear también el cleanup de Level C |
| Retention: All | YES con condiciones | High (espacio) | 137G libres no alcanzan para ~790G aparentes de una campaña de 10 ejecuciones sin compresión inmediata |
| ZIP final case | YES | Low-Medium | ZIP64 ya probado empíricamente en este stack; evitar copiar el sparse antes de comprimir |
| ZIP Last N | YES | Medium | Mismo mecanismo, coste ×N; planificar espacio |
| ZIP all cases | YES con condiciones | High (espacio+CPU+I-O) | Mismo riesgo que "Retain All"; usar `archive_destination` externo, no in-place |
| Verified cleanup (archive→verify→delete) | YES | Low | `testzip()` + sha256 + custody entry, todo con primitivas ya existentes; mejora estricta sobre el borrado no verificado de hoy |
| Level A unaffected | YES | Low | Ruta de lanzamiento separada; patrón de ocultación por nivel ya probado |
| Level B support | YES | Medium | Punto de integración principal; requiere corregir un hueco ya existente (`preserve_final_case` no expuesto en la API) |
| Level C support | YES | Medium-High | Requiere además parchear `global_cleanup_service` — el único riesgo de coordinación real de todo el estudio |

---

## 6. Recomendación final por bloque

- **Condiciones experimentales de evidencia (selector + evidence suppression + temporal uncertainty con validación por escenario):** **GO WITH CHANGES**.
- **OT semantic degradation, variante gruesa (export vacío vía control de ventana):** **GO WITH CHANGES**.
- **OT semantic degradation, variantes finas (parcial/selectiva):** **NO-GO por ahora** — depende de una mejora del evaluador y de resolver primero la decisión de autor sobre C3 pendiente de la auditoría anterior. Tratar como fase 2 separada.
- **Integración en el dashboard (selectores ocultables por nivel):** **GO** — patrón ya probado, sin riesgo para el comportamiento baseline.
- **Retención Last 1 / Last N:** **GO WITH CHANGES**, condicionado a parchear el cleanup dual de Level C.
- **Retención All:** **GO WITH CHANGES**, condicionado a compresión inmediata por caso o almacenamiento externo — **NO-GO tal como está especificado** (conservar todo en crudo online) dado el espacio real disponible.
- **Archivado ZIP/ZIP64 + verificación antes de cleanup:** **GO** — tecnología ya probada en este stack, primitivas de hash/custody ya reutilizables, único trabajo real es la secuenciación y la gestión de espacio.
- **Level A sin tocar:** **GO** — trivial con el patrón existente.

No se ha escrito ni modificado ningún código como parte de este estudio.
