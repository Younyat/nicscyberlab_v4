# Análisis de Evidencia Forense y Soporte Científico

**Campaña analizada:** `CMP-20260903-083211-125A` (escenario `industrial_file`, ataque `T0831_MANIPULATION_OF_CONTROL_MODBUS`, 10 repeticiones)
**Paquete analizado:** [`app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/)
**Generado:** 2026-09-07
**Autor de este análisis:** revisión directa de cada fichero del paquete (no un resumen de lo que "debería" haber — cada afirmación de este documento está verificada contra datos reales del paquete en la fecha indicada).

---

## 1. Alcance de este documento

Este documento responde a dos preguntas distintas, porque tienen criterios distintos:

1. **¿Es suficiente desde el punto de vista forense?** — ¿Sostendría este paquete una investigación DFIR real: cadena de custodia, integridad verificable, reconstrucción causal, evidencia cruda disponible para re-análisis independiente?
2. **¿Es suficiente para respaldar el paper con evidencia real?** — ¿Hay métricas cuantitativas con repetición estadística, trazabilidad afirmación→evidencia con hash, limitaciones documentadas honestamente, y algo presentable a un revisor?

No son la misma pregunta. Un paquete puede ser forensemente sólido y aun así insuficiente para un paper (o al revés). Se evalúan por separado en las secciones 4 y 5.

---

## 2. Veredicto (resumen ejecutivo)

| Criterio | Estado |
|---|---|
| Cadena de custodia | ✅ Presente y válida (`custody_chain_valid: true`) |
| Integridad de evidencia | ⚠️ Parcial pero honesta (98.58% de artefactos con hash validado, no 100%) |
| Reconstrucción causal cuantitativa | ✅ Real, 10/10 ejecuciones, CPR medio 0.8625 ± 0.0375 |
| Trazabilidad afirmación→evidencia con hash | ✅ Presente (Nivel A, `evidence_to_claim_map.json`) |
| Evidencia cruda re-analizable de forma independiente | ⚠️ Solo 1 de 10 repeticiones tiene el caso completo crudo (78GB); las otras 9 son paquetes ligeros (~1.3MB, perfiles y resúmenes, no memoria/disco/red crudos) |
| Reproducibilidad de entorno entre repeticiones | ✅ Verificado (mismo escenario, mismos nodos/instancias en las 10) |
| Limitaciones documentadas honestamente | ✅ Sí, por ejecución y sin ocultar nada |
| Comparación entre repeticiones | ✅ Real, con umbral de aceptación explícito |

**Conclusión corta:** el paquete es forensemente sólido para un caso concreto (el de la última repetición) y estadísticamente sólido para las 10 repeticiones como conjunto de métricas, pero **no permite re-análisis forense independiente de 9 de las 10 repeticiones** porque su evidencia cruda ya no existe (se redujo a paquete ligero tras el análisis, por diseño de retención del sistema). Para el paper esto es aceptable (las métricas y su trazabilidad sí están completas); para una auditoría forense externa de "cualquier repetición al azar" no lo es — ver sección 6.

---

## 3. Qué contiene el paquete, dónde está, y qué respalda

### 3.1 Resumen de campaña
- **Dónde:** [`CAMPAIGN_SUMMARY_REPORT.md`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/CAMPAIGN_SUMMARY_REPORT.md) / [`CAMPAIGN_SUMMARY_REPORT.json`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/CAMPAIGN_SUMMARY_REPORT.json)
- **Qué es:** tabla de las 10 ejecuciones (estado, CPR, Weighted CPR, soporte de hipótesis, confianza temporal), tabla de los 10 informes Nivel A anidados, resumen de la comparación entre repeticiones, y la captura del dashboard.
- **Qué respalda:** es el punto de entrada — permite a un revisor ver de un vistazo que las 10 repeticiones son reales, consistentes, y con una sola degradación real (EXEC-0006).

### 3.2 Nivel B — 10 ejecuciones reales
- **Dónde:** [`level_B/EXEC-0001`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/level_B/EXEC-0001) … [`level_B/EXEC-0010`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/level_B/EXEC-0010)
- **Qué es, por cada ejecución:** `execution_manifest.json` (estado por etapa), `forensic_comparison_profile.json` (CPR/WCPR/soporte de hipótesis/incertidumbre — corregido el 2026-09-04, ver README del módulo), `ground_truth.json` + `ground_truth_seal.json` (verdad de referencia sellada), `attack_profile.json`, `detection_trigger_profile.json`, y `retained_case_lightweight_bundle/` (perfiles + análisis derivado del caso, sin los artefactos crudos).
- **Informes legibles:** [`reports/level_B/`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/reports/level_B) — 10 carpetas con `level_b_repetition_summary.md`, `LEVEL_B_EXECUTION_AUDIT_README.md`, y CSVs de métricas listos para tablas de paper (`level_b_paper_metrics.csv`, `level_b_reconstruction_metrics.csv`, `level_b_timing_metrics.csv`).
- **Qué respalda:** es la columna vertebral cuantitativa — CPR real por ejecución (9× 0.875, 1× 0.75 en EXEC-0006), con razón de degradación documentada, no oculta.

### 3.3 Nivel A — 10 informes anidados con trazabilidad evidencia→afirmación
- **Dónde:** [`level_A/EXEC-0001`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/level_A/EXEC-0001) … [`level_A/EXEC-0010`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/level_A/EXEC-0010), con los informes legibles en [`reports/level_A/`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/reports/level_A)
- **Qué es:** por cada repetición Level B, un reanálisis Level A de solo lectura sobre el mismo caso preservado. Cada uno incluye `SCIENTIFIC_LEVEL_A_REPORT.md` (informe narrativo completo) y, lo más valioso para un paper, **`evidence_to_claim_map.json`** — una lista de afirmaciones científicas concretas (p. ej. "el análisis multicapa se completó"), cada una con el fichero fuente exacto, su **hash SHA-256**, y los campos usados. Esto es trazabilidad afirmación→evidencia con verificación criptográfica, no una narrativa sin respaldo.
- **Qué respalda:** exactamente el tipo de evidencia que un revisor de paper pediría — "¿cómo sé que esta cifra viene de un dato real y no de una tabla escrita a mano?" La respuesta está en `evidence_to_claim_map.json`: el hash del fichero fuente real.

### 3.4 Nivel C — orquestación y reproducibilidad de entorno
- **Dónde:** [`level_C/LC-20260903-083211-88F7/`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/level_C/LC-20260903-083211-88F7) (datos crudos: `job_state.json`, `comparison_report.json`), informe legible en [`reports/level_C/LEVEL_C_REPETITION_REPORT.md`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/reports/level_C/LEVEL_C_REPETITION_REPORT.md)
- **Qué es:** confirma que las 10 repeticiones corrieron contra el **mismo escenario, mismo número de nodos (5/5) y mismas instancias (5/5)** en las 10 — es decir, que la variable que cambió entre repeticiones fue el experimento, no el entorno. Estado de despliegue OT (fuxa/plc) por repetición, todas `ok`.
- **Qué respalda:** es la evidencia de que "10 repeticiones" son comparables entre sí y no 10 configuraciones distintas por accidente — necesario para poder calcular una media/desviación estándar con sentido.

### 3.5 Comparación entre repeticiones
- **Dónde:** [`comparisons/comparison-f5c86237186b/`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/comparisons/comparison-f5c86237186b) (`comparability_result.json`, `comparison_matrix.json`, `comparability_report.md`)
- **Qué es:** clasificación explícita `Comparable With Degradation`, con un umbral de aceptación matemático declarado (`delta_cpr_allowed: 0.125`, `delta_wcpr_allowed: 0.1`) — no un juicio subjetivo. 30 razones de degradación reales y específicas por ejecución (edges causales degradados, confianza temporal, integridad parcial).
- **Qué respalda:** demuestra reproducibilidad estadística real: el sistema define de antemano qué desviación es aceptable y mide contra eso, en vez de decidir "parece razonable" a posteriori.

### 3.6 Captura del dashboard + datos crudos
- **Dónde:** [`reports/dashboard_capture.png`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/reports/dashboard_capture.png) (imagen de página completa) + [`reports/dashboard_data.json`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/reports/dashboard_data.json) (los datos exactos detrás de la imagen)
- **Qué es:** CPR medio real de la campaña: **0.8625 ± 0.0375** (10 valores: `[0.875, 0.875, 0.875, 0.875, 0.875, 0.75, 0.875, 0.875, 0.875, 0.875]`), ratio de integridad medio 0.9983, 10/10 casos sellados.
- **Qué respalda:** es la figura/tabla lista para el paper — y como el JSON de datos está al lado, cualquiera puede verificar que la imagen no está retocada.

### 3.7 Caso final preservado completo (evidencia cruda)
- **Dónde:** [`final_sample_case/CASE-20260903-221042/`](app_core/infrastructure/forensics/evidence_store/campaign_packages/CMP-20260903-083211-125A_package/final_sample_case/CASE-20260903-221042)
- **Qué es:** el único caso de las 10 repeticiones preservado **íntegro, sin reducir** — 78GB reales: 3 volcados de memoria LiME (8.0GB) con hash SHA-256, 3 imágenes de disco crudas (70GB) con hash SHA-256, 9 capturas de red pcap (92MB), export OT Modbus, `chain_of_custody.log` (26 entradas), y `manifest.json` con 608 artefactos catalogados.
- **Integridad real, sin maquillar:** `case_wide_integrity_ratio: 0.9858` (555/563 artefactos con hash validado) — estado `"partial"`, no `"complete"`. El propio sistema lo declara así, no es un dato que haya que buscar escondido.
- **Qué respalda:** es la prueba de que el sistema puede producir evidencia forense de calidad de investigación real (no simulada) — memoria y disco crudos con cadena de custodia verificable — para al menos un caso completo por campaña.

---

## 4. Evaluación desde el punto de vista forense

**Fortalezas verificadas:**
- Cadena de custodia real y válida, no un campo puesto a `true` sin datos detrás (`chain_of_custody.log` con 26 entradas reales).
- Hashes SHA-256 en los artefactos críticos (memoria, disco).
- El propio sistema reporta su integridad como "partial" (98.58%) en vez de redondear a "complete" — esto es honestidad forense, no un fallo.
- El caso final preservado tiene los 5 dominios de evidencia esperables en DFIR industrial: red, memoria, disco, OT, alertas.

**Limitación real, no cosmética:** de las 10 repeticiones, **solo 1 conserva su evidencia cruda**. Las otras 9 se redujeron a `retained_case_lightweight_bundle/` (~1.3MB cada una: perfiles JSON, resúmenes, sin memoria/disco/pcap). Esto es una decisión de retención de espacio del sistema (documentada, no un error), pero significa que **no se puede re-analizar de forma independiente ninguna de esas 9 repeticiones desde cero** — solo se puede confiar en los resultados ya calculados y guardados. Si un auditor forense externo pidiera "dame el volcado de memoria crudo de la repetición 3 para verificarlo yo mismo", ese dato ya no existe.

Lo que sí queda registrado para las 9 repeticiones sin evidencia cruda: cada `retained_case_lightweight_bundle/*/manifest.json` conserva el tamaño exacto y el hash SHA-256 de cada artefacto que existió en el momento de la adquisición, aunque el binario ya no esté. Las 10 repeticiones (incluida la que sí conserva los bytes) registran el mismo patrón consistente: 3 volcados de memoria LiME de 2+2+4 GiB (8.0GiB), 3 imágenes de disco crudas de 15+15+40 GiB (70GiB), y capturas de red pcap de tamaño variable por repetición (entre 0.06GiB y 2.3GiB, reflejando tráfico real capturado en cada ejecución). Es decir: se sabe con certeza cuánta evidencia se generó y se puede verificar su integridad por hash, aunque los bytes en sí ya no estén disponibles para 9 de las 10.

## 5. Evaluación desde el punto de vista de respaldo del paper

**Fortalezas verificadas:**
- 10 repeticiones reales (no simuladas) con media y desviación estándar calculables directamente de datos reales (`0.8625 ± 0.0375`).
- Trazabilidad afirmación→evidencia con hash SHA-256 (`evidence_to_claim_map.json`) — responde directamente a la pregunta típica de un revisor: "¿de dónde sale este número?"
- Reproducibilidad de entorno verificada entre repeticiones (Nivel C) — sin esto, la comparación entre repeticiones no tendría validez estadística.
- Limitaciones y degradaciones documentadas por ejecución, no ocultas — esto en un paper juega a favor, no en contra (demuestra rigor).
- Un caso completo con evidencia cruda real disponible como muestra reproducible/citable.

**Suficiente para el paper, con una condición:** las 9 repeticiones sin evidencia cruda **siguen siendo válidas para las métricas agregadas** (CPR medio, desviación, comparabilidad) porque esos números se calcularon y guardaron ANTES de reducir el caso — no se están inventando a posteriori. Pero si el paper necesita mostrar un ejemplo de evidencia cruda (una captura de pantalla de un volcado de memoria, un fragmento de pcap), solo se puede usar la repetición 10 — es la única con datos crudos disponibles.

## 6. Limitaciones honestas / huecos reales

1. **9 de 10 repeticiones sin evidencia cruda** — ya explicado arriba. No es corregible sin cambiar la política de retención (guardar más de un caso completo por campaña, a coste de espacio en disco).
2. **Integridad case-wide al 98.58%, no 100%** — 8 de 563 artefactos sin hash validado en el caso final. El sistema lo reporta correctamente como "partial"; para el paper esto debe citarse como está, no redondearse a "100% verificado".
3. **1 de 10 repeticiones con degradación real** (EXEC-0006, CPR 0.75 en vez de 0.875) — dentro del umbral de aceptación declarado, pero es una desviación real, no ruido.
4. **`uncertainty_class: null`** en los perfiles de repetibilidad de Nivel A (visto en `analysis_repeatability_profile.json`) — un campo que existe pero nunca se rellena en este flujo; no afecta a las métricas ya usadas (CPR/WCPR/soporte), pero es un campo declarado y vacío que convendría revisar en otra sesión si se va a citar textualmente.

## 7. Recomendación

Para el paper: **sí, es suficiente tal como está**, citando las métricas agregadas (10 repeticiones, CPR 0.8625 ± 0.0375, reproducibilidad de entorno verificada) y usando la repetición 10 como caso de evidencia cruda ilustrativo. Las limitaciones de la sección 6 deben mencionarse explícitamente en el paper (ya están documentadas en los datos, así que citarlas es honestidad, no debilidad).

Para una auditoría forense externa rigurosa: sería recomendable, en una futura campaña, preservar el caso completo de **más de una** repetición (no solo la última), si el espacio en disco lo permite, para poder ofrecer re-análisis independiente de varias repeticiones y no solo de una.
