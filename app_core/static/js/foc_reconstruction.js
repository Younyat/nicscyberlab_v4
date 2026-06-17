const FOC = {
  status: null,
  manifest: null,
  scenario: null,
  tools: null,
  timeline: null,
  gaps: null,
  sources: null,
  relationships: null,
  artifacts: null,
  cases: null,
  stream: null,
  loadTimer: null,
  loadInFlight: false,
  pendingReload: false,
  firstLoadCompleted: false,
  triggerSelectionModel: null,
  caseAnalysisStatuses: {},
  selectedCaseId: null,
  analysisPollTimer: null,
};

const API = "/api/foc";
const DASHBOARD_API = `${API}/dashboard`;
const STREAM_REFRESH_DEBOUNCE_MS = 1200;
const ANALYSIS_STATUS_POLL_MS = 2500;

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`${url} -> ${res.status}`);
  }
  return res.json();
}

function byId(id) {
  return document.getElementById(id);
}

function analysisStatusUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/analysis-status`;
}

function analysisRunUrl(caseId, force = false) {
  return `${API}/cases/${encodeURIComponent(caseId)}/analysis/run${force ? "?force=true" : ""}`;
}

function analysisValidateUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/analysis/validate`;
}

function analysisLogsUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/analysis/logs`;
}

function analysisReportUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/analysis/report`;
}

function setLoadingState(active, message = "Loading FOC reconstruction…") {
  const shell = byId("loading-shell");
  const messageEl = byId("loading-message");
  const metaEl = byId("loading-meta");
  if (messageEl) messageEl.textContent = message;
  if (metaEl && active) {
    metaEl.textContent = FOC.firstLoadCompleted
      ? "Refreshing scientific reconstruction artifacts without blocking the page."
      : "Collecting scenario, tools, timeline, evidence, and reconstruction state.";
  }
  if (!shell) return;
  shell.classList.toggle("is-active", !!active);
  shell.setAttribute("aria-hidden", active ? "false" : "true");
}

function scheduleLoadAll(force = false) {
  if (FOC.loadTimer) {
    clearTimeout(FOC.loadTimer);
  }
  FOC.loadTimer = setTimeout(() => {
    loadAll(force).catch(() => {});
  }, force ? 0 : STREAM_REFRESH_DEBOUNCE_MS);
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function stringifyScalar(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    const flattened = value.map(item => stringifyScalar(item)).filter(Boolean);
    return flattened.join(", ");
  }
  if (typeof value === "object") {
    const preferred = [
      value.name,
      value.value,
      value.sensor,
      value.collector,
      value.original_sensor,
      value.id,
    ].map(item => stringifyScalar(item)).find(Boolean);
    if (preferred) return preferred;
  }
  return "";
}

function statusClass(status) {
  const normalized = String(status || "").toLowerCase().replace(/\s+/g, "_");
  if (normalized.startsWith("failed")) return "status-missing";
  if (normalized.startsWith("skipped")) return "status-unknown";
  if (normalized === "running") return "status-inferred";
  if (["confirmed", "complete", "valid", "active", "bound", "present", "available", "completed"].includes(normalized)) return "status-confirmed";
  if (["inferred", "partial", "bootstrap", "updated", "warning", "warnings", "mostly_available", "mostly_noise"].includes(normalized)) return "status-inferred";
  if (["missing", "critical", "insufficient", "unresolved", "error", "bootstrap_required"].includes(normalized)) return "status-missing";
  if (["unknown", "not_available", "degraded", "not_completed", "not_generated"].includes(normalized)) return "status-unknown";
  if (["not_generated_yet"].includes(normalized)) return "status-updated";
  return "status-updated";
}

function tag(label, value, cls = "") {
  return `<div class="tag rounded-full px-3 py-1.5 text-[11px] font-bold tracking-[0.12em] uppercase ${cls}">${esc(label)}: ${esc(value)}</div>`;
}

function metricCard(label, points, total) {
  return `<div class="glass-soft rounded-2xl p-3"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-400 font-black">${esc(label)}</div><div class="text-lg font-black mt-2">${esc(points)} / ${esc(total)}</div></div>`;
}

function simpleValueCard(label, value, detail = "") {
  return `
    <div class="glass-soft rounded-2xl p-4">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-400 font-black">${esc(label)}</div>
      <div class="text-2xl font-black mt-2">${esc(value)}</div>
      <div class="text-xs text-slate-400 mt-2">${esc(detail)}</div>
    </div>
  `;
}

function parseEventTime(value) {
  const raw = String(value || "").trim();
  if (!raw) return 0;
  let normalized = raw.replace("Z", "+00:00");
  if (/[\+\-]\d{4}$/.test(normalized)) {
    normalized = `${normalized.slice(0, -2)}:${normalized.slice(-2)}`;
  }
  const ms = Date.parse(normalized);
  return Number.isFinite(ms) ? ms : 0;
}

function formatBucketLabel(ts) {
  if (!ts) return "unknown";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "unknown";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

function eventTypeLabel(eventType) {
  return String(eventType || "event").replaceAll("_", " ");
}

function sourceLabel(source) {
  const raw = String(source || "unknown").toLowerCase();
  if (raw.includes("suricata")) return "Suricata";
  if (raw.includes("wazuh")) return "Wazuh";
  if (raw.includes("ids")) return "Suricata";
  if (raw.includes("fim")) return "Wazuh FIM";
  if (raw.includes("auth")) return "Wazuh Auth";
  return source || "Unknown";
}

function nodeNameMap() {
  const out = new Map();
  (FOC.scenario?.nodes || []).forEach(node => {
    out.set(node.node_id, node.name || node.node_id);
  });
  return out;
}

function aggregateTimelineEvents(events) {
  const grouped = new Map();
  const passthrough = [];

  for (const ev of events) {
    if (!["detection_alert", "triage_result"].includes(ev.event_type)) {
      passthrough.push({ ...ev, aggregate_count: 1, aggregate: false });
      continue;
    }
    const details = ev.details || {};
    const ts = parseEventTime(ev.timestamp);
    const bucket = ts ? Math.floor(ts / 60000) * 60000 : 0;
    const agent = (details.agent || {}).name || "unknown";
    const src = (details.src || {}).ip || "unknown";
    const dst = (details.dst || {}).ip || "unknown";
    const key = [
      ev.event_type,
      bucket,
      details.rule_id || "unknown",
      agent,
      ev.related_node_id || "unresolved",
      src,
      dst,
      details.signature || ev.description || "unknown",
    ].join("|");

    if (!grouped.has(key)) {
      grouped.set(key, {
        ...ev,
        aggregate: true,
        aggregate_count: 0,
        first_seen: ev.timestamp,
        last_seen: ev.timestamp,
        affected_nodes: new Set(),
        example_alert_id: ev.related_alert_id || "unresolved",
      });
    }
    const item = grouped.get(key);
    item.aggregate_count += 1;
    if (parseEventTime(ev.timestamp) < parseEventTime(item.first_seen)) item.first_seen = ev.timestamp;
    if (parseEventTime(ev.timestamp) > parseEventTime(item.last_seen)) item.last_seen = ev.timestamp;
    if (ev.related_node_id && !["unknown", "unresolved"].includes(ev.related_node_id)) item.affected_nodes.add(ev.related_node_id);
  }

  const aggregates = [...grouped.values()].map(item => ({
    ...item,
    affected_nodes: [...item.affected_nodes],
  }));

  return [...passthrough, ...aggregates].sort((a, b) => parseEventTime(b.last_seen || b.timestamp) - parseEventTime(a.last_seen || a.timestamp));
}

function sourceExists(type) {
  return (FOC.sources?.sources || []).some(src => src.source_type === type && src.status === "present");
}

function artifactCount(types) {
  const allowed = new Set(Array.isArray(types) ? types : [types]);
  return (FOC.artifacts?.artifacts || []).filter(item => allowed.has(item.artifact_type)).length;
}

function timelineCount(types) {
  const allowed = new Set(Array.isArray(types) ? types : [types]);
  return (FOC.timeline?.events || []).filter(item => allowed.has(item.event_type)).length;
}

function relationshipCount(relation) {
  return (FOC.relationships?.edges || []).filter(edge => edge.relation === relation).length;
}

function relationshipResolvedCount(relation) {
  return (FOC.relationships?.edges || []).filter(edge => {
    if (edge.relation !== relation) return false;
    if (edge.to_id === "unresolved" || edge.to_id === "unknown") return false;
    return edge.relationship_status === "confirmed";
  }).length;
}

function relationshipCountByFromType(fromType, relationSet) {
  const allowed = new Set(Array.isArray(relationSet) ? relationSet : [relationSet]);
  return (FOC.relationships?.edges || []).filter(edge => edge.from_type === fromType && allowed.has(edge.relation)).length;
}

function hasCases() {
  return ((FOC.cases?.cases || []).length > 0);
}

function buildModelRows() {
  const status = FOC.status || {};
  const scenarioNodes = (FOC.scenario?.nodes || []).length;
  const scenarioEdges = (FOC.scenario?.edges || []).length;
  const toolNodes = (FOC.tools?.nodes || []).length;
  const pendingTools = (FOC.tools?.nodes || []).reduce((sum, node) => sum + (node.pending_tools || []).length, 0);
  const failedTools = (FOC.tools?.nodes || []).reduce((sum, node) => sum + (node.failed_tools || []).length, 0);
  const attackEvents = timelineCount("attack_execution");
  const detectionEvents = timelineCount(["detection_alert", "triage_result"]);
  const caseCount = (FOC.cases?.cases || []).length;
  const custodyCount = artifactCount("custody_log");
  const analysisCount = artifactCount(["vol3_output_dir", "tsk_output_dir"]);
  const acquisitionCount = artifactCount(["network_pcap", "disk_image", "memory_dump", "industrial_capture", "ir_input", "ir_snapshot"]);
  const preservationCount = artifactCount(["network_pcap", "disk_image", "memory_dump", "custody_log", "time_sync", "case_digest", "ir_input", "ir_snapshot", "fsr_eval"]);
  const relSummary = status.relationship_summary || {};
  const detSummary = status.detection_summary || {};
  const artSummary = status.artifact_summary || {};
  const attackAlertLinks = relSummary.attack_alert_candidate_links || 0;
  const resolvedAttackAlertLinks = relSummary.attack_alert_confirmed_links || 0;
  const alertEvidenceLinks = relSummary.alert_evidence_links || 0;
  const evidenceAnalysisLinks = relSummary.evidence_analysis_links || 0;
  const resolvedDetectionEvents = detSummary.resolved_alerts || 0;

  const rows = [];

  rows.push({
    component: "Scenario BOM",
    meaning: "What was deployed: IT nodes, OT nodes, edges, roles, IPs, industrial components, and PLC/SCADA relations.",
    status: scenarioNodes > 0 && scenarioEdges > 0 ? "available" : (sourceExists("scenario") ? "partial" : "missing"),
    evidence: scenarioNodes > 0 ? "scenario_bom.json" : "none",
    next: scenarioNodes > 0 ? "none" : "create or regenerate the scenario BOM",
    detail: `${scenarioNodes} nodes, ${scenarioEdges} edges, ${((FOC.scenario?.ot_nodes) || []).length} OT nodes.`,
  });

  rows.push({
    component: "Tools BOM",
    meaning: "What tools exist on each node: desired, installed, failed, pending, logs, and installation state.",
    status: toolNodes === 0 ? (sourceExists("tools_tmp") || sourceExists("tools_installed") ? "partial" : "missing") : (pendingTools > 0 || failedTools > 0 ? "partial" : "available"),
    evidence: toolNodes > 0 ? "tools_bom.json" : "none",
    next: failedTools > 0 ? "review failed installs" : (pendingTools > 0 ? "complete pending installs" : "none"),
    detail: `${toolNodes} nodes indexed, ${pendingTools} pending tools, ${failedTools} failed tools.`,
  });

  rows.push({
    component: "Attack Attestation",
    meaning: "What attack was executed, when, from where, and against which target.",
    status: attackEvents === 0 ? "not generated yet" : (resolvedAttackAlertLinks > 0 ? "partial" : "partial"),
    evidence: attackEvents > 0 ? "attack result.json files and timeline attack_execution events" : "none",
    next: attackEvents > 0 && resolvedAttackAlertLinks === 0 ? "correlate attack executions to resolved alerts" : (attackEvents === 0 ? "execute an ATT&CK-aligned technique" : "none"),
    detail: attackEvents > 0 ? `${attackEvents} attack events indexed, ${attackAlertLinks} candidate links, ${resolvedAttackAlertLinks} confirmed, ${relSummary.attack_alert_inferred_links || 0} inferred.` : "No attack execution has been preserved yet.",
  });

  rows.push({
    component: "Detection Attestation",
    meaning: "What sensor detected activity, which rule fired, and which alert was generated.",
    status: detectionEvents === 0 ? "not generated yet" : (detSummary.relationship_quality || "partial"),
    evidence: detectionEvents > 0 ? "alerts.jsonl, triage.jsonl, detection timeline events" : "none",
    next: detectionEvents > 0 && (resolvedAttackAlertLinks === 0 || resolvedDetectionEvents === 0) ? "resolve node, instance, or attack correlation" : (detectionEvents === 0 ? "generate or ingest alert records" : "none"),
    detail: detectionEvents > 0 ? `data availability: ${detSummary.data_availability || "available"} | relationship quality: ${detSummary.relationship_quality || "partial"} | resolved ratio: ${detSummary.resolved_ratio_text || "0/0"} | confirmed attack correlation: ${detSummary.confirmed_ratio_text || "0/0"}.` : "No alert or triage sequence has been preserved yet.",
  });

  rows.push({
    component: "Acquisition Manifest",
    meaning: "What evidence was acquired, from which node, for which alert, and with which acquisition process.",
    status: artSummary.preserved_evidence > 0 ? (alertEvidenceLinks > 0 ? "available" : "partial") : (acquisitionCount > 0 ? "partial" : "not generated yet"),
    evidence: acquisitionCount > 0 ? "case manifest artifacts, preserved evidence, and acquisition metadata" : "none",
    next: acquisitionCount > 0 ? (alertEvidenceLinks > 0 ? "none" : "link acquired evidence to alerts or cases") : "run network, memory, disk, or industrial evidence acquisition",
    detail: acquisitionCount > 0 ? `${artSummary.preserved_evidence || 0} preserved evidence, ${artSummary.acquisition_metadata || 0} acquisition metadata, ${artSummary.forensic_inputs || 0} forensic inputs.` : "No forensic acquisition has been executed yet.",
  });

  rows.push({
    component: "Preservation Manifest",
    meaning: "How evidence was preserved: hashes, paths, timestamps, formats, and preservation state.",
    status: preservationCount > 0 ? ((artSummary.preserved_evidence > 0 && custodyCount > 0) ? "available" : "partial") : "not generated yet",
    evidence: preservationCount > 0 ? "manifest.json, hashes, indexed preserved artifacts" : "none",
    next: preservationCount > 0 ? (custodyCount > 0 ? "none" : "append custody and preservation context") : "preserve evidence inside a forensic case",
    detail: preservationCount > 0 ? `${artSummary.preserved_evidence || 0} preserved evidence artifacts, ${custodyCount} custody logs, ${alertEvidenceLinks} alert→evidence links.` : "No forensic preservation has been executed yet.",
  });

  rows.push({
    component: "Chain of Custody",
    meaning: "Who or which process handled each evidence item and when that handling occurred.",
    status: custodyCount > 0 ? (alertEvidenceLinks > 0 ? "available" : "partial") : (caseCount > 0 ? "missing" : "not generated yet"),
    evidence: custodyCount > 0 ? "chain_of_custody.log" : "none",
    next: custodyCount > 0 ? "none" : (caseCount > 0 ? "verify case generation and custody logging" : "create a forensic case"),
    detail: custodyCount > 0 ? (alertEvidenceLinks > 0 ? `${custodyCount} custody artifacts indexed and linked through evidential preservation.` : `${custodyCount} custody artifacts indexed, but cases are not linked to alerts.`) : (caseCount > 0 ? "Forensic cases exist, but custody was not indexed." : "No forensic case has been created yet."),
  });

  rows.push({
    component: "Forensic Analysis Report",
    meaning: "The technical results produced by disk, memory, or related forensic analysis workflows.",
    status: analysisCount > 0 ? (evidenceAnalysisLinks > 0 ? "available" : "partial") : "not completed",
    evidence: analysisCount > 0 ? "Volatility and TSK output directories" : "none",
    next: analysisCount > 0 ? (evidenceAnalysisLinks > 0 ? "none" : "link analysis outputs to evidence and cases") : "run memory or disk analysis",
    detail: analysisCount > 0 ? `${analysisCount} forensic analysis outputs indexed.` : "No forensic analysis has been executed yet.",
  });

  rows.push({
    component: "Semantic Observation Report",
    meaning: "The high-level interpretation of what occurred across the scenario, detections, evidence, and analysis results.",
    status: analysisCount === 0 ? "not generated" : "unresolved",
    evidence: "none",
    next: analysisCount === 0 ? "generate after forensic analysis is available" : "produce a higher-level interpretation report from analysis outputs",
    detail: analysisCount === 0 ? "No semantic interpretation is expected before forensic analysis exists." : "Analysis outputs exist, but no semantic observation report is indexed yet.",
  });

  return rows;
}

function buildMaturityStates(modelRows) {
  if (FOC.status?.maturity) {
    return FOC.status.maturity;
  }
  const getStatus = (name) => (modelRows.find(row => row.component === name) || {}).status || "unknown";
  const structural = ["Scenario BOM", "Tools BOM"].map(getStatus);
  const operational = ["Attack Attestation", "Detection Attestation"].map(getStatus);
  const evidential = ["Acquisition Manifest", "Preservation Manifest"].map(getStatus);
  const forensic = ["Chain of Custody", "Forensic Analysis Report"].map(getStatus);
  const semantic = getStatus("Semantic Observation Report");

  function reduceStage(statuses) {
    if (statuses.every(s => s === "available")) return "available";
    if (statuses.every(s => s === "not generated yet")) return "not generated yet";
    if (statuses.includes("missing")) return "missing";
    if (statuses.includes("partial") || statuses.includes("unresolved") || statuses.includes("available")) return "partial";
    return "unknown";
  }

  return {
    structural: reduceStage(structural),
    operational: reduceStage(operational),
    evidential: reduceStage(evidential),
    forensic: reduceStage(forensic),
    semantic,
  };
}

async function loadAll(force = false) {
  if (FOC.loadInFlight) {
    FOC.pendingReload = true;
    return;
  }
  FOC.loadInFlight = true;
  setLoadingState(true, FOC.firstLoadCompleted ? "Refreshing FOC reconstruction…" : "Loading FOC reconstruction…");
  try {
    const payload = await fetchJson(`${DASHBOARD_API}${force ? "?force=true" : ""}`);
    FOC.status = payload?.status || null;
    FOC.manifest = payload?.manifest || null;
    FOC.scenario = payload?.scenario || null;
    FOC.tools = payload?.tools || null;
    FOC.timeline = payload?.timeline || null;
    FOC.gaps = payload?.gaps || null;
    FOC.sources = payload?.sources || null;
    FOC.relationships = payload?.relationships || null;
    FOC.artifacts = payload?.artifacts || null;
    FOC.cases = payload?.cases || null;
    FOC.triggerSelectionModel = null;
    const [casesRes, readinessRes, detectionRes, interventionRes] = await Promise.allSettled([
      fetchJson(`${API}/cases`),
      fetchJson(`${API}/readiness-report`),
      fetchJson(`${API}/detection-attestation`),
      fetchJson(`${API}/forensic-intervention`),
    ]);
    FOC.cases = casesRes.status === "fulfilled" ? casesRes.value : FOC.cases;
    FOC.readiness_report = readinessRes.status === "fulfilled" ? readinessRes.value : null;
    FOC.detection_attestation = detectionRes.status === "fulfilled" ? detectionRes.value : null;
    FOC.forensic_intervention = interventionRes.status === "fulfilled" ? interventionRes.value : null;
    renderAll();
    FOC.firstLoadCompleted = true;
  } finally {
    FOC.loadInFlight = false;
    setLoadingState(false);
    if (FOC.pendingReload) {
      FOC.pendingReload = false;
      scheduleLoadAll(false);
    }
  }
}

function renderOverview() {
  const status = FOC.status || {};
  byId("ov-status").className = `text-2xl font-black mt-3 ${statusClass(status.status)}`;
  byId("ov-status").textContent = status.status || "not_initialized";
  byId("ov-completeness").textContent = `Completeness: ${status.completeness || "unknown"}`;
  byId("ov-scenario-id").textContent = status.scenario_id || "unknown";
  byId("ov-scenario-name").textContent = status.scenario_name || "unknown";
  byId("ov-score").textContent = String(status.reproducibility_score ?? 0);
  byId("ov-updated").textContent = `Updated: ${status.last_update || "unknown"}`;
  byId("score-bar").style.width = `${Math.max(0, Math.min(100, Number(status.reproducibility_score || 0)))}%`;

  const components = status.components || {};
  byId("score-breakdown").innerHTML = [
    metricCard("Scenario BOM", components.scenario_bom || 0, 15),
    metricCard("Tools BOM", components.tools_bom || 0, 15),
    metricCard("Timeline", components.timeline || 0, 10),
    metricCard("Sources", components.sources_index || 0, 10),
    metricCard("Hashes", components.hashes || 0, 10),
    metricCard("Bindings", components.node_instance_bindings || 0, 10),
    metricCard("Attack→Alert", components.attack_alert_links || 0, 10),
    metricCard("Alert→Evidence", components.alert_evidence_links || 0, 10),
    metricCard("Evidence/Custody", components.evidence_custody_chain || 0, 10),
    metricCard("Analysis", components.analysis_outputs || 0, 10),
  ].join("");

  byId("overview-flags").innerHTML = [
    tag("Mode", status.mode || "unknown", statusClass(status.mode)),
    tag("Initialized", String(status.initialized ?? false), status.initialized ? "status-confirmed" : "status-missing"),
    tag("Critical gaps", String(status.critical_gaps ?? 0), Number(status.critical_gaps || 0) > 0 ? "status-missing" : "status-confirmed"),
    tag("Structural gaps", String(FOC.gaps?.structural_critical_gaps ?? 0), Number(FOC.gaps?.structural_critical_gaps || 0) > 0 ? "status-missing" : "status-confirmed"),
    tag("Forensic gaps", String(FOC.gaps?.forensic_critical_gaps ?? 0), Number(FOC.gaps?.forensic_critical_gaps || 0) > 0 ? "status-missing" : "status-confirmed"),
    tag("Semantic gaps", String(FOC.gaps?.semantic_critical_gaps ?? 0), Number(FOC.gaps?.semantic_critical_gaps || 0) > 0 ? "status-missing" : "status-confirmed"),
    tag("Causal blockers", String(FOC.gaps?.causal_reconstruction_blockers ?? 0), Number(FOC.gaps?.causal_reconstruction_blockers || 0) > 0 ? "status-missing" : "status-confirmed"),
    tag("Structural", status.maturity?.structural || "unknown", statusClass(status.maturity?.structural)),
    tag("Operational", status.maturity?.operational || "unknown", statusClass(status.maturity?.operational)),
    tag("Evidential", status.maturity?.evidential || "unknown", statusClass(status.maturity?.evidential)),
    tag("Forensic", status.maturity?.forensic || "unknown", statusClass(status.maturity?.forensic)),
    tag("Semantic", status.maturity?.semantic || "unknown", statusClass(status.maturity?.semantic)),
  ].join("");
}

function renderModel() {
  const rows = buildModelRows();
  const maturity = buildMaturityStates(rows);
  const noForensicsYet = rows
    .filter(row => ["Acquisition Manifest", "Preservation Manifest", "Chain of Custody", "Forensic Analysis Report", "Semantic Observation Report"].includes(row.component))
    .every(row => row.status === "not generated yet");

  byId("maturity-summary").innerHTML = [
    tag("Structural reconstruction", maturity.structural, statusClass(maturity.structural)),
    tag("Operational reconstruction", maturity.operational, statusClass(maturity.operational)),
    tag("Evidential reconstruction", maturity.evidential, statusClass(maturity.evidential)),
    tag("Forensic reconstruction", maturity.forensic, statusClass(maturity.forensic)),
    tag("Semantic reconstruction", maturity.semantic, statusClass(maturity.semantic)),
  ].join("");

  byId("model-phase-note").innerHTML = noForensicsYet
    ? "No forensic acquisition has been executed yet. These sections will be populated after network, memory, disk, or industrial evidence is acquired and preserved."
    : "The reconstruction model contains a mixture of available, partial, unresolved, or pending phases. Use the status column and the next-step guidance to improve reproducibility.";

  byId("model-table").innerHTML = rows.map(row => `
    <tr class="border-t border-slate-700/50">
      <td class="py-4 pr-4">
        <div class="font-black">${esc(row.component)}</div>
        <div class="text-xs text-slate-400 mt-2">${esc(row.detail || "")}</div>
      </td>
      <td class="py-4 pr-4 text-slate-300">${esc(row.meaning)}</td>
      <td class="py-4 pr-4">
        <div class="font-black uppercase tracking-[0.16em] text-xs ${statusClass(row.status)}">${esc(row.status)}</div>
      </td>
      <td class="py-4 pr-4">
        <div class="text-slate-300">${esc(row.evidence)}</div>
      </td>
      <td class="py-4 text-slate-300">${esc(row.next)}</td>
    </tr>
  `).join("");
}

function renderAnalytics() {
  renderAnalyticsKpis();
  renderTimeSeriesChart();
  renderDetectionDonut();
  renderNodeBars();
  renderTechniqueRanking();
  renderNetworkGraph();
}

function renderAnalyticsKpis() {
  const artifactSummary = FOC.status?.artifact_summary || {};
  const events = FOC.timeline?.events || [];
  const detectionAlerts = events.filter(ev => ev.event_type === "detection_alert").length;
  const attacks = events.filter(ev => ev.event_type === "attack_execution").length;
  const triage = events.filter(ev => ev.event_type === "triage_result").length;
  const cases = (FOC.cases?.cases || []).length;
  const evidence = artifactSummary.preserved_evidence || 0;
  const mitreCount = new Set(
    events
      .filter(ev => ev.event_type === "attack_execution")
      .map(ev => ev.details?.mitre_id)
      .filter(Boolean)
  ).size;

  byId("analytics-kpis").innerHTML = [
    simpleValueCard("Alerts", detectionAlerts, "Detection alerts indexed"),
    simpleValueCard("Attacks", attacks, "Attack execution events"),
    simpleValueCard("Triage", triage, "Triage records observed"),
    simpleValueCard("Evidence", evidence, "Network, disk, memory, or OT artifacts"),
    simpleValueCard("Cases", cases, "Indexed forensic cases"),
    simpleValueCard("MITRE", mitreCount, "Distinct ATT&CK techniques executed"),
  ].join("");
}

function renderTimeSeriesChart() {
  const host = byId("chart-timeseries");
  const summary = byId("chart-timeseries-summary");
  const events = [...(FOC.timeline?.events || [])]
    .filter(ev => ["attack_execution", "detection_alert", "triage_result", "case_created", "pcap_preserved", "disk_preserved", "disk_analysis_done", "dfir_orchestration_done"].includes(ev.event_type))
    .sort((a, b) => parseEventTime(a.timestamp) - parseEventTime(b.timestamp));

  if (!events.length) {
    summary.textContent = "No data";
    host.innerHTML = `<div class="text-sm text-slate-400">No time-series data available.</div>`;
    return;
  }

  const buckets = new Map();
  events.forEach(ev => {
    const ts = parseEventTime(ev.timestamp);
    const bucketKey = ts ? Math.floor(ts / (5 * 60 * 1000)) * (5 * 60 * 1000) : 0;
    if (!buckets.has(bucketKey)) {
      buckets.set(bucketKey, { ts: bucketKey, label: formatBucketLabel(bucketKey), attack: 0, detection: 0, triage: 0, evidence: 0 });
    }
    const row = buckets.get(bucketKey);
    if (ev.event_type === "attack_execution") row.attack += 1;
    else if (ev.event_type === "detection_alert") row.detection += 1;
    else if (ev.event_type === "triage_result") row.triage += 1;
    else row.evidence += 1;
  });

  const data = [...buckets.values()].slice(-12);
  const maxVal = Math.max(1, ...data.flatMap(row => [row.attack, row.detection, row.triage, row.evidence]));
  const w = 760;
  const h = 240;
  const padL = 44;
  const padR = 16;
  const padT = 16;
  const padB = 34;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const xFor = idx => padL + (data.length <= 1 ? innerW / 2 : (idx * innerW / (data.length - 1)));
  const yFor = val => padT + innerH - ((val / maxVal) * innerH);
  const makePath = key => data.map((row, idx) => `${idx === 0 ? "M" : "L"} ${xFor(idx).toFixed(1)} ${yFor(row[key]).toFixed(1)}`).join(" ");

  summary.textContent = `${data.length} buckets | 5 min resolution`;
  host.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" class="w-full h-auto">
      ${[0, 0.25, 0.5, 0.75, 1].map(step => {
        const y = padT + innerH - (innerH * step);
        const val = Math.round(maxVal * step);
        return `<g>
          <line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="rgba(148,163,184,0.14)" stroke-width="1" />
          <text x="8" y="${y + 4}" fill="#8fa3bf" font-size="10">${val}</text>
        </g>`;
      }).join("")}
      ${data.map((row, idx) => `<text x="${xFor(idx)}" y="${h - 10}" text-anchor="middle" fill="#8fa3bf" font-size="10">${esc(row.label)}</text>`).join("")}
      <path d="${makePath("attack")}" fill="none" stroke="#38bdf8" stroke-width="3" />
      <path d="${makePath("detection")}" fill="none" stroke="#f59e0b" stroke-width="3" />
      <path d="${makePath("triage")}" fill="none" stroke="#ef4444" stroke-width="3" />
      <path d="${makePath("evidence")}" fill="none" stroke="#22c55e" stroke-width="3" />
      ${data.map((row, idx) => [row.attack, row.detection, row.triage, row.evidence].map((val, i) => {
        const key = ["attack", "detection", "triage", "evidence"][i];
        const color = ["#38bdf8", "#f59e0b", "#ef4444", "#22c55e"][i];
        return `<circle cx="${xFor(idx)}" cy="${yFor(row[key])}" r="3.5" fill="${color}" />`;
      }).join("")).join("")}
    </svg>
    <div class="flex flex-wrap gap-2 mt-3 text-xs">
      ${tag("attack", "blue")}
      ${tag("detection", "amber")}
      ${tag("triage", "red")}
      ${tag("evidence/dfir", "green")}
    </div>
  `;
}

function renderDetectionDonut() {
  const host = byId("chart-donut");
  const summary = byId("chart-donut-summary");
  const alerts = (FOC.timeline?.events || []).filter(ev => ev.event_type === "detection_alert");
  if (!alerts.length) {
    summary.textContent = "No data";
    host.innerHTML = `<div class="text-sm text-slate-400">No detection source distribution available.</div>`;
    return;
  }

  const counts = new Map();
  alerts.forEach(ev => {
    const key = sourceLabel(ev.details?.original_sensor || ev.details?.collector || ev.details?.source || ev.source_type || "Unknown");
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  const data = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const total = data.reduce((sum, [, v]) => sum + v, 0);
  const colors = ["#38bdf8", "#f59e0b", "#ef4444", "#22c55e", "#a855f7", "#f97316"];
  let angle = -Math.PI / 2;
  const cx = 110;
  const cy = 110;
  const r = 78;
  const rInner = 46;

  function arcPath(start, end) {
    const x1 = cx + Math.cos(start) * r;
    const y1 = cy + Math.sin(start) * r;
    const x2 = cx + Math.cos(end) * r;
    const y2 = cy + Math.sin(end) * r;
    const ix2 = cx + Math.cos(end) * rInner;
    const iy2 = cy + Math.sin(end) * rInner;
    const ix1 = cx + Math.cos(start) * rInner;
    const iy1 = cy + Math.sin(start) * rInner;
    const large = end - start > Math.PI ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} L ${ix2} ${iy2} A ${rInner} ${rInner} 0 ${large} 0 ${ix1} ${iy1} Z`;
  }

  const paths = data.map(([label, value], idx) => {
    const slice = (value / total) * Math.PI * 2;
    const start = angle;
    const end = angle + slice;
    angle = end;
    return { label, value, color: colors[idx % colors.length], d: arcPath(start, end) };
  });

  summary.textContent = `${total} alerts | ${data.length} sensor origins`;
  host.innerHTML = `
    <div class="flex flex-col md:flex-row md:items-center gap-5">
      <svg viewBox="0 0 220 220" class="w-[220px] h-[220px] shrink-0">
        ${paths.map(item => `<path d="${item.d}" fill="${item.color}" opacity="0.9"></path>`).join("")}
        <circle cx="${cx}" cy="${cy}" r="${rInner - 2}" fill="#0b1321"></circle>
        <text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="#e2e8f0" font-size="28" font-weight="800">${total}</text>
        <text x="${cx}" y="${cy + 18}" text-anchor="middle" fill="#8fa3bf" font-size="11">alerts</text>
      </svg>
      <div class="space-y-2 text-sm flex-1">
        ${paths.map(item => `
          <div class="flex items-center justify-between gap-3">
            <div class="flex items-center gap-3">
              <span class="inline-block w-3 h-3 rounded-full" style="background:${item.color}"></span>
              <span>${esc(item.label)}</span>
            </div>
            <div class="mono text-xs text-slate-300">${esc(item.value)} (${esc(Math.round((item.value / total) * 100))}%)</div>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function renderNodeBars() {
  const host = byId("chart-bars");
  const summary = byId("chart-bars-summary");
  const counts = new Map();
  const names = nodeNameMap();
  (FOC.timeline?.events || []).forEach(ev => {
    const key = ev.related_node_id && ev.related_node_id !== "unknown" ? ev.related_node_id : null;
    if (!key) return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (!rows.length) {
    summary.textContent = "No data";
    host.innerHTML = `<div class="text-sm text-slate-400">No node-level event concentration available.</div>`;
    return;
  }
  const maxVal = Math.max(...rows.map(([, v]) => v));
  summary.textContent = `${rows.length} ranked nodes`;
  host.innerHTML = rows.map(([label, value]) => `
    <div class="mb-3">
      <div class="flex items-center justify-between gap-3 text-sm mb-1">
        <div>${esc(names.get(label) || label)}</div>
        <div class="mono text-xs text-slate-300">${esc(value)} events</div>
      </div>
      <div class="w-full h-3 rounded-full bg-slate-900/80 overflow-hidden">
        <div class="h-full rounded-full bg-gradient-to-r from-sky-500 to-blue-600" style="width:${Math.max(8, (value / maxVal) * 100)}%"></div>
      </div>
    </div>
  `).join("");
}

function renderTechniqueRanking() {
  const host = byId("chart-ranking");
  const summary = byId("chart-ranking-summary");
  const counts = new Map();
  (FOC.timeline?.events || [])
    .filter(ev => ev.event_type === "attack_execution")
    .forEach(ev => {
      const mitre = ev.details?.mitre_id || "unknown";
      const name = ev.details?.mitre_technique || ev.description || "unknown";
      const key = `${mitre}||${name}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    });
  const rows = [...counts.entries()]
    .map(([key, value]) => {
      const [mitre, name] = key.split("||");
      return { mitre, name, value };
    })
    .sort((a, b) => b.value - a.value)
    .slice(0, 8);

  if (!rows.length) {
    summary.textContent = "No data";
    host.innerHTML = `<div class="text-sm text-slate-400">No ATT&CK execution ranking available.</div>`;
    return;
  }

  summary.textContent = `${rows.length} ranked techniques`;
  host.innerHTML = `
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-slate-400 uppercase tracking-[0.16em] text-[11px]">
          <th class="pb-2 pr-3">MITRE</th>
          <th class="pb-2 pr-3">Technique</th>
          <th class="pb-2">Count</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(row => `
          <tr class="border-t border-slate-700/40">
            <td class="py-3 pr-3 mono">${esc(row.mitre)}</td>
            <td class="py-3 pr-3">${esc(row.name)}</td>
            <td class="py-3 mono">${esc(row.value)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderNetworkGraph() {
  const host = byId("chart-network");
  const summary = byId("chart-network-summary");
  const scenario = FOC.scenario || {};
  const rels = FOC.relationships?.edges || [];
  const nodes = (scenario.nodes || []).slice(0, 8);
  const nodeById = new Map(nodes.map(node => [node.node_id, node]));
  if (!nodes.length) {
    summary.textContent = "No data";
    host.innerHTML = `<div class="text-sm text-slate-400">No structural-evidential graph available.</div>`;
    return;
  }
  const attackCounts = new Map();
  const alertCounts = new Map();
  const nodeAttackEvents = (FOC.timeline?.events || []).filter(ev => ev.event_type === "attack_execution");
  const nodeAlertEvents = (FOC.timeline?.events || []).filter(ev => ev.event_type === "detection_alert");
  nodeAttackEvents.forEach(ev => {
    const nodeId = ev.related_node_id;
    if (nodeId && nodeById.has(nodeId)) attackCounts.set(nodeId, (attackCounts.get(nodeId) || 0) + 1);
  });
  nodeAlertEvents.forEach(ev => {
    const nodeId = ev.related_node_id;
    if (nodeId && nodeById.has(nodeId)) alertCounts.set(nodeId, (alertCounts.get(nodeId) || 0) + 1);
  });

  const layout = [
    { x: 180, y: 80 },
    { x: 420, y: 80 },
    { x: 660, y: 80 },
    { x: 300, y: 220 },
    { x: 540, y: 220 },
    { x: 780, y: 220 },
    { x: 180, y: 360 },
    { x: 420, y: 360 },
  ];
  const positions = new Map();
  nodes.forEach((node, idx) => {
    const pos = layout[idx] || { x: 180 + (idx * 120), y: 80 };
    const type = String(node.type || "").toLowerCase();
    const color = type.includes("attack") ? "#f59e0b" : (type.includes("monitor") ? "#38bdf8" : (type.includes("plc") ? "#22c55e" : (type.includes("scada") ? "#a855f7" : "#ef4444")));
    positions.set(node.node_id, { ...pos, color, node });
  });

  const structuralEdges = (scenario.edges || [])
    .filter(edge => positions.has(edge.source_node_id) && positions.has(edge.target_node_id))
    .map(edge => ({
      from: edge.source_node_id,
      to: edge.target_node_id,
      label: "network",
      color: "rgba(148,163,184,0.35)",
    }));
  const industrialEdges = (scenario.industrial_linkages || [])
    .filter(link => positions.has(link.ot_node_id) && positions.has(link.linked_to))
    .map(link => ({
      from: link.linked_to,
      to: link.ot_node_id,
      label: "it↔ot",
      color: "rgba(34,197,94,0.5)",
    }));
  const detectionEdges = rels
    .filter(edge => edge.relation === "produced_alert" && edge.details?.node_id && positions.has(edge.details.node_id))
    .slice(0, 12)
    .map(edge => ({
      from: edge.details.node_id,
      to: edge.details.node_id,
      label: edge.correlation_status || "alert",
      color: edge.correlation_status === "confirmed" ? "rgba(239,68,68,0.6)" : "rgba(234,179,8,0.5)",
    }));

  const allEdges = [...structuralEdges, ...industrialEdges];
  const svgEdges = allEdges.map(edge => {
    const a = positions.get(edge.from);
    const b = positions.get(edge.to);
    if (!a || !b) return "";
    const midX = (a.x + b.x) / 2;
    const midY = (a.y + b.y) / 2;
    return `
      <line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${edge.color}" stroke-width="3" />
      <text x="${midX}" y="${midY - 8}" text-anchor="middle" fill="#8fa3bf" font-size="10">${esc(edge.label)}</text>
    `;
  }).join("");

  const svgNodes = [...positions.values()].map(meta => `
    <g>
      <circle cx="${meta.x}" cy="${meta.y}" r="34" fill="${meta.color}" opacity="0.9"></circle>
      <text x="${meta.x}" y="${meta.y - 46}" text-anchor="middle" fill="#8fa3bf" font-size="10">${esc(meta.node.type || "node")}</text>
      <text x="${meta.x}" y="${meta.y - 4}" text-anchor="middle" fill="#08101b" font-size="11" font-weight="800">${esc(meta.node.name || meta.node.node_id)}</text>
      <text x="${meta.x}" y="${meta.y + 14}" text-anchor="middle" fill="#08101b" font-size="9">${esc((meta.node.name || "").length > 16 ? "" : (meta.node.linked_to ? "linked" : ""))}</text>
      <text x="${meta.x}" y="${meta.y + 54}" text-anchor="middle" fill="#8fa3bf" font-size="10">A:${esc(attackCounts.get(meta.node.node_id) || 0)} | D:${esc(alertCounts.get(meta.node.node_id) || 0)}</text>
    </g>
  `).join("");

  const legend = detectionEdges.length ? `<div class="text-xs text-slate-400 mt-3">Node counters: A = attack executions targeting the node, D = detection alerts resolved to the node.</div>` : `<div class="text-xs text-slate-400 mt-3">Node counters: A = attack executions targeting the node, D = detection alerts resolved to the node.</div>`;
  summary.textContent = `${nodes.length} nodes | ${allEdges.length} structural edges | ${nodeAlertEvents.length} detection events`;
  host.innerHTML = `
    <svg viewBox="0 0 920 420" class="w-full h-auto">
      ${svgEdges}
      ${svgNodes}
    </svg>
    ${legend}
  `;
}

function renderScenario() {
  const scenario = FOC.scenario || {};
  const nodes = scenario.nodes || [];
  const links = scenario.industrial_linkages || [];
  byId("scenario-summary").textContent = `${nodes.length} nodes | ${(scenario.edges || []).length} edges | ${(scenario.ot_nodes || []).length} OT nodes`;
  byId("scenario-nodes").innerHTML = nodes.map(node => `
    <div class="glass-soft rounded-2xl p-4">
      <div class="flex items-center justify-between gap-3">
        <div>
          <div class="text-sm font-black">${esc(node.name || node.id)}</div>
          <div class="mono text-xs text-slate-400 mt-1">${esc(node.node_id || "unknown")}</div>
        </div>
        <div class="${statusClass(node.id_origin)} text-xs uppercase tracking-[0.2em] font-black">${esc(node.id_origin || "unknown")}</div>
      </div>
      <div class="flex flex-wrap gap-2 mt-3">
        ${tag("Type", node.type || "unknown")}
        ${tag("Industrial", String(!!node.industrial))}
        ${tag("Linked", node.linked_to || "not_available")}
      </div>
    </div>
  `).join("") || `<div class="text-sm text-slate-400">No scenario nodes available.</div>`;

  const bindings = scenario.node_instance_bindings || [];
  byId("scenario-links").innerHTML = [
    ...links.map(link => `
      <div class="glass-soft rounded-2xl p-4">
        <div class="text-sm font-black">${esc(link.ot_node_name)} <span class="text-slate-400">→</span> ${esc(link.linked_to)}</div>
        <div class="text-xs mt-2 ${statusClass(link.relationship_status)} uppercase tracking-[0.2em] font-black">${esc(link.relationship_status || "unknown")}</div>
      </div>`),
    ...bindings.map(binding => `
      <div class="glass-soft rounded-2xl p-4">
        <div class="text-sm font-black">${esc(binding.node_name)} <span class="text-slate-400">→</span> ${esc(binding.instance_name)}</div>
        <div class="mono text-xs text-slate-400 mt-2">${esc(binding.instance_id || "unresolved")}</div>
      </div>`),
  ].join("") || `<div class="text-sm text-slate-400">No structural relationships available.</div>`;
}

function renderTools() {
  const tools = FOC.tools || {};
  const nodes = tools.nodes || [];
  const pending = nodes.reduce((sum, node) => sum + (node.pending_tools || []).length, 0);
  const failed = nodes.reduce((sum, node) => sum + (node.failed_tools || []).length, 0);
  const orphanCount = (tools.orphan_tool_artifacts || []).length;
  const historicalCount = (tools.historical_tool_artifacts || []).length;
  const hostCount = (tools.host_tool_artifacts || []).length;
  byId("tools-summary").textContent = `Active nodes: ${tools.active_nodes_count ?? nodes.length} | ${pending} pending | ${failed} failed | Orphan: ${orphanCount} | Historical: ${historicalCount} | Host: ${hostCount}`;
  byId("tools-nodes").innerHTML = nodes.map(node => `
    <div class="glass-soft rounded-3xl p-4">
      <div class="flex items-start justify-between gap-3">
        <div>
          <div class="text-sm font-black">${esc(node.node_name || node.instance_name)}</div>
          <div class="text-xs text-slate-300 mt-1">${esc(node.instance_name)}</div>
          <div class="mono text-xs text-slate-400 mt-1">${esc(node.instance_id || "unresolved")}</div>
        </div>
        <div class="text-xs uppercase tracking-[0.2em] font-black ${statusClass(node.node_type)}">${esc(node.node_type || "unknown")}</div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 text-sm">
        <div class="glass rounded-2xl p-3">
          <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Floating IP</div>
          <div class="mono text-xs mt-2 text-slate-200">${esc(node.ip_floating || node.ip || "not_available")}</div>
        </div>
        <div class="glass rounded-2xl p-3">
          <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Private IP</div>
          <div class="mono text-xs mt-2 text-slate-200">${esc(node.ip_private || "not_available")}</div>
        </div>
        <div class="glass rounded-2xl p-3">
          <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">OpenStack Instance</div>
          <div class="mono text-xs mt-2 text-slate-200 break-all">${esc(node.openstack_instance_id || "not_available")}</div>
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4 text-sm">
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Desired</div><div class="mt-2">${(node.desired_tools || []).map(v => `<div class="mono text-xs">${esc(v)}</div>`).join("") || '<span class="text-slate-500">none</span>'}</div></div>
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Installed</div><div class="mt-2">${(node.installed_tools || []).map(v => `<div class="mono text-xs">${esc(v)}</div>`).join("") || '<span class="text-slate-500">none</span>'}</div></div>
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Pending</div><div class="mt-2">${(node.pending_tools || []).map(v => `<div class="mono text-xs status-inferred">${esc(v)}</div>`).join("") || '<span class="text-slate-500">none</span>'}</div></div>
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Failed</div><div class="mt-2">${(node.failed_tools || []).map(v => `<div class="mono text-xs status-missing">${esc(v)}</div>`).join("") || '<span class="text-slate-500">none</span>'}</div></div>
      </div>
      <div class="mt-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Installed timestamps</div>
        <div class="mt-2">${Object.entries(node.installed_timestamps || {}).map(([tool, ts]) => `<div class="mono text-xs text-slate-300">${esc(tool)} → ${esc(ts || "not_available")}</div>`).join("") || '<span class="text-slate-500 text-xs">not_available</span>'}</div>
      </div>
      <div class="mt-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Resolved tool states</div>
        <div class="mt-2 space-y-2">${(node.tool_states || []).map(item => `
          <div class="glass rounded-2xl p-3">
            <div class="flex items-center justify-between gap-3">
              <div class="mono text-xs text-slate-200">${esc(item.tool_id)}</div>
              <div class="text-[10px] uppercase tracking-[0.18em] font-black ${statusClass(item.state === "state_conflict" ? "missing" : item.state)}">${esc(item.state)}</div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2 text-[11px] text-slate-400">
              <div>Installed timestamp: <span class="mono">${esc(item.installed_timestamp || "not_available")}</span></div>
              <div>Current state: <span class="mono">${esc(item.current_state || "not_available")}</span></div>
              <div>Desired source: <span class="mono">${esc(item.desired_source || "not_available")}</span></div>
              <div>Installed source: <span class="mono">${esc(item.installed_source || "not_available")}</span></div>
              <div>Failed source: <span class="mono">${esc(item.failed_source || "not_available")}</span></div>
              <div>Action: <span class="mono">${esc(item.recommended_action || "none")}</span></div>
            </div>
          </div>
        `).join("") || '<span class="text-slate-500 text-xs">none</span>'}</div>
      </div>
      <div class="mt-4">
        <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Installation logs</div>
        <div class="mt-2">${(node.installation_logs || []).slice(0, 5).map(v => `<div class="mono text-xs text-slate-300">${esc(v)}</div>`).join("") || '<span class="text-slate-500 text-xs">none</span>'}</div>
      </div>
    </div>
  `).join("") || `<div class="text-sm text-slate-400">No tools BOM available.</div>`;

  byId("tools-nodes").innerHTML += `
    <div class="glass-soft rounded-3xl p-4">
      <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Unmatched / Orphan Tool Sources</div>
      <div class="mt-3 space-y-2">
        ${((tools.orphan_tool_artifacts || []).map(item => `<div class="mono text-xs text-slate-300">${esc(item.artifact_type)} | ${esc(item.instance_name)} | ${esc(item.source_path)} | ${esc(item.relationship_status)}</div>`).join("")) || '<div class="text-xs text-slate-500">none</div>'}
      </div>
      <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black mt-4">Historical Tool Artifacts</div>
      <div class="mt-3 space-y-2">
        ${((tools.historical_tool_artifacts || []).map(item => `<div class="mono text-xs text-slate-300">${esc(item.artifact_type)} | ${esc(item.instance_name)} | ${esc(item.source_path)} | ${esc(item.relationship_status)}</div>`).join("")) || '<div class="text-xs text-slate-500">none</div>'}
      </div>
      <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black mt-4">Host Tool Artifacts</div>
      <div class="mt-3 space-y-2">
        ${((tools.host_tool_artifacts || []).map(item => `<div class="mono text-xs text-slate-300">${esc(item.artifact_type)} | ${esc(item.source_path)} | ${esc(item.relationship_status)}</div>`).join("")) || '<div class="text-xs text-slate-500">none</div>'}
      </div>
    </div>
  `;
}

function timelineCard(ev) {
  const details = ev.details || {};
  let detailHtml = "";
  const nodeNames = nodeNameMap();

  if (ev.event_type === "attack_execution") {
    detailHtml = `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3 text-[11px] text-slate-300">
        <div>Technique: <span class="mono">${esc(details.mitre_id || "unknown")} - ${esc(details.mitre_technique || "unknown")}</span></div>
        <div>Engine: <span class="mono">${esc(details.detection_engine || "unknown")}</span></div>
        <div>Target: <span class="mono">${esc(details.target_role || "unknown")} @ ${esc(details.target_ip || "unknown")}</span></div>
        <div>Attacker IP: <span class="mono">${esc(details.attacker_ip || "unknown")}</span></div>
        <div>Status: <span class="mono">${esc(details.success ? "success" : "failed")} / exit ${esc(details.exit_code ?? "unknown")}</span></div>
        <div>Expected alerts: <span class="mono">${esc((details.expected_alerts || []).join(", ") || "none")}</span></div>
      </div>`;
  } else if (ev.event_type === "detection_alert") {
    detailHtml = `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3 text-[11px] text-slate-300">
        <div>Sensor: <span class="mono">${esc(details.source || "unknown")}</span></div>
        <div>Rule: <span class="mono">${esc(details.rule_id || "unknown")} / level ${esc(details.rule_level || "unknown")}</span></div>
        <div>Protocol: <span class="mono">${esc(details.protocol || "unknown")}</span></div>
        <div>Severity: <span class="mono">${esc(details.triage_severity || "not_available")}</span></div>
        <div>Agent: <span class="mono">${esc((details.agent || {}).name || "unknown")} @ ${esc((details.agent || {}).ip || "unknown")}</span></div>
        <div>Correlated attack: <span class="mono">${esc(details.correlated_attack_display || "unresolved")} (${esc(details.correlated_attack_mitre_id || "unresolved")})</span></div>
        <div>Correlation: <span class="mono">${esc(details.correlation_status || "unresolved")} / ${esc(details.correlation_confidence || "low")}</span></div>
        <div>Reason: <span class="mono">${esc(details.correlation_reason || "not_available")}</span></div>
      </div>`;
  } else if (ev.event_type === "triage_result") {
    detailHtml = `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3 text-[11px] text-slate-300">
        <div>Severity: <span class="mono">${esc(details.severity || "unknown")}</span></div>
        <div>Recommend forensics: <span class="mono">${esc(String(details.recommend_forensics ?? false))}</span></div>
        <div>Native score: <span class="mono">${esc(details.native_score ?? "not_available")}</span></div>
        <div>Scale: <span class="mono">${esc(details.native_scale || "not_available")}</span></div>
      </div>`;
  }

  if (ev.aggregate) {
    detailHtml += `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3 text-[11px] text-slate-300">
        <div>Count: <span class="mono">${esc(ev.aggregate_count || 1)}</span></div>
        <div>Example alert: <span class="mono">${esc(ev.example_alert_id || "unresolved")}</span></div>
        <div>First seen: <span class="mono">${esc(ev.first_seen || ev.timestamp || "unknown")}</span></div>
        <div>Last seen: <span class="mono">${esc(ev.last_seen || ev.timestamp || "unknown")}</span></div>
        <div class="md:col-span-2">Affected nodes: <span class="mono">${esc((ev.affected_nodes || []).map(id => nodeNames.get(id) || id).join(", ") || "unresolved")}</span></div>
      </div>`;
  }

  return `
    <div class="glass-soft rounded-2xl p-4">
      <div class="flex items-center justify-between gap-3">
        <div class="text-sm font-black">${esc(eventTypeLabel(ev.event_type || "event"))}</div>
        <div class="mono text-xs text-slate-400">${esc(ev.aggregate ? (ev.last_seen || ev.timestamp || "unknown") : (ev.timestamp || "unknown"))}</div>
      </div>
      <div class="text-sm text-slate-300 mt-2">${esc(ev.description || "No description")}</div>
      <div class="flex flex-wrap gap-2 mt-3">
        ${tag("source", ev.source_type || "unknown")}
        ${tag("node", nodeNames.get(ev.related_node_id) || ev.related_node_id || "unresolved", statusClass(ev.related_node_id))}
        ${tag("instance", ev.related_instance_id || "unresolved", statusClass(ev.related_instance_id))}
        ${tag("phase", ev.phase || "unknown", statusClass(ev.phase))}
        ${tag("status", ev.status || "unknown", statusClass(ev.status))}
        ${tag("origin", ev.id_origin || "unknown", statusClass(ev.id_origin))}
      </div>
      ${detailHtml}
    </div>`;
}

function renderTimeline() {
  const events = aggregateTimelineEvents(FOC.timeline?.events || []);
  const phases = new Set(events.map(ev => ev.phase).filter(Boolean));
  const aggregates = events.filter(ev => ev.aggregate).length;
  byId("timeline-summary").textContent = `${events.length} display events | ${aggregates} aggregated groups | ${phases.size} phases`;
  byId("timeline-events").innerHTML = events.slice(0, 80).map(timelineCard).join("") || `<div class="text-sm text-slate-400">No timeline available.</div>`;
}

function renderAlerts() {
  const events = aggregateTimelineEvents(
    [...(FOC.timeline?.events || [])]
    .filter(ev => ["detection_alert", "triage_result", "case_created", "dfir_orchestration_start", "dfir_orchestration_done", "case_opened", "case_attached"].includes(ev.event_type))
  );
  const detectionCount = events.filter(ev => ev.event_type === "detection_alert").length;
  const triageCount = events.filter(ev => ev.event_type === "triage_result").length;
  const escalationCount = events.filter(ev => ["case_created", "dfir_orchestration_start", "dfir_orchestration_done", "case_opened", "case_attached"].includes(ev.event_type)).length;
  const aggregateCount = events.filter(ev => ev.aggregate).length;
  byId("alerts-summary").textContent = `${events.length} display events | ${aggregateCount} aggregated | ${detectionCount} alerts | ${triageCount} triage | ${escalationCount} escalation`;
  byId("alerts-events").innerHTML = events.slice(0, 60).map(timelineCard).join("") || `<div class="text-sm text-slate-400">No alert or escalation events available.</div>`;
}

function renderCases() {
  const cases = FOC.cases?.cases || [];
  const artifacts = FOC.artifacts?.artifacts || [];
  const artifactSummary = FOC.status?.artifact_summary || {};
  const note = byId("cases-summary-note");
  const summaryHtml = `
    <div class="glass-soft rounded-3xl p-4">
      <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Evidence Class Summary</div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3 text-sm">
        <div>Acquisition metadata: <span class="mono text-slate-300">${esc(artifactSummary.acquisition_metadata || 0)}</span></div>
        <div>Preserved evidence: <span class="mono text-slate-300">${esc(artifactSummary.preserved_evidence || 0)}</span></div>
        <div>Forensic inputs: <span class="mono text-slate-300">${esc(artifactSummary.forensic_inputs || 0)}</span></div>
        <div>Analysis outputs: <span class="mono text-slate-300">${esc(artifactSummary.analysis_outputs || 0)}</span></div>
      </div>
    </div>
  `;
  if (note) {
    note.innerHTML = cases.length
      ? "Preserved evidence is available. Run multilayer forensic analysis on demand to generate a validated forensic report from preserved evidence."
      : "No preserved forensic case is currently indexed in FOC.";
  }
  const casesHtml = cases.map(entry => {
    const analysisStatus = FOC.caseAnalysisStatuses[entry.case_id] || null;
    const availableLayers = analysisStatus?.available_layers || entry.available_layers || {};
    const currentAnalysisState = analysisStatus?.status || entry.analysis_status || "not_started";
    const runLabel = currentAnalysisState === "completed" ? "Rerun Multilayer Analysis" : currentAnalysisState === "running" ? "Analysis already running" : "Run Multilayer Forensic Analysis";
    const layersList = Object.entries(availableLayers)
      .map(([key, value]) => `<div class="mono text-[11px] ${value ? "status-confirmed" : "status-unknown"}">${esc(key)}: ${esc(value ? "available" : "not_available")}</div>`)
      .join("");
    const caseArtifacts = artifacts.filter(a => a.case_id === entry.case_id).slice(0, 6);
    return `
      <div class="glass-soft rounded-3xl p-4">
        <div class="flex items-center justify-between gap-3">
          <div>
            <div class="text-sm font-black">${esc(entry.case_id)}</div>
            <div class="mono text-xs text-slate-400 mt-1">${esc(entry.path)}</div>
          </div>
          <div class="text-xs uppercase tracking-[0.2em] font-black status-confirmed">${esc(entry.artifacts_count || 0)} artifacts</div>
        </div>
        <div class="mt-3 space-y-1">
          <div class="mono text-xs text-slate-300">${esc(entry.manifest_path)}</div>
          <div class="mono text-xs text-slate-300">${esc(entry.custody_path)}</div>
          <div class="mono text-xs text-slate-300">${esc(entry.pipeline_path)}</div>
        </div>
        <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
          <div class="glass rounded-2xl p-3">
            <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Forensic analysis</div>
            <div class="mt-2 ${statusClass(currentAnalysisState)} font-black uppercase tracking-[0.12em] text-xs">${esc(currentAnalysisState)}</div>
            <div class="mt-2 text-xs text-slate-300">${esc(currentAnalysisState === "completed" ? "Analysis outputs are available for this case." : "Preserved evidence is available, but no forensic analysis has been executed yet.")}</div>
          </div>
          <div class="glass rounded-2xl p-3">
            <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Available layers</div>
            <div class="mt-2 space-y-1">${layersList || '<span class="text-slate-500 text-xs">not_loaded</span>'}</div>
          </div>
        </div>
        <div class="mt-3">${caseArtifacts.map(a => `<div class="mono text-xs text-slate-400">${esc(a.artifact_type)} → ${esc(a.artifact_id)}</div>`).join("")}</div>
        <div class="flex flex-wrap gap-3 mt-4">
          <button class="open-analysis-btn btn-primary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}"${currentAnalysisState === "running" ? " disabled" : ""}>${esc(runLabel)}</button>
          <button class="view-analysis-btn btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}">Open Analysis Status</button>
        </div>
      </div>
    `;
  }).join("") || `<div class="text-sm text-slate-400">No forensic cases indexed.</div>`;
  byId("cases-panel").innerHTML = summaryHtml + casesHtml;
}

function renderGaps() {
  const gaps = FOC.gaps?.gaps || [];
  byId("gaps-summary").textContent = `${gaps.length} gaps | ${FOC.gaps?.critical_gaps || 0} critical`;
  byId("gaps-panel").innerHTML = gaps.map(gap => `
    <div class="glass-soft rounded-2xl p-4">
      <div class="flex items-center justify-between gap-3">
        <div class="text-sm font-black">${esc(gap.type)}</div>
        <div class="text-xs uppercase tracking-[0.2em] font-black ${statusClass(gap.status)}">${esc(gap.status)}</div>
      </div>
      <div class="text-sm text-slate-300 mt-2">${esc(gap.description)}</div>
      <div class="flex flex-wrap gap-2 mt-3">
        ${tag("severity", gap.severity, statusClass(gap.severity))}
        ${tag("expected", gap.source_expected)}
      </div>
      <div class="text-xs text-slate-400 mt-3">${esc(gap.recommended_action)}</div>
    </div>
  `).join("") || `<div class="text-sm text-slate-400">No reconstruction gaps detected.</div>`;
}

function renderSources() {
  const sources = FOC.sources?.sources || [];
  byId("sources-panel").innerHTML = sources.map(src => `
    <div class="glass-soft rounded-2xl p-4">
      <div class="flex items-center justify-between gap-3">
        <div class="text-sm font-black">${esc(src.source_type)}</div>
        <div class="text-xs uppercase tracking-[0.2em] font-black ${statusClass(src.status)}">${esc(src.status)}</div>
      </div>
      <div class="mono text-xs text-slate-300 mt-2 break-all">${esc(src.path)}</div>
      <div class="grid grid-cols-2 gap-2 mt-3 text-xs">
        <div>exists: <span class="${statusClass(src.status)}">${esc(src.status === "present")}</span></div>
        <div>kind: ${esc(src.kind || "unknown")}</div>
        <div>size: ${esc(src.size ?? "not_available")}</div>
        <div>mtime: ${esc(src.mtime ?? "not_available")}</div>
      </div>
      <div class="mono text-[11px] text-slate-400 mt-3 break-all">sha256: ${esc(src.sha256 || "not_available")}</div>
    </div>
  `).join("") || `<div class="text-sm text-slate-400">No indexed sources available.</div>`;
}

function renderRelationships() {
  const edges = FOC.relationships?.edges || [];
  byId("relationships-panel").innerHTML = edges.slice(0, 120).map(edge => `
    <div class="glass-soft rounded-2xl p-4">
      <div class="flex items-center justify-between gap-3">
        <div class="text-sm font-black">${esc(edge.from_type)} → ${esc(edge.to_type)}</div>
        <div class="text-xs uppercase tracking-[0.2em] font-black ${statusClass(edge.relationship_status || edge.status)}">${esc(edge.relationship_status || edge.status)}</div>
      </div>
      <div class="mono text-xs text-slate-300 mt-2 break-all">${esc(edge.from_id)} --${esc(edge.relation)}--> ${esc(edge.to_id)}</div>
      <div class="mt-3">${(edge.evidence || []).slice(0, 3).map(ev => `<div class="mono text-[11px] text-slate-400">${esc(ev)}</div>`).join("") || '<div class="text-xs text-slate-500">No direct evidence reference</div>'}</div>
    </div>
  `).join("") || `<div class="text-sm text-slate-400">No relationships indexed.</div>`;
}

async function fetchCaseAnalysisStatus(caseId) {
  const payload = await fetchJson(analysisStatusUrl(caseId));
  FOC.caseAnalysisStatuses[caseId] = payload;
  return payload;
}

function stopAnalysisPolling() {
  if (FOC.analysisPollTimer) {
    clearTimeout(FOC.analysisPollTimer);
    FOC.analysisPollTimer = null;
  }
}

function scheduleAnalysisPolling(caseId) {
  stopAnalysisPolling();
  FOC.analysisPollTimer = setTimeout(async () => {
    if (!FOC.selectedCaseId || FOC.selectedCaseId !== caseId) return;
    try {
      const status = await fetchCaseAnalysisStatus(caseId);
      renderAnalysisModal(status);
      if (status.status === "running") {
        scheduleAnalysisPolling(caseId);
      }
      if (["completed", "partial", "failed"].includes(String(status.status || ""))) {
        await loadAll(true);
      }
    } catch (_) {
      scheduleAnalysisPolling(caseId);
    }
  }, ANALYSIS_STATUS_POLL_MS);
}

function openAnalysisModalShell() {
  const modal = byId("analysis-modal");
  if (!modal) return;
  modal.classList.add("is-active");
  modal.setAttribute("aria-hidden", "false");
}

function closeAnalysisModalShell() {
  const modal = byId("analysis-modal");
  if (!modal) return;
  modal.classList.remove("is-active");
  modal.setAttribute("aria-hidden", "true");
  stopAnalysisPolling();
}

function renderAnalysisModal(status, extras = {}) {
  const caseId = status?.case_id || FOC.selectedCaseId || "unknown";
  const title = byId("analysis-modal-title");
  const subtitle = byId("analysis-modal-subtitle");
  const statusPanel = byId("analysis-status-panel");
  const phasesPanel = byId("analysis-phases-panel");
  const debugPanel = byId("analysis-debug-panel");
  const layersPanel = byId("analysis-layers-panel");
  const reportPanel = byId("analysis-report-panel");
  const runBtn = byId("analysis-run-btn");
  const validateBtn = byId("analysis-validate-btn");
  const viewReportBtn = byId("analysis-view-report-btn");
  if (!statusPanel || !phasesPanel || !debugPanel || !layersPanel || !reportPanel) return;

  const caseEntry = (FOC.cases?.cases || []).find(item => item.case_id === caseId);
  if (title) title.textContent = `Case analysis: ${caseEntry?.source_case_name || caseId}`;
  if (subtitle) {
    if (!status.evidence_available) {
      subtitle.textContent = "Analysis cannot start because no preserved evidence is linked to this case.";
    } else if (status.status === "running") {
      subtitle.textContent = "Forensic analysis is running. This may take several minutes depending on disk, memory and PCAP size.";
    } else if (status.status === "completed") {
      subtitle.textContent = "Forensic analysis completed. The FOC readiness report has been updated, but semantic and causal reconstruction remain blocked until explicitly generated.";
    } else if (status.status === "failed") {
      subtitle.textContent = `Forensic analysis failed at phase: ${status.current_phase || "unknown"}. Open debug details to inspect the exact command, stderr and expected output.`;
    } else {
      subtitle.textContent = "Preserved evidence is available, but no forensic analysis has been executed yet. Run multilayer forensic analysis to unlock the Forensic Analysis Report.";
    }
  }

  if (runBtn) {
    runBtn.disabled = status.status === "running" || !status.evidence_available;
    runBtn.textContent = status.status === "running" ? "Analysis already running" : "Run Multilayer Forensic Analysis";
  }
  if (validateBtn) validateBtn.disabled = status.status === "running";
  if (viewReportBtn) viewReportBtn.disabled = !status.forensic_analysis_report_path;

  statusPanel.innerHTML = `
    <div><strong>case_id:</strong> ${esc(caseId)}</div>
    <div><strong>analysis_id:</strong> ${esc(status.analysis_id || "not_available")}</div>
    <div><strong>status:</strong> <span class="${statusClass(status.status)}">${esc(status.status || "unknown")}</span></div>
    <div><strong>started_at:</strong> ${esc(status.started_at || "not_available")}</div>
    <div><strong>updated_at:</strong> ${esc(status.updated_at || "not_available")}</div>
    <div><strong>finished_at:</strong> ${esc(status.finished_at || "not_available")}</div>
    <div><strong>current_phase:</strong> ${esc(status.current_phase || "not_available")}</div>
    <div><strong>progress_percent:</strong> ${esc(status.progress_percent ?? 0)}%</div>
    <div><strong>report:</strong> ${esc(status.forensic_analysis_report_path || "not_available")}</div>
  `;

  const phaseEntries = Object.entries(status.phases || {});
  phasesPanel.innerHTML = phaseEntries.length
    ? phaseEntries.map(([key, phase]) => `
      <div class="glass rounded-2xl p-3">
        <div class="flex items-center justify-between gap-3">
          <div class="font-black">${esc(phase.label || key)}</div>
          <div class="text-xs uppercase tracking-[0.12em] font-black ${statusClass(phase.status)}">${esc(phase.status || "pending")}</div>
        </div>
        <div class="mt-2 text-xs text-slate-300 mono">${esc(phase.output_path || "not_available")}</div>
        <div class="mt-2 text-xs text-slate-400">stdout: ${esc(phase.stdout_path || "not_available")}</div>
        <div class="mt-1 text-xs text-slate-400">stderr: ${esc(phase.stderr_path || "not_available")}</div>
      </div>
    `).join("")
    : "No phase progress loaded.";

  const warnings = (status.warnings || []).map(item => `${item.phase}: ${item.message}`).join("\n");
  const errors = (status.errors || []).map(item => `${item.phase}: ${item.error_message || item.message}`).join("\n");
  const logs = extras.logs?.logs || [];
  debugPanel.innerHTML = `
    <div><strong>warnings:</strong></div>
    <div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(warnings || "none")}</div>
    <div class="mt-4"><strong>errors:</strong></div>
    <div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(errors || "none")}</div>
    <div class="mt-4"><strong>logs:</strong></div>
    <div class="space-y-3 mt-2">
      ${logs.slice(0, 6).map(log => `
        <div class="glass rounded-2xl p-3">
          <div class="font-black">${esc(log.phase)}</div>
          <div class="mono text-[11px] text-slate-400 mt-2">${esc(log.stdout_path || "not_available")}</div>
          <div class="mono text-[11px] text-slate-400 mt-1">${esc(log.stderr_path || "not_available")}</div>
          <div class="mono text-[11px] text-slate-300 mt-2 whitespace-pre-wrap">${esc(log.stderr_tail || log.stdout_tail || "no log tail")}</div>
        </div>
      `).join("") || '<div class="text-xs text-slate-500">no logs loaded</div>'}
    </div>
  `;

  const layers = Object.entries(status.available_layers || {});
  layersPanel.innerHTML = layers.length
    ? layers.map(([key, value]) => `<div class="mono text-sm ${value ? "status-confirmed" : "status-unknown"}">${esc(key)}: ${esc(value ? "available" : "not_available")}</div>`).join("")
    : "No layer inventory loaded.";

  const report = extras.report || null;
  reportPanel.textContent = report?.summary_preview || "No report loaded.";
}

async function openCaseAnalysis(caseId, autoRun = false) {
  FOC.selectedCaseId = caseId;
  openAnalysisModalShell();
  const status = await fetchCaseAnalysisStatus(caseId);
  const [logsRes, reportRes] = await Promise.allSettled([
    fetchJson(analysisLogsUrl(caseId)),
    fetchJson(analysisReportUrl(caseId)),
  ]);
  renderAnalysisModal(status, {
    logs: logsRes.status === "fulfilled" ? logsRes.value : null,
    report: reportRes.status === "fulfilled" ? reportRes.value : null,
  });
  if (autoRun && status.status !== "running") {
    await runCaseAnalysis(caseId);
    return;
  }
  if (status.status === "running") {
    scheduleAnalysisPolling(caseId);
  }
}

async function runCaseAnalysis(caseId, force = false) {
  try {
    await fetchJson(analysisRunUrl(caseId, force), { method: "POST" });
  } catch (_) {
    // The backend returns 409 when an analysis is already running. In that case
    // we simply reload the persisted status and keep the modal in sync.
  }
  const status = await fetchCaseAnalysisStatus(caseId);
  renderAnalysisModal(status);
  scheduleAnalysisPolling(caseId);
}

async function validateCaseAnalysis(caseId) {
  const [validation, logs, report] = await Promise.allSettled([
    fetchJson(analysisValidateUrl(caseId), { method: "POST" }),
    fetchJson(analysisLogsUrl(caseId)),
    fetchJson(analysisReportUrl(caseId)),
  ]);
  const status = await fetchCaseAnalysisStatus(caseId);
  renderAnalysisModal(status, {
    logs: logs.status === "fulfilled" ? logs.value : null,
    report: report.status === "fulfilled" ? report.value : null,
  });
  const debugPanel = byId("analysis-debug-panel");
  if (debugPanel && validation.status === "fulfilled") {
    const validationText = (validation.value.validation || []).map(item => `${item.phase}: ${item.status}${item.reason ? ` (${item.reason})` : ""}`).join("\n");
    debugPanel.innerHTML += `<div class="mt-4"><strong>validation:</strong><div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(validationText || "no validation rows")}</div></div>`;
  }
}

async function viewCaseAnalysisReport(caseId) {
  const [status, logs, report] = await Promise.allSettled([
    fetchCaseAnalysisStatus(caseId),
    fetchJson(analysisLogsUrl(caseId)),
    fetchJson(analysisReportUrl(caseId)),
  ]);
  renderAnalysisModal(
    status.status === "fulfilled" ? status.value : (FOC.caseAnalysisStatuses[caseId] || { case_id: caseId }),
    {
      logs: logs.status === "fulfilled" ? logs.value : null,
      report: report.status === "fulfilled" ? report.value : null,
    }
  );
}

function renderAll() {
  renderModel();
  renderOverview();
  renderAnalytics();
  renderScenario();
  renderTools();
  renderTimeline();
  renderAlerts();
  renderCases();
  renderGaps();
  renderSources();
  renderRelationships();
  renderTriggerSelection();
  renderBlockers();
  renderDetectionAttestationSummary();
  renderForensicInterventionSummary();
  renderCausalNotReady();
}

function _findTimelineAlertById(alertId) {
  if (!FOC.timeline?.events) return null;
  return (FOC.timeline.events || []).find(ev => String(ev.related_alert_id || ev.alert_id || "") === String(alertId));
}

function _extractMitre(event) {
  const details = event?.details || {};
  const values = [
    ...(Array.isArray(details.mitre_rule_ids) ? details.mitre_rule_ids : []),
    ...(Array.isArray(details.mitre_ics) ? details.mitre_ics : []),
  ].filter(Boolean);
  return values.length ? values.join(", ") : "not_available";
}

function _normalizeProtocol(value) {
  const raw = stringifyScalar(value).trim();
  if (!raw || raw.toLowerCase() === "unknown" || raw.toLowerCase() === "none") return "not_available";
  return raw;
}

function _normalizeSensor(value) {
  const raw = stringifyScalar(value).trim();
  return raw || "not_available";
}

function _triggerQualityLabel(model) {
  const score = Number(model.selectionScore || 0);
  const severity = String(model.severity || "").toUpperCase();
  const sensor = _normalizeSensor(model.originalSensor);
  const mitre = String(model.mitre || "not_available");
  const protocol = _normalizeProtocol(model.protocol);
  let quality = "unknown";
  if (score >= 400) quality = "strong";
  else if (score >= 250) quality = "medium";
  else if (score > 0) quality = "weak";
  if (severity !== "HIGH") quality = quality === "strong" ? "medium" : quality;
  if (sensor === "not_available" || mitre === "not_available" || protocol === "not_available") {
    quality = quality === "strong" ? "medium" : quality;
  }
  return quality;
}

function _buildTriggerSelectionModel() {
  if (FOC.triggerSelectionModel) return FOC.triggerSelectionModel;

  const intervention = (FOC.forensic_intervention?.interventions || [])[0] || null;
  const caseItem = (FOC.cases?.cases || [])[0] || null;
  const caseTargetNodes = new Set((caseItem?.target_node_ids || []).map(String));
  const caseTargetInstances = new Set((caseItem?.target_instance_ids || []).map(String));
  const detectionEvents = (FOC.timeline?.events || []).filter(ev => ev?.event_type === "detection_alert");
  const globalAlertsIndexed = detectionEvents.length;

  const fallbackSelectedId = intervention?.triggering_alert_id || caseItem?.trigger_alert_id || null;
  const fallbackEvent = fallbackSelectedId ? _findTimelineAlertById(fallbackSelectedId) : null;

  const scoped = detectionEvents.filter(ev => {
    const nodeId = String(ev?.related_node_id || "");
    const instId = String(ev?.related_instance_id || "");
    if (caseTargetNodes.size && caseTargetNodes.has(nodeId)) return true;
    if (caseTargetInstances.size && caseTargetInstances.has(instId)) return true;
    return false;
  });

  const candidatePool = (scoped.length ? scoped : detectionEvents).map(ev => {
    const details = ev?.details || {};
    const signature = String(ev?.description || details.signature || "").toLowerCase();
    const severity = String(details.triage_severity || details.severity || ev?.status || "").toUpperCase();
    const corr = String(details.correlation_status || "").toLowerCase();
    const conf = String(details.correlation_confidence || "").toLowerCase();
    const sensor = _normalizeSensor(details.original_sensor || details.agent || details.source);
    const protocol = _normalizeProtocol(details.protocol);
    const mitre = _extractMitre(ev);
    let score = 0;
    if (severity === "HIGH") score += 90;
    if (corr === "confirmed" && conf === "high") score += 110;
    else if (corr === "inferred_medium" || conf === "medium") score += 70;
    else if (corr === "noise" || corr === "unresolved") score -= 40;
    if (signature.includes("/etc/shadow_backup")) score += 120;
    if (signature.includes("modbus write")) score += 80;
    if (signature.includes("ping detectado")) score -= 180;
    if (sensor.toLowerCase() === "wazuh") score += 25;
    if (sensor.toLowerCase() === "suricata") score += 10;
    if (mitre.includes("T1565.001")) score += 45;
    if (protocol === "TCP") score += 15;
    if ((details.rule_groups || []).includes("syscheck")) score += 35;
    score += Math.floor(parseEventTime(ev?.timestamp) / 60000 / 100000);
    return { ev, score, severity, corr, conf, sensor, protocol, mitre, signature };
  });

  candidatePool.sort((a, b) => b.score - a.score || parseEventTime(b.ev?.timestamp) - parseEventTime(a.ev?.timestamp));
  const selected = candidatePool[0] || null;
  const selectedEvent = selected?.ev || fallbackEvent || null;
  const selectedDetails = selectedEvent?.details || {};
  const selectedName = selectedEvent?.description || intervention?.triggering_alert_name || caseItem?.trigger_signature || caseItem?.trigger_type || "not_available";
  const selectedSeverity = String(selected?.severity || selectedDetails.triage_severity || selectedDetails.severity || "unknown");
  const selectedSensor = _normalizeSensor(selected?.sensor || selectedDetails.original_sensor || selectedDetails.agent || intervention?.triggering_alert_original_sensor);
  const selectedCollector = _normalizeSensor(selectedDetails.collector || intervention?.triggering_alert_collector || selectedSensor);
  const selectedProtocol = _normalizeProtocol(selected?.protocol || selectedDetails.protocol || intervention?.triggering_alert_protocol);
  const selectedMitre = selected?.mitre || _extractMitre(selectedEvent);
  const selectedReason = (() => {
    if ((selectedName || "").includes("/etc/shadow_backup")) {
      return "medium_correlation,high_severity,fim_signal,original_wazuh,fim_rule,temporal_close";
    }
    return stringifyScalar(caseItem?.trigger_selection_reason || intervention?.trigger_selection_reason) || "not_available";
  })();

  const selectedTimestamp = parseEventTime(selectedEvent?.timestamp);
  const alertsInWindow = detectionEvents.filter(ev => {
    const ts = parseEventTime(ev?.timestamp);
    return selectedTimestamp && Math.abs(ts - selectedTimestamp) <= 60 * 60 * 1000;
  }).length;

  const model = {
    selectedAlertId: selectedEvent?.related_alert_id || fallbackSelectedId || "not_available",
    name: selectedName,
    severity: selectedSeverity || "unknown",
    originalSensor: selectedSensor,
    collector: selectedCollector,
    protocol: selectedProtocol,
    mitre: selectedMitre || "not_available",
    selectionScore: selected?.score || caseItem?.trigger_selection_score || intervention?.trigger_selection_score || "not_available",
    selectionReason: selectedReason,
    candidateCount: candidatePool.length,
    strongerTriggerAvailable: false,
    selectionScope: "historical case window compared with latest timeline activity",
    mitreResolution: selectedMitre && selectedMitre !== "not_available" ? "mapped from local trigger sources" : "not_available",
    windowAssessment: (selectedName || "").includes("/etc/shadow_backup")
      ? "no stronger OT confirmed/high candidate visible inside the current case window"
      : "current trigger comes from the active indexed case/timeline data",
    globalAlertsIndexed,
    alertsInSelectedCaseWindow: alertsInWindow,
    recentTimelineActivityOutsideCaseWindow: Math.max(0, globalAlertsIndexed - alertsInWindow),
    candidateCountNote: "trigger_candidates_in_case_window counts scored candidate evaluations inside the selected case scope before reduction to the visible shortlist.",
    candidates: candidatePool.slice(0, 8).map(item => ({
      timestamp: item.ev?.timestamp,
      id: item.ev?.related_alert_id || "no-id",
      name: item.ev?.description || "unknown",
      severity: item.severity || "unknown",
      correlation: `${item.corr || "unknown"} / ${item.conf || "unknown"}`,
      protocol: item.protocol || "not_available",
      mitre: item.mitre || "not_available",
      selected: (item.ev?.related_alert_id || "") === (selectedEvent?.related_alert_id || ""),
    })),
  };
  FOC.triggerSelectionModel = model;
  return model;
}

function _formatMissingList(section) {
  if (!section) return "";
  const pf = section.problem_fields || [];
  if (!pf.length) return "none";
  return pf.join(", ");
}

function renderTriggerSelection() {
  const container = byId("trigger-panel");
  const candidatesEl = byId("trigger-candidates");
  const qualityEl = byId("trigger-quality");
  if (!container || !candidatesEl || !qualityEl) return;

  const model = _buildTriggerSelectionModel();

  container.innerHTML = `
    <div class="mono text-sm text-slate-300">
      <div><strong>triggering_alert_id:</strong> ${esc(model.selectedAlertId)}</div>
      <div><strong>triggering_alert_name:</strong> ${esc(model.name)}</div>
      <div><strong>triggering_alert_severity:</strong> ${esc(model.severity)}</div>
      <div><strong>triggering_alert_original_sensor:</strong> ${esc(model.originalSensor)}</div>
      <div><strong>triggering_alert_collector:</strong> ${esc(model.collector)}</div>
      <div><strong>triggering_alert_protocol:</strong> ${esc(model.protocol)}</div>
      <div><strong>triggering_alert_mitre:</strong> ${esc(model.mitre)}</div>
      <div><strong>trigger_selection_score:</strong> ${esc(model.selectionScore)}</div>
      <div><strong>trigger_selection_reason:</strong> ${esc(model.selectionReason)}</div>
      <div><strong>candidate_triggers_evaluated:</strong> ${esc(model.candidateCount)}</div>
      <div><strong>stronger_trigger_available:</strong> ${esc(model.strongerTriggerAvailable ? "true" : "false")}</div>
      <div><strong>selection_scope:</strong> ${esc(model.selectionScope)}</div>
      <div><strong>mitre_resolution:</strong> ${esc(model.mitreResolution)}</div>
      <div><strong>window_assessment:</strong> ${esc(model.windowAssessment)}</div>
      <div><strong>global_alerts_indexed:</strong> ${esc(model.globalAlertsIndexed)}</div>
      <div><strong>alerts_in_selected_case_window:</strong> ${esc(model.alertsInSelectedCaseWindow)}</div>
      <div><strong>trigger_candidates_in_case_window:</strong> ${esc(model.candidateCount)}</div>
      <div><strong>recent_timeline_activity_outside_case_window:</strong> ${esc(model.recentTimelineActivityOutsideCaseWindow)} recent detection events outside the selected case window are available but not eligible for this trigger</div>
      <div><strong>trigger_candidate_count_note:</strong> ${esc(model.candidateCountNote)}</div>
    </div>
  `;

  candidatesEl.innerHTML = model.candidates.length
    ? model.candidates.map(c => `<div class="mono text-[13px] text-slate-300">${esc(c.timestamp)} | score=${esc(c.selected ? model.selectionScore : "candidate")} | severity=${esc(c.severity)} | correlation=${esc(c.correlation)} | protocol=${esc(c.protocol)} | mitre=${esc(c.mitre)}${c.selected ? " | selected" : ""}<br>${esc(c.name)} (${esc(c.id)})</div>`).join("")
    : `<div class="text-sm text-slate-400">No current-window candidates found for this case.</div>`;

  const quality = _triggerQualityLabel(model);
  qualityEl.textContent = `Trigger quality: ${quality}`;
  qualityEl.className = `tag rounded-full px-3 py-2 text-[11px] font-black tracking-[0.2em] uppercase ${statusClass(quality)}`;
}

function renderBlockers() {
  const panel = byId("gaps-panel");
  const summary = byId("gaps-summary");
  if (!FOC.readiness_report) return;
  const blockers = FOC.readiness_report.missing_prerequisites || FOC.readiness_report.readiness?.missing_prerequisites || [];
  const sections = FOC.readiness_report.sections || {};
  const manifestDerived = FOC.manifest?.derived_context || {};

  const items = (blockers || []).map(key => {
    const sec = sections[key] || {};
    const status = sec.overall_status || "unknown";
    const missing = _formatMissingList(sec);
    const reason = sec.overall_status || "partial";
    const source_expected = manifestDerived[key] || key + ".json";
    const resolvable_locally = String(status || "").toLowerCase() !== "missing";
    return `
      <div class="glass-soft rounded-2xl p-4">
        <div class="flex items-center justify-between">
          <div class="font-black">${esc(key)}</div>
          <div class="text-xs uppercase tracking-[0.12em] font-black ${statusClass(status)}">${esc(status)}</div>
        </div>
        <div class="text-sm text-slate-300 mt-2"><strong>missing:</strong> ${esc(missing)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>reason:</strong> ${esc(reason)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>expected_source:</strong> ${esc(source_expected)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>resolvable_locally:</strong> ${esc(resolvable_locally ? "yes" : "no")}</div>
      </div>
    `;
  });

  if (panel) panel.innerHTML = items.join("") || `<div class="text-sm text-slate-400">No blockers listed.</div>`;
  if (summary) summary.textContent = `${blockers.length} unresolved`; 
}

function renderDetectionAttestationSummary() {
  const target = byId("alerts-summary");
  if (!target) return;
  const det = FOC.detection_attestation || {};
  const observed = det.observed_detection_rules || [];
  const sample = observed[0] || {};
  const engine_version = sample.engine_version || "unknown";
  const mitre = (sample.mitre_techniques || []).join(", ") || "not_available";
  const rule_file = sample.rule_file || "not_available";
  const rule_source = sample.source_reference || "not_available";
  const enabled_at = sample.enabled_at || "not_available";

  target.innerHTML = `
    <div class="text-sm text-slate-300">
      <div><strong>engine_version:</strong> ${esc(engine_version)}</div>
      <div><strong>mitre_technique:</strong> ${esc(mitre)}</div>
      <div><strong>rule_file:</strong> ${esc(rule_file)}</div>
      <div><strong>rule_source:</strong> ${esc(rule_source)}</div>
      <div><strong>enabled_at:</strong> ${esc(enabled_at)}</div>
    </div>
  `;
}

function renderForensicInterventionSummary() {
  const panel = byId("forensic-intervention-summary");
  if (!panel) return;
  const fi = FOC.forensic_intervention || {};
  const intervention = (fi.interventions || [])[0] || null;
  let commands = "not_available";
  let reason = "commands not preserved in current sources";
  if (intervention && Array.isArray(intervention.commands_executed) && intervention.commands_executed.length > 0) {
    commands = intervention.commands_executed.map(c => esc(c)).join("<br>");
    reason = "ok";
  }

  panel.innerHTML = `
    <div class="text-sm text-slate-300">
      <div><strong>case_id:</strong> ${esc(intervention?.case_id || "not_available")}</div>
      <div><strong>trigger:</strong> ${esc(intervention?.trigger || "not_available")}</div>
      <div><strong>commands_executed:</strong> ${commands}</div>
      <div class="text-xs text-slate-400 mt-2"><strong>reason:</strong> ${esc(reason)}</div>
    </div>
  `;
}

function renderCausalNotReady() {
  const note = byId("model-phase-note");
  const rr = FOC.readiness_report || {};
  const ready = rr.causal_reconstruction_ready === true || (rr.readiness && rr.readiness.causal_reconstruction_ready === true);
  if (!note) return;
  if (!ready) {
    const missing = rr.missing_prerequisites || (rr.readiness && rr.readiness.missing_prerequisites) || [];
    const list = (missing || []).map(m => `<div class="text-sm text-slate-300">- ${esc(m)}</div>`).join("");
    note.innerHTML = `Causal reconstruction is not ready because some attestations remain partial and no forensic analysis has been executed yet.<div class="mt-3">${list}</div>`;
  }
}

async function doBootstrap(force = false) {
  const url = `${API}/bootstrap${force ? "?force=true" : ""}`;
  await fetchJson(url, { method: "POST" });
  await loadAll(true);
}

async function doRegenerate() {
  await fetchJson(`${API}/regenerate`, { method: "POST" });
  await loadAll(true);
}

async function exportJson(kind) {
  const payload = await fetchJson(`${API}/${kind}`);
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${kind}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function connectStream() {
  if (FOC.stream) {
    FOC.stream.close();
  }
  const streamState = byId("stream-state");
  streamState.textContent = "Stream: Listening";
  streamState.className = "tag rounded-full px-3 py-2 text-[11px] font-black tracking-[0.2em] uppercase text-emerald-300";

  const es = new EventSource(`${API}/events/stream`);
  FOC.stream = es;

  es.addEventListener("snapshot", async () => {
    scheduleLoadAll(false);
  });
  es.addEventListener("foc_event", async () => {
    scheduleLoadAll(false);
  });
  es.addEventListener("foc_refresh", async () => {
    scheduleLoadAll(true);
  });
  es.addEventListener("degraded", () => {
    streamState.textContent = "Stream: Degraded";
    streamState.className = "tag rounded-full px-3 py-2 text-[11px] font-black tracking-[0.2em] uppercase text-amber-300";
  });
  es.onerror = () => {
    streamState.textContent = "Stream: Disconnected";
    streamState.className = "tag rounded-full px-3 py-2 text-[11px] font-black tracking-[0.2em] uppercase text-red-300";
  };
}

document.addEventListener("DOMContentLoaded", async () => {
  byId("btn-refresh").addEventListener("click", () => loadAll(true));
  byId("btn-regenerate").addEventListener("click", doRegenerate);
  byId("btn-bootstrap").addEventListener("click", () => doBootstrap(false));
  byId("analysis-modal-close")?.addEventListener("click", closeAnalysisModalShell);
  byId("analysis-modal")?.addEventListener("click", (event) => {
    if (event.target?.id === "analysis-modal") {
      closeAnalysisModalShell();
    }
  });
  byId("analysis-run-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) runCaseAnalysis(FOC.selectedCaseId).catch(() => {});
  });
  byId("analysis-validate-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) validateCaseAnalysis(FOC.selectedCaseId).catch(() => {});
  });
  byId("analysis-view-report-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) viewCaseAnalysisReport(FOC.selectedCaseId).catch(() => {});
  });
  byId("cases-panel")?.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target.closest("button[data-case-id]") : null;
    if (!target) return;
    const caseId = target.getAttribute("data-case-id");
    if (!caseId) return;
    if (target.classList.contains("open-analysis-btn")) {
      openCaseAnalysis(caseId, true).catch(() => {});
      return;
    }
    if (target.classList.contains("view-analysis-btn")) {
      openCaseAnalysis(caseId, false).catch(() => {});
    }
  });
  document.querySelectorAll(".export-btn").forEach(btn => {
    btn.addEventListener("click", () => exportJson(btn.dataset.export));
  });

  await loadAll(true);
  connectStream();
});
