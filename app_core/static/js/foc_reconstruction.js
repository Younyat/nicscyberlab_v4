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
};

const API = "/api/foc";

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

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function statusClass(status) {
  const normalized = String(status || "").toLowerCase().replace(/\s+/g, "_");
  if (["confirmed", "complete", "valid", "active", "bound", "present", "available", "completed"].includes(normalized)) return "status-confirmed";
  if (["inferred", "partial", "bootstrap", "updated", "warning", "warnings", "mostly_available"].includes(normalized)) return "status-inferred";
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

async function loadAll() {
  const loaders = await Promise.allSettled([
    fetchJson(`${API}/status`),
    fetchJson(`${API}/manifest`).catch(() => null),
    fetchJson(`${API}/scenario-bom`).catch(() => null),
    fetchJson(`${API}/tools-bom`).catch(() => null),
    fetchJson(`${API}/timeline`).catch(() => null),
    fetchJson(`${API}/gaps`).catch(() => null),
    fetchJson(`${API}/sources`).catch(() => null),
    fetchJson(`${API}/relationships`).catch(() => null),
    fetchJson(`${API}/artifacts`).catch(() => null),
    fetchJson(`${API}/cases`).catch(() => null),
  ]);

  [
    FOC.status,
    FOC.manifest,
    FOC.scenario,
    FOC.tools,
    FOC.timeline,
    FOC.gaps,
    FOC.sources,
    FOC.relationships,
    FOC.artifacts,
    FOC.cases,
  ] = loaders.map(item => item.status === "fulfilled" ? item.value : null);

  renderAll();
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
    const key = sourceLabel(ev.details?.source || ev.source_type || "Unknown");
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

  summary.textContent = `${total} alerts | ${data.length} detection sources`;
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
    host.innerHTML = `<div class="text-sm text-slate-400">No causal relationship graph available.</div>`;
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
  const casesHtml = cases.map(entry => {
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
        <div class="mt-3">${caseArtifacts.map(a => `<div class="mono text-xs text-slate-400">${esc(a.artifact_type)} → ${esc(a.artifact_id)}</div>`).join("")}</div>
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
}

async function doBootstrap(force = false) {
  const url = `${API}/bootstrap${force ? "?force=true" : ""}`;
  await fetchJson(url, { method: "POST" });
  await loadAll();
}

async function doRegenerate() {
  await fetchJson(`${API}/regenerate`, { method: "POST" });
  await loadAll();
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
    await loadAll();
  });
  es.addEventListener("foc_event", async () => {
    await loadAll();
  });
  es.addEventListener("foc_refresh", async () => {
    await loadAll();
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
  byId("btn-refresh").addEventListener("click", loadAll);
  byId("btn-regenerate").addEventListener("click", doRegenerate);
  byId("btn-bootstrap").addEventListener("click", () => doBootstrap(false));
  document.querySelectorAll(".export-btn").forEach(btn => {
    btn.addEventListener("click", () => exportJson(btn.dataset.export));
  });

  await loadAll();
  connectStream();
});
