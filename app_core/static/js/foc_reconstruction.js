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
  attack_attestation: null,
  detection_attestation: null,
  forensic_intervention: null,
  case_manifest_link: null,
  alert_correlation_summary: null,
  readiness_report: null,
  stream: null,
  loadTimer: null,
  loadInFlight: false,
  pendingReload: false,
  firstLoadCompleted: false,
  triggerSelectionModel: null,
  caseAnalysisStatuses: {},
  selectedCaseId: null,
  analysisPollTimer: null,
  causalPollTimer: null,
  timeSyncPollTimer: null,
  analysisVisualState: {
    selectedNodeId: "case",
    timelineMode: "pipeline",
    showRaw: false,
    reportRequested: false,
    currentCaseEntryName: null,
  },
  causalVisualState: {
    currentCaseId: null,
    currentStatus: null,
    cachedUncertainty: null,
    cachedGraphSummary: null,
    cachedMarkdown: null,
    expandedDetails: {},
  },
  timeSyncVisualState: {
    currentCaseId: null,
    currentStatus: null,
  },
  graphState: {
    layers: {
      topology: true,
      attack: true,
      detection: true,
      attack_alert: true,
      evidence: true,
      custody: true,
      analysis: true,
      timeline: false,
      findings: false,
      semantic: false,
      causal: false,
    },
    filters: {
      node: "all",
      severity: "all",
      mitre: "all",
      sensor: "all",
      confirmedOnly: false,
      hideNoise: true,
      evidenceLinkedOnly: true,
      correlationFocus: "all",
    },
    selected: null,
    cacheKey: "",
    aggregate: null,
    activeQuestionId: null,
  },
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

function analysisVisualUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/analysis/visual-summary`;
}

function timeSyncStatusUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/time-sync/status`;
}

function timeSyncRunUrl(caseId) {
  return `${API}/cases/${encodeURIComponent(caseId)}/time-sync/run`;
}

function causalStatusUrl(caseId) {
  return `${API}/causal/status?case_id=${encodeURIComponent(caseId)}`;
}

function causalRunUrl() {
  return `${API}/causal/run`;
}

function causalReportUrl(caseId) {
  return `${API}/causal/report?case_id=${encodeURIComponent(caseId)}`;
}

function causalUncertaintyUrl(caseId) {
  return `${API}/causal/uncertainty?case_id=${encodeURIComponent(caseId)}`;
}

function causalGraphSummaryUrl(caseId) {
  return `${API}/causal/graph-summary?case_id=${encodeURIComponent(caseId)}`;
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
  if (["completed_with_degradation", "partial", "limited", "degraded", "ambiguous", "ready_to_run", "weak_reconstruction", "weak"].includes(normalized)) return "status-inferred";
  if (["blocked_missing_ground_truth", "blocked_missing_analysis", "blocked", "invalid"].includes(normalized)) return "status-missing";
  if (["confirmed", "complete", "valid", "active", "bound", "present", "available", "completed", "strong", "recovered", "supported", "synchronized"].includes(normalized)) return "status-confirmed";
  if (["inferred", "partial", "bootstrap", "updated", "warning", "warnings", "mostly_available", "mostly_noise", "mostly_completed", "constrained", "limited"].includes(normalized)) return "status-inferred";
  if (["missing", "critical", "insufficient", "unresolved", "error", "bootstrap_required", "failed", "not_synchronized"].includes(normalized)) return "status-missing";
  if (["unknown", "not_available", "degraded", "not_completed", "not_generated", "not_started"].includes(normalized)) return "status-unknown";
  if (["not_generated_yet"].includes(normalized)) return "status-updated";
  return "status-updated";
}

function visualStateClass(state) {
  const normalized = String(state || "").toLowerCase();
  if (normalized === "success") return "status-confirmed";
  if (normalized === "warning") return "status-inferred";
  if (normalized === "error") return "status-missing";
  if (normalized === "running") return "status-updated";
  if (normalized === "pending") return "status-unknown";
  if (normalized === "unavailable") return "status-unknown";
  return "status-unknown";
}

function titleizeStatus(value) {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, ch => ch.toUpperCase());
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
  const cases = FOC.cases?.cases || [];
  const caseCount = cases.length;
  const custodyCount = artifactCount("custody_log");
  const analysisCount = artifactCount(["vol3_output_dir", "tsk_output_dir"]);
  const indexedAnalysisOutputs = Number(status?.artifact_summary?.analysis_outputs || 0);
  const analysisComponentScore = Number(status?.components?.analysis_outputs || 0);
  const analyzedCases = cases.filter((entry) => {
    const normalized = String(entry?.analysis_status || "").toLowerCase();
    return ["completed", "partial"].includes(normalized);
  }).length;
  const analysisAvailable = analysisCount > 0 || indexedAnalysisOutputs > 0 || analysisComponentScore > 0 || analyzedCases > 0;
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
    status: analysisAvailable ? (evidenceAnalysisLinks > 0 || analysisComponentScore > 0 ? "available" : "partial") : "not completed",
    evidence: analysisAvailable ? "Case analysis outputs, visual summaries, and preserved-case forensic analysis artifacts" : "none",
    next: analysisAvailable ? (evidenceAnalysisLinks > 0 || analysisComponentScore > 0 ? "none" : "link analysis outputs to evidence and cases") : "run memory or disk analysis",
    detail: analysisAvailable
      ? `${indexedAnalysisOutputs || analysisCount || "Some"} forensic analysis outputs indexed across ${analyzedCases || 1} analyzed case(s).`
      : "No forensic analysis has been executed yet.",
  });

  rows.push({
    component: "Semantic Observation Report",
    meaning: "The high-level interpretation of what occurred across the scenario, detections, evidence, and analysis results.",
    status: analysisAvailable ? "unresolved" : "not generated",
    evidence: "none",
    next: analysisAvailable ? "produce a higher-level interpretation report from analysis outputs" : "generate after forensic analysis is available",
    detail: analysisAvailable ? "Analysis outputs exist, but no semantic observation report is indexed yet." : "No semantic interpretation is expected before forensic analysis exists.",
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

function analysisAvailableGlobal() {
  const components = FOC.status?.components || {};
  const artifactSummary = FOC.status?.artifact_summary || {};
  const indexedCases = FOC.cases?.cases || [];
  const liveStatuses = Object.values(FOC.caseAnalysisStatuses || {});
  const completedStates = new Set(["completed", "partial", "completed_with_degradation"]);
  return Number(components.analysis_outputs || 0) > 0
    || Number(artifactSummary.analysis_outputs || 0) > 0
    || indexedCases.some(entry => completedStates.has(String(entry.analysis_status || "").toLowerCase()))
    || liveStatuses.some(entry => completedStates.has(String(entry.status || "").toLowerCase()));
}

function semanticAvailableGlobal() {
  const semantic = String(FOC.status?.maturity?.semantic || "").toLowerCase();
  return ["available", "complete", "completed", "present", "generated"].includes(semantic);
}

function causalReadyGlobal() {
  const rr = FOC.readiness_report || {};
  return rr.causal_reconstruction_ready === true || rr.readiness?.causal_reconstruction_ready === true;
}

function scientificConclusionReadiness() {
  if (!analysisAvailableGlobal()) return "not_ready";
  if (!causalReadyGlobal() && !semanticAvailableGlobal()) return "partial";
  if (!causalReadyGlobal()) return "limited";
  if (!semanticAvailableGlobal()) return "partial";
  return "strong";
}

function _readinessSection(key) {
  return (FOC.readiness_report?.sections || {})[key] || {};
}

function _blockerActionMeta(key) {
  const mapping = {
    attack_attestation: {
      label: "Attack attestation remains partial",
      requiredArtifact: "attack_attestation.json",
      recommendedAction: "Refresh attack attestation from preserved attack results and then regenerate reconstruction.",
      backendAction: "POST /api/foc/regenerate",
    },
    detection_attestation: {
      label: "Detection attestation remains partial",
      requiredArtifact: "detection_attestation.json",
      recommendedAction: "Rebuild detection attestation from alerts, triage and timeline correlation sources.",
      backendAction: "POST /api/foc/regenerate",
    },
    alerts_normalized: {
      label: "Normalized alert context remains incomplete",
      requiredArtifact: "alerts_normalized.json",
      recommendedAction: "Regenerate normalized alert context before causal replay.",
      backendAction: "POST /api/foc/regenerate",
    },
    alert_correlation: {
      label: "Attack-to-alert correlation remains weak",
      requiredArtifact: "alert_correlation_summary.json",
      recommendedAction: "Rebuild alert correlation so the trigger and attack path are explicitly linked.",
      backendAction: "POST /api/foc/regenerate",
    },
    forensic_intervention: {
      label: "Forensic intervention linkage remains partial",
      requiredArtifact: "forensic_intervention.json",
      recommendedAction: "Regenerate intervention context so the selected trigger, acquisition action and case creation are explicitly connected.",
      backendAction: "POST /api/foc/regenerate",
    },
    case_manifest_link: {
      label: "Alert-to-evidence linkage remains weak",
      requiredArtifact: "case_manifest_link.json",
      recommendedAction: "Rebuild the case-manifest linkage so triggering alert -> forensic intervention -> case -> manifest -> custody is explicit.",
      backendAction: "POST /api/foc/regenerate",
    },
    semantic_observation_report: {
      label: "Semantic observation report is missing",
      requiredArtifact: "semantic_observation_report.json",
      recommendedAction: "Generate a higher-level semantic observation report from scenario, attack, detection, evidence and analysis outputs before causal interpretation.",
      backendAction: "POST /api/foc/regenerate, then POST /api/foc/causal/run",
    },
  };
  return mapping[key] || {
    label: key.replaceAll("_", " "),
    requiredArtifact: `${key}.json`,
    recommendedAction: "Regenerate reconstruction context and then rerun the blocked causal stage.",
    backendAction: "POST /api/foc/regenerate",
  };
}

function _blockerCurrentEvidence(key) {
  if (key === "attack_attestation") {
    const executions = FOC.attack_attestation?.attested_executions || [];
    return executions.length
      ? `${executions.length} attested execution(s) indexed, but command-exit status or process-effect evidence remains partial.`
      : "No attested attack execution is currently indexed.";
  }
  if (key === "detection_attestation") {
    const det = FOC.detection_attestation || {};
    const resolved = det.resolved_alerts || 0;
    const confirmed = det.confirmed_attack_correlation || 0;
    return resolved || confirmed
      ? `${resolved} resolved alert(s) and ${confirmed} confirmed attack-correlation alert(s) are indexed, but the attestation quality remains partial.`
      : "No strong detection attestation evidence is currently indexed.";
  }
  if (key === "alerts_normalized") {
    const total = FOC.alert_correlation_summary?.total_alerts || 0;
    return total ? `${total} alert record(s) are indexed, but normalized causal inputs remain incomplete.` : "No normalized alert context is currently indexed.";
  }
  if (key === "alert_correlation") {
    const summary = FOC.alert_correlation_summary || {};
    return summary.confirmed_correlations
      ? `${summary.confirmed_correlations} confirmed correlation(s) across ${summary.unique_confirmed_attack_pairs || 0} unique attack pair(s) are available, but causal precision remains weak.`
      : "No confirmed attack-alert correlation is currently indexed.";
  }
  if (key === "forensic_intervention") {
    const intervention = (FOC.forensic_intervention?.interventions || [])[0] || {};
    return intervention.case_id
      ? `Generated case ${intervention.case_id} exists, but trigger-to-intervention linkage remains partial.`
      : "No generated forensic intervention case is currently linked.";
  }
  if (key === "case_manifest_link") {
    const link = FOC.case_manifest_link || {};
    return link.case_id
      ? `${link.linked_artifacts || 0} linked artifact(s) and ${link.custody_entries || 0} custody entr${(link.custody_entries || 0) === 1 ? "y" : "ies"} are indexed for ${link.case_id}.`
      : "No explicit case-manifest linkage is currently indexed.";
  }
  if (key === "semantic_observation_report") {
    return analysisAvailableGlobal()
      ? "Forensic analysis outputs are available, but no semantic observation layer is indexed yet."
      : "Forensic analysis outputs are still missing, so semantic interpretation cannot start.";
  }
  return "Current evidence is partial or unresolved for this prerequisite.";
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
    const [casesRes, readinessRes, detectionRes, interventionRes, attackAttRes, caseLinkRes, correlationRes] = await Promise.allSettled([
      fetchJson(`${API}/cases`),
      fetchJson(`${API}/readiness-report`),
      fetchJson(`${API}/detection-attestation`),
      fetchJson(`${API}/forensic-intervention`),
      fetchJson(`${API}/attack-attestation`),
      fetchJson(`${API}/case-manifest-link`),
      fetchJson(`${API}/alert-correlation-summary`),
    ]);
    FOC.cases = casesRes.status === "fulfilled" ? casesRes.value : FOC.cases;
    FOC.readiness_report = readinessRes.status === "fulfilled" ? readinessRes.value : null;
    FOC.detection_attestation = detectionRes.status === "fulfilled" ? detectionRes.value : null;
    FOC.forensic_intervention = interventionRes.status === "fulfilled" ? interventionRes.value : null;
    FOC.attack_attestation = attackAttRes.status === "fulfilled" ? attackAttRes.value : null;
    FOC.case_manifest_link = caseLinkRes.status === "fulfilled" ? caseLinkRes.value : null;
    FOC.alert_correlation_summary = correlationRes.status === "fulfilled" ? correlationRes.value : null;
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
  const scientificReadiness = scientificConclusionReadiness();
  const causalReadiness = causalReadyGlobal() ? "ready" : "blocked";
  const semanticReadiness = semanticAvailableGlobal() ? "available" : "not generated";
  byId("ov-status").className = `text-2xl font-black mt-3 ${statusClass(status.status)}`;
  byId("ov-status").textContent = status.status || "not_initialized";
  byId("ov-completeness").textContent = `Structural/evidential readiness: ${status.completeness || "unknown"}`;
  byId("ov-scenario-id").textContent = status.scenario_id || "unknown";
  byId("ov-scenario-name").textContent = status.scenario_name || "unknown";
  byId("ov-score").textContent = String(status.reproducibility_score ?? 0);
  byId("ov-updated").textContent = `Updated: ${status.last_update || "unknown"}`;
  byId("score-bar").style.width = `${Math.max(0, Math.min(100, Number(status.reproducibility_score || 0)))}%`;
  byId("ov-score-note").textContent = "This score measures availability and consistency of FOC structural, evidential, custody and analysis components. It does not by itself prove causal reconstruction completeness.";
  byId("scientific-state-note").innerHTML = `
    <div class="font-black">The FOC structural and evidential layers are available, but causal reconstruction is not yet complete.</div>
    <div class="mt-2">A high FOC readiness score does not mean that the causal explanation is fully reconstructable.</div>
    <div class="mt-3 flex flex-wrap gap-2">
      ${tag("FOC structural/evidential readiness", status.status || "unknown", statusClass(status.status))}
      ${tag("Causal reconstruction readiness", causalReadiness, statusClass(causalReadiness))}
      ${tag("Semantic interpretation", semanticReadiness, statusClass(semanticReadiness))}
      ${tag("Scientific conclusion readiness", scientificReadiness, statusClass(scientificReadiness))}
    </div>
  `;

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
    tag("Causal readiness", causalReadiness, statusClass(causalReadiness)),
    tag("Scientific confidence", scientificReadiness, statusClass(scientificReadiness)),
  ].join("");
}

function renderModel() {
  const rows = buildModelRows();
  const maturity = buildMaturityStates(rows);
  const analysisAvailable = analysisAvailableGlobal();
  const causalReady = causalReadyGlobal();
  const semanticAvailable = semanticAvailableGlobal();

  byId("maturity-summary").innerHTML = [
    tag("Structural reconstruction", maturity.structural, statusClass(maturity.structural)),
    tag("Operational reconstruction", maturity.operational, statusClass(maturity.operational)),
    tag("Evidential reconstruction", maturity.evidential, statusClass(maturity.evidential)),
    tag("Forensic reconstruction", maturity.forensic, statusClass(maturity.forensic)),
    tag("Semantic reconstruction", maturity.semantic, statusClass(maturity.semantic)),
  ].join("");

  if (!analysisAvailable) {
    byId("model-phase-note").innerHTML = "No forensic acquisition or preserved-case analysis has been indexed yet. These sections will become stronger after network, memory, disk, or industrial evidence is acquired, preserved and analyzed.";
  } else if (!causalReady) {
    byId("model-phase-note").innerHTML = "Forensic analysis outputs are available, but causal reconstruction remains blocked because some causal, semantic, or attestation requirements are still partial or unresolved.";
  } else if (!semanticAvailable) {
    byId("model-phase-note").innerHTML = "Structural, evidential and forensic layers are available, but the semantic interpretation layer is still missing or not indexed yet.";
  } else {
    byId("model-phase-note").innerHTML = "The reconstruction model contains a mixture of available, partial, unresolved, or pending phases. Use the status column and the next-step guidance to improve reproducibility.";
  }

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
  const detectionSummary = FOC.status?.detection_summary || {};
  const events = FOC.timeline?.events || [];
  const timelineDetectionAlerts = events.filter(ev => ev.event_type === "detection_alert").length;
  const timelineAttacks = events.filter(ev => ev.event_type === "attack_execution").length;
  const timelineTriage = events.filter(ev => ev.event_type === "triage_result").length;
  const detectionAlerts = timelineDetectionAlerts || detectionSummary.alerts_total || 0;
  const attacks = timelineAttacks || detectionSummary.attack_events || 0;
  const triage = timelineTriage || detectionSummary.triage_total || 0;
  const cases = (FOC.cases?.cases || []).length;
  const evidence = artifactSummary.preserved_evidence || 0;
  let mitreCount = new Set(
    events
      .filter(ev => ev.event_type === "attack_execution")
      .map(ev => ev.details?.mitre_id)
      .filter(Boolean)
  ).size;
  if (!mitreCount) {
    const attacksPayload = FOC.attack_attestation?.attacks || [];
    mitreCount = new Set(
      attacksPayload
        .map(item => item?.mitre?.technique_id)
        .filter(Boolean)
    ).size;
  }

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

const GRAPH_LAYER_META = {
  topology: { label: "Topology", color: "#94a3b8" },
  attack: { label: "Attack", color: "#ef4444" },
  detection: { label: "Detection", color: "#f59e0b" },
  attack_alert: { label: "Attack→Alert", color: "#f97316" },
  evidence: { label: "Evidence", color: "#22d3ee" },
  custody: { label: "Custody", color: "#22c55e" },
  analysis: { label: "Analysis", color: "#a855f7" },
  timeline: { label: "Timeline", color: "#64748b" },
  findings: { label: "Findings", color: "#8b5cf6" },
  semantic: { label: "Semantic", color: "#8b5cf6" },
  causal: { label: "Causal", color: "#7c3aed" },
};

const DEFAULT_GRAPH_VIEW = {
  layers: {
    topology: true,
    attack: true,
    detection: true,
    attack_alert: true,
    evidence: true,
    custody: true,
    analysis: true,
    timeline: false,
    findings: false,
    semantic: false,
    causal: false,
  },
  filters: {
    node: "all",
    severity: "all",
    mitre: "all",
    sensor: "all",
    confirmedOnly: false,
    hideNoise: true,
    evidenceLinkedOnly: true,
    correlationFocus: "all",
  },
};

const CUSTOM_GRAPH_VIEW_KEY = "nics_foc_graph_custom_view";

const INVESTIGATION_QUESTIONS = [
  {
    id: "affected_assets",
    title: "What systems were affected?",
    purpose: "Identify the incident scope before entering forensic detail.",
    preset: {
      layers: { topology: true, attack: true, detection: false, attack_alert: false, evidence: false, custody: false, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: true, evidenceLinkedOnly: false, correlationFocus: "all" },
    },
    answer: "The graph shows the affected assets and their high-level attack footprint first, without distracting detection or evidential detail.",
    evidenceBasis: "Scenario structure plus indexed attack aggregates by target node.",
    practicalConclusion: "The analyst can identify the incident scope quickly.",
    limitations: "This view does not prove which detections or artifacts support each asset yet.",
  },
  {
    id: "attacks_by_asset",
    title: "Which attacks targeted each asset?",
    purpose: "Understand offensive activity by target without alert volume.",
    preset: {
      layers: { topology: true, attack: true, detection: false, attack_alert: false, evidence: false, custody: false, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: true, evidenceLinkedOnly: false, correlationFocus: "all" },
    },
    answer: "The graph groups attack executions by target node and MITRE technique so offensive activity can be reviewed asset by asset.",
    evidenceBasis: "Attack attestation aggregates with target-node resolution.",
    practicalConclusion: "The analyst can compare which assets were probed or manipulated.",
    limitations: "Execution status and aggregate counts do not alone prove monitoring coverage.",
  },
  {
    id: "detections_by_target",
    title: "Which detections were generated for each target?",
    purpose: "Review the monitoring surface per target and per sensor.",
    preset: {
      layers: { topology: true, attack: true, detection: true, attack_alert: false, evidence: false, custody: false, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "HIGH", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: true, evidenceLinkedOnly: false, correlationFocus: "all" },
    },
    answer: "The graph shows aggregated detection groups by target, highlighting dominant severity and original sensor versus collector.",
    evidenceBasis: "Detection attestation and indexed alert summaries.",
    practicalConclusion: "The analyst can see whether the monitoring layer observed the activity and which detection source contributed.",
    limitations: "This view is about observation, not direct proof of attack-to-alert linkage.",
  },
  {
    id: "confirmed_attack_alert",
    title: "Which alerts are clearly linked to attack activity?",
    purpose: "Focus on primary alert evidence only.",
    preset: {
      layers: { topology: false, attack: true, detection: true, attack_alert: true, evidence: true, custody: false, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: true, hideNoise: true, evidenceLinkedOnly: true, correlationFocus: "confirmed" },
    },
    answer: "The graph shows only confirmed attack-to-alert correlation groups and hides low-value noise.",
    evidenceBasis: "Attack outputs, indexed detections and evidence-linked correlation summaries already present in FOC.",
    practicalConclusion: "These alerts are the strongest alert evidence for the reconstructed scenario.",
    limitations: "Confirmed correlation is not the same as full causality. It still reflects correlation backed by indexed evidence.",
  },
  {
    id: "uncertain_alerts",
    title: "Which alerts are still uncertain and require analyst review?",
    purpose: "Separate verified evidence from uncertain correlation.",
    preset: {
      layers: { topology: false, attack: false, detection: true, attack_alert: true, evidence: false, custody: false, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: false, evidenceLinkedOnly: false, correlationFocus: "uncertain" },
    },
    answer: "The graph highlights inferred and unresolved correlation groups that still require analyst review.",
    evidenceBasis: "Detection-summary correlation classes derived from indexed alerts.",
    practicalConclusion: "The analyst can avoid presenting unresolved alert groups as proven facts.",
    limitations: "Uncertain alerts may still become relevant after deeper artifact review.",
  },
  {
    id: "noise_alerts",
    title: "Which alerts are probably noise?",
    purpose: "Justify which detections are excluded from the main reconstruction.",
    preset: {
      layers: { topology: false, attack: false, detection: true, attack_alert: true, evidence: false, custody: false, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: false, evidenceLinkedOnly: false, correlationFocus: "noise" },
    },
    answer: "The graph isolates low-value or non-actionable alert groups classified as noise.",
    evidenceBasis: "FOC correlation summary and detection aggregates.",
    practicalConclusion: "The analyst can justify why these alerts are excluded from the primary forensic path.",
    limitations: "Noise does not necessarily mean false; it means low value for the main reconstruction.",
  },
  {
    id: "supporting_evidence",
    title: "What evidence supports the reconstruction?",
    purpose: "Show the preserved artifacts supporting the scenario.",
    preset: {
      layers: { topology: false, attack: false, detection: false, attack_alert: false, evidence: true, custody: true, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: true, evidenceLinkedOnly: true, correlationFocus: "all" },
    },
    answer: "The graph shows the forensic case and grouped preserved evidence supporting the reconstruction.",
    evidenceBasis: "Artifacts index, case manifests and evidence grouping already indexed by FOC.",
    practicalConclusion: "The analyst can identify which preserved artifacts back the reconstruction.",
    limitations: "This view does not inspect individual artifacts unless you drill down.",
  },
  {
    id: "custody_complete",
    title: "Is the chain of custody complete?",
    purpose: "Assess whether preserved artifacts satisfy custody checks.",
    preset: {
      layers: { topology: false, attack: false, detection: false, attack_alert: false, evidence: true, custody: true, analysis: false, timeline: false, findings: false, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: true, evidenceLinkedOnly: true, correlationFocus: "all" },
    },
    answer: "The graph emphasizes custody verification as an aggregated state over the preserved case set.",
    evidenceBasis: "Indexed manifests, custody logs and evidence/custody completeness score.",
    practicalConclusion: "The analyst can decide whether preserved artifacts satisfy platform custody checks.",
    limitations: "This remains an aggregated custody view, not a per-artifact legal review.",
  },
  {
    id: "analysis_complete",
    title: "Is the forensic analysis complete?",
    purpose: "Check whether analytical outputs exist and support reporting.",
    preset: {
      layers: { topology: false, attack: false, detection: false, attack_alert: false, evidence: true, custody: true, analysis: true, timeline: false, findings: true, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: false, hideNoise: true, evidenceLinkedOnly: true, correlationFocus: "all" },
    },
    answer: "The graph shows whether indexed forensic analysis outputs exist and whether findings are available at aggregate level.",
    evidenceBasis: "Analysis outputs component, case status and indexed findings layers.",
    practicalConclusion: "The analyst can judge whether the case is ready for reporting or still needs more analysis.",
    limitations: "Analysis availability does not automatically unlock semantic or causal reconstruction.",
  },
  {
    id: "full_story",
    title: "What happened in the full forensic story?",
    purpose: "Show the end-to-end reconstructed scenario path.",
    preset: {
      layers: { topology: true, attack: true, detection: true, attack_alert: true, evidence: true, custody: true, analysis: true, timeline: false, findings: true, semantic: false, causal: false },
      filters: { node: "all", severity: "all", mitre: "all", sensor: "all", confirmedOnly: true, hideNoise: true, evidenceLinkedOnly: true, correlationFocus: "confirmed" },
    },
    answer: "The graph shows the complete path from affected assets to attacks, detections, confirmed alert correlation, evidence preservation, custody and analysis.",
    evidenceBasis: "Scenario BOM, attack attestation, detection aggregates, evidence groups, custody state and analysis outputs already indexed by FOC.",
    practicalConclusion: "The analyst gets a defensible end-to-end reconstruction snapshot.",
    limitations: "This still represents correlation and evidential support, not full causality unless explicitly generated later.",
  },
];

function graphLayerAvailable(layer) {
  if (layer === "semantic") {
    return String(FOC.status?.maturity?.semantic || "unknown").toLowerCase() !== "not_generated";
  }
  if (layer === "causal") {
    return FOC.readiness_report?.causal_reconstruction_ready === true;
  }
  if (layer === "analysis") {
    return Number(FOC.status?.components?.analysis_outputs || 0) > 0 || (FOC.cases?.cases || []).some(entry => String(entry.analysis_status || "").toLowerCase() === "completed");
  }
  if (layer === "findings") {
    return Number(FOC.status?.components?.analysis_outputs || 0) > 0;
  }
  if (layer === "timeline") {
    return Number(FOC.status?.components?.timeline || 0) > 0 || Number((FOC.timeline?.events || []).length) > 0;
  }
  return true;
}

function graphFilters() {
  return FOC.graphState.filters;
}

function graphLayers() {
  return FOC.graphState.layers;
}

function cloneGraphView(view) {
  return {
    layers: { ...(view?.layers || {}) },
    filters: { ...(view?.filters || {}) },
  };
}

function snapshotCurrentGraphView() {
  return {
    layers: { ...graphLayers() },
    filters: { ...graphFilters() },
  };
}

function loadSavedGraphView() {
  try {
    const raw = localStorage.getItem(CUSTOM_GRAPH_VIEW_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch (_) {
    return null;
  }
}

function saveCurrentGraphView() {
  try {
    localStorage.setItem(CUSTOM_GRAPH_VIEW_KEY, JSON.stringify(snapshotCurrentGraphView()));
    return true;
  } catch (_) {
    return false;
  }
}

function normalizeGraphState(view) {
  const base = cloneGraphView(DEFAULT_GRAPH_VIEW);
  const incoming = cloneGraphView(view);
  return {
    layers: { ...base.layers, ...incoming.layers },
    filters: { ...base.filters, ...incoming.filters },
  };
}

function applyGraphView(view, options = {}) {
  const normalized = normalizeGraphState(view);
  FOC.graphState.layers = normalized.layers;
  FOC.graphState.filters = normalized.filters;
  FOC.graphState.selected = null;
  FOC.graphState.activeQuestionId = options.questionId || null;
}

function activeQuestion() {
  return INVESTIGATION_QUESTIONS.find(item => item.id === FOC.graphState.activeQuestionId) || null;
}

function activeFilterSummary() {
  const parts = [];
  const enabledLayers = Object.entries(graphLayers())
    .filter(([key, enabled]) => enabled && graphLayerAvailable(key))
    .map(([key]) => GRAPH_LAYER_META[key]?.label || key);
  if (enabledLayers.length) parts.push(`Layers: ${enabledLayers.join(", ")}`);
  if (graphFilters().node !== "all") parts.push(`Node=${graphFilters().node}`);
  if (graphFilters().severity !== "all") parts.push(`Severity=${graphFilters().severity}`);
  if (graphFilters().mitre !== "all") parts.push(`MITRE=${graphFilters().mitre}`);
  if (graphFilters().sensor !== "all") parts.push(`Sensor=${graphFilters().sensor}`);
  if (graphFilters().confirmedOnly) parts.push("Confirmed only");
  if (graphFilters().hideNoise) parts.push("Hide noise");
  if (graphFilters().evidenceLinkedOnly) parts.push("Evidence linked only");
  if (graphFilters().correlationFocus && graphFilters().correlationFocus !== "all") parts.push(`Correlation=${graphFilters().correlationFocus}`);
  return parts;
}

function questionPresetPreview(question) {
  const state = normalizeGraphState(question.preset);
  const layers = Object.entries(state.layers).filter(([, enabled]) => enabled).map(([key]) => GRAPH_LAYER_META[key]?.label || key);
  const filters = [];
  if (state.filters.hideNoise) filters.push("Hide noise");
  if (state.filters.confirmedOnly) filters.push("Confirmed only");
  if (state.filters.evidenceLinkedOnly) filters.push("Evidence linked");
  if (state.filters.severity !== "all") filters.push(`Severity ${state.filters.severity}`);
  if (state.filters.sensor !== "all") filters.push(`Sensor ${state.filters.sensor}`);
  if (state.filters.correlationFocus !== "all") filters.push(`Correlation ${state.filters.correlationFocus}`);
  return `${layers.join(", ")}${filters.length ? ` | ${filters.join(", ")}` : ""}`;
}

function matchesGraphNodeFilter(nodeId) {
  const selected = graphFilters().node;
  return !selected || selected === "all" || selected === nodeId;
}

function buildGraphAggregate() {
  const cacheKey = [
    FOC.status?.last_update || "",
    FOC.scenario?.generated_at || "",
    (FOC.timeline?.events || []).length,
    (FOC.attack_attestation?.attacks || []).length,
    (FOC.detection_attestation?.observed_detection_rules || []).length,
    (FOC.artifacts?.artifacts || []).length,
    (FOC.cases?.cases || []).length,
  ].join("|");
  if (FOC.graphState.cacheKey === cacheKey && FOC.graphState.aggregate) {
    return FOC.graphState.aggregate;
  }

  const scenario = FOC.scenario || {};
  const scenarioNodes = (scenario.nodes || []).map(node => ({
    ...node,
    normalized_type: String(node.type || "node").toLowerCase(),
  }));
  const attackEvents = FOC.attack_attestation?.attacks || [];
  const detectionRules = FOC.detection_attestation?.observed_detection_rules || [];
  const timelineEvents = FOC.timeline?.events || [];
  const artifactEntries = FOC.artifacts?.artifacts || [];
  const cases = FOC.cases?.cases || [];
  const detectionSummary = FOC.status?.detection_summary || {};
  const nodeStats = new Map();

  scenarioNodes.forEach(node => {
    nodeStats.set(node.node_id, {
      node,
      attacks: { total: 0, success: 0, failed: 0, byTechnique: new Map() },
      detections: { total: 0, bySeverity: new Map(), bySensor: new Map(), collectors: new Map(), confirmed: 0, inferred: 0, noise: 0, unresolved: 0 },
      timeline: { attacks: 0, alerts: 0, triage: 0 },
      evidence: { total: 0, byType: new Map() },
      cases: new Set(),
    });
  });

  attackEvents.forEach(entry => {
    const target = entry.target || {};
    const nodeId = target.node_id;
    if (!nodeId || !nodeStats.has(nodeId)) return;
    const stats = nodeStats.get(nodeId);
    stats.attacks.total += 1;
    if (String(entry.execution_status || "").toLowerCase() === "success") stats.attacks.success += 1;
    else stats.attacks.failed += 1;
    const mitre = stringifyScalar(entry.mitre?.technique_id) || "unknown";
    stats.attacks.byTechnique.set(mitre, (stats.attacks.byTechnique.get(mitre) || 0) + 1);
  });

  detectionRules.forEach(entry => {
    const nodeId = entry.node_id;
    if (!nodeId || !nodeStats.has(nodeId)) return;
    const severity = String(entry.severity || "unknown").toUpperCase();
    const sensor = stringifyScalar(entry.original_sensor || entry.detector || "unknown");
    const collector = stringifyScalar(entry.collector || "unknown");
    const stats = nodeStats.get(nodeId);
    stats.detections.total += 1;
    stats.detections.bySeverity.set(severity, (stats.detections.bySeverity.get(severity) || 0) + 1);
    stats.detections.bySensor.set(sensor, (stats.detections.bySensor.get(sensor) || 0) + 1);
    stats.detections.collectors.set(collector, (stats.detections.collectors.get(collector) || 0) + 1);
  });

  timelineEvents.forEach(event => {
    const nodeId = event.related_node_id;
    if (!nodeId || !nodeStats.has(nodeId)) return;
    const stats = nodeStats.get(nodeId);
    if (event.event_type === "attack_execution") stats.timeline.attacks += 1;
    if (event.event_type === "detection_alert") stats.timeline.alerts += 1;
    if (event.event_type === "triage_result") stats.timeline.triage += 1;
  });

  const seenArtifacts = new Set();
  artifactEntries.forEach(entry => {
    const dedupeKey = `${entry.artifact_id || "na"}|${entry.artifact_type || "unknown"}|${entry.case_id || "na"}|${entry.path || "na"}`;
    if (seenArtifacts.has(dedupeKey)) return;
    seenArtifacts.add(dedupeKey);
    const caseId = entry.case_id;
    const nodeId = entry.source_node_id;
    if (nodeId && nodeStats.has(nodeId)) {
      const stats = nodeStats.get(nodeId);
      stats.evidence.total += 1;
      stats.evidence.byType.set(entry.artifact_type || "unknown", (stats.evidence.byType.get(entry.artifact_type || "unknown") || 0) + 1);
      if (caseId) stats.cases.add(caseId);
    }
  });

  cases.forEach(entry => {
    (entry.target_node_ids || []).forEach(nodeId => {
      if (nodeStats.has(nodeId)) nodeStats.get(nodeId).cases.add(entry.case_id);
    });
  });

  const evidenceTypes = new Map();
  [...seenArtifacts].forEach(key => {
    const [, artifactType] = key.split("|");
    evidenceTypes.set(artifactType, (evidenceTypes.get(artifactType) || 0) + 1);
  });

  const aggregate = {
    scenarioNodes,
    nodeStats,
    evidenceTypes: [...evidenceTypes.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count),
    cases,
    detectionSummary,
    timelineSummary: {
      attacks: detectionSummary.attack_events || 0,
      alerts: detectionSummary.alerts_total || 0,
      triage: detectionSummary.triage_total || 0,
    },
    mitreOptions: [...new Set(attackEvents.map(item => stringifyScalar(item.mitre?.technique_id)).filter(Boolean))].sort(),
    sensorOptions: [...new Set(detectionRules.map(item => stringifyScalar(item.original_sensor || item.detector)).filter(Boolean))].sort(),
  };

  FOC.graphState.cacheKey = cacheKey;
  FOC.graphState.aggregate = aggregate;
  return aggregate;
}

function graphDetailList(items) {
  return items.map(item => `<div class="text-sm text-slate-300">${item}</div>`).join("");
}

function renderGraphDetail(payload = null) {
  const panel = byId("graph-detail-panel");
  if (!panel) return;
  const question = activeQuestion();
  const questionBlock = question ? `
    <div class="glass-soft rounded-2xl p-4 mb-4">
      <div class="text-xs uppercase tracking-[0.18em] text-slate-400 font-black">Selected question</div>
      <div class="text-lg font-black mt-2">${esc(question.title)}</div>
      <div class="mt-3 space-y-2">
        ${graphDetailList([
          `<strong>Active filters:</strong> ${esc(activeFilterSummary().join(" | ") || "none")}`,
          `<strong>Short answer:</strong> ${esc(question.answer)}`,
          `<strong>Evidence basis:</strong> ${esc(question.evidenceBasis)}`,
          `<strong>Practical conclusion:</strong> ${esc(question.practicalConclusion)}`,
          `<strong>Limitations:</strong> ${esc(question.limitations)}`,
        ])}
      </div>
    </div>
  ` : "";
  if (!payload) {
    panel.innerHTML = `
      ${questionBlock}
      <div class="text-sm text-slate-300">Select a graph node or relation to inspect its aggregated FOC context.</div>
      <div class="mt-4">${graphDetailList([
        `<strong>Active layers:</strong> ${esc(Object.entries(graphLayers()).filter(([key, enabled]) => enabled && graphLayerAvailable(key)).map(([key]) => GRAPH_LAYER_META[key]?.label || key).join(", ") || "none")}`,
        "<strong>Rendering mode:</strong> aggregated snapshot",
        "<strong>Evidence policy:</strong> no individual alert or artifact explosion in the overview graph",
      ])}</div>
    `;
    return;
  }
  panel.innerHTML = `
    ${questionBlock}
    <div class="text-xs uppercase tracking-[0.18em] text-slate-400 font-black">${esc(payload.kind || "selection")}</div>
    <div class="text-xl font-black mt-2">${esc(payload.title || "Selected element")}</div>
    <div class="mt-4 space-y-2">${graphDetailList(payload.lines || [])}</div>
  `;
}

function graphNodeColor(type) {
  const raw = String(type || "").toLowerCase();
  if (raw.includes("attack")) return "#ef4444";
  if (raw.includes("monitor")) return "#38bdf8";
  if (raw.includes("plc")) return "#22c55e";
  if (raw.includes("scada")) return "#a855f7";
  if (raw.includes("victim")) return "#f97316";
  return "#94a3b8";
}

function graphEdgeLabelClass(edge) {
  if (edge.style === "confirmed") return "";
  if (edge.style === "inferred") return 'stroke-dasharray="8 6"';
  if (edge.style === "unresolved") return 'stroke-dasharray="4 8"';
  return 'stroke-dasharray="2 8"';
}

function topMapEntries(mapLike, limit = 3) {
  return [...(mapLike || new Map()).entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function renderGraphControls(aggregate) {
  const layerHost = byId("graph-layer-controls");
  const nodeSelect = byId("graph-filter-node");
  const mitreSelect = byId("graph-filter-mitre");
  const sensorSelect = byId("graph-filter-sensor");
  if (!layerHost || !nodeSelect || !mitreSelect || !sensorSelect) return;

  layerHost.innerHTML = Object.entries(GRAPH_LAYER_META).map(([key, meta]) => {
    const enabled = graphLayers()[key];
    const available = graphLayerAvailable(key);
    const unavailableText = key === "semantic" ? "unavailable" : (key === "causal" ? "blocked" : "unavailable");
    return `
      <button
        class="graph-layer-btn tag rounded-full px-3 py-2 text-[11px] font-black tracking-[0.14em] uppercase ${enabled && available ? "text-slate-100" : "text-slate-400 opacity-70"}"
        data-layer="${esc(key)}"
        ${available ? "" : "data-disabled=true"}
        style="border-color:${meta.color}55;background:${enabled && available ? `${meta.color}22` : 'rgba(15,23,42,0.7)'}"
      >${esc(meta.label)}${available ? "" : `: ${esc(unavailableText)}`}</button>
    `;
  }).join("");

  const selectedNode = graphFilters().node || "all";
  nodeSelect.innerHTML = [`<option value="all">All nodes</option>`]
    .concat(aggregate.scenarioNodes.map(node => `<option value="${esc(node.node_id)}">${esc(node.name || node.node_id)}</option>`))
    .join("");
  nodeSelect.value = aggregate.scenarioNodes.some(node => node.node_id === selectedNode) ? selectedNode : "all";

  const selectedMitre = graphFilters().mitre || "all";
  mitreSelect.innerHTML = [`<option value="all">All techniques</option>`]
    .concat(aggregate.mitreOptions.map(id => `<option value="${esc(id)}">${esc(id)}</option>`))
    .join("");
  mitreSelect.value = aggregate.mitreOptions.includes(selectedMitre) ? selectedMitre : "all";

  const selectedSensor = graphFilters().sensor || "all";
  sensorSelect.innerHTML = [`<option value="all">All sensors</option>`]
    .concat(aggregate.sensorOptions.map(sensor => `<option value="${esc(sensor)}">${esc(sensor)}</option>`))
    .join("");
  sensorSelect.value = aggregate.sensorOptions.includes(selectedSensor) ? selectedSensor : "all";

  byId("graph-filter-severity").value = graphFilters().severity || "all";
  byId("graph-filter-confirmed").checked = !!graphFilters().confirmedOnly;
  byId("graph-filter-hide-noise").checked = !!graphFilters().hideNoise;
  byId("graph-filter-evidence-linked").checked = !!graphFilters().evidenceLinkedOnly;
  renderInvestigationQuestions();
}

function renderInvestigationQuestions() {
  const host = byId("investigation-questions");
  const currentView = byId("graph-current-view");
  if (!host || !currentView) return;
  const active = activeQuestion();
  const savedCustom = loadSavedGraphView();
  currentView.innerHTML = active
    ? `<strong>Selected question:</strong> ${esc(active.title)}<br><span class="text-slate-400">${esc(activeFilterSummary().join(" | ") || "No active filters")}</span>`
    : `Default FOC overview<br><span class="text-slate-400">${esc(activeFilterSummary().join(" | ") || "No active filters")}</span>`;

  const questionCards = INVESTIGATION_QUESTIONS.map(question => {
    const isActive = active?.id === question.id;
    return `
      <div class="glass-soft rounded-2xl p-4 ${isActive ? "ring-1 ring-sky-400/40" : ""}">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="text-sm font-black">${esc(question.title)}</div>
            <div class="text-xs text-slate-400 mt-1">${esc(question.purpose)}</div>
          </div>
          <button class="question-apply-btn btn-secondary rounded-2xl px-3 py-2 text-[11px] font-extrabold tracking-[0.14em] uppercase" data-question-id="${esc(question.id)}">Apply</button>
        </div>
        <div class="text-[11px] text-slate-300 mt-3">${esc(questionPresetPreview(question))}</div>
        ${isActive ? `<div class="text-xs text-sky-200 mt-3">${esc(question.answer)}</div>` : ""}
      </div>
    `;
  });

  const customCard = savedCustom ? `
    <div class="glass-soft rounded-2xl p-4 border border-sky-400/20">
      <div class="flex items-start justify-between gap-3">
        <div>
          <div class="text-sm font-black">Saved Custom View</div>
          <div class="text-xs text-slate-400 mt-1">Reuse the current filter configuration later without recalculating data.</div>
        </div>
        <button class="question-apply-btn btn-secondary rounded-2xl px-3 py-2 text-[11px] font-extrabold tracking-[0.14em] uppercase" data-question-id="__custom__">Apply</button>
      </div>
      <div class="text-[11px] text-slate-300 mt-3">Stored locally in the browser for this view only.</div>
    </div>
  ` : "";

  host.innerHTML = customCard + questionCards.join("");
}

function renderNetworkGraph() {
  const host = byId("chart-network");
  const summary = byId("chart-network-summary");
  const aggregate = buildGraphAggregate();
  renderGraphControls(aggregate);

  if (!aggregate.scenarioNodes.length) {
    summary.textContent = "No data";
    host.innerHTML = `<div class="text-sm text-slate-400">No reconstruction snapshot is available.</div>`;
    renderGraphDetail(null);
    return;
  }

  const filters = graphFilters();
  const layers = graphLayers();
  const nodes = [];
  const edges = [];
  const positions = new Map();
  const graphNodePayload = new Map();
  const graphEdgePayload = new Map();
  const scenarioNodes = aggregate.scenarioNodes
    .filter(node => node.normalized_type !== "monitor" || filters.node === node.node_id)
    .filter(node => matchesGraphNodeFilter(node.node_id));

  const baseY = [96, 190, 284, 378, 472];
  scenarioNodes.forEach((node, idx) => {
    const y = baseY[idx] || (96 + (idx * 84));
    positions.set(node.node_id, { x: 150, y });
    const stats = aggregate.nodeStats.get(node.node_id);
    nodes.push({
      id: node.node_id,
      x: 150,
      y,
      label: node.name || node.node_id,
      subtitle: String(node.type || "node").replaceAll("_", " "),
      foot: `A:${stats?.attacks.total || 0} D:${stats?.timeline.alerts || stats?.detections.total || 0} E:${stats?.evidence.total || 0}`,
      color: graphNodeColor(node.type),
      shape: "circle",
      layer: "topology",
    });
    graphNodePayload.set(node.node_id, {
      kind: "Topology node",
      title: node.name || node.node_id,
      lines: [
        `<strong>Type:</strong> ${esc(String(node.type || "node").replaceAll("_", " "))}`,
        `<strong>Attacks targeting node:</strong> ${esc(stats?.attacks.total || 0)}`,
        `<strong>Detection alerts:</strong> ${esc(stats?.timeline.alerts || stats?.detections.total || 0)}`,
        `<strong>Triage records:</strong> ${esc(stats?.timeline.triage || 0)}`,
        `<strong>Evidence linked:</strong> ${esc(stats?.evidence.total || 0)}`,
        `<strong>Cases:</strong> ${esc(stats ? stats.cases.size : 0)}`,
        `<strong>Top MITRE:</strong> ${esc(topMapEntries(stats?.attacks.byTechnique || new Map(), 3).map(([key, value]) => `${key} x${value}`).join(", ") || "not_available")}`,
        `<strong>Sensors:</strong> ${esc(topMapEntries(stats?.detections.bySensor || new Map(), 3).map(([key, value]) => `${key} x${value}`).join(", ") || "not_available")}`,
      ],
    });
  });

  if (layers.topology) {
    (FOC.scenario?.edges || []).forEach((edge, idx) => {
      if (!positions.has(edge.source_node_id) || !positions.has(edge.target_node_id)) return;
      const id = `edge-struct-${idx}`;
      edges.push({ id, from: edge.source_node_id, to: edge.target_node_id, label: "network", color: "rgba(148,163,184,0.45)", style: "confirmed", width: 2 });
      graphEdgePayload.set(id, {
        kind: "Topology relation",
        title: "Network linkage",
        lines: [
          `<strong>Relation:</strong> network`,
          `<strong>Source:</strong> ${esc(edge.source_node_id)}`,
          `<strong>Target:</strong> ${esc(edge.target_node_id)}`,
          "<strong>Basis:</strong> scenario_bom structural edge",
        ],
      });
    });

    (FOC.scenario?.industrial_linkages || []).forEach((edge, idx) => {
      if (!positions.has(edge.linked_to) || !positions.has(edge.ot_node_id)) return;
      const id = `edge-itot-${idx}`;
      edges.push({ id, from: edge.linked_to, to: edge.ot_node_id, label: "it↔ot", color: "rgba(34,197,94,0.55)", style: "confirmed", width: 2 });
      graphEdgePayload.set(id, {
        kind: "Industrial linkage",
        title: "IT / OT linkage",
        lines: [
          `<strong>Relation:</strong> IT ↔ OT`,
          `<strong>Source:</strong> ${esc(edge.linked_to)}`,
          `<strong>Target:</strong> ${esc(edge.ot_node_id)}`,
          "<strong>Basis:</strong> scenario_bom industrial linkage",
        ],
      });
    });
  }

  const selectedMitre = filters.mitre;
  const selectedSeverity = String(filters.severity || "all").toUpperCase();
  const selectedSensor = filters.sensor;

  if (layers.attack) {
    scenarioNodes.forEach(node => {
      const stats = aggregate.nodeStats.get(node.node_id);
      if (!stats || !stats.attacks.total) return;
      const topTechnique = topMapEntries(stats.attacks.byTechnique, 1)[0];
      if (selectedMitre !== "all" && (!topTechnique || topTechnique[0] !== selectedMitre)) return;
      const attackNodeId = `attack-${node.node_id}`;
      nodes.push({
        id: attackNodeId,
        x: 370,
        y: positions.get(node.node_id).y,
        label: `ATT x${stats.attacks.total}`,
        subtitle: topTechnique ? topTechnique[0] : "technique mix",
        foot: `${stats.attacks.success} exec ok / ${stats.attacks.failed} exit-failed`,
        color: GRAPH_LAYER_META.attack.color,
        shape: "rect",
        layer: "attack",
      });
      edges.push({ id: `edge-attack-${node.node_id}`, from: node.node_id, to: attackNodeId, label: "targets", color: "rgba(239,68,68,0.65)", style: "confirmed", width: 2 });
      graphNodePayload.set(attackNodeId, {
        kind: "Attack aggregate",
        title: `${node.name || node.node_id} attack surface`,
        lines: [
          `<strong>Total attack executions:</strong> ${esc(stats.attacks.total)}`,
          `<strong>Command exit ok:</strong> ${esc(stats.attacks.success)}`,
          `<strong>Command exit failed:</strong> ${esc(stats.attacks.failed)}`,
          `<strong>Technique distribution:</strong> ${esc(topMapEntries(stats.attacks.byTechnique, 4).map(([key, value]) => `${key} x${value}`).join(", ") || "not_available")}`,
          `<strong>Interpretation:</strong> command-exit failure does not by itself mean no traffic, no detection, or no OT process effect evidence was observed.`,
        ],
      });
      graphEdgePayload.set(`edge-attack-${node.node_id}`, {
        kind: "Attack relation",
        title: "Attack targeting aggregate",
        lines: [
          `<strong>Status:</strong> confirmed aggregate`,
          `<strong>Meaning:</strong> attacks attested against this node`,
          `<strong>Filter basis:</strong> attack_attestation target.node_id`,
        ],
      });
    });
  }

  if (layers.detection) {
    scenarioNodes.forEach(node => {
      const stats = aggregate.nodeStats.get(node.node_id);
      if (!stats) return;
      const severityCount = selectedSeverity === "ALL" ? stats.detections.total : (stats.detections.bySeverity.get(selectedSeverity) || 0);
      const sensorCount = selectedSensor === "all" ? stats.detections.total : (stats.detections.bySensor.get(selectedSensor) || 0);
      let effectiveCount = stats.timeline.alerts || stats.detections.total;
      if (selectedSeverity !== "ALL") {
        effectiveCount = severityCount;
      }
      if (selectedSensor !== "all") {
        effectiveCount = selectedSeverity !== "ALL" ? Math.min(effectiveCount, sensorCount) : sensorCount;
      }
      if (!effectiveCount) return;
      const detNodeId = `det-${node.node_id}`;
      nodes.push({
        id: detNodeId,
        x: 610,
        y: positions.get(node.node_id).y,
        label: `DET x${effectiveCount}`,
        subtitle: topMapEntries(stats.detections.bySensor, 1)[0]?.[0] || "sensor mix",
        foot: topMapEntries(stats.detections.bySeverity, 1)[0] ? `${topMapEntries(stats.detections.bySeverity, 1)[0][0]} dominant` : "aggregated",
        color: GRAPH_LAYER_META.detection.color,
        shape: "rect",
        layer: "detection",
      });
      edges.push({ id: `edge-det-${node.node_id}`, from: node.node_id, to: detNodeId, label: "detected", color: "rgba(245,158,11,0.7)", style: "confirmed", width: 2 });
      graphNodePayload.set(detNodeId, {
        kind: "Detection aggregate",
        title: `${node.name || node.node_id} detection surface`,
        lines: [
          `<strong>Observed detection records:</strong> ${esc(stats.detections.total)}`,
          `<strong>Timeline alerts:</strong> ${esc(stats.timeline.alerts)}`,
          `<strong>Severity distribution:</strong> ${esc(topMapEntries(stats.detections.bySeverity, 4).map(([key, value]) => `${key} x${value}`).join(", ") || "not_available")}`,
          `<strong>Original sensors:</strong> ${esc(topMapEntries(stats.detections.bySensor, 4).map(([key, value]) => `${key} x${value}`).join(", ") || "not_available")}`,
          `<strong>Collectors:</strong> ${esc(topMapEntries(stats.detections.collectors, 4).map(([key, value]) => `${key} x${value}`).join(", ") || "not_available")}`,
        ],
      });
      graphEdgePayload.set(`edge-det-${node.node_id}`, {
        kind: "Detection relation",
        title: "Detection aggregate relation",
        lines: [
          `<strong>Meaning:</strong> detection observations resolved to this node`,
          `<strong>Collector/original sensor split:</strong> preserved`,
        ],
      });
    });
  }

  if (layers.attack_alert) {
    const correlationCounts = aggregate.detectionSummary.correlation_counts || {};
    let statuses = [
      { key: "confirmed", label: "Confirmed", y: 110, color: "#ef4444", style: "confirmed" },
      { key: "inferred_medium", label: "Inferred", y: 190, color: "#f59e0b", style: "inferred" },
      { key: "unresolved", label: "Unresolved", y: 270, color: "#94a3b8", style: "unresolved" },
      { key: "noise", label: "Noise", y: 350, color: "#64748b", style: "noise" },
    ];
    if (filters.hideNoise) {
      statuses = statuses.filter(item => item.key !== "noise");
    }
    if (filters.correlationFocus === "confirmed") {
      statuses = statuses.filter(item => item.key === "confirmed");
    } else if (filters.correlationFocus === "uncertain") {
      statuses = statuses.filter(item => ["inferred_medium", "unresolved"].includes(item.key));
    } else if (filters.correlationFocus === "noise") {
      statuses = statuses.filter(item => item.key === "noise");
    }
    const corrNodeId = "corr-root";
    nodes.push({
      id: corrNodeId,
      x: 840,
      y: 230,
      label: "ATT→ALERT",
      subtitle: "correlation surface",
      foot: `${aggregate.detectionSummary.confirmed_ratio_text || "0/0"} confirmed`,
      color: GRAPH_LAYER_META.attack_alert.color,
      shape: "rect",
      layer: "attack_alert",
    });
    graphNodePayload.set(corrNodeId, {
      kind: "Correlation aggregate",
      title: "Attack to alert correlation surface",
      lines: [
        `<strong>Confirmed:</strong> ${esc(correlationCounts.confirmed || 0)}`,
        `<strong>Inferred medium:</strong> ${esc(correlationCounts.inferred_medium || 0)}`,
        `<strong>Inferred low:</strong> ${esc(correlationCounts.inferred_low || 0)}`,
        `<strong>Weak candidates:</strong> ${esc(correlationCounts.weak_candidate || 0)}`,
        `<strong>Unresolved:</strong> ${esc(correlationCounts.unresolved || 0)}`,
        `<strong>Noise:</strong> ${esc(correlationCounts.noise || 0)}`,
      ],
    });
    statuses.forEach(item => {
      const value = Number(correlationCounts[item.key] || 0);
      if (filters.confirmedOnly && item.key !== "confirmed") return;
      if (filters.evidenceLinkedOnly && item.key !== "confirmed") return;
      const id = `corr-${item.key}`;
      nodes.push({
        id,
        x: 1040,
        y: item.y,
        label: `${item.label} x${value}`,
        subtitle: "aggregate relation",
        foot: item.key.replaceAll("_", " "),
        color: item.color,
        shape: "rect",
        layer: "attack_alert",
      });
      edges.push({ id: `edge-${id}`, from: corrNodeId, to: id, label: item.label.toLowerCase(), color: `${item.color}aa`, style: item.style, width: 2 });
      graphNodePayload.set(id, {
        kind: "Correlation status",
        title: `${item.label} correlations`,
        lines: [
          `<strong>Count:</strong> ${esc(value)}`,
          `<strong>Status type:</strong> ${esc(item.label)}`,
          "<strong>Basis:</strong> FOC detection summary correlation counts",
        ],
      });
      graphEdgePayload.set(`edge-${id}`, {
        kind: "Correlation relation",
        title: `${item.label} status edge`,
        lines: [
          `<strong>Visual style:</strong> ${esc(item.style)}`,
          "<strong>Meaning:</strong> aggregated correlation class from indexed alerts",
        ],
      });
    });
  }

  const caseEntry = aggregate.cases[0] || null;
  if (layers.evidence && caseEntry && (!filters.evidenceLinkedOnly || Number(caseEntry.artifacts_count || 0) > 0)) {
    const caseNodeId = `case-${caseEntry.case_id}`;
    nodes.push({
      id: caseNodeId,
      x: 330,
      y: 510,
      label: caseEntry.source_case_name || caseEntry.case_id,
      subtitle: "forensic case",
      foot: `${caseEntry.artifacts_count || 0} indexed artifacts`,
      color: GRAPH_LAYER_META.evidence.color,
      shape: "rect",
      layer: "evidence",
    });
    graphNodePayload.set(caseNodeId, {
      kind: "Forensic case",
      title: caseEntry.source_case_name || caseEntry.case_id,
      lines: [
        `<strong>Case id:</strong> ${esc(caseEntry.case_id)}`,
        `<strong>Artifacts indexed:</strong> ${esc(caseEntry.artifacts_count || 0)}`,
        `<strong>Trigger alert:</strong> ${esc(caseEntry.trigger_alert_id || "not_available")}`,
        `<strong>Trigger type:</strong> ${esc(caseEntry.trigger_type || "not_available")}`,
        `<strong>Target nodes:</strong> ${esc((caseEntry.target_node_ids || []).join(", ") || "not_available")}`,
      ],
    });

    aggregate.evidenceTypes.slice(0, 6).forEach((entry, idx) => {
      const id = `evidence-${entry.type}`;
      nodes.push({
        id,
        x: 500 + ((idx % 3) * 170),
        y: 470 + (Math.floor(idx / 3) * 90),
        label: `${entry.type} x${entry.count}`,
        subtitle: "evidence group",
        foot: "aggregated artifacts",
        color: GRAPH_LAYER_META.evidence.color,
        shape: "rect",
        layer: "evidence",
      });
      edges.push({ id: `edge-${id}`, from: caseNodeId, to: id, label: "preserves", color: "rgba(34,211,238,0.7)", style: "confirmed", width: 2 });
      graphNodePayload.set(id, {
        kind: "Evidence group",
        title: entry.type,
        lines: [
          `<strong>Count:</strong> ${esc(entry.count)}`,
          "<strong>Meaning:</strong> aggregated evidence type linked to the indexed case set",
        ],
      });
      graphEdgePayload.set(`edge-${id}`, {
        kind: "Evidence relation",
        title: "Case to evidence relation",
        lines: [
          `<strong>Relation:</strong> preserves`,
          "<strong>Basis:</strong> artifacts_index grouped by artifact_type",
        ],
      });
    });
  }

  if (layers.custody && caseEntry) {
    const custodyNodeId = "custody-root";
    nodes.push({
      id: custodyNodeId,
      x: 1010,
      y: 470,
      label: "Custody",
      subtitle: "verification state",
      foot: `${FOC.status?.components?.evidence_custody_chain || 0}/10 score`,
      color: GRAPH_LAYER_META.custody.color,
      shape: "rect",
      layer: "custody",
    });
    graphNodePayload.set(custodyNodeId, {
      kind: "Custody aggregate",
      title: "Chain of custody overview",
      lines: [
        `<strong>Evidence/custody component:</strong> ${esc(FOC.status?.components?.evidence_custody_chain || 0)} / 10`,
        `<strong>Custody path:</strong> ${esc(caseEntry.custody_path || "not_available")}`,
        `<strong>Manifest path:</strong> ${esc(caseEntry.manifest_path || "not_available")}`,
      ],
    });
    if (caseEntry) {
      edges.push({ id: "edge-custody-case", from: `case-${caseEntry.case_id}`, to: custodyNodeId, label: "custody", color: "rgba(34,197,94,0.75)", style: "confirmed", width: 2 });
      graphEdgePayload.set("edge-custody-case", {
        kind: "Custody relation",
        title: "Case to custody linkage",
        lines: [
          "<strong>Relation:</strong> custody / verification",
          "<strong>Basis:</strong> indexed manifest and chain of custody records",
        ],
      });
    }
  }

  if (layers.analysis) {
    const analysisNodeId = "analysis-root";
    const analysisAvailable = graphLayerAvailable("analysis");
    nodes.push({
      id: analysisNodeId,
      x: 1010,
      y: 560,
      label: analysisAvailable ? "Analysis" : "Analysis unavailable",
      subtitle: analysisAvailable ? "forensic outputs" : "not executed yet",
      foot: analysisAvailable ? `${FOC.status?.components?.analysis_outputs || 0}/10 score` : "run on demand",
      color: GRAPH_LAYER_META.analysis.color,
      shape: "rect",
      layer: "analysis",
    });
    graphNodePayload.set(analysisNodeId, {
      kind: "Analysis layer",
      title: analysisAvailable ? "Forensic analysis available" : "Forensic analysis has not been executed yet",
      lines: analysisAvailable ? [
        `<strong>Analysis outputs component:</strong> ${esc(FOC.status?.components?.analysis_outputs || 0)} / 10`,
        "<strong>Meaning:</strong> PCAP, memory, disk or OT analysis outputs are indexed",
      ] : [
        "Forensic analysis has not been executed yet.",
        "This layer remains informative until multilayer analysis produces validated outputs.",
      ],
    });
  }

  if (layers.timeline) {
    const id = "timeline-root";
    nodes.push({
      id,
      x: 170,
      y: 560,
      label: "Timeline",
      subtitle: "phase aggregate",
      foot: `${aggregate.timelineSummary.attacks}/${aggregate.timelineSummary.alerts}/${aggregate.timelineSummary.triage}`,
      color: GRAPH_LAYER_META.timeline.color,
      shape: "rect",
      layer: "timeline",
    });
    graphNodePayload.set(id, {
      kind: "Timeline aggregate",
      title: "Lifecycle and incident timeline",
      lines: [
        `<strong>Attack events:</strong> ${esc(aggregate.timelineSummary.attacks)}`,
        `<strong>Detection alerts:</strong> ${esc(aggregate.timelineSummary.alerts)}`,
        `<strong>Triage results:</strong> ${esc(aggregate.timelineSummary.triage)}`,
        "<strong>Policy:</strong> aggregated only, full event sequence remains in the timeline panel",
      ],
    });
  }

  if (layers.findings) {
    const id = "findings-root";
    const analysisAvailable = graphLayerAvailable("findings");
    nodes.push({
      id,
      x: 840,
      y: 560,
      label: analysisAvailable ? "Findings" : "Findings unavailable",
      subtitle: analysisAvailable ? "cross-layer outputs" : "awaiting analysis",
      foot: analysisAvailable ? "analysis-backed" : "not generated",
      color: GRAPH_LAYER_META.findings.color,
      shape: "rect",
      layer: "findings",
    });
    graphNodePayload.set(id, {
      kind: "Findings layer",
      title: analysisAvailable ? "Cross-layer findings available" : "Cross-layer findings unavailable",
      lines: analysisAvailable ? [
        "Analysis-derived findings are available in indexed outputs.",
      ] : [
        "Cross-layer findings remain unavailable until analysis outputs are generated.",
      ],
    });
  }

  nodes.forEach(node => {
    positions.set(node.id, { x: node.x, y: node.y });
  });

  const visibleNodeIds = new Set(nodes.map(node => node.id));
  const visibleEdges = edges.filter(edge => visibleNodeIds.has(edge.from) && visibleNodeIds.has(edge.to)).slice(0, 90);
  const viewBox = "0 0 1120 620";

  summary.textContent = `${nodes.length} nodes | ${visibleEdges.length} edges | aggregated snapshot`;
  host.innerHTML = `
    <svg viewBox="${viewBox}" class="w-full h-auto">
      ${visibleEdges.map(edge => {
        const a = positions.get(edge.from);
        const b = positions.get(edge.to);
        if (!a || !b) return "";
        const midX = ((a.x + b.x) / 2).toFixed(1);
        const midY = ((a.y + b.y) / 2).toFixed(1);
        return `
          <g class="cursor-pointer" data-graph-edge="${esc(edge.id)}">
            <line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${edge.color}" stroke-width="${edge.width || 2}" ${graphEdgeLabelClass(edge)} />
            <text x="${midX}" y="${midY - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">${esc(edge.label)}</text>
          </g>
        `;
      }).join("")}
      ${nodes.map(node => {
        const titleY = node.shape === "circle" ? node.y - 40 : node.y - 28;
        const body = node.shape === "circle"
          ? `<circle cx="${node.x}" cy="${node.y}" r="30" fill="${node.color}" opacity="0.92" stroke="rgba(226,232,240,0.18)" stroke-width="2"></circle>`
          : `<rect x="${node.x - 58}" y="${node.y - 28}" width="116" height="56" rx="18" fill="${node.color}" opacity="0.92" stroke="rgba(226,232,240,0.18)" stroke-width="2"></rect>`;
        return `
          <g class="cursor-pointer" data-graph-node="${esc(node.id)}">
            <text x="${node.x}" y="${titleY}" text-anchor="middle" fill="#8fa3bf" font-size="10">${esc(node.subtitle)}</text>
            ${body}
            <text x="${node.x}" y="${node.y - 4}" text-anchor="middle" fill="#08101b" font-size="11" font-weight="800">${esc(node.label)}</text>
            <text x="${node.x}" y="${node.y + 14}" text-anchor="middle" fill="#08101b" font-size="9">${esc(node.foot || "")}</text>
          </g>
        `;
      }).join("")}
    </svg>
    <div class="text-xs text-slate-400 mt-3">Visual semantics: gray structure, red attack, amber detection, orange correlation, cyan evidence, green custody, purple analysis, dashed edges for inferred or unresolved relations.</div>
  `;

  if (FOC.graphState.selected?.type === "node" && graphNodePayload.has(FOC.graphState.selected.id)) {
    renderGraphDetail(graphNodePayload.get(FOC.graphState.selected.id));
  } else if (FOC.graphState.selected?.type === "edge" && graphEdgePayload.has(FOC.graphState.selected.id)) {
    renderGraphDetail(graphEdgePayload.get(FOC.graphState.selected.id));
  } else {
    renderGraphDetail(null);
  }

  host.onclick = (event) => {
    const node = event.target.closest("[data-graph-node]");
    const edge = event.target.closest("[data-graph-edge]");
    if (node) {
      const id = node.getAttribute("data-graph-node");
      FOC.graphState.selected = { type: "node", id };
      renderGraphDetail(graphNodePayload.get(id) || null);
      return;
    }
    if (edge) {
      const id = edge.getAttribute("data-graph-edge");
      FOC.graphState.selected = { type: "edge", id };
      renderGraphDetail(graphEdgePayload.get(id) || null);
      return;
    }
    FOC.graphState.selected = null;
    renderGraphDetail(null);
  };
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
    if (!cases.length) {
      note.innerHTML = "No preserved forensic case is currently indexed in FOC.";
    } else if (analysisAvailableGlobal()) {
      note.innerHTML = "Preserved evidence and forensic analysis outputs are available. The current scientific gap is no longer raw analysis generation, but the semantic and causal linkage required for stronger reconstruction confidence.";
    } else {
      note.innerHTML = "Preserved evidence is available. Run multilayer forensic analysis on demand to generate a validated forensic report from preserved evidence.";
    }
  }
  const casesHtml = cases.map(entry => {
    const analysisStatus = FOC.caseAnalysisStatuses[entry.case_id] || null;
    const causalState = entry.causal_state || null;
    const timeSyncState = entry.time_sync_state || null;
    const availableLayers = analysisStatus?.available_layers || entry.available_layers || {};
    const currentAnalysisState = analysisStatus?.status || entry.analysis_status || "not_started";
    const currentCausalState = causalState?.status || "not_available";
    const runLabel = currentAnalysisState === "completed" ? "Rerun Multilayer Analysis" : currentAnalysisState === "running" ? "Analysis already running" : "Run Multilayer Forensic Analysis";
    const causalRunLabel = currentCausalState === "completed" || currentCausalState === "completed_with_degradation" ? "Rerun Causal Reconstruction" : currentCausalState === "running" ? "Causal reconstruction running" : "Run Causal Reconstruction";
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
            <div class="mt-2 text-xs text-slate-300">${esc(currentAnalysisState === "completed" ? "Analysis outputs are available for this case." : currentAnalysisState === "partial" ? "Analysis outputs are partially available for this case." : "Preserved evidence is available, but forensic analysis outputs are not indexed yet for this case.")}</div>
          </div>
          <div class="glass rounded-2xl p-3">
            <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Available layers</div>
            <div class="mt-2 space-y-1">${layersList || '<span class="text-slate-500 text-xs">not_loaded</span>'}</div>
          </div>
        </div>
        <div class="mt-4 grid grid-cols-1 gap-3 text-sm">
          <div class="glass rounded-2xl p-3">
            <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Time synchronization</div>
            <div class="mt-2 ${statusClass(timeSyncState?.temporal_sync_status || timeSyncState?.status || "unknown")} font-black uppercase tracking-[0.12em] text-xs">${esc(timeSyncState?.temporal_sync_status || timeSyncState?.status || "unknown")}</div>
            <div class="mt-2 text-xs text-slate-300">${esc(timeSyncState?.reason || "No preserved time synchronization measurement is available for this case.")}</div>
            <div class="mt-3 grid grid-cols-2 md:grid-cols-5 gap-2 text-[11px] text-slate-300">
              <div>Max offset: <span class="mono">${esc(timeSyncState?.max_clock_offset_ms ?? "na")}</span> ms</div>
              <div>Nodes OK: <span class="mono">${esc(timeSyncState?.nodes_ok ?? 0)}</span></div>
              <div>Nodes failed: <span class="mono">${esc(timeSyncState?.nodes_failed ?? 0)}</span></div>
              <div>Correction: <span class="mono">${esc(String(timeSyncState?.correction_applied ?? false))}</span></div>
              <div>Worst node: <span class="mono">${esc(timeSyncState?.worst_node?.name || "na")}</span></div>
            </div>
          </div>
          <div class="glass rounded-2xl p-3">
            <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Causal reconstruction</div>
            <div class="mt-2 ${statusClass(currentCausalState)} font-black uppercase tracking-[0.12em] text-xs">${esc(currentCausalState)}</div>
            <div class="mt-2 text-xs text-slate-300">${esc(causalState?.reason || "Causal reconstruction has not been generated yet.")}</div>
            ${causalState?.metrics_preview ? `
              <div class="mt-3 grid grid-cols-2 md:grid-cols-5 gap-2 text-[11px] text-slate-300">
                <div>CPR: <span class="mono">${esc(causalState.metrics_preview.causal_path_recoverability ?? "na")}</span></div>
                <div>wCPR: <span class="mono">${esc(causalState.metrics_preview.weighted_cpr ?? "na")}</span></div>
                <div>Recovered: <span class="mono">${esc(causalState.metrics_preview.recovered_edges ?? 0)}</span></div>
                <div>Degraded: <span class="mono">${esc(causalState.metrics_preview.degraded_edges ?? 0)}</span></div>
                <div>Missing: <span class="mono">${esc(causalState.metrics_preview.missing_edges ?? 0)}</span></div>
              </div>
            ` : ""}
          </div>
        </div>
        <div class="mt-3">${caseArtifacts.map(a => `<div class="mono text-xs text-slate-400">${esc(a.artifact_type)} → ${esc(a.artifact_id)}</div>`).join("")}</div>
        <div class="flex flex-wrap gap-3 mt-4">
          <button class="open-analysis-btn btn-primary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}"${currentAnalysisState === "running" ? " disabled" : ""}>${esc(runLabel)}</button>
          <button class="view-time-sync-btn btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}">Time Synchronization</button>
          <button class="view-analysis-btn btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}">Open Analysis Status</button>
          <button class="view-analysis-report-btn btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}">View Analysis Report</button>
          <button class="run-causal-btn btn-primary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}"${["running", "blocked_missing_analysis", "blocked_missing_ground_truth", "not_available"].includes(currentCausalState) ? " disabled" : ""}>${esc(causalRunLabel)}</button>
          <button class="view-causal-btn btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-case-id="${esc(entry.case_id)}">View Causal Cockpit</button>
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

function bindGraphControls() {
  const layerHost = byId("graph-layer-controls");
  layerHost?.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-layer]");
    if (!btn || btn.getAttribute("data-disabled") === "true") return;
    const key = btn.getAttribute("data-layer");
    if (!Object.prototype.hasOwnProperty.call(FOC.graphState.layers, key)) return;
    FOC.graphState.layers[key] = !FOC.graphState.layers[key];
    if (!FOC.graphState.layers[key] && FOC.graphState.selected?.id?.startsWith(key)) {
      FOC.graphState.selected = null;
    }
    renderNetworkGraph();
  });

  byId("investigation-questions")?.addEventListener("click", (event) => {
    const btn = event.target.closest(".question-apply-btn");
    if (!btn) return;
    const questionId = btn.getAttribute("data-question-id");
    if (questionId === "__custom__") {
      const saved = loadSavedGraphView();
      if (saved) {
        applyGraphView(saved, { questionId: null });
        renderNetworkGraph();
      }
      return;
    }
    const question = INVESTIGATION_QUESTIONS.find(item => item.id === questionId);
    if (!question) return;
    applyGraphView(question.preset, { questionId: question.id });
    renderNetworkGraph();
  });

  byId("graph-reset-view-btn")?.addEventListener("click", () => {
    applyGraphView(DEFAULT_GRAPH_VIEW, { questionId: null });
    renderNetworkGraph();
  });

  byId("graph-save-custom-btn")?.addEventListener("click", () => {
    saveCurrentGraphView();
    renderInvestigationQuestions();
    renderGraphDetail(null);
  });

  byId("graph-filter-node")?.addEventListener("change", (event) => {
    FOC.graphState.filters.node = event.target.value || "all";
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
  byId("graph-filter-severity")?.addEventListener("change", (event) => {
    FOC.graphState.filters.severity = event.target.value || "all";
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
  byId("graph-filter-mitre")?.addEventListener("change", (event) => {
    FOC.graphState.filters.mitre = event.target.value || "all";
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
  byId("graph-filter-sensor")?.addEventListener("change", (event) => {
    FOC.graphState.filters.sensor = event.target.value || "all";
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
  byId("graph-filter-confirmed")?.addEventListener("change", (event) => {
    FOC.graphState.filters.confirmedOnly = !!event.target.checked;
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
  byId("graph-filter-hide-noise")?.addEventListener("change", (event) => {
    FOC.graphState.filters.hideNoise = !!event.target.checked;
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
  byId("graph-filter-evidence-linked")?.addEventListener("change", (event) => {
    FOC.graphState.filters.evidenceLinkedOnly = !!event.target.checked;
    FOC.graphState.selected = null;
    renderNetworkGraph();
  });
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
      renderAnalysisModal(status, {
        logs: FOC.analysisVisualState.currentLogs || null,
        report: FOC.analysisVisualState.currentReport || null,
        visualSummary: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentSummary || null) : null,
      });
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

function openAnalysisReportModalShell() {
  const modal = byId("analysis-report-modal");
  if (!modal) return;
  modal.classList.add("is-active");
  modal.setAttribute("aria-hidden", "false");
}

function closeAnalysisReportModalShell() {
  const modal = byId("analysis-report-modal");
  if (!modal) return;
  modal.classList.remove("is-active");
  modal.setAttribute("aria-hidden", "true");
}

function stopCausalPolling() {
  if (FOC.causalPollTimer) {
    clearTimeout(FOC.causalPollTimer);
    FOC.causalPollTimer = null;
  }
}

function openCausalReportModalShell() {
  const modal = byId("causal-report-modal");
  if (!modal) return;
  modal.classList.add("is-active");
  modal.setAttribute("aria-hidden", "false");
}

function closeCausalReportModalShell() {
  const modal = byId("causal-report-modal");
  if (!modal) return;
  modal.classList.remove("is-active");
  modal.setAttribute("aria-hidden", "true");
  stopCausalPolling();
}

function openSymbolGenModal() {
  const modal = byId("symbolgen-modal");
  if (!modal) return;
  byId("symbolgen-status").textContent = "";
  byId("symbolgen-report-panel").textContent = "No report loaded.";
  modal.classList.add("is-active");
  modal.setAttribute("aria-hidden", "false");
  loadSymbolGenerationStatus().catch(err => {
    byId("symbolgen-status").textContent = `Status load failed: ${err.message || err}`;
  });
}

function closeSymbolGenModal() {
  const modal = byId("symbolgen-modal");
  if (!modal) return;
  modal.classList.remove("is-active");
  modal.setAttribute("aria-hidden", "true");
}

function stopTimeSyncPolling() {
  if (FOC.timeSyncPollTimer) {
    clearTimeout(FOC.timeSyncPollTimer);
    FOC.timeSyncPollTimer = null;
  }
}

function openTimeSyncModalShell() {
  const modal = byId("time-sync-modal");
  if (!modal) return;
  modal.classList.add("is-active");
  modal.setAttribute("aria-hidden", "false");
}

function closeTimeSyncModalShell() {
  const modal = byId("time-sync-modal");
  if (!modal) return;
  modal.classList.remove("is-active");
  modal.setAttribute("aria-hidden", "true");
  stopTimeSyncPolling();
}

function renderTimeSyncModal(status) {
  const panel = byId("time-sync-modal-panel");
  const title = byId("time-sync-modal-title");
  const subtitle = byId("time-sync-modal-subtitle");
  if (!panel) return;
  const caseId = status?.case_id || FOC.selectedCaseId || "unknown";
  const caseEntry = (FOC.cases?.cases || []).find(item => item.case_id === caseId);
  if (title) title.textContent = `Time Synchronization: ${caseEntry?.source_case_name || caseId}`;
  if (subtitle) {
    subtitle.textContent = status?.status === "running"
      ? `Time synchronization is running at ${status?.progress_percent ?? 0}% in step ${status?.current_step || "unknown"}.`
      : "Measure-only is the safe default. Correction is explicit, logged, and treated as infrastructure intervention.";
  }
  FOC.timeSyncVisualState.currentCaseId = caseId;
  FOC.timeSyncVisualState.currentStatus = status;
  FOC.timeSyncState = status;
  const summary = status?.summary || status || {};
  const policy = status?.policy || {};
  const before = summary.before || {};
  const after = summary.after || {};
  const outputPaths = summary.output_paths || status?.output_paths || {};
  panel.innerHTML = `
    <div class="space-y-4">
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        ${simpleValueCard("Sync status", summary.temporal_sync_status || summary.status || "unknown", "Measured platform time state")}
        ${simpleValueCard("Max clock offset", summary.max_clock_offset_ms ?? "na", "Milliseconds")}
        ${simpleValueCard("Temporal sync threshold", summary.synchronization_threshold_ms ?? "na", "Milliseconds")}
        ${simpleValueCard("Nodes measured", summary.nodes_ok ?? 0, "Nodes with usable offset")}
        ${simpleValueCard("Nodes failed", summary.nodes_failed ?? 0, "Nodes with SSH or chrony failure")}
        ${simpleValueCard("Correction applied", String(summary.correction_applied ?? false), "Explicit infrastructure correction")}
      </div>
      <div class="glass-soft rounded-2xl p-4 text-sm text-slate-300">
        <div><strong>Reason:</strong> ${esc(summary.reason || status?.reason || "not_available")}</div>
        <div class="mt-1"><strong>Worst node:</strong> ${esc(summary.worst_node?.name || "na")} ${summary.worst_node?.offset_ms != null ? `(${esc(summary.worst_node.offset_ms)} ms)` : ""}</div>
        <div class="mt-1"><strong>Generated at:</strong> ${esc(summary.generated_at_utc || status?.updated_at || "not_available")}</div>
        <div class="mt-1"><strong>Mode:</strong> ${esc(summary.mode || "unknown")}</div>
      </div>
      <div class="glass-soft rounded-2xl p-4 text-sm ${policy.active_case_present ? "text-amber-200 border border-amber-500/30" : "text-slate-300"}">
        <div><strong>Policy state:</strong> ${esc(policy.policy_state || "not_available")}</div>
        <div class="mt-1"><strong>Policy reason:</strong> ${esc(policy.reason || "not_available")}</div>
        ${policy.active_case_id ? `<div class="mt-1"><strong>Active case:</strong> ${esc(policy.active_case_id)}</div>` : ""}
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="glass-soft rounded-2xl p-4 text-sm text-slate-300">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Before</div>
          <div class="mt-2">Max offset: ${esc(before.max_clock_offset_ms ?? "na")} ms</div>
          <div class="mt-1">Status: ${esc(before.temporal_sync_status || "not_available")}</div>
        </div>
        <div class="glass-soft rounded-2xl p-4 text-sm text-slate-300">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">After / Effective</div>
          <div class="mt-2">Max offset: ${esc((after.max_clock_offset_ms ?? summary.max_clock_offset_ms) ?? "na")} ms</div>
          <div class="mt-1">Status: ${esc(after.temporal_sync_status || summary.temporal_sync_status || "not_available")}</div>
        </div>
      </div>
      <div class="glass-soft rounded-2xl p-4 text-xs text-slate-400 mono whitespace-pre-wrap">${esc(Object.entries(outputPaths).map(([k, v]) => `${k}: ${v}`).join("\n") || "No output paths available.")}</div>
    </div>
  `;
}

async function fetchTimeSyncStatus(caseId) {
  return fetchJson(timeSyncStatusUrl(caseId));
}

function scheduleTimeSyncPolling(caseId) {
  stopTimeSyncPolling();
  FOC.timeSyncPollTimer = setTimeout(async () => {
    try {
      const status = await fetchTimeSyncStatus(caseId);
      renderTimeSyncModal(status);
      if (status.status === "running") {
        scheduleTimeSyncPolling(caseId);
      } else {
        await loadAll(true);
      }
    } catch (_) {
      scheduleTimeSyncPolling(caseId);
    }
  }, ANALYSIS_STATUS_POLL_MS);
}

async function openTimeSyncModal(caseId) {
  FOC.selectedCaseId = caseId;
  openTimeSyncModalShell();
  const status = await fetchTimeSyncStatus(caseId);
  renderTimeSyncModal(status);
  if (status.status === "running") scheduleTimeSyncPolling(caseId);
}

async function runTimeSync(caseId, fixTime = false) {
  const currentPolicy = FOC.timeSyncState?.policy || {};
  let maintenanceOverride = false;
  if (fixTime) {
    const confirmed = window.confirm("Fix Time Synchronization changes node state and may install/start chrony, apply chronyc makestep, and alter timestamps, logs or volatile evidence ordering. Continue?");
    if (!confirmed) return;
    if (currentPolicy?.active_case_present) {
      const overrideConfirmed = window.confirm(`An active forensic case (${currentPolicy.active_case_id || "unknown"}) is present. Corrective time synchronization is normally blocked during an active case. Continue only as explicit laboratory or maintenance override intervention?`);
      if (!overrideConfirmed) return;
      maintenanceOverride = true;
    }
  }
  FOC.selectedCaseId = caseId;
  openTimeSyncModalShell();
  renderTimeSyncModal({
    case_id: caseId,
    status: "running",
    progress_percent: 0,
    current_step: "queued",
    reason: fixTime ? "Starting time synchronization correction..." : "Starting safe clock offset measurement...",
    summary: { temporal_sync_status: "running", correction_applied: fixTime },
  });
  const result = await fetchJson(timeSyncRunUrl(caseId), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fix_time: fixTime, maintenance_override: maintenanceOverride }),
  }).catch(async () => fetchTimeSyncStatus(caseId));
  renderTimeSyncModal(result);
  if (result.status === "running") {
    scheduleTimeSyncPolling(caseId);
  } else if (result.status !== "blocked_policy") {
    await loadAll(true);
  } else {
    return;
  }
}

async function generateSymbolsForSelectedCase() {
  const caseId = FOC.selectedCaseId;
  if (!caseId) return;
  const runBtn = byId("symbolgen-run-btn");
  try {
    const memory_artifact_id = byId("symbolgen-dump-select")?.value || undefined;
    const overwrite = !!byId("symbolgen-overwrite")?.checked;
    const payload = { memory_artifact_id, overwrite, mode: "manual" };
    if (runBtn) {
      runBtn.disabled = true;
      runBtn.textContent = "Generating…";
    }
    byId("symbolgen-status").textContent = "Requesting symbol generation...";
    const url = `${API}/cases/${encodeURIComponent(caseId)}/symbols/generate`;
    const res = await fetchJson(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    byId("symbolgen-status").textContent = res.status ? `status: ${res.status}` : "queued";
    await pollSymbolGenerationJob(caseId, res.job_id);
    try {
      const status = await fetchCaseAnalysisStatus(caseId);
      renderAnalysisModal(status, {
        logs: FOC.analysisVisualState.currentLogs || null,
        report: FOC.analysisVisualState.currentReport || null,
        visualSummary: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentSummary || null) : null,
      });
    } catch (_) {}
  } catch (err) {
    byId("symbolgen-status").textContent = `Request failed: ${err.message || err}`;
  } finally {
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.textContent = "Generate";
    }
  }
}

async function loadSymbolGenerationStatus() {
  const caseId = FOC.selectedCaseId;
  if (!caseId) return;
  const status = await fetchJson(`${API}/cases/${encodeURIComponent(caseId)}/symbols/status`);
  const dumps = status?.dumps || [];
  const select = byId("symbolgen-dump-select");
  if (select) {
    select.innerHTML = dumps.length
      ? dumps.map(item => `<option value="${esc(item.memory_artifact_id)}">${esc(item.memory_artifact_id)} | ${esc(item.required_kernel || "unknown kernel")} | ${esc(item.status)}</option>`).join("")
      : `<option value="">No memory artifacts found</option>`;
  }
  const panel = byId("symbolgen-inventory-panel");
  if (panel) {
    const lines = [];
    lines.push(`Host symbol store: ${status.linux_dir || "not_available"}`);
    lines.push(`Available symbols on host: ${(status.symbols || []).length}`);
    if (dumps.length) {
      lines.push("");
      dumps.forEach(item => {
        lines.push(`- ${item.memory_artifact_id}`);
        lines.push(`  node=${item.target_node_name || "unknown"} ip=${item.target_ip || "unknown"} kernel=${item.required_kernel || "unknown"} status=${item.status}`);
        if (item.symbol_candidates?.length) {
          lines.push(`  symbol=${item.symbol_candidates[0].path}`);
        } else if (item.reason) {
          lines.push(`  reason=${item.reason}`);
        }
      });
    }
    panel.textContent = lines.join("\n");
  }
  byId("symbolgen-report-panel").textContent = JSON.stringify(status, null, 2);
}

async function pollSymbolGenerationJob(caseId, jobId) {
  const panel = byId("symbolgen-report-panel");
  const statusLabel = byId("symbolgen-status");
  for (;;) {
    const res = await fetchJson(`${API}/cases/${encodeURIComponent(caseId)}/symbols/jobs/${encodeURIComponent(jobId)}`);
    if (panel) panel.textContent = JSON.stringify(res, null, 2);
    if (statusLabel) statusLabel.textContent = res.status ? `status: ${res.status}` : "running";
    if (["completed", "failed", "blocked"].includes(res.status)) {
      await loadSymbolGenerationStatus().catch(() => {});
      return res;
    }
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
}

async function cancelCaseAnalysis(caseId) {
    if (!caseId) return;
    const btn = byId("analysis-cancel-btn");
    try {
      if (btn) { btn.disabled = true; btn.textContent = "Cancelling…"; }
      const url = `${API}/cases/${encodeURIComponent(caseId)}/analysis/cancel`;
      const res = await fetch(url, { method: "POST" });
      let json = null;
      try { json = await res.json(); } catch (e) { json = { status: res.status }; }
      const debugPanel = byId("analysis-debug-panel");
      if (debugPanel) debugPanel.innerHTML += `<div class="mt-4"><strong>cancel_request:</strong><div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(JSON.stringify(json, null, 2))}</div></div>`;
      // refresh status
      try {
        const status = await fetchCaseAnalysisStatus(caseId);
        renderAnalysisModal(status, {
          logs: FOC.analysisVisualState.currentLogs || null,
          report: FOC.analysisVisualState.currentReport || null,
          visualSummary: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentSummary || null) : null,
        });
      } catch (_) {}
      return json;
    } catch (err) {
      const debugPanel = byId("analysis-debug-panel");
      if (debugPanel) debugPanel.innerHTML += `<div class="mt-4"><strong>cancel_request_error:</strong><div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(String(err))}</div></div>`;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "Stop Analysis"; }
  }
}

function analysisLabel(kind, value) {
  const normalized = String(value || "").toLowerCase();
  if (kind === "execution") {
    if (normalized === "completed") return "Finished";
    if (normalized === "partial") return "Finished with limitations";
    if (normalized === "running") return "Running";
    if (normalized === "failed") return "Failed";
    if (normalized === "cancelled") return "Cancelled";
    return titleizeStatus(value);
  }
  if (kind === "evidence") {
    if (normalized === "mostly_completed") return "Mostly completed";
    if (normalized === "completed") return "Completed";
    if (normalized === "partial") return "Partial";
    if (normalized === "failed") return "Failed";
    return titleizeStatus(value);
  }
  if (kind === "reconstruction") {
    if (normalized === "partial") return "Partial";
    if (normalized === "completed") return "Completed";
    if (normalized === "not_started") return "Not generated";
    return titleizeStatus(value);
  }
  if (kind === "confidence") {
    if (normalized === "limited") return "Limited";
    if (normalized === "constrained") return "Constrained";
    if (normalized === "strong") return "Strong";
    return titleizeStatus(value);
  }
  return titleizeStatus(value);
}

function layerBadge(state, label) {
  return `<span class="tag rounded-full px-2.5 py-1 text-[10px] font-black tracking-[0.14em] uppercase ${visualStateClass(state)}">${esc(label)}</span>`;
}

function renderEvidenceCoverageRing(summary) {
  const layers = [
    ["alerts", "Alerts", summary.layer_statuses?.alerts_detection_analysis],
    ["chain_of_custody", "Custody", summary.layer_statuses?.integrity_custody_validation],
    ["disk", "Disk", summary.layer_statuses?.disk_analysis],
    ["memory", "Memory", summary.layer_statuses?.memory_analysis],
    ["network", "Network", summary.layer_statuses?.network_analysis],
    ["ot_exports", "OT", summary.layer_statuses?.ot_export_analysis],
    ["time_sync", "Time", summary.layer_statuses?.temporal_validation],
    ["timeline", "Timeline", summary.layer_statuses?.unified_forensic_timeline],
    ["cross_layer_findings", "Cross-layer", summary.layer_statuses?.cross_layer_findings],
  ];
  const radius = 128;
  const center = 170;
  const nodes = layers.map(([, label, layer], index) => {
    const angle = (-90 + (360 / layers.length) * index) * (Math.PI / 180);
    const x = center + Math.cos(angle) * radius;
    const y = center + Math.sin(angle) * radius;
    const state = layer?.visual_state || "unavailable";
    return `
      <div style="position:absolute;left:${x - 42}px;top:${y - 20}px;width:84px"
           class="text-center">
        <div class="mx-auto rounded-full border px-2 py-2 text-[10px] font-black tracking-[0.12em] uppercase ${visualStateClass(state)}" style="background:rgba(15,23,42,0.86);border-color:rgba(148,163,184,0.16)">${esc(label)}</div>
      </div>
    `;
  }).join("");
  return `
    <div class="relative mx-auto" style="width:340px;height:340px">
      <div class="absolute inset-0 rounded-full border" style="border-color:rgba(148,163,184,0.12)"></div>
      <div class="absolute inset-[42px] rounded-full border" style="border-color:rgba(148,163,184,0.08)"></div>
      ${nodes}
      <div class="absolute" style="left:${center - 64}px;top:${center - 64}px;width:128px;height:128px">
        <div class="h-full w-full rounded-full border flex flex-col items-center justify-center text-center px-4" style="background:rgba(8,15,28,0.96);border-color:rgba(148,163,184,0.18)">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Case</div>
          <div class="text-sm font-black mt-2">${esc(summary.case_id || "unknown")}</div>
          <div class="text-[11px] text-slate-400 mt-1">${esc(analysisLabel("reconstruction", summary.forensic_reconstruction_status))}</div>
        </div>
      </div>
    </div>
  `;
}

function renderStructuralGraph(summary) {
  const selectedId = FOC.analysisVisualState.selectedNodeId || summary.graph_nodes?.[0]?.id || "case";
  const nodes = Array.isArray(summary.graph_nodes) ? summary.graph_nodes : [];
  const selected = nodes.find(node => node.id === selectedId) || nodes[0] || null;
  const edges = (summary.graph_edges || []).filter(edge => edge.from === selected?.id || edge.to === selected?.id);
  return `
    <div class="grid grid-cols-1 xl:grid-cols-12 gap-4">
      <div class="xl:col-span-7">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          ${nodes.map(node => `
            <button data-visual-node="${esc(node.id)}" class="glass rounded-2xl p-4 text-left ${String(node.id) === String(selected?.id) ? "ring-2 ring-sky-500/60" : ""}">
              <div class="flex items-center justify-between gap-3">
                <div class="font-black">${esc(node.label)}</div>
                ${layerBadge(node.visual_state || "unavailable", node.type || "node")}
              </div>
              <div class="mt-2 text-xs text-slate-400">${esc(titleizeStatus(node.status || "unknown"))}</div>
              <div class="mt-2 text-xs text-slate-300">${esc(node.summary || "No summary")}</div>
            </button>
          `).join("")}
        </div>
        <div class="glass rounded-2xl p-4 mt-4">
          <div class="text-[11px] tracking-[0.18em] uppercase text-slate-400 font-black">Graph edges</div>
          <div class="mt-3 space-y-2">
            ${edges.length ? edges.map(edge => `
              <div class="text-xs text-slate-300 mono">${esc(edge.from)} -> ${esc(edge.to)} <span class="text-slate-500">(${esc(edge.label || "edge")})</span></div>
            `).join("") : '<div class="text-xs text-slate-500">No graph edges for the selected node.</div>'}
          </div>
        </div>
      </div>
      <div class="xl:col-span-5">
        <div class="glass rounded-2xl p-4">
          <div class="text-[11px] tracking-[0.18em] uppercase text-slate-400 font-black">Selected node</div>
          ${selected ? `
            <div class="flex items-center justify-between gap-3 mt-3">
              <div class="text-xl font-black">${esc(selected.label)}</div>
              ${layerBadge(selected.visual_state || "unavailable", selected.type || "node")}
            </div>
            <div class="mt-3 text-sm text-slate-300"><strong>status:</strong> ${esc(titleizeStatus(selected.status || "unknown"))}</div>
            <div class="mt-1 text-sm text-slate-300"><strong>summary:</strong> ${esc(selected.summary || "No summary available.")}</div>
            ${selected.id && summary.layer_statuses?.[selected.id] ? `
              <div class="mt-4 space-y-2 text-sm text-slate-300">
                <div><strong>effective status:</strong> ${esc(titleizeStatus(summary.layer_statuses[selected.id].effective_status || "unknown"))}</div>
                <div><strong>artifact path:</strong> <span class="mono text-xs text-slate-400">${esc(summary.layer_statuses[selected.id].artifact_path || "not_available")}</span></div>
                <div><strong>stdout log:</strong> <span class="mono text-xs text-slate-400">${esc(summary.layer_statuses[selected.id].stdout_log_path || "not_available")}</span></div>
                <div><strong>stderr log:</strong> <span class="mono text-xs text-slate-400">${esc(summary.layer_statuses[selected.id].stderr_log_path || "not_available")}</span></div>
                <div><strong>warning:</strong> ${esc(summary.layer_statuses[selected.id].warning || "none")}</div>
                <div><strong>limitation:</strong> ${esc(summary.layer_statuses[selected.id].short_limitation || "none")}</div>
              </div>
            ` : ""}
          ` : '<div class="mt-3 text-sm text-slate-500">No graph node selected.</div>'}
        </div>
      </div>
    </div>
  `;
}

function renderAnalysisVisualCockpit(summary, report) {
  if (!summary) {
    return '<div class="text-sm text-slate-500">No visual summary loaded.</div>';
  }
  const timelineMode = FOC.analysisVisualState.timelineMode || "pipeline";
  const pipelineEntries = Array.isArray(summary.pipeline_timeline_entries) ? summary.pipeline_timeline_entries : [];
  const forensicEntries = Array.isArray(summary.forensic_timeline_entries) ? summary.forensic_timeline_entries : [];
  const timelineEntries = timelineMode === "forensic" ? forensicEntries : pipelineEntries;
  const matrixRows = Object.values(summary.layer_statuses || {});
  const executionNarrative = String(summary.execution_status || "").toLowerCase() === "running"
    ? "Pipeline execution is still running. Evidence-analysis and reconstruction indicators below are provisional until the final phases complete."
    : "Pipeline execution completed, but forensic reconstruction remains partial because some layers are partial and semantic or causal reconstruction have not yet been generated.";
  return `
    <div class="space-y-5">
      <div class="glass rounded-[24px] p-5">
        <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Multilayer Forensic Evidence Cockpit</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Case ID</div>
            <div class="mono text-sm font-black mt-2">${esc(summary.case_id || "unknown")}</div>
            <div class="text-xs text-slate-400 mt-2">Analysis ID: ${esc(summary.analysis_id || "not_available")}</div>
          </div>
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Execution status</div>
            <div class="text-xl font-black mt-2 ${statusClass(summary.execution_status)}">${esc(analysisLabel("execution", summary.execution_status))}</div>
            <div class="text-xs text-slate-400 mt-2">Progress: ${esc(summary.progress_percent ?? 0)}%</div>
          </div>
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Evidence analysis</div>
            <div class="text-xl font-black mt-2 ${statusClass(summary.evidence_analysis_status)}">${esc(analysisLabel("evidence", summary.evidence_analysis_status))}</div>
            <div class="text-xs text-slate-400 mt-2">Forensic reconstruction: ${esc(analysisLabel("reconstruction", summary.forensic_reconstruction_status))}</div>
          </div>
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Scientific confidence</div>
            <div class="text-xl font-black mt-2 ${statusClass(summary.confidence_state)}">${esc(analysisLabel("confidence", summary.confidence_state))}</div>
            <div class="text-xs text-slate-400 mt-2">Report: <span class="mono">${esc(summary.generated_report_path || "not_available")}</span></div>
          </div>
        </div>
        <div class="glass-soft rounded-2xl p-4 mt-4 text-sm text-slate-300">
          <strong>Main limitation:</strong> ${esc(summary.main_limitation || "No main limitation recorded.")}
        </div>
        <div class="mt-3 text-xs text-slate-400">${esc(executionNarrative)}</div>
      </div>

      <div class="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div class="glass rounded-[24px] p-5 xl:col-span-7">
          <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Layer status matrix</div>
          <div class="space-y-3 mt-4">
            ${matrixRows.map(layer => `
              <div class="glass-soft rounded-2xl p-4">
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <div class="font-black">${esc(layer.label || layer.phase)}</div>
                    <div class="text-xs text-slate-400 mt-1">artifact: <span class="mono">${esc(layer.artifact_path || "not_available")}</span></div>
                  </div>
                  <div class="flex flex-wrap gap-2 justify-end">
                    ${layerBadge(layer.visual_state || "unavailable", layer.status || "unknown")}
                    ${layerBadge(layer.visual_state || "unavailable", layer.effective_status || "unknown")}
                  </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3 text-xs text-slate-300">
                  <div>stdout: <span class="mono text-slate-400">${esc(layer.stdout_log_path || "not_available")}</span></div>
                  <div>stderr: <span class="mono text-slate-400">${esc(layer.stderr_log_path || "not_available")}</span></div>
                </div>
                <div class="mt-3 text-sm text-slate-300"><strong>summary:</strong> ${esc(layer.summary || "No summary.")}</div>
                <div class="mt-1 text-sm text-slate-400"><strong>limitation:</strong> ${esc(layer.short_limitation || layer.warning || "none")}</div>
              </div>
            `).join("")}
          </div>
        </div>
        <div class="glass rounded-[24px] p-5 xl:col-span-5">
          <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Evidence coverage ring</div>
          <div class="mt-4">${renderEvidenceCoverageRing(summary)}</div>
        </div>
      </div>

      <div class="glass rounded-[24px] p-5">
        <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Structural-evidential analysis graph</div>
        <div class="mt-4">${renderStructuralGraph(summary)}</div>
      </div>

      <div class="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div class="glass rounded-[24px] p-5 xl:col-span-7">
          <div class="flex items-center justify-between gap-3">
            <div>
              <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Timeline panel</div>
              <div class="text-sm text-slate-300 mt-2">Switch between pipeline execution chronology and preserved forensic events.</div>
            </div>
            <div class="flex gap-2">
              <button data-analysis-timeline-mode="pipeline" class="btn-secondary rounded-xl px-3 py-2 text-[11px] font-extrabold tracking-[0.14em] uppercase ${timelineMode === "pipeline" ? "ring-2 ring-sky-500/60" : ""}">Pipeline execution</button>
              <button data-analysis-timeline-mode="forensic" class="btn-secondary rounded-xl px-3 py-2 text-[11px] font-extrabold tracking-[0.14em] uppercase ${timelineMode === "forensic" ? "ring-2 ring-sky-500/60" : ""}">Forensic events</button>
            </div>
          </div>
          <div class="space-y-3 mt-4">
            ${timelineEntries.length ? timelineEntries.map(item => `
              <div class="glass-soft rounded-2xl p-4">
                <div class="flex items-center justify-between gap-3">
                  <div class="font-black">${esc(item.label || item.event || item.phase || "entry")}</div>
                  <div class="text-xs uppercase tracking-[0.12em] ${statusClass(item.status || "unknown")}">${esc(item.status || item.source || "unknown")}</div>
                </div>
                <div class="mt-2 text-xs text-slate-400">started: ${esc(item.started_at || item.timestamp || "not_available")}</div>
                <div class="mt-1 text-xs text-slate-400">finished: ${esc(item.finished_at || "not_available")}</div>
                ${item.artifact_path ? `<div class="mt-1 text-xs text-slate-400 mono">${esc(item.artifact_path)}</div>` : ""}
                ${item.details ? `<div class="mt-2 text-xs text-slate-300 mono whitespace-pre-wrap">${esc(JSON.stringify(item.details, null, 2))}</div>` : ""}
              </div>
            `).join("") : `<div class="text-sm text-slate-500">${timelineMode === "forensic" ? "Unified forensic timeline has not been generated yet." : "No pipeline execution timeline entries are available."}</div>`}
          </div>
        </div>
        <div class="glass rounded-[24px] p-5 xl:col-span-5">
          <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Limitations</div>
          <div class="space-y-2 mt-4">
            ${(summary.blockers || []).map(item => `<div class="glass-soft rounded-2xl p-3 text-sm text-amber-300">${esc(item)}</div>`).join("") || '<div class="text-sm text-slate-500">No blockers recorded.</div>'}
            ${(summary.main_warnings || []).map(item => `<div class="glass-soft rounded-2xl p-3 text-sm text-slate-300">${esc(item)}</div>`).join("")}
            ${(summary.visual_recommendations || []).map(item => `<div class="text-xs text-slate-400">${esc(item)}</div>`).join("")}
            <div class="glass-soft rounded-2xl p-3 text-sm text-slate-400">Semantic reconstruction: not generated</div>
            <div class="glass-soft rounded-2xl p-3 text-sm text-slate-400">Causal reconstruction: blocked or not generated</div>
          </div>
        </div>
      </div>

      <details class="glass rounded-[24px] p-5">
        <summary class="cursor-pointer text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Raw technical report access</summary>
        <div class="grid grid-cols-1 xl:grid-cols-2 gap-4 mt-4">
          <div class="glass-soft rounded-2xl p-4">
            <div class="font-black">Visual summary JSON</div>
            <div class="mono text-xs text-slate-300 mt-3 whitespace-pre-wrap">${esc(JSON.stringify(summary, null, 2))}</div>
          </div>
          <div class="glass-soft rounded-2xl p-4">
            <div class="font-black">Forensic analysis report JSON</div>
            <div class="mono text-xs text-slate-300 mt-3 whitespace-pre-wrap">${esc(JSON.stringify(report || {}, null, 2))}</div>
          </div>
        </div>
      </details>
    </div>
  `;
}

function renderAnalysisReportPlaceholder(status) {
  const normalized = String(status?.status || "not_started").toLowerCase();
  const missingOutputs = Object.entries(status?.phases || {})
    .filter(([, phase]) => {
      const phaseStatus = String(phase?.status || "");
      return ["completed", "partial"].some(prefix => phaseStatus.startsWith(prefix)) && !phase?.output_path;
    })
    .map(([key, phase]) => `${phase.label || key}: missing output artifact`);

  let title = "Visual report available on demand";
  let body = "Press `View Report` to generate and load the Multilayer Forensic Evidence Cockpit for this case.";
  if (normalized === "not_started") {
    title = "No completed analysis is available yet";
    body = "No multilayer forensic analysis has been executed for this case yet, so there is no visual cockpit to display.";
  } else if (normalized === "running") {
    title = "Analysis is still running";
    body = `The multilayer analysis is still running at ${status?.progress_percent ?? 0}% in phase \`${status?.current_phase || "unknown"}\`. Press \`View Report\` again to request the latest available cockpit once outputs exist.`;
  } else if (!status?.forensic_analysis_report_path && !status?.analysis_visual_summary_path) {
    title = "Analysis finished but no visual report is ready";
    body = "The pipeline has status information, but the visual report outputs are not yet available. Validate outputs or inspect missing phase artifacts before requesting the cockpit.";
  }

  return `
    <div class="glass rounded-[24px] p-5">
      <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Multilayer Forensic Evidence Cockpit</div>
      <div class="text-xl font-black mt-3">${esc(title)}</div>
      <div class="text-sm text-slate-300 mt-3">${esc(body)}</div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Execution state</div>
          <div class="mt-2 text-sm text-slate-300">status: <span class="${statusClass(status?.status)}">${esc(titleizeStatus(status?.status || "unknown"))}</span></div>
          <div class="mt-1 text-sm text-slate-300">progress: ${esc(status?.progress_percent ?? 0)}%</div>
          <div class="mt-1 text-sm text-slate-300">current phase: ${esc(status?.current_phase || "not_available")}</div>
        </div>
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Known report outputs</div>
          <div class="mt-2 text-xs text-slate-400 mono">report: ${esc(status?.forensic_analysis_report_path || "not_available")}</div>
          <div class="mt-1 text-xs text-slate-400 mono">visual summary: ${esc(status?.analysis_visual_summary_path || "not_available")}</div>
        </div>
      </div>
      <div class="glass-soft rounded-2xl p-4 mt-4">
        <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Missing or incomplete items</div>
        <div class="mt-3 space-y-2">
          ${(missingOutputs.length ? missingOutputs : [])
            .map(item => `<div class="text-sm text-amber-300">${esc(item)}</div>`).join("") || '<div class="text-sm text-slate-400">No explicit missing derived outputs detected from the current status payload.</div>'}
          ${(status?.errors || []).slice(0, 6).map(item => `<div class="text-sm text-red-300">${esc(`${item.phase}: ${item.error_message || item.message || "unknown error"}`)}</div>`).join("")}
          ${(status?.warnings || []).slice(0, 6).map(item => `<div class="text-sm text-slate-300">${esc(`${item.phase}: ${item.message || "warning"}`)}</div>`).join("")}
        </div>
      </div>
    </div>
  `;
}

function renderAnalysisReportModal(status, extras = {}) {
  const panel = byId("analysis-report-modal-panel");
  const title = byId("analysis-report-modal-title");
  const subtitle = byId("analysis-report-modal-subtitle");
  if (!panel) return;
  const caseId = status?.case_id || FOC.selectedCaseId || "unknown";
  const caseEntry = (FOC.cases?.cases || []).find(item => item.case_id === caseId);
  const caseName = caseEntry?.source_case_name || FOC.analysisVisualState.currentCaseEntryName || caseId;
  if (title) title.textContent = `Analysis Report: ${caseName}`;
  if (subtitle) {
    if (String(status?.status || "").toLowerCase() === "running") {
      subtitle.textContent = `Analysis is still running at ${status?.progress_percent ?? 0}% in phase ${status?.current_phase || "unknown"}. The report panel shows the latest available derived status without forcing new forensic execution.`;
    } else if (String(status?.status || "").toLowerCase() === "not_started") {
      subtitle.textContent = "No multilayer analysis has been executed yet. Run analysis first, then request the report on demand.";
    } else {
      subtitle.textContent = "This wide transparent window renders the on-demand multilayer forensic evidence cockpit and related technical context.";
    }
  }
  const report = extras.report || null;
  const visualSummary = extras.visualSummary || null;
  FOC.analysisVisualState.currentReport = report;
  FOC.analysisVisualState.currentSummary = visualSummary;
  panel.innerHTML = (visualSummary || report)
    ? renderAnalysisVisualCockpit(visualSummary, report)
    : renderAnalysisReportPlaceholder(status);
}

function renderCausalReportPlaceholder(status) {
  const normalized = String(status?.status || "not_available").toLowerCase();
  let title = "Causal reconstruction not generated";
  let body = "Run causal reconstruction on demand to derive CPR, uncertainty and edge support from preserved FOC artifacts.";
  if (normalized === "running") {
    title = "Causal reconstruction is running";
    body = `The derived causal reconstruction is still running at ${status?.progress_percent ?? 0}% in step \`${status?.current_step || "unknown"}\`.`;
  } else if (normalized === "blocked_missing_ground_truth") {
    title = "Ground truth is missing or incomplete";
    body = status?.reason || "Causal reconstruction is blocked because scenario_ground_truth.json is missing or does not define expected edges.";
  } else if (normalized === "blocked_missing_analysis") {
    title = "Multilayer forensic analysis is missing";
    body = status?.reason || "Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.";
  } else if (normalized === "completed" || normalized === "completed_with_degradation") {
    title = "Causal reconstruction outputs are available";
    body = status?.reason || "Open the derived artifacts and KPI cockpit below.";
  } else if (normalized === "failed") {
    title = "Causal reconstruction failed";
    body = status?.reason || "Review requirements, outputs and the preserved prerequisites.";
  }
  const req = status?.requirements || {};
  const gts = status?.ground_truth_summary || {};
  return `
    <div class="glass rounded-[24px] p-5">
      <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Causal Reconstruction</div>
      <div class="text-xl font-black mt-3">${esc(title)}</div>
      <div class="text-sm text-slate-300 mt-3">${esc(body)}</div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Execution status</div>
          <div class="mt-2 text-sm font-black ${statusClass(status?.execution_status)}">${esc(titleizeStatus(status?.execution_status || "not_started"))}</div>
          <div class="mt-1 text-xs text-slate-400">Execution progress: ${esc(status?.progress_percent ?? 0)}% — current step: ${esc(status?.current_step || "not_available")}</div>
        </div>
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Reconstruction state</div>
          <div class="mt-2 text-sm font-black ${statusClass(status?.reconstruction_state)}">${esc(titleizeStatus(status?.reconstruction_state || "not_available"))}</div>
          <div class="mt-1 text-xs text-slate-400">Quality of the causal reconstruction produced, independent of execution.</div>
        </div>
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Scientific confidence</div>
          <div class="mt-2 text-sm font-black ${statusClass(status?.scientific_confidence)}">${esc(titleizeStatus(status?.scientific_confidence || "unknown"))}</div>
          <div class="mt-1 text-xs text-slate-400">Interpretive weight this result can carry, never an absolute proof of causality.</div>
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Requirements</div>
          <div class="mt-2 text-xs text-slate-300">foc_context_available: ${esc(String(req.foc_context_available ?? false))}</div>
          <div class="mt-1 text-xs text-slate-300">evidence_links_present: ${esc(String(req.evidence_links_present ?? false))}</div>
          <div class="mt-2 text-xs text-slate-300">manifest_present: ${esc(String(req.manifest_present ?? false))}</div>
          <div class="mt-1 text-xs text-slate-300">chain_of_custody_present: ${esc(String(req.chain_of_custody_present ?? false))}</div>
          <div class="mt-1 text-xs text-slate-300">analysis_report_present: ${esc(String(req.analysis_report_present ?? false))}</div>
          <div class="mt-1 text-xs text-slate-300">analysis_visual_summary_present: ${esc(String(req.analysis_visual_summary_present ?? false))}</div>
        </div>
        <div class="glass-soft rounded-2xl p-4">
          <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Ground truth</div>
          <div class="mt-2 text-xs text-slate-300">status: ${esc(gts.ground_truth_status || req.ground_truth_status || "unknown")}</div>
          <div class="mt-1 text-xs text-slate-300">validation: ${esc(gts.ground_truth_validation_status || "unknown")}</div>
          <div class="mt-1 text-xs text-slate-300">version: ${esc(gts.ground_truth_version || "not_available")}</div>
          <div class="mt-1 text-xs text-slate-300">scenario_id: ${esc(gts.scenario_id || "unknown")}</div>
          <div class="mt-1 text-xs text-slate-300">expected_edges: ${esc(gts.expected_edges ?? "na")}</div>
          <div class="mt-1 text-xs text-slate-300 mono break-all">path: ${esc(gts.ground_truth_path || req.ground_truth_path || "not_available")}</div>
        </div>
      </div>
      <div class="glass-soft rounded-2xl p-4 mt-4">
        <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Checked ground truth paths</div>
        <div class="mt-3 text-xs text-slate-400 mono whitespace-pre-wrap">${esc((req.ground_truth_checked_paths || []).join("\n") || "not_available")}</div>
      </div>
    </div>
  `;
}

function renderCausalGraphPreview(graph) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (!nodes.length || !edges.length) {
    return `<div class="text-sm text-slate-500">No causal graph preview is available yet.</div>`;
  }
  const byIdMap = new Map(nodes.map(node => [node.node_id, node]));
  const truncatedBanner = graph?.truncated
    ? `<div class="text-xs text-amber-300 mb-2">Graph preview truncated to ${edges.length} of ${graph.total_edges ?? edges.length} edges and ${nodes.length} of ${graph.total_nodes ?? nodes.length} nodes. Showing a flat table view.</div>`
    : "";
  if (graph?.truncated) {
    return `
      ${truncatedBanner}
      <div class="overflow-x-auto">
        <table class="w-full text-xs text-slate-300">
          <thead><tr class="text-left text-slate-400"><th class="pr-3">Source</th><th class="pr-3">Target</th><th class="pr-3">Relation</th><th>Support</th></tr></thead>
          <tbody>
            ${edges.map(edge => {
              const source = byIdMap.get(edge.source);
              const target = byIdMap.get(edge.target);
              return `<tr><td class="pr-3">${esc(source?.label || edge.source)}</td><td class="pr-3">${esc(target?.label || edge.target)}</td><td class="pr-3">${esc(edge.relation_type || "")}</td><td class="${statusClass(edge.support_status)}">${esc(edge.support_status || "unknown")}</td></tr>`;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;
  }
  return `
    <div class="space-y-3">
      ${edges.map(edge => {
        const source = byIdMap.get(edge.source);
        const target = byIdMap.get(edge.target);
        const color = edge.support_status === "recovered"
          ? "text-emerald-300"
          : edge.support_status === "degraded"
            ? "text-amber-300"
            : edge.support_status === "ambiguous"
              ? "text-sky-300"
              : "text-red-300";
        return `
          <div class="glass-soft rounded-2xl p-4">
            <div class="flex items-center justify-between gap-3">
              <div class="font-black">${esc(source?.label || edge.source)} → ${esc(target?.label || edge.target)}</div>
              <div class="text-xs uppercase tracking-[0.12em] font-black ${color}">${esc(edge.support_status || "unknown")}</div>
            </div>
            <div class="mt-2 text-sm text-slate-300">${esc(edge.relation_type || "derived_relation")}</div>
            <div class="mt-2 text-xs text-slate-400">evidence: ${esc((edge.evidence_refs || []).join(", ") || "not_available")}</div>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function kpiSeverityClass(severity) {
  if (severity === "ok") return "status-confirmed";
  if (severity === "warning") return "status-degraded";
  if (severity === "critical") return "status-missing";
  return "status-unknown";
}

function renderCausalKpiCard(kpi) {
  return `
    <div class="glass-soft rounded-2xl p-4">
      <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">${esc(kpi.name)}</div>
      <div class="mt-2 text-xl font-black ${kpiSeverityClass(kpi.severity)}">${esc(kpi.value ?? "na")}</div>
      <div class="mt-1 text-xs text-slate-400">${esc(kpi.meaning || "")}</div>
      <div class="mt-1 text-xs text-slate-300">${esc(kpi.interpretation || "")}</div>
    </div>
  `;
}

function renderCausalEdgeMatrixDetail(graph) {
  const edges = graph?.edges || [];
  if (!edges.length) return `<div class="text-sm text-slate-500">No expected edges are available.</div>`;
  return `
    <div class="space-y-3">
      ${edges.map(edge => `
        <div class="glass-soft rounded-2xl p-4">
          <div class="flex items-center justify-between gap-3">
            <div>
              <div class="font-black">${esc(edge.edge_id)}</div>
              <div class="text-xs text-slate-400 mt-1">${esc(edge.relation_type)}</div>
            </div>
            <div class="flex flex-wrap gap-2">
              ${tag("support", edge.support_status || "unknown", statusClass(edge.support_status))}
              ${tag("confidence", edge.confidence || "unknown", statusClass(edge.confidence))}
              ${tag("temporal", edge.temporal_status || "unknown", statusClass(edge.temporal_status))}
            </div>
          </div>
          <div class="mt-3 text-sm text-slate-300">${esc(edge.meaning || "")}</div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3 text-xs text-slate-300">
            <div>Required evidence: <span class="mono">${esc((edge.required_evidence || []).join(", ") || "none")}</span></div>
            <div>Evidence found: <span class="mono">${esc((edge.evidence_refs || []).join(", ") || "not_available")}</span></div>
            <div>Evidence missing: <span class="mono">${esc((edge.missing_evidence || []).join(", ") || "none")}</span></div>
            <div>Semantic check: <span class="mono">${esc(edge.semantic_status || "unknown")}</span></div>
            <div>Temporal check: <span class="mono">${esc(edge.temporal_status || "unknown")}</span></div>
            <div>Graph-artifact integrity: <span class="mono">${esc(edge.graph_artifact_integrity_status || edge.integrity_status || "unknown")}</span></div>
            <div>Case-wide integrity: <span class="mono">${esc(edge.case_wide_integrity_status || "unknown")}</span></div>
          </div>
          <div class="mt-3 text-sm text-slate-300"><strong>Why this status:</strong> ${esc(edge.status_reason || "not_available")}</div>
          <div class="mt-2 text-sm text-slate-400">${esc((edge.limitations || []).join(" | ") || "no additional limitations")}</div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderCausalUncertaintyDetail(uncertainty) {
  const t = uncertainty?.temporal || {};
  const c = uncertainty?.completeness || {};
  const i = uncertainty?.integrity || {};
  return `
    <div class="space-y-3">
      <div class="glass-soft rounded-2xl p-4 text-sm text-slate-300">
        <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Temporal uncertainty</div>
        <div class="mt-2"><strong>Sync status:</strong> ${esc(t.temporal_sync_status || "unknown")}</div>
        <div class="mt-2"><strong>Temporal confidence:</strong> ${esc(t.temporal_confidence_state || "unknown")}</div>
        <div class="mt-1"><strong>Uncertainty window:</strong> ${esc(t.uncertainty_window_seconds ?? "na")}s (${esc(t.uncertainty_window_ms ?? "na")}ms)</div>
        <div class="mt-1"><strong>Max clock offset:</strong> ${esc(t.max_clock_offset_seconds ?? "na")}s</div>
        <div class="mt-1"><strong>Synchronized:</strong> ${esc(String(t.synchronized ?? false))}</div>
        <div class="mt-1"><strong>Correction applied:</strong> ${esc(String(t.correction_applied ?? false))}</div>
        <div class="mt-1"><strong>Worst node:</strong> ${esc(t.worst_node?.name || "na")}</div>
        <div class="mt-1"><strong>Nodes measured / failed:</strong> ${esc(t.nodes_ok ?? 0)} / ${esc(t.nodes_failed ?? 0)}</div>
        <div class="mt-2 text-slate-400">${esc(t.temporal_limitation || "")}</div>
        ${t.temporal_warning ? `<div class="mt-2 text-amber-300 font-black">${esc(t.temporal_warning)}</div>` : ""}
        ${t.temporal_caution ? `<div class="mt-1 text-amber-200">${esc(t.temporal_caution)}</div>` : ""}
      </div>
      <div class="glass-soft rounded-2xl p-4 text-sm text-slate-300">
        <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Evidence completeness</div>
        <div class="mt-2"><strong>Ratio:</strong> ${esc(c.evidence_completeness_ratio ?? "na")} (${esc(c.recovered_expected_artifacts ?? "na")} / ${esc(c.expected_artifacts ?? "na")})</div>
        <div class="mt-1 text-slate-400">Missing: ${esc((c.missing_expected_artifacts || []).join(", ") || "none")}</div>
      </div>
      <div class="glass-soft rounded-2xl p-4 text-sm text-slate-300">
        <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Integrity and custody</div>
        <div class="mt-2"><strong>Graph-scope integrity ratio:</strong> ${esc(i.graph_scope_integrity_ratio ?? "na")} (${esc(i.artifacts_present ?? "na")} / ${esc(i.artifacts_used_by_graph ?? "na")} artifacts referenced by the graph)</div>
        <div class="mt-1"><strong>Case-wide integrity ratio:</strong> ${esc(i.case_wide_integrity_ratio ?? "na")} (${esc(i.case_manifest_hash_validated ?? "na")} / ${esc(i.case_manifest_artifacts_total ?? "na")} manifest artifacts)</div>
        <div class="mt-1"><strong>Graph-artifact integrity status:</strong> <span class="${statusClass(i.graph_artifact_integrity_status)}">${esc(i.graph_artifact_integrity_status || "unknown")}</span></div>
        <div class="mt-1"><strong>Case-wide integrity status:</strong> <span class="${statusClass(i.case_wide_integrity_status)}">${esc(i.case_wide_integrity_status || "unknown")}</span></div>
        <div class="mt-2 text-slate-400">${esc(i.integrity_limitation || "")}</div>
      </div>
    </div>
  `;
}

function renderCausalDetailSection(key, label, caseId, isExpanded, contentHtml) {
  return `
    <div class="glass rounded-[24px] p-5">
      <button type="button" class="w-full flex items-center justify-between gap-3 text-left" data-causal-detail="${esc(key)}" data-case-id="${esc(caseId)}">
        <span class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">${esc(label)}</span>
        <span class="text-xs text-slate-400 font-black">${isExpanded ? "Hide ▲" : "Show ▼"}</span>
      </button>
      ${isExpanded ? `<div class="mt-4">${contentHtml}</div>` : ""}
    </div>
  `;
}

function renderCausalCockpit(status) {
  const caseId = status?.case_id || FOC.causalVisualState.currentCaseId || FOC.selectedCaseId || "unknown";
  const metricsPreview = status?.metrics_preview || {};
  const kpis = metricsPreview.kpis || [];
  const outputs = status?.outputs || {};
  const gts = status?.ground_truth_summary || {};
  const expanded = FOC.causalVisualState.expandedDetails || {};
  const graphSummary = FOC.causalVisualState.cachedGraphSummary || null;
  const uncertainty = FOC.causalVisualState.cachedUncertainty || null;
  const markdown = FOC.causalVisualState.cachedMarkdown || null;
  const warnings = status?.warnings || [];

  const staleBanner = status?.is_stale
    ? `<div class="glass-soft rounded-2xl p-4 mt-4 text-sm text-amber-300 flex items-center justify-between gap-3">
        <span>Causal reconstruction is stale because analysis outputs were modified after causal artifacts were generated.</span>
        <button type="button" class="px-3 py-1.5 rounded-xl bg-amber-500/20 text-amber-200 font-black text-xs shrink-0" data-causal-regenerate="1" data-case-id="${esc(caseId)}">Regenerate Causal Reconstruction</button>
      </div>`
    : "";

  const warningsBanner = warnings.length
    ? `<div class="glass-soft rounded-2xl p-4 mt-4 text-sm text-amber-300 space-y-1">${warnings.map(w => `<div>${esc(w)}</div>`).join("")}</div>`
    : "";

  return `
    <div class="space-y-5">
      <div class="glass rounded-[24px] p-5">
        <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Executive Status</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mt-4 text-sm">
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Execution status</div>
            <div class="mt-2 font-black ${statusClass(status?.execution_status)}">${esc(titleizeStatus(status?.execution_status || "not_started"))}</div>
            <div class="mt-2 text-slate-300">Execution progress: ${esc(status?.progress_percent ?? 100)}%</div>
            <div class="mt-1 text-slate-300">Current step: ${esc(status?.current_step || "completed")}</div>
          </div>
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Reconstruction state</div>
            <div class="mt-2 font-black ${statusClass(status?.reconstruction_state)}">${esc(titleizeStatus(status?.reconstruction_state || "not_available"))}</div>
            <div class="mt-1 text-slate-300">Temporal confidence: ${esc(metricsPreview.temporal_confidence_state || "unknown")}</div>
          </div>
          <div class="glass-soft rounded-2xl p-4">
            <div class="text-[10px] uppercase tracking-[0.18em] text-slate-400 font-black">Scientific confidence</div>
            <div class="mt-2 font-black ${statusClass(status?.scientific_confidence)}">${esc(titleizeStatus(status?.scientific_confidence || "unknown"))}</div>
            <div class="mt-1 text-slate-300">Never an absolute proof of causality.</div>
          </div>
        </div>
        <div class="glass-soft rounded-2xl p-4 mt-4 text-sm text-slate-300">${esc(metricsPreview.interpretation || status?.reason || "not_available")}</div>
        ${warningsBanner}
        ${staleBanner}
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div class="glass rounded-[24px] p-5">
          <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Ground Truth</div>
          <div class="mt-3 text-sm text-slate-300 space-y-1">
            <div>status: <span class="${statusClass(gts.ground_truth_status)}">${esc(gts.ground_truth_status || "unknown")}</span></div>
            <div>validation: ${esc(gts.ground_truth_validation_status || "unknown")}</div>
            <div>version: ${esc(gts.ground_truth_version || "not_available")}</div>
            <div>scenario_id: ${esc(gts.scenario_id || "unknown")}</div>
            <div>expected_edges: ${esc(gts.expected_edges ?? "na")}</div>
            <div>loaded_at: ${esc(gts.ground_truth_loaded_at || "not_available")}</div>
            <div class="mono text-xs text-slate-400 break-all">path: ${esc(gts.ground_truth_path || "not_available")}</div>
          </div>
        </div>
        <div class="glass rounded-[24px] p-5">
          <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Derived Outputs</div>
          <div class="mt-3 text-xs text-slate-300 mono space-y-1">
            ${Object.entries(outputs).map(([key, entry]) => `<div>${esc(key)}: <span class="${statusClass(entry.status)}">${esc(entry.status)}</span> (${esc(entry.path || "not_available")})</div>`).join("") || '<div>not_available</div>'}
          </div>
        </div>
      </div>

      <div class="glass rounded-[24px] p-5">
        <div class="text-[11px] tracking-[0.22em] uppercase text-slate-400 font-black">Causal Reconstruction KPIs</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 mt-4">
          ${kpis.map(renderCausalKpiCard).join("") || '<div class="text-sm text-slate-500">KPI metadata is not available; re-run causal reconstruction to populate it.</div>'}
        </div>
      </div>

      ${renderCausalDetailSection("edges", "Edge status matrix", caseId, !!expanded.edges, graphSummary ? renderCausalEdgeMatrixDetail(graphSummary) : '<div class="text-sm text-slate-400">Loading…</div>')}
      ${renderCausalDetailSection("uncertainty", "Uncertainty budget", caseId, !!expanded.uncertainty, uncertainty ? renderCausalUncertaintyDetail(uncertainty) : '<div class="text-sm text-slate-400">Loading…</div>')}
      ${renderCausalDetailSection("graph", "Causal graph preview", caseId, !!expanded.graph, graphSummary ? renderCausalGraphPreview(graphSummary) : '<div class="text-sm text-slate-400">Loading…</div>')}
      ${renderCausalDetailSection("report", "Raw markdown report", caseId, !!expanded.report, markdown !== null ? `<div class="glass-soft rounded-2xl p-4 mono text-xs text-slate-300 whitespace-pre-wrap">${esc(markdown || "not_available")}</div>` : '<div class="text-sm text-slate-400">Loading… (this section is the heaviest, fetched on demand)</div>')}
    </div>
  `;
}

// Each detail section fetches only what it needs, independently and lazily,
// on first expand - opening one section never triggers a fetch for another.
async function ensureCausalUncertaintyLoaded(caseId) {
  if (FOC.causalVisualState.cachedUncertainty) return FOC.causalVisualState.cachedUncertainty;
  const data = await fetchJson(causalUncertaintyUrl(caseId)).catch(() => null);
  FOC.causalVisualState.cachedUncertainty = data;
  return data;
}

async function ensureCausalGraphSummaryLoaded(caseId) {
  if (FOC.causalVisualState.cachedGraphSummary) return FOC.causalVisualState.cachedGraphSummary;
  const data = await fetchJson(causalGraphSummaryUrl(caseId)).catch(() => null);
  FOC.causalVisualState.cachedGraphSummary = data;
  return data;
}

// The raw markdown report only lives in the bundled /report endpoint - this
// is the one section explicitly allowed to be heavier, per spec.
async function ensureCausalMarkdownLoaded(caseId) {
  if (FOC.causalVisualState.cachedMarkdown !== null) return FOC.causalVisualState.cachedMarkdown;
  const report = await fetchJson(causalReportUrl(caseId)).catch(() => null);
  const markdown = report?.report_markdown ?? "not_available";
  FOC.causalVisualState.cachedMarkdown = markdown;
  return markdown;
}

const CAUSAL_DETAIL_LOADERS = {
  edges: ensureCausalGraphSummaryLoaded,
  graph: ensureCausalGraphSummaryLoaded,
  uncertainty: ensureCausalUncertaintyLoaded,
  report: ensureCausalMarkdownLoaded,
};

async function toggleCausalDetail(caseId, key) {
  const expanded = FOC.causalVisualState.expandedDetails;
  expanded[key] = !expanded[key];
  renderCausalReportModal(FOC.causalVisualState.currentStatus);
  const loader = CAUSAL_DETAIL_LOADERS[key];
  if (expanded[key] && loader) {
    await loader(caseId);
    renderCausalReportModal(FOC.causalVisualState.currentStatus);
  }
}

function renderCausalReportModal(status) {
  const panel = byId("causal-report-modal-panel");
  const title = byId("causal-report-modal-title");
  const subtitle = byId("causal-report-modal-subtitle");
  if (!panel) return;
  const caseId = status?.case_id || FOC.selectedCaseId || "unknown";
  const caseEntry = (FOC.cases?.cases || []).find(item => item.case_id === caseId);
  const caseName = caseEntry?.source_case_name || caseId;
  if (title) title.textContent = `Causal Reconstruction: ${caseName}`;
  if (subtitle) {
    if (String(status?.status || "").toLowerCase() === "running") {
      subtitle.textContent = `Causal reconstruction is running at ${status?.progress_percent ?? 0}% in step ${status?.current_step || "unknown"}.`;
    } else {
      subtitle.textContent = "This wide transparent window renders the on-demand causal reconstruction cockpit derived from preserved FOC and multilayer analysis artifacts. It is not a live monitoring view.";
    }
  }
  FOC.causalVisualState.currentCaseId = caseId;
  FOC.causalVisualState.currentStatus = status;
  const hasCockpitData = status && (status.outputs || status.ground_truth_summary || status.metrics_preview);
  panel.innerHTML = hasCockpitData ? renderCausalCockpit(status) : renderCausalReportPlaceholder(status);
}

async function fetchCausalStatus(caseId) {
  return fetchJson(causalStatusUrl(caseId));
}

function scheduleCausalPolling(caseId) {
  stopCausalPolling();
  FOC.causalPollTimer = setTimeout(async () => {
    try {
      const status = await fetchCausalStatus(caseId);
      renderCausalReportModal(status);
      if (status.status === "running") {
        scheduleCausalPolling(caseId);
      } else {
        await loadAll(true);
      }
    } catch (_) {
      scheduleCausalPolling(caseId);
    }
  }, ANALYSIS_STATUS_POLL_MS);
}

// Only causal_status.json is fetched on open - it already carries the KPI
// summary, ground truth block and derived-outputs map. Each detail section
// (edges/graph, uncertainty, raw report) fetches its own narrow endpoint
// lazily, once, the first time it is expanded (see toggleCausalDetail).
function _resetCausalDetailCaches() {
  FOC.causalVisualState.cachedUncertainty = null;
  FOC.causalVisualState.cachedGraphSummary = null;
  FOC.causalVisualState.cachedMarkdown = null;
  FOC.causalVisualState.expandedDetails = {};
}

async function viewCausalReconstruction(caseId) {
  openCausalReportModalShell();
  _resetCausalDetailCaches();
  const status = await fetchCausalStatus(caseId);
  FOC.selectedCaseId = caseId;
  renderCausalReportModal(status);
  if (status.status === "running") {
    scheduleCausalPolling(caseId);
  }
}

async function runCausalReconstruction(caseId) {
  openCausalReportModalShell();
  _resetCausalDetailCaches();
  renderCausalReportModal({ case_id: caseId, status: "running", progress_percent: 0, current_step: "queued", reason: "Starting background causal reconstruction…" });
  const result = await fetchJson(causalRunUrl(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ case_id: caseId, degraded_ok: true }),
  }).catch(async () => {
    return fetchCausalStatus(caseId);
  });
  renderCausalReportModal(result);
  if (result.status === "running") {
    scheduleCausalPolling(caseId);
  } else {
    await loadAll(true);
  }
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
  const cancelBtn = byId("analysis-cancel-btn");
  if (!statusPanel || !phasesPanel || !debugPanel || !layersPanel || !reportPanel) return;
  FOC.analysisVisualState.currentCaseId = caseId;
  FOC.analysisVisualState.currentStatus = status;
  FOC.analysisVisualState.currentLogs = extras.logs || null;
  FOC.analysisVisualState.currentReport = extras.report || null;
  FOC.analysisVisualState.currentSummary = extras.visualSummary || null;
  FOC.caseAnalysisStatuses[caseId] = status;

  const caseEntry = (FOC.cases?.cases || []).find(item => item.case_id === caseId);
  if (title) title.textContent = `Case analysis: ${caseEntry?.source_case_name || caseId}`;
  if (subtitle) {
    if (!status.evidence_available) {
      subtitle.textContent = "Analysis cannot start because no preserved evidence is linked to this case.";
    } else if (status.status === "running") {
      subtitle.textContent = "Forensic analysis is running. This may take several minutes depending on disk, memory and PCAP size.";
    } else if (status.status === "partial") {
      subtitle.textContent = "Forensic analysis completed partially. Review memory, disk or alert layers to see which evidence was analyzed, which failed and which limitations remain.";
    } else if (status.status === "completed") {
      subtitle.textContent = "Forensic analysis completed. The FOC readiness report has been updated, but semantic and causal reconstruction remain blocked until explicitly generated.";
    } else if (status.status === "failed") {
      subtitle.textContent = `Forensic analysis failed at phase: ${status.current_phase || "unknown"}. Open debug details to inspect the exact command, stderr and expected output.`;
    } else {
      subtitle.textContent = "Preserved evidence is available, but forensic analysis outputs are not indexed yet. Run multilayer forensic analysis to unlock the Forensic Analysis Report.";
    }
  }

  if (runBtn) {
    runBtn.disabled = status.status === "running" || !status.evidence_available;
    runBtn.textContent = status.status === "running" ? "Analysis already running" : "Run Multilayer Forensic Analysis";
  }
  const report = extras.report || null;
  const visualSummary = extras.visualSummary || null;
  const memory = report?.memory_analysis || null;
  const visualSummaryPath = status.analysis_visual_summary_path || (visualSummary && status.analysis_dir ? `${status.analysis_dir}/visual/analysis_visual_summary.json` : null);
  if (cancelBtn) {
    cancelBtn.disabled = status.status !== "running";
    cancelBtn.textContent = status.status === "running" ? "Stop Analysis" : "Stop Analysis";
  }
  if (validateBtn) validateBtn.disabled = status.status === "running";

  statusPanel.innerHTML = `
    <div><strong>case_id:</strong> ${esc(caseId)}</div>
    <div><strong>analysis_id:</strong> ${esc(status.analysis_id || "not_available")}</div>
    <div><strong>status:</strong> <span class="${statusClass(status.status)}">${esc(status.status || "unknown")}</span></div>
    <div><strong>started_at:</strong> ${esc(status.started_at || "not_available")}</div>
    <div><strong>updated_at:</strong> ${esc(status.updated_at || "not_available")}</div>
    <div><strong>finished_at:</strong> ${esc(status.finished_at || "not_available")}</div>
    <div><strong>current_phase:</strong> ${esc(status.current_phase || "not_available")}</div>
    <div><strong>progress_percent:</strong> ${esc(status.progress_percent ?? 0)}%</div>
    <div><strong>partial_phases:</strong> ${esc((status.partial_phases || []).join(", ") || "none")}</div>
    <div><strong>report:</strong> ${esc(status.forensic_analysis_report_path || "not_available")}</div>
    <div><strong>visual_summary:</strong> ${esc(visualSummaryPath || "not_available")}</div>
    ${visualSummary ? `
      <div class="mt-3"><strong>execution_status:</strong> <span class="${statusClass(visualSummary.execution_status)}">${esc(analysisLabel("execution", visualSummary.execution_status))}</span></div>
      <div><strong>evidence_analysis_status:</strong> <span class="${statusClass(visualSummary.evidence_analysis_status)}">${esc(analysisLabel("evidence", visualSummary.evidence_analysis_status))}</span></div>
      <div><strong>forensic_reconstruction_status:</strong> <span class="${statusClass(visualSummary.forensic_reconstruction_status)}">${esc(analysisLabel("reconstruction", visualSummary.forensic_reconstruction_status))}</span></div>
      <div><strong>confidence_state:</strong> <span class="${statusClass(visualSummary.confidence_state)}">${esc(analysisLabel("confidence", visualSummary.confidence_state))}</span></div>
    ` : ""}
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
        ${key === "memory_analysis" && memory ? `
          <div class="mt-2 text-xs text-slate-400">preflight: ${esc(phase.memory_preflight_path || "not_available")}</div>
          <div class="mt-1 text-xs text-slate-400">findings: ${esc(phase.memory_findings_path || "not_available")}</div>
          <div class="mt-3 text-xs text-slate-300"><strong>memory status:</strong> ${esc(memory.status || "unknown")}</div>
          <div class="mt-1 text-xs text-slate-400">dumps analysed: ${esc(memory.dumps_analysed ?? 0)}</div>
          <div class="mt-1 text-xs text-slate-400">completed plugins: ${esc((memory.plugins_completed || []).join(", ") || "none")}</div>
          <div class="mt-1 text-xs text-slate-400">failed plugins: ${esc((memory.plugins_failed || []).join(", ") || "none")}</div>
          <div class="mt-2 text-xs text-slate-400">execution reports:</div>
          <div class="mono text-[11px] text-slate-500 mt-1 whitespace-pre-wrap">${esc((phase.memory_results || []).map(item => item.execution_report_path).join("\n") || "not_available")}</div>
        ` : ""}
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
    ${memory ? `
      <div class="mt-4"><strong>memory analysis:</strong></div>
      <div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(
        memory.status === "failed" || memory.status === "partial"
          ? [
              `status=${memory.status || "unknown"}`,
              `reason=${memory.reason || "not_available"}`,
              `recommended_action=${memory.recommended_action || "not_available"}`,
              ...((memory.blocking_errors || []).slice(0, 12)),
            ].join("\n")
          : "no memory blocking errors"
      )}</div>
    ` : ""}
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

  reportPanel.classList.remove("mono", "whitespace-pre-wrap");
  reportPanel.innerHTML = FOC.analysisVisualState.reportRequested
    ? ((visualSummary || report) ? renderAnalysisVisualCockpit(visualSummary, report) : renderAnalysisReportPlaceholder(status))
    : renderAnalysisReportPlaceholder(status);
}

async function openCaseAnalysis(caseId, autoRun = false) {
  FOC.selectedCaseId = caseId;
  FOC.analysisVisualState.selectedNodeId = "case";
  FOC.analysisVisualState.timelineMode = "pipeline";
  FOC.analysisVisualState.reportRequested = false;
  FOC.analysisVisualState.currentSummary = null;
  FOC.analysisVisualState.currentReport = null;
  openAnalysisModalShell();
  const status = await fetchCaseAnalysisStatus(caseId);
  const [logsRes] = await Promise.allSettled([
    fetchJson(analysisLogsUrl(caseId)),
  ]);
  renderAnalysisModal(status, {
    logs: logsRes.status === "fulfilled" ? logsRes.value : null,
    report: null,
    visualSummary: null,
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
  renderAnalysisModal(status, {
    logs: FOC.analysisVisualState.currentLogs || null,
    report: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentReport || null) : null,
    visualSummary: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentSummary || null) : null,
  });
  scheduleAnalysisPolling(caseId);
}

async function validateCaseAnalysis(caseId) {
  const [validation, logs] = await Promise.allSettled([
    fetchJson(analysisValidateUrl(caseId), { method: "POST" }),
    fetchJson(analysisLogsUrl(caseId)),
  ]);
  const status = await fetchCaseAnalysisStatus(caseId);
  renderAnalysisModal(status, {
    logs: logs.status === "fulfilled" ? logs.value : null,
    report: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentReport || null) : null,
    visualSummary: FOC.analysisVisualState.reportRequested ? (FOC.analysisVisualState.currentSummary || null) : null,
  });
  const debugPanel = byId("analysis-debug-panel");
  if (debugPanel && validation.status === "fulfilled") {
    const validationText = (validation.value.validation || []).map(item => `${item.phase}: ${item.status}${item.reason ? ` (${item.reason})` : ""}`).join("\n");
    debugPanel.innerHTML += `<div class="mt-4"><strong>validation:</strong><div class="mono text-xs text-slate-400 mt-2 whitespace-pre-wrap">${esc(validationText || "no validation rows")}</div></div>`;
  }
}

async function viewCaseAnalysisReport(caseId) {
  FOC.analysisVisualState.reportRequested = true;
  FOC.analysisVisualState.selectedNodeId = "case";
  FOC.analysisVisualState.timelineMode = "pipeline";
  const caseEntry = (FOC.cases?.cases || []).find(item => item.case_id === caseId);
  FOC.analysisVisualState.currentCaseEntryName = caseEntry?.source_case_name || caseId;
  openAnalysisReportModalShell();
  const [status, logs, report, visualSummary] = await Promise.allSettled([
    fetchCaseAnalysisStatus(caseId),
    fetchJson(analysisLogsUrl(caseId)),
    fetchJson(analysisReportUrl(caseId)),
    fetchJson(analysisVisualUrl(caseId)),
  ]);
  const currentStatus = status.status === "fulfilled" ? status.value : (FOC.caseAnalysisStatuses[caseId] || { case_id: caseId });
  FOC.selectedCaseId = caseId;
  FOC.analysisVisualState.currentLogs = logs.status === "fulfilled" ? logs.value : null;
  FOC.analysisVisualState.currentReport = report.status === "fulfilled" ? report.value : null;
  FOC.analysisVisualState.currentSummary = visualSummary.status === "fulfilled" ? visualSummary.value : null;
  FOC.analysisVisualState.currentStatus = currentStatus;
  renderAnalysisReportModal(currentStatus, {
    logs: FOC.analysisVisualState.currentLogs,
    report: FOC.analysisVisualState.currentReport,
    visualSummary: FOC.analysisVisualState.currentSummary,
  });
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
  const alertEvidenceEl = byId("alert-evidence-quality");
  if (!container || !candidatesEl || !qualityEl) return;

  const model = _buildTriggerSelectionModel();
  const link = FOC.case_manifest_link || {};
  const intervention = (FOC.forensic_intervention?.interventions || [])[0] || {};
  const alertEvidenceScore = FOC.status?.components?.alert_evidence_links ?? "not_available";
  const lowLinkReason = _blockerActionMeta("case_manifest_link").recommendedAction;
  const reasonBits = [];
  if ((intervention.trigger_selection_score || model.selectionScore || 0) < 180) {
    reasonBits.push("the selected trigger was not a high-confidence OT-focused trigger");
  }
  if (!(link.linked_artifacts > 0)) {
    reasonBits.push("explicit manifest artifact links from the selected trigger to preserved evidence are still weak");
  }
  if (!(link.custody_entries > 0)) {
    reasonBits.push("chain-of-custody linkage is not yet strong enough for a high alert-to-evidence score");
  }
  if (!reasonBits.length) {
    reasonBits.push("the selected trigger, intervention and manifest linkage are present, but the current weighting still treats this case as only partially traceable");
  }

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
  if (alertEvidenceEl) {
    alertEvidenceEl.innerHTML = `
      <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Alert-to-Evidence Link Quality</div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3 text-sm text-slate-300">
        <div><strong>selected trigger alert:</strong> ${esc(intervention.triggering_alert_id || model.selectedAlertId)}</div>
        <div><strong>generated case:</strong> ${esc(intervention.case_id || link.case_id || "not_available")}</div>
        <div><strong>preserved artifacts linked to that alert:</strong> ${esc(link.linked_artifacts || 0)}</div>
        <div><strong>acquisition profile:</strong> ${esc(intervention.acquisition_profile || "not_available")}</div>
        <div><strong>chain of custody entries:</strong> ${esc(link.custody_entries || 0)}</div>
        <div><strong>alert→evidence score:</strong> ${esc(alertEvidenceScore)} / 10</div>
        <div><strong>manifest path:</strong> ${esc(link.manifest_path || "not_available")}</div>
        <div><strong>custody path:</strong> ${esc(link.chain_of_custody_path || "not_available")}</div>
      </div>
      <div class="mt-3"><strong>Why this score is low:</strong> ${esc(reasonBits.join("; "))}.</div>
      <div class="mt-2"><strong>Recommended action:</strong> ${esc(lowLinkReason)}</div>
    `;
  }
}

function renderBlockers() {
  const panel = byId("gaps-panel");
  const summary = byId("gaps-summary");
  if (!FOC.readiness_report) return;
  const blockers = [...(FOC.readiness_report.missing_prerequisites || FOC.readiness_report.readiness?.missing_prerequisites || [])];
  const sections = FOC.readiness_report.sections || {};
  const manifestDerived = FOC.manifest?.derived_context || {};
  const analysisAvailable = analysisAvailableGlobal();
  if (analysisAvailable && !semanticAvailableGlobal()) {
    blockers.unshift("semantic_observation_report");
  }

  const items = (blockers || []).map(key => {
    const sec = sections[key] || {};
    const status = sec.overall_status || (key === "semantic_observation_report" ? "unresolved" : "unknown");
    const missing = _formatMissingList(sec);
    const meta = _blockerActionMeta(key);
    const reason = sec.status_note || sec.reason || sec.overall_status || "partial";
    const source_expected = manifestDerived[key] || meta.requiredArtifact || (key + ".json");
    const resolvable_locally = String(status || "").toLowerCase() !== "missing";
    return `
      <div class="glass-soft rounded-2xl p-4">
        <div class="flex items-center justify-between">
          <div class="font-black">${esc(meta.label)}</div>
          <div class="text-xs uppercase tracking-[0.12em] font-black ${statusClass(status)}">${esc(status)}</div>
        </div>
        <div class="text-sm text-slate-300 mt-2"><strong>blocker name:</strong> ${esc(key)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>required artifact:</strong> ${esc(source_expected)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>current evidence available:</strong> ${esc(_blockerCurrentEvidence(key))}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>missing or weak fields:</strong> ${esc(missing)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>why causal is blocked:</strong> ${esc(reason)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>recommended action:</strong> ${esc(meta.recommendedAction)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>backend action:</strong> ${esc(meta.backendAction)}</div>
        <div class="text-sm text-slate-300 mt-1"><strong>resolvable locally:</strong> ${esc(resolvable_locally ? "yes" : "no")}</div>
      </div>
    `;
  });

  if (panel) {
    panel.innerHTML = `
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black">Why causal reconstruction is still blocked</div>
        <div class="text-sm text-slate-300 mt-2">Forensic analysis outputs are already available, but causal replay still depends on semantic interpretation and stronger attack, detection and alert-to-evidence linkage.</div>
      </div>
      ${items.join("") || `<div class="text-sm text-slate-400">No blockers listed.</div>`}
    `;
  }
  if (summary) summary.textContent = `${blockers.length} actionable blocker(s)`; 
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
  const attackSample = (FOC.attack_attestation?.attested_executions || [])[0] || {};
  const attackInterpretation = attackSample.execution_interpretation?.status_note || "not_available";
  const detectionSeen = FOC.triggerSelectionModel?.selectedAlertId && FOC.triggerSelectionModel.selectedAlertId !== "no-id" ? "yes" : "no";
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
      <div><strong>triggering_alert_id:</strong> ${esc(intervention?.triggering_alert_id || "not_available")}</div>
      <div><strong>triggering_alert_severity:</strong> ${esc(intervention?.triggering_alert_severity || "not_available")}</div>
      <div><strong>attack execution status:</strong> ${esc(attackSample.execution_status || "not_available")}</div>
      <div><strong>detection generated:</strong> ${esc(detectionSeen)}</div>
      <div><strong>process effect confirmation:</strong> ${esc(attackInterpretation)}</div>
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
    const baseMessage = analysisAvailableGlobal()
      ? "Forensic analysis outputs are available, but causal reconstruction requires additional semantic and evidential linkage outputs."
      : "Causal reconstruction is not ready because preserved-case analysis outputs are still missing.";
    note.innerHTML = `${baseMessage}<div class="mt-3">${list}</div>`;
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
  bindGraphControls();
  byId("analysis-modal-close")?.addEventListener("click", closeAnalysisModalShell);
  byId("analysis-modal")?.addEventListener("click", (event) => {
    if (event.target?.id === "analysis-modal") {
      closeAnalysisModalShell();
    }
  });
  byId("analysis-report-modal-close")?.addEventListener("click", closeAnalysisReportModalShell);
  byId("analysis-report-modal")?.addEventListener("click", (event) => {
    if (event.target?.id === "analysis-report-modal") {
      closeAnalysisReportModalShell();
    }
  });
  byId("time-sync-modal-close")?.addEventListener("click", closeTimeSyncModalShell);
  byId("time-sync-modal")?.addEventListener("click", (event) => {
    if (event.target?.id === "time-sync-modal") {
      closeTimeSyncModalShell();
    }
  });
  byId("time-sync-measure-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) runTimeSync(FOC.selectedCaseId, false).catch(() => {});
  });
  byId("time-sync-fix-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) runTimeSync(FOC.selectedCaseId, true).catch(() => {});
  });
  byId("causal-report-modal-close")?.addEventListener("click", closeCausalReportModalShell);
  byId("causal-report-modal")?.addEventListener("click", (event) => {
    if (event.target?.id === "causal-report-modal") {
      closeCausalReportModalShell();
    }
  });
  byId("causal-report-modal-panel")?.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const detailTarget = event.target.closest("button[data-causal-detail]");
    if (detailTarget) {
      const key = detailTarget.getAttribute("data-causal-detail");
      const caseId = detailTarget.getAttribute("data-case-id") || FOC.causalVisualState.currentCaseId || FOC.selectedCaseId;
      if (key && caseId) toggleCausalDetail(caseId, key).catch(() => {});
      return;
    }
    const regenerateTarget = event.target.closest("button[data-causal-regenerate]");
    if (regenerateTarget) {
      const caseId = regenerateTarget.getAttribute("data-case-id") || FOC.causalVisualState.currentCaseId || FOC.selectedCaseId;
      if (caseId) runCausalReconstruction(caseId).catch(() => {});
    }
  });
  byId("analysis-generate-symbols-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) openSymbolGenModal();
  });
  byId("symbolgen-close")?.addEventListener("click", closeSymbolGenModal);
  byId("symbolgen-modal")?.addEventListener("click", (event) => {
    if (event.target?.id === "symbolgen-modal") {
      closeSymbolGenModal();
    }
  });
  byId("symbolgen-run-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) generateSymbolsForSelectedCase().catch(() => {});
  });
  byId("analysis-run-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) runCaseAnalysis(FOC.selectedCaseId).catch(() => {});
  });
  byId("analysis-cancel-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) cancelCaseAnalysis(FOC.selectedCaseId).catch(() => {});
  });
  byId("analysis-validate-btn")?.addEventListener("click", () => {
    if (FOC.selectedCaseId) validateCaseAnalysis(FOC.selectedCaseId).catch(() => {});
  });
  byId("analysis-report-modal-panel")?.addEventListener("click", (event) => {
    if (!FOC.analysisVisualState.reportRequested) return;
    const target = event.target instanceof Element ? event.target.closest("[data-visual-node],[data-analysis-timeline-mode]") : null;
    if (!target) return;
    if (target.hasAttribute("data-visual-node")) {
      FOC.analysisVisualState.selectedNodeId = target.getAttribute("data-visual-node") || "case";
    }
    if (target.hasAttribute("data-analysis-timeline-mode")) {
      FOC.analysisVisualState.timelineMode = target.getAttribute("data-analysis-timeline-mode") || "pipeline";
    }
    const currentStatus = FOC.analysisVisualState.currentStatus || (FOC.selectedCaseId ? FOC.caseAnalysisStatuses[FOC.selectedCaseId] : null);
    if (currentStatus) {
      renderAnalysisReportModal(currentStatus, {
        logs: FOC.analysisVisualState.currentLogs || null,
        report: FOC.analysisVisualState.currentReport || null,
        visualSummary: FOC.analysisVisualState.currentSummary || null,
      });
    }
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
    if (target.classList.contains("view-time-sync-btn")) {
      openTimeSyncModal(caseId).catch(() => {});
      return;
    }
    if (target.classList.contains("view-analysis-btn")) {
      openCaseAnalysis(caseId, false).catch(() => {});
      return;
    }
    if (target.classList.contains("view-analysis-report-btn")) {
      viewCaseAnalysisReport(caseId).catch(() => {});
      return;
    }
    if (target.classList.contains("run-causal-btn")) {
      runCausalReconstruction(caseId).catch(() => {});
      return;
    }
    if (target.classList.contains("view-causal-btn")) {
      viewCausalReconstruction(caseId).catch(() => {});
    }
  });
  document.querySelectorAll(".export-btn").forEach(btn => {
    btn.addEventListener("click", () => exportJson(btn.dataset.export));
  });

  await loadAll(true);
  connectStream();
});
