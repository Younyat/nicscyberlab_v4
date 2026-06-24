const API = "/api/foc";
const DashboardState = {
  cases: [],
  selectedCaseId: null,
  dashboard: null,
  trackedJobId: null,
  pollTimer: null,
  evidenceSupportDetail: null,
  evidenceSupportDetailVisible: false,
};

const RailSectionLinks = {
  scenario_deployed: [
    ["Executive Summary", "executive-summary-section"],
    ["Evidence Lifecycle Rail", "evidence-lifecycle-rail-section"],
  ],
  attack_executed: [
    ["Causal Reconstruction Summary", "causal-summary-section"],
    ["Evidence-Based Reconstruction Story", "evidence-story-section"],
    ["Modbus Specificity", "modbus-specificity-section"],
  ],
  detection_observed: [
    ["Alert Triage and Trigger Selection", "alert-triage-section"],
    ["Evidence-Based Hypothesis Support", "evidence-support-section"],
  ],
  trigger_selected: [
    ["Alert Triage and Trigger Selection", "alert-triage-section"],
    ["Acquisition Trigger Path vs Reconstructed Attack Path", "trigger-causal-section"],
    ["Final Forensic Conclusion", "final-conclusion-section"],
  ],
  acquisition_executed: [
    ["Alert Triage and Trigger Selection", "alert-triage-section"],
    ["Reports and Artifacts", "reports-section"],
  ],
  evidence_preserved: [
    ["Executive Summary", "executive-summary-section"],
    ["Reports and Artifacts", "reports-section"],
    ["Limitations", "limitations-section"],
  ],
  integrity_custody_checked: [
    ["Uncertainty Summary", "uncertainty-summary-section"],
    ["Limitations", "limitations-section"],
    ["Next Required Actions", "next-actions-section"],
  ],
  time_synchronization_validated: [
    ["Uncertainty Summary", "uncertainty-summary-section"],
    ["Lifecycle Actions", "lifecycle-actions-section"],
  ],
  multilayer_analysis_completed: [
    ["Multilayer Forensic Analysis", "multilayer-analysis-section"],
    ["Memory Analysis Coverage", "memory-analysis-section"],
    ["Alert Triage and Trigger Selection", "alert-triage-section"],
  ],
  timeline_generated: [
    ["Multilayer Forensic Analysis", "multilayer-analysis-section"],
    ["Evidence-Based Reconstruction Story", "evidence-story-section"],
  ],
  cross_layer_findings_generated: [
    ["Multilayer Forensic Analysis", "multilayer-analysis-section"],
    ["Evidence-Based Hypothesis Support", "evidence-support-section"],
    ["Final Forensic Conclusion", "final-conclusion-section"],
  ],
  causal_reconstruction_generated: [
    ["Causal Reconstruction Summary", "causal-summary-section"],
    ["Uncertainty Summary", "uncertainty-summary-section"],
    ["Modbus Specificity", "modbus-specificity-section"],
    ["Evidence-Based Reconstruction Story", "evidence-story-section"],
  ],
  executive_conclusion_produced: [
    ["Final Forensic Conclusion", "final-conclusion-section"],
    ["Limitations", "limitations-section"],
    ["Next Required Actions", "next-actions-section"],
  ],
};

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

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  let payload = null;
  try {
    payload = await res.json();
  } catch (err) {
    payload = null;
  }
  if (!res.ok) {
    const message = payload?.reason || payload?.warning || payload?.error || `${url} -> ${res.status}`;
    throw new Error(message);
  }
  return payload;
}

async function postJson(url, body) {
  return fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

function titleize(value) {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, ch => ch.toUpperCase());
}

function statusTone(status) {
  const normalized = String(status || "").toLowerCase();
  if (["completed", "completed_with_useful_output", "synchronized", "confirmed", "ok", "strong", "preserved_and_analyzed", "strong_support", "moderate_support"].includes(normalized)) {
    return "status-ok";
  }
  if (normalized.includes("failed") || normalized.includes("missing") || normalized === "blocked" || normalized === "not_synchronized" || normalized === "contradicted" || normalized === "no_support") {
    return "status-error";
  }
  if (normalized.includes("running") || normalized.includes("queued")) {
    return "status-info";
  }
  if (normalized.includes("partial") || normalized.includes("degradation") || normalized.includes("ambiguous") || normalized.includes("limited") || normalized.includes("stale") || normalized.includes("degraded") || normalized === "weak_support") {
    return "status-warning";
  }
  return "status-muted";
}

function tag(label, value, cls = "") {
  return `<div class="tag rounded-full px-3 py-1.5 text-[11px] font-black tracking-[0.14em] uppercase ${cls}">${esc(label)}: ${esc(value)}</div>`;
}

function valueCard(label, value, detail = "", tone = "status-muted") {
  return `
    <div class="glass-soft rounded-[24px] p-4">
      <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">${esc(label)}</div>
      <div class="text-2xl font-black mt-2 ${tone}">${esc(value)}</div>
      <div class="text-xs text-slate-400 mt-2">${esc(detail)}</div>
    </div>
  `;
}

function listItems(items, emptyText) {
  if (!Array.isArray(items) || !items.length) {
    return `<div class="text-slate-500">${esc(emptyText)}</div>`;
  }
  return items.map(item => `<div class="glass-soft rounded-xl p-3">${esc(item)}</div>`).join("");
}

function formatMaybeNumber(value, digits = 3) {
  if (value === null || value === undefined || value === "") return "not_available";
  const num = Number(value);
  return Number.isFinite(num) ? String(Number(num.toFixed(digits))) : String(value);
}

function maybeTruncate(value, max = 220) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function setJobPanel(html) {
  const panel = byId("lifecycle-job-panel");
  if (panel) panel.innerHTML = html;
}

function reportPath(payload, type) {
  const reports = payload?.reports_index || payload?.summary?.reports_and_artifacts || [];
  const entry = Array.isArray(reports) ? reports.find(item => item.type === type) : null;
  return entry?.path || "not_available";
}

function flashSection(sectionId) {
  const el = byId(sectionId);
  if (!el) return;
  el.classList.remove("section-highlight");
  void el.offsetWidth;
  el.classList.add("section-highlight");
  window.setTimeout(() => el.classList.remove("section-highlight"), 1800);
}

function scrollToDashboardSection(sectionId) {
  const el = byId(sectionId);
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
  window.setTimeout(() => flashSection(sectionId), 180);
}

function renderRailLinks(phase) {
  const links = RailSectionLinks[phase] || [];
  if (!links.length) return `<div class="text-slate-500">No related detailed sections are mapped for this phase.</div>`;
  return `
    <div class="flex flex-wrap gap-2">
      ${links.map(([label, sectionId]) => `
        <button type="button" class="btn-secondary rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.14em] uppercase rail-jump-btn" data-target-section="${esc(sectionId)}">
          ${esc(label)}
        </button>
      `).join("")}
    </div>
  `;
}

function buildRailPhaseDetail(phase, status, summary, payload) {
  const exec = summary?.execution_summary || {};
  const trigger = summary?.trigger_summary || {};
  const causal = summary?.causal_summary || {};
  const uncertainty = summary?.uncertainty_summary || {};
  const integrity = summary?.integrity_summary || {};
  const multi = summary?.multilayer_analysis_summary || {};
  const memory = summary?.memory_analysis_detail || {};
  const alertTriage = summary?.alert_triage_summary || {};
  const story = summary?.evidence_based_reconstruction_story || {};
  const common = {
    status,
    phase,
    relatedSections: RailSectionLinks[phase] || [],
  };
  switch (phase) {
    case "scenario_deployed":
      return {
        ...common,
        title: "Scenario deployed",
        meaning: "This phase records that a controlled scenario context exists for the case and defines the scientific frame under which the evidence lifecycle is interpreted.",
        why: `The case is tied to scenario ${summary?.scenario_id || "unknown"} (${summary?.scenario_name || "unknown"}).`,
        evidence: [
          `Executive summary snapshot for case ${summary?.case_id || "unknown"}.`,
          `Scenario context reflected in the causal ground truth: ${causal.ground_truth_path || "not_available"}.`,
        ],
        limitation: summary?.summary_status?.status === "stale" ? summary.summary_status.reason : "none",
        action: summary?.summary_status?.status === "stale" ? "Regenerate executive summary if scenario-linked derived artifacts changed." : null,
      };
    case "attack_executed":
      return {
        ...common,
        title: "Attack executed",
        meaning: "This phase represents the controlled intervention or expected attack path declared by the scenario and later evaluated by the causal reconstruction.",
        why: `Selected attack path: ${(causal.selected_attack || {}).technique_id || "not_available"} ${(causal.selected_attack || {}).protocol || ""} -> ${(causal.selected_attack || {}).target || "not_available"}.`,
        evidence: [
          `Ground truth path: ${causal.ground_truth_path || "not_available"}`,
          `Attack evidence summarized in the causal reconstruction: ${reportPath(payload, "causal_status")}`,
        ],
        limitation: causal.main_limitation || "none",
        action: "Inspect the causal summary and Modbus specificity if stronger protocol-level causal claims are required.",
      };
    case "detection_observed":
      return {
        ...common,
        title: "Detection observed",
        meaning: "This phase captures that preserved detections and alerts were observed and made available to the case, independently of whether they perfectly align with the reconstructed OT attack path.",
        why: `Alerts were summarized and triaged; total indexed alerts: ${alertTriage.total_alerts_indexed ?? "not_available"}, correlated alerts: ${alertTriage.correlated_alerts ?? "not_available"}.`,
        evidence: [
          `Alerts findings: ${reportPath(payload, "alert_findings")}`,
          `Evidence support report: ${summary?.evidence_support_extract?.path || "not_available"}`,
        ],
        limitation: summary?.evidence_support_extract?.main_limitation || "Detection evidence exists, but some of it remains inferred or only partially aligned with the causal path.",
        action: "Use Alert Triage and Evidence-Based Hypothesis Support to inspect which detections support, degrade, or contradict the causal model.",
      };
    case "trigger_selected":
      return {
        ...common,
        title: "Trigger selected",
        meaning: "This phase records which preserved alert or signal triggered the forensic acquisition workflow.",
        why: `The selected trigger was ${trigger.trigger || "not_available"} using rule ${trigger.triggering_alert_rule_id || "not_available"} with score ${trigger.trigger_selection_score ?? "not_available"}.`,
        evidence: [
          `Alert triage summary captured ${alertTriage.trigger_candidates_evaluated ?? "not_available"} evaluated trigger candidates.`,
          `Selected trigger source: ${trigger.trigger_type || "not_available"} / ${alertTriage.selected_trigger_source || "not_available"}.`,
        ],
        limitation: (causal.trigger_vs_causal_path || {}).message || "none",
        action: "Review the trigger-versus-causal-path section if a direct OT-to-acquisition link is required.",
      };
    case "acquisition_executed":
      return {
        ...common,
        title: "Acquisition executed",
        meaning: "This phase means the acquisition workflow preserved case artifacts after the selected trigger fired.",
        why: `The preserved intervention status is ${trigger.intervention_status || "not_available"} and target nodes count is ${(trigger.target_nodes || []).length}.`,
        evidence: [
          `Manifest path: ${summary?.evidence_lifecycle?.manifest_path || "not_available"}`,
          `Chain of custody path: ${summary?.evidence_lifecycle?.chain_of_custody_path || "not_available"}`,
        ],
        limitation: (causal.trigger_vs_causal_path || {}).same_event_family === false ? "Acquisition was triggered by a host/FIM-oriented path rather than a directly confirmed OT alert." : "none",
        action: "Generate an OT-triggered case if direct OT-to-acquisition linkage is scientifically required.",
      };
    case "evidence_preserved":
      return {
        ...common,
        title: "Evidence preserved",
        meaning: "This phase states that artifacts were sealed into the preserved case structure under manifest and custody tracking.",
        why: `Manifest present: ${integrity.manifest_present ? "yes" : "no"}; chain of custody present: ${integrity.chain_of_custody_present ? "yes" : "no"}.`,
        evidence: [
          `Manifest: ${summary?.evidence_lifecycle?.manifest_path || "not_available"}`,
          `Chain of custody: ${summary?.evidence_lifecycle?.chain_of_custody_path || "not_available"}`,
        ],
        limitation: integrity.main_limitation || "none",
        action: integrity.main_limitation ? "Review preservation and integrity limitations before escalating confidence claims." : null,
      };
    case "integrity_custody_checked":
      return {
        ...common,
        title: "Integrity and custody checked",
        meaning: "This phase means the integrity and custody validation step executed and produced an evaluable result. It does not automatically mean the global integrity result is complete.",
        why: `Validation execution: ${integrity.validation_execution_status || "unknown"}; validation output: ${integrity.validation_output_status || "unknown"}; case-wide integrity completeness: ${integrity.case_wide_integrity_completeness || "unknown"}.`,
        evidence: [
          `Integrity and custody report: ${integrity.artifact_path || "not_available"}`,
          `Case-wide integrity ratio: ${formatMaybeNumber(integrity.case_wide_integrity_ratio, 4)}`,
        ],
        limitation: integrity.case_wide_integrity_completeness && integrity.case_wide_integrity_completeness !== "completed" ? "The integrity and custody validation step completed successfully, but the case-wide integrity assessment remains partial." : (integrity.main_limitation || "none"),
        action: integrity.case_wide_integrity_completeness && integrity.case_wide_integrity_completeness !== "completed" ? "Review missing or unvalidated integrity conditions before making stronger admissibility-oriented claims." : null,
      };
    case "time_synchronization_validated":
      return {
        ...common,
        title: "Time synchronization validated",
        meaning: "This phase evaluates node clock offset and synchronization state. It does not by itself guarantee strong causal temporal ordering.",
        why: `Clock synchronization is ${uncertainty.synchronized_status || "unknown"} with max clock offset ${formatMaybeNumber(uncertainty.max_clock_offset_seconds)}s, but causal temporal ordering confidence remains ${uncertainty.causal_temporal_ordering_confidence || "unknown"}.`,
        evidence: [
          `Time sync metadata: ${uncertainty.latest_path || "not_available"}`,
          `Uncertainty report: ${reportPath(payload, "uncertainty_report")}`,
        ],
        limitation: uncertainty.causal_temporal_ordering_reason || "A synchronized infrastructure does not guarantee that all forensic artifacts contain usable timestamps for causal ordering.",
        action: "Inspect uncertainty and temporal validation before asserting strong time-order causality.",
      };
    case "multilayer_analysis_completed":
      return {
        ...common,
        title: "Multilayer analysis completed",
        meaning: "This phase records whether the preserved case evidence was processed across the expected forensic layers and whether those layers produced useful output.",
        why: `${multi.layers_with_useful_output || 0} of ${multi.layers_expected || 0} expected layers produced useful output; memory dumps analyzed: ${memory.dumps_analyzed || 0}.`,
        evidence: [
          `Forensic analysis report: ${multi.report_path || "not_available"}`,
          `Memory findings: ${reportPath(payload, "memory_findings")}`,
          `Network findings: ${reportPath(payload, "network_findings")}`,
          `Disk findings: ${reportPath(payload, "disk_findings")}`,
          `OT findings: ${reportPath(payload, "ot_findings")}`,
        ],
        limitation: multi.main_limitation || "none",
        action: multi.main_limitation ? "Inspect the affected layer matrix entries and regenerate the multilayer analysis if upstream artifacts changed." : null,
      };
    case "timeline_generated":
      return {
        ...common,
        title: "Timeline generated",
        meaning: "This phase captures whether the unified forensic timeline was generated from preserved and derived artifacts.",
        why: `Timeline entries generated: ${multi.timeline_entries || 0}.`,
        evidence: [
          `Unified forensic timeline: ${reportPath(payload, "unified_forensic_timeline")}`,
          `Cross-layer findings: ${reportPath(payload, "cross_layer_findings")}`,
        ],
        limitation: story.status === "available" ? "Timeline availability does not mean every causal edge can be temporally ordered." : "none",
        action: "Use the evidence-based reconstruction story and uncertainty summary to understand which timeline relations remain unresolved.",
      };
    case "cross_layer_findings_generated":
      return {
        ...common,
        title: "Cross-layer findings generated",
        meaning: "This phase indicates that the dashboard has cross-layer findings or support relationships linking multiple forensic layers together.",
        why: `Cross-layer findings count: ${multi.cross_layer_findings || 0}.`,
        evidence: [
          `Cross-layer findings artifact: ${reportPath(payload, "cross_layer_findings")}`,
          `Evidence support report: ${summary?.evidence_support_extract?.path || "not_available"}`,
        ],
        limitation: summary?.evidence_support_extract?.main_limitation || "none",
        action: "Review the evidence support matrix to see where cross-layer support is direct, partial, contradictory, or not evaluable.",
      };
    case "causal_reconstruction_generated":
      return {
        ...common,
        title: "Causal reconstruction generated",
        meaning: "This phase means the derived causal-forensic reconstruction was generated from preserved FOC and multilayer artifacts. It does not imply complete or absolute causality.",
        why: `Recovered edges: ${causal.recovered_edges || 0} / ${causal.expected_edges || 0}; degraded edges: ${causal.degraded_edges || 0}; CPR: ${formatMaybeNumber(causal.cpr)}.`,
        evidence: [
          `Causal status: ${reportPath(payload, "causal_status")}`,
          `Causal graph: ${reportPath(payload, "causal_graph")}`,
          `Reconstruction metrics: ${reportPath(payload, "reconstruction_metrics")}`,
          `Uncertainty report: ${reportPath(payload, "uncertainty_report")}`,
        ],
        limitation: causal.main_limitation || "none",
        action: "Inspect CPR, Modbus specificity, uncertainty, and evidence story before making stronger causal claims.",
      };
    case "executive_conclusion_produced":
      return {
        ...common,
        title: "Executive conclusion produced",
        meaning: "This phase consolidates the preserved evidence lifecycle, multilayer analysis, causal reconstruction, and uncertainty into an auditable scientific conclusion.",
        why: `The executive summary snapshot is ${summary?.summary_status?.status || "unknown"} and the final conclusion currently reports ${exec.evidence_processing_coverage || "unknown"} evidence processing coverage, ${exec.forensic_reconstruction_confidence || "unknown"} forensic reconstruction confidence, and ${exec.causal_interpretation_confidence || "unknown"} causal interpretation confidence.`,
        evidence: [
          `Executive summary snapshot: ${payload?.summary_path || "not_available"}`,
          `Final conclusion panel supported by: ${reportPath(payload, "forensic_analysis_report")}`,
        ],
        limitation: exec.main_limitation || "none",
        action: summary?.summary_status?.status === "stale" ? "Regenerate the executive summary before citing it as the current authoritative scientific conclusion." : "Review supported, degraded, unsupported claims, limitations, and next actions before exporting conclusions.",
      };
    default:
      return {
        ...common,
        title: titleize(phase),
        meaning: "This rail phase summarizes one stage of the preserved evidence lifecycle.",
        why: `Current state: ${status}.`,
        evidence: [],
        limitation: "none",
        action: null,
      };
  }
}

function openRailPhaseModal(phase, summary, payload) {
  const rail = summary?.evidence_lifecycle?.rail || [];
  const step = rail.find(item => item.phase === phase) || {};
  const detail = buildRailPhaseDetail(phase, step.status || "unknown", summary, payload);
  const title = byId("rail-phase-title");
  const status = byId("rail-phase-status");
  const body = byId("rail-phase-body");
  const modal = byId("rail-phase-modal");
  if (!title || !status || !body || !modal) return;
  title.textContent = detail.title;
  status.innerHTML = `<span class="${statusTone(detail.status)} font-black uppercase tracking-[0.14em]">${esc(titleize(detail.status || "unknown"))}</span>`;
  body.innerHTML = `
    <div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
      <div class="glass-soft rounded-[24px] p-5">
        <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">What this phase means</div>
        <div class="mt-3">${esc(detail.meaning || "not_available")}</div>
      </div>
      <div class="glass-soft rounded-[24px] p-5">
        <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">Why this phase has this state</div>
        <div class="mt-3">${esc(detail.why || "not_available")}</div>
      </div>
    </div>
    <div class="glass-soft rounded-[24px] p-5">
      <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">Supporting evidence and artifacts</div>
      <div class="mt-4 space-y-2">
        ${(detail.evidence || []).length ? (detail.evidence || []).map(item => `<div class="rounded-xl bg-slate-950/30 px-4 py-3">${esc(item)}</div>`).join("") : `<div class="text-slate-500">No direct artifact summary is available for this phase.</div>`}
      </div>
    </div>
    <div class="glass-soft rounded-[24px] p-5">
      <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">Related detailed sections</div>
      <div class="mt-4">${renderRailLinks(phase)}</div>
    </div>
    <div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
      <div class="glass-soft rounded-[24px] p-5">
        <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">Scientific limitation</div>
        <div class="mt-3">${esc(detail.limitation || "none")}</div>
      </div>
      <div class="glass-soft rounded-[24px] p-5">
        <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">Future reinforcement action</div>
        <div class="mt-3">${esc(detail.action || "No specific follow-up action is required beyond normal case review.")}</div>
      </div>
    </div>
  `;
  modal.classList.add("is-active");
}

async function loadCases() {
  const payload = await fetchJson(`${API}/cases`);
  DashboardState.cases = payload?.cases || [];
  renderCaseList();
  if (!DashboardState.selectedCaseId && DashboardState.cases.length) {
    DashboardState.selectedCaseId = DashboardState.cases[0].case_id;
  }
  if (DashboardState.selectedCaseId) {
    await loadDashboard(DashboardState.selectedCaseId);
  }
}

function renderCaseList() {
  const container = byId("lifecycle-case-list");
  if (!container) return;
  if (!DashboardState.cases.length) {
    container.innerHTML = `<div class="text-slate-500">No forensic cases are indexed in FOC.</div>`;
    return;
  }
  container.innerHTML = DashboardState.cases.map(entry => {
    const selected = entry.case_id === DashboardState.selectedCaseId;
    const analysis = entry.analysis_status || "not_started";
    const causal = (entry.causal_state || {}).status || "not_available";
    const sync = ((entry.time_sync_state || {}).summary || {}).temporal_sync_status || entry.time_sync_state?.status || "unknown";
    return `
      <button data-case-id="${esc(entry.case_id)}" class="case-item w-full text-left rounded-[22px] px-4 py-4 ${selected ? "bg-cyan-500/12 border border-cyan-400/30" : "glass-soft"}">
        <div class="text-xs uppercase tracking-[0.22em] text-slate-400 font-black">${esc(entry.source_case_name || entry.case_id)}</div>
        <div class="mono text-sm font-bold mt-2">${esc(entry.case_id)}</div>
        <div class="flex flex-wrap gap-2 mt-3">
          ${tag("analysis", analysis, statusTone(analysis))}
          ${tag("causal", causal, statusTone(causal))}
          ${tag("time", sync, statusTone(sync))}
        </div>
      </button>
    `;
  }).join("");
}

async function loadDashboard(caseId) {
  DashboardState.selectedCaseId = caseId;
  renderCaseList();
  const payload = await fetchJson(`${API}/evidence-lifecycle-dashboard?case_id=${encodeURIComponent(caseId)}`);
  DashboardState.dashboard = payload;
  renderDashboard();
  syncPolling();
}

function renderDashboard() {
  const payload = DashboardState.dashboard;
  if (!payload) return;
  const summary = payload.summary;
  const live = payload.live_status || {};

  const title = byId("lifecycle-title");
  const subtitle = byId("lifecycle-subtitle");
  const tags = byId("lifecycle-header-tags");
  if (title) title.textContent = summary ? `${summary.source_case_name || summary.case_id} · ${summary.scenario_name || summary.scenario_id}` : `${payload.source_case_name || payload.case_id}`;
  if (subtitle) {
    subtitle.textContent = summary
      ? "This executive surface summarizes preserved evidence, multilayer analysis, causal reconstruction, uncertainty, and auditable scientific conclusions."
      : "Executive evidence lifecycle summary has not been generated yet. You can still inspect live analysis, time-sync, and causal state below.";
  }
  if (tags) {
    const exec = summary?.execution_summary || {};
    tags.innerHTML = [
      tag("case", payload.case_id),
      tag("summary", payload.summary_available ? "available" : "not_generated", payload.summary_available ? "status-ok" : "status-warning"),
      tag("analysis", live.analysis?.status || "not_started", statusTone(live.analysis?.status)),
      tag("causal", live.causal?.status || "not_available", statusTone(live.causal?.status)),
    ].join("");
  }

  renderExecutiveGrid(summary, payload);
  renderLifecycleRail(summary, payload);
  renderJobPanel(payload);
  renderMultilayer(summary, payload);
  renderMemoryAnalysis(summary);
  renderAlertTriage(summary);
  renderCausalAndUncertainty(summary, payload);
  renderTriggerAndModbus(summary, payload);
  renderEvidenceStory(summary);
  renderEvidenceSupportSummary(summary, payload);
  renderConclusion(summary, payload);
  renderReports(summary, payload);
  renderLists(summary, payload);
}

function supportLevelLabel(level) {
  return titleize(level || "not_evaluable");
}

function renderEvidenceSupportSummary(summary, payload) {
  const container = byId("evidence-support-summary");
  const note = byId("evidence-support-note");
  if (!container || !note) return;
  const extract = summary?.evidence_support_extract;
  if (!extract || extract.status === "not_available") {
    note.innerHTML = "";
    container.innerHTML = valueCard(
      "Evidence support status",
      "Not generated",
      "Reason: evidence-based hypothesis support has not been generated for this case yet. Required action: generate evidence-based hypothesis support.",
      "status-warning"
    );
    return;
  }
  const tone = extract.status === "stale" ? "status-warning" : statusTone(extract.global_support_level);
  note.innerHTML = extract.status === "stale"
    ? `<div class="glass-soft rounded-[24px] p-4 text-sm text-amber-200"><div class="font-black uppercase tracking-[0.16em] text-xs mb-2">Evidence support status: stale</div><div><span class="font-black">Reason:</span> one or more source artifacts changed after the evidence support extract was generated.</div><div class="mt-2">This support extract is stale. The displayed support metrics may not reflect the latest causal reconstruction artifacts.</div><div class="mt-2 flex items-center justify-between gap-3 flex-wrap"><span><span class="font-black">Required action:</span> regenerate evidence support extract.</span><button type="button" class="run-action-btn btn-secondary rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.16em] uppercase" data-run-action="generate-evidence-support">Regenerate Evidence-Based Hypothesis Support</button></div></div>`
    : "";
  container.innerHTML = [
    valueCard("Status", titleize(extract.status), `${extract.path || "not_available"}${extract.status === "stale" ? " · stale snapshot" : ""}`, tone),
    valueCard("Hypothesis ID", extract.hypothesis_id || "not_available", extract.claim_evaluated || "not_available", "status-info"),
    valueCard("Global support", titleize(extract.global_support_level || "not_evaluable"), extract.status === "stale" ? "Stale snapshot; not authoritative until regenerated." : "Aggregated across independent evidentiary layers; never strong unless cross-layer, temporally resolvable, and not contradicted.", statusTone(extract.global_support_level)),
    valueCard("Supporting evidence", extract.supporting_findings ?? 0, extract.status === "stale" ? "Stale value." : "Atoms that support the hypothesis.", "status-ok"),
    valueCard("Partially supporting", extract.degraded_or_ambiguous_findings ?? 0, extract.status === "stale" ? "Stale value." : "Atoms with weak or indirect support only.", "status-warning"),
    valueCard("Contradicting evidence", extract.contradictions ?? 0, extract.status === "stale" ? "Stale value." : "Atoms that contradict a specific causal claim.", (extract.contradictions ?? 0) > 0 ? "status-error" : "status-muted"),
    valueCard("Missing / not evaluable", extract.missing_or_not_evaluable_findings ?? 0, extract.status === "stale" ? "Stale value." : "Required evidence layers with no atom coverage."),
  ].join("");
}

async function loadEvidenceSupportDetail() {
  const caseId = DashboardState.selectedCaseId;
  if (!caseId) return;
  const container = byId("evidence-support-details");
  if (!container) return;
  container.classList.remove("hidden");
  container.innerHTML = `<div class="text-slate-500 text-sm">Loading evidence-based hypothesis support…</div>`;
  try {
    const [report, storyline, claimability, counterEvidence] = await Promise.all([
      fetchJson(`${API}/evidence-support/report?case_id=${encodeURIComponent(caseId)}`).catch(() => null),
      fetchJson(`${API}/evidence-support/storyline?case_id=${encodeURIComponent(caseId)}`).catch(() => null),
      fetchJson(`${API}/evidence-support/claimability?case_id=${encodeURIComponent(caseId)}`).catch(() => null),
      fetchJson(`${API}/evidence-support/counter-evidence?case_id=${encodeURIComponent(caseId)}`).catch(() => null),
    ]);
    DashboardState.evidenceSupportDetail = { report, storyline, claimability, counterEvidence };
    renderEvidenceSupportDetailContainer();
  } catch (err) {
    container.innerHTML = `<div class="status-error text-sm">Could not load evidence-based hypothesis support: ${esc(err.message)}</div>`;
  }
}

function renderEvidenceSupportDetailContainer() {
  const container = byId("evidence-support-details");
  if (!container) return;
  container.classList.remove("hidden");
  const detail = DashboardState.evidenceSupportDetail;
  if (!detail?.report) {
    container.innerHTML = `<div class="text-slate-500 text-sm">No Evidence-Based Hypothesis Support has been generated yet for this case.</div>`;
    return;
  }
  if (!byId("evidence-support-hypothesis")) {
    // The 5-card skeleton lives in the HTML; if it is missing, fall back to a minimal render.
    container.innerHTML = `<div class="text-slate-500 text-sm">Report available, markup not generated. Markup unavailable because the normalized evidence-support detail containers are missing from the current view template.</div>`;
    return;
  }
  renderEvidenceSupportHypothesis(detail.report);
  renderEvidenceSupportMatrix(detail.report);
  renderEvidenceSupportStoryline(detail.storyline);
  renderEvidenceSupportClaimability(detail.claimability);
  renderEvidenceSupportGaps(detail.counterEvidence);
}

function renderEvidenceSupportHypothesis(report) {
  const container = byId("evidence-support-hypothesis");
  if (!container) return;
  container.innerHTML = `
    ${report.is_stale ? `<div class="glass-soft rounded-2xl p-4 text-sm text-amber-200 mb-4">This report is stale because source artifacts changed after it was generated. Regenerate it above.</div>` : ""}
    <div class="flex items-center justify-between gap-3 flex-wrap mb-3">
      <div class="font-black">${esc(report.hypothesis_id)}</div>
      <div class="text-xs uppercase tracking-[0.14em] font-black ${statusTone(report.global_support_level)}">${esc(supportLevelLabel(report.global_support_level))} · confidence: ${esc(report.global_confidence || "unknown")}</div>
    </div>
    <div class="text-sm text-slate-300">${esc(report.hypothesis_text)}</div>
    <div class="mt-3 text-sm font-semibold ${statusTone(report.global_support_level)}">${esc(report.final_claimability_status || "")}</div>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
      <div class="text-xs text-slate-300"><strong>Temporal limitations:</strong> ${listItems(report.temporal_limitations, "none")}</div>
      <div class="text-xs text-slate-300"><strong>Integrity limitations:</strong> ${listItems(report.integrity_limitations, "none")}</div>
      <div class="text-xs text-slate-300"><strong>Causal limitations:</strong> ${listItems(report.causal_limitations, "none")}</div>
    </div>
  `;
}

function renderEvidenceSupportMatrix(report) {
  const container = byId("evidence-support-matrix");
  if (!container) return;
  const layerMatrix = report.layer_contribution_matrix;
  if (!layerMatrix) {
    container.innerHTML = `<div class="text-slate-500 text-sm">Layer contribution matrix is not available in this report.</div>`;
    return;
  }
  container.innerHTML = `
    <table class="w-full text-xs text-slate-300">
      <thead><tr class="text-left text-slate-400 uppercase tracking-[0.12em]"><th class="pr-3 py-2">Layer</th><th class="pr-3 py-2">Supports</th><th class="pr-3 py-2">Partially supports</th><th class="pr-3 py-2">Contradicts</th><th class="pr-3 py-2">Not evaluable</th><th class="pr-3 py-2">Timestamp quality</th><th class="pr-3 py-2">Limitation</th></tr></thead>
      <tbody>
        ${Object.entries(layerMatrix).map(([layer, row]) => `
          <tr class="border-t border-slate-800/70 align-top">
            <td class="py-3 pr-3 font-semibold">${esc(row.label || titleize(layer))}</td>
            <td class="py-3 pr-3 status-ok">${esc(row.supports ?? 0)}</td>
            <td class="py-3 pr-3 status-warning">${esc(row.partially_supports ?? 0)}</td>
            <td class="py-3 pr-3 status-error">${esc(row.contradicts ?? 0)}</td>
            <td class="py-3 pr-3">${esc(row.not_evaluable ?? 0)}</td>
            <td class="py-3 pr-3">${esc(titleize(row.timestamp_quality || "not_applicable"))}</td>
            <td class="py-3 pr-3">${esc(maybeTruncate(row.limitation || "none", 140))}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderEvidenceSupportStoryline(storyline) {
  const container = byId("evidence-support-storyline");
  if (!container) return;
  const steps = storyline?.steps || [];
  if (!steps.length) {
    container.innerHTML = `<div class="text-slate-500 text-sm">No forensic storyline is available yet.</div>`;
    return;
  }
  container.innerHTML = steps.map((step, index) => `
    <div class="glass-soft rounded-2xl p-4">
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div class="font-black">${esc(index + 1)}. ${esc(step.event_description)}</div>
        <div class="text-xs uppercase tracking-[0.14em] font-black ${statusTone(step.confidence)}">${esc(titleize(step.confidence || "unknown"))}</div>
      </div>
      <div class="text-xs text-slate-400 mt-2">Layers: ${esc((step.evidence_layers || []).map(titleize).join(", ") || "none")} · Timestamp: ${esc(step.timestamp || "not_available")} (${esc(titleize(step.timestamp_status || "unavailable"))})</div>
      ${step.limitation ? `<div class="text-xs text-amber-300 mt-2">${esc(step.limitation)}</div>` : ""}
      <button type="button" class="run-action-btn btn-secondary rounded-xl px-3 py-1.5 text-[11px] font-extrabold tracking-[0.14em] uppercase mt-3" data-run-action="view-storyline-step" data-step-id="${esc(step.step_id)}">View supporting evidence (${esc((step.supporting_atoms || []).length)})</button>
      <div class="evidence-step-atoms mt-2 hidden text-xs mono text-slate-400" data-step-id="${esc(step.step_id)}">${esc((step.supporting_atoms || []).join(", ") || "none")}</div>
    </div>
  `).join("");
}

function renderEvidenceSupportClaimability(claimability) {
  const supported = byId("evidence-support-claim-supported");
  const partial = byId("evidence-support-claim-partial");
  const unsupported = byId("evidence-support-claim-unsupported");
  if (!supported || !partial || !unsupported) return;
  supported.innerHTML = listItems(claimability?.supported_claims, "none");
  partial.innerHTML = listItems(claimability?.partially_supported_claims, "none");
  unsupported.innerHTML = listItems(claimability?.unsupported_or_not_claimable_claims, "none");
}

function renderEvidenceSupportGaps(counterEvidence) {
  const container = byId("evidence-support-gaps");
  if (!container) return;
  if (!counterEvidence) {
    container.innerHTML = `<div class="text-slate-500 text-sm">No counter-evidence report is available yet.</div>`;
    return;
  }
  const groups = [
    ["Contradicting evidence", counterEvidence.contradicting_evidence, item => `${item.evidence_layer}: ${item.observed_value}`],
    ["Missing or not evaluable", counterEvidence.missing_or_not_evaluable_evidence, item => `${item.evidence_layer}: ${item.limitation}`],
    ["Indirect-only evidence", counterEvidence.indirect_only_evidence, item => `${item.evidence_layer}: ${item.observed_value}`],
    ["Temporally unresolvable", counterEvidence.temporally_unresolvable_evidence, item => `${item.evidence_layer}: ${item.atom_id}`],
  ];
  container.innerHTML = groups.map(([title, items, fmt]) => `
    <div class="mb-3">
      <div class="text-[11px] uppercase tracking-[0.18em] text-slate-400 font-black mb-2">${esc(title)} (${(items || []).length})</div>
      ${listItems((items || []).map(fmt), "none")}
    </div>
  `).join("");
}

function renderExecutiveGrid(summary, payload) {
  const container = byId("lifecycle-exec-grid");
  const note = byId("lifecycle-exec-note");
  if (!container || !note) return;
  if (!summary) {
    note.innerHTML = `<div class="glass-soft rounded-[24px] p-4 text-sm text-amber-200"><div class="font-black uppercase tracking-[0.16em] text-xs mb-2">Executive summary status: not generated</div><div>Source: executive summary snapshot</div><div class="mt-2">Required action: generate executive summary.</div></div>`;
    container.innerHTML = [
      valueCard("Summary status", "Not generated", "Generate the executive summary to expose the synthesized scientific lifecycle.", "status-warning"),
      valueCard("Analysis", payload.live_status?.analysis?.status || "not_started", "Live multilayer analysis state from the case pipeline.", statusTone(payload.live_status?.analysis?.status)),
      valueCard("Time sync", payload.live_status?.time_sync?.status || "unknown", "Live time-synchronization state for the case.", statusTone(payload.live_status?.time_sync?.status)),
      valueCard("Causal", payload.live_status?.causal?.status || "not_available", "Live causal reconstruction state.", statusTone(payload.live_status?.causal?.status)),
    ].join("");
    return;
  }
  const exec = summary.execution_summary || {};
  const summaryStatus = summary.summary_status || {};
  note.innerHTML = `
    <div class="glass-soft rounded-[24px] p-4 text-sm ${summaryStatus.status === "stale" ? "text-amber-200" : "text-slate-300"}">
      <div class="font-black uppercase tracking-[0.16em] text-xs mb-2">Executive summary status: ${esc(titleize(summaryStatus.status || "current"))}</div>
      <div>Source: ${esc(summaryStatus.source_label || "executive summary snapshot")}</div>
      ${summaryStatus.reason ? `<div class="mt-2"><span class="font-black">Reason:</span> ${esc(summaryStatus.reason)}</div>` : ""}
      ${summaryStatus.required_action ? `<div class="mt-2 flex items-center justify-between gap-3 flex-wrap"><span><span class="font-black">Required action:</span> ${esc(summaryStatus.required_action)}.</span><button type="button" class="run-action-btn btn-secondary rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.16em] uppercase" data-run-action="generate-summary">Regenerate Executive Summary</button></div>` : ""}
    </div>
  `;
  container.innerHTML = [
    valueCard("Case ID", summary.case_id, summary.case_path, "status-info"),
    valueCard("Scenario", summary.scenario_id || "unknown", summary.scenario_name || "unknown", "status-info"),
    valueCard("Evidence lifecycle", exec.evidence_lifecycle_status || "unknown", "Preservation, integrity, and analysis lifecycle state.", statusTone(exec.evidence_lifecycle_status)),
    valueCard("Last multilayer analysis", exec.multilayer_analysis_status || "unknown", "Snapshot baked into the executive summary at generation time, not live pipeline state.", statusTone(exec.multilayer_analysis_status)),
    valueCard("Last causal reconstruction", exec.causal_reconstruction_status || "unknown", "Snapshot baked into the executive summary at generation time, not live pipeline state.", statusTone(exec.causal_reconstruction_status)),
    valueCard("Evidence processing coverage", exec.evidence_processing_coverage || exec.evidence_analysis_confidence || "unknown", exec.evidence_processing_interpretation || "Coverage of the multilayer evidence processing stage, not of the global conclusion.", statusTone(exec.evidence_processing_coverage || exec.evidence_analysis_confidence)),
    valueCard("Forensic reconstruction confidence", exec.forensic_reconstruction_confidence || "unknown", "Reconstruction-level confidence from the multilayer view.", statusTone(exec.forensic_reconstruction_confidence)),
    valueCard("Causal interpretation confidence", exec.causal_interpretation_confidence || "unknown", "Confidence in the derived causal interpretation.", statusTone(exec.causal_interpretation_confidence)),
  ].join("");
}

function renderLifecycleRail(summary, payload) {
  const container = byId("lifecycle-rail");
  const stale = byId("lifecycle-stale-note");
  if (!container || !stale) return;
  stale.innerHTML = summary?.is_stale
    ? `<div class="flex items-center justify-between gap-3 flex-wrap"><span>${esc(summary.stale_reason || "Executive summary is stale.")}</span><button type="button" class="run-action-btn btn-secondary rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.16em] uppercase" data-run-action="generate-summary">Regenerate Executive Summary</button></div>`
    : "";
  const rail = summary?.evidence_lifecycle?.rail;
  if (!Array.isArray(rail) || !rail.length) {
    container.innerHTML = `<div class="text-slate-500">Executive lifecycle rail is not available until the summary is generated.</div>`;
    return;
  }
  container.innerHTML = rail.map(step => `
    <div class="rail-step relative min-w-[180px] max-w-[220px]">
      <button type="button" class="glass-soft rounded-[22px] p-4 h-full w-full text-left rail-phase-btn" data-rail-phase="${esc(step.phase)}">
        <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">${esc(step.label)}</div>
        <div class="text-sm font-black mt-3 ${statusTone(step.status)}">${esc(titleize(step.status))}</div>
        <div class="text-[11px] text-slate-500 mt-3 uppercase tracking-[0.14em] font-black">View explanation</div>
      </button>
    </div>
  `).join("");
}

function renderJobPanel(payload) {
  const live = payload.live_status || {};
  const analysis = live.analysis || {};
  const timeSync = live.time_sync || {};
  const causal = live.causal || {};
  const trackedJobId = DashboardState.trackedJobId;
  if (!trackedJobId) {
    const summary = payload.summary;
    const lastMultilayer = summary?.execution_summary?.multilayer_analysis_status;
    const lastCausal = summary?.execution_summary?.causal_reconstruction_status;
    const conflicts = [];
    if (analysis.status === "running" && lastMultilayer && lastMultilayer !== "running") {
      conflicts.push(`A new multilayer analysis run is currently in progress (phase: ${analysis.current_phase || "unknown"}); the executive summary above still reflects the previous "${lastMultilayer}" run.`);
    }
    if (String(causal.status || "").toLowerCase() === "running" && lastCausal && lastCausal !== "running") {
      conflicts.push(`A new causal reconstruction run is currently in progress; the executive summary above still reflects the previous "${lastCausal}" run.`);
    }
    setJobPanel(`
      <div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black mb-3">Current job / live pipeline status (not the executive summary snapshot)</div>
      ${conflicts.length ? `<div class="glass-soft rounded-2xl p-4 text-sm text-amber-200 mb-4 space-y-1">${conflicts.map(item => `<div>${esc(item)}</div>`).join("")}</div>` : ""}
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Live analysis</div><div class="text-lg font-black mt-2 ${statusTone(analysis.status)}">${esc(titleize(analysis.status || "not_started"))}</div><div class="text-xs text-slate-400 mt-2">${esc(analysis.current_phase || "not_running")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Live time sync</div><div class="text-lg font-black mt-2 ${statusTone(timeSync.status)}">${esc(titleize(timeSync.status || "unknown"))}</div><div class="text-xs text-slate-400 mt-2">${esc(timeSync.current_step || timeSync.reason || "not_running")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.2em] text-slate-400 font-black">Live causal</div><div class="text-lg font-black mt-2 ${statusTone(causal.status)}">${esc(titleize(causal.status || "not_available"))}</div><div class="text-xs text-slate-400 mt-2">${esc(causal.current_step || causal.reason || "not_running")}</div></div>
      </div>
    `);
    return;
  }
}

async function refreshTrackedJob() {
  if (!DashboardState.trackedJobId) return;
  try {
    const job = await fetchJson(`${API}/lifecycle/job-status?job_id=${encodeURIComponent(DashboardState.trackedJobId)}`);
    renderTrackedJob(job);
    if (!["queued", "running"].includes(job.status)) {
      DashboardState.trackedJobId = null;
      await loadDashboard(DashboardState.selectedCaseId);
    }
  } catch (err) {
    setJobPanel(`<div class="status-error">Job tracking failed: ${esc(err.message)}</div>`);
  }
}

function renderTrackedJob(job) {
  setJobPanel(`
    <div class="flex flex-col gap-4">
      <div class="flex flex-wrap gap-2">
        ${tag("job", job.job_type || "unknown")}
        ${tag("status", job.status || "unknown", statusTone(job.status))}
        ${tag("progress", `${job.progress_percent ?? 0}%`, statusTone(job.status))}
        ${tag("phase", job.current_phase || "unknown", statusTone(job.status))}
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        ${(job.phases || []).map(phase => `
          <div class="glass rounded-2xl p-4">
            <div class="text-xs uppercase tracking-[0.18em] text-slate-400 font-black">${esc(phase.name)}</div>
            <div class="text-sm font-black mt-2 ${statusTone(phase.status)}">${esc(titleize(phase.status || "unknown"))}</div>
            <div class="text-xs text-slate-400 mt-2">${esc(phase.summary || phase.error_message || phase.artifact_path || "no details")}</div>
          </div>
        `).join("")}
      </div>
      ${(job.warnings || []).length ? `<div class="glass-soft rounded-2xl p-4 text-sm text-amber-200"><div class="font-black uppercase tracking-[0.18em] text-xs mb-2">Warnings</div>${(job.warnings || []).map(item => `<div>${esc(item)}</div>`).join("")}</div>` : ""}
      ${(job.errors || []).length ? `<div class="glass-soft rounded-2xl p-4 text-sm text-rose-200"><div class="font-black uppercase tracking-[0.18em] text-xs mb-2">Errors</div>${(job.errors || []).map(item => `<div>${esc(item)}</div>`).join("")}</div>` : ""}
    </div>
  `);
}

function renderMultilayer(summary, payload) {
  const tags = byId("multilayer-summary-tags");
  const overview = byId("multilayer-overview");
  const matrix = byId("multilayer-matrix");
  const bridge = byId("multilayer-causal-bridge-note");
  if (!tags || !overview || !matrix || !bridge) return;
  const multi = summary?.multilayer_analysis_summary;
  if (!multi) {
    tags.innerHTML = tag("status", payload.live_status?.analysis?.status || "not_started", statusTone(payload.live_status?.analysis?.status));
    overview.innerHTML = valueCard("Summary", "Not generated", "Run or regenerate multilayer analysis and then generate the executive summary.", "status-warning");
    bridge.innerHTML = "Multilayer analysis evaluates whether the preserved evidence was processed across the expected forensic layers. Causal reconstruction evaluates whether the expected attack relations can be reconstructed from the preserved evidence.";
    matrix.innerHTML = `<tr><td colspan="6" class="py-6 text-slate-500">No multilayer executive summary is available yet.</td></tr>`;
    return;
  }
  tags.innerHTML = [
    tag("execution", multi.execution_status || "unknown", statusTone(multi.execution_status)),
    tag("evidence", multi.evidence_analysis_status || "unknown", statusTone(multi.evidence_analysis_status)),
    tag("forensic", multi.forensic_reconstruction_status || "unknown", statusTone(multi.forensic_reconstruction_status)),
    tag("confidence", multi.analysis_confidence || "unknown", statusTone(multi.analysis_confidence)),
  ].join("");
  overview.innerHTML = [
    valueCard("Expected layers", multi.layers_expected || 0, "Layers expected in the scientific lifecycle view."),
    valueCard("Completed", multi.layers_completed || 0, "Pipeline layers completed."),
    valueCard("Useful output", multi.layers_with_useful_output || 0, "Layers that produced effective findings.", "status-ok"),
    valueCard("Partial", multi.layers_partial || 0, "Layers with partial or degraded results.", "status-warning"),
    valueCard("Failed", multi.layers_failed || 0, "Layers that failed or remain unavailable.", multi.main_limitation || "", "status-error"),
    valueCard("Report", multi.execution_status || "unknown", multi.report_path || "report_not_available", statusTone(multi.execution_status)),
  ].join("");
  bridge.innerHTML = `
    <div class="font-black text-slate-200">Multilayer analysis evaluates whether the preserved evidence was processed across the expected forensic layers.</div>
    <div class="mt-2">Causal reconstruction evaluates whether the expected attack relations can be reconstructed from the preserved evidence.</div>
    <div class="mt-2 text-slate-400">Therefore, ${esc(String(multi.layers_completed || 0))} completed layers does not mean ${esc(String(summary?.causal_summary?.expected_edges || 0))} causal edges must be fully recovered.</div>
  `;
  matrix.innerHTML = (multi.layers || []).map(layer => `
    <tr class="border-t border-slate-800/70 align-top">
      <td class="py-4 pr-4 font-semibold">${esc(layer.layer_name)}</td>
      <td class="py-4 pr-4 ${statusTone(layer.status)}">${esc(titleize(layer.status))}</td>
      <td class="py-4 pr-4 ${statusTone(layer.usefulness_status)}">${esc(titleize(layer.usefulness_status))}</td>
      <td class="py-4 pr-4">${esc(maybeTruncate(layer.summary || "not_available", 180))}</td>
      <td class="py-4 pr-4">${esc(maybeTruncate((layer.limitations || []).join(" | ") || "none", 180))}</td>
      <td class="py-4 pr-4">
        <details class="glass-soft rounded-xl p-3">
          <summary class="cursor-pointer font-black text-slate-200">View technical details</summary>
          <div class="text-xs text-slate-300 mt-3 space-y-2">
            <div>artifact: <span class="mono">${esc(layer.artifact_path || "not_available")}</span></div>
            <div>stdout: <span class="mono">${esc(layer.stdout_log || "not_available")}</span></div>
            <div>stderr: <span class="mono">${esc(layer.stderr_log || "not_available")}</span></div>
            <div>started_at: <span class="mono">${esc(layer.started_at || "not_available")}</span></div>
            <div>finished_at: <span class="mono">${esc(layer.finished_at || "not_available")}</span></div>
            <div>duration_seconds: <span class="mono">${esc(formatMaybeNumber(layer.duration_seconds))}</span></div>
            <div>error_message: <span class="mono">${esc(layer.error_message || "none")}</span></div>
          </div>
        </details>
      </td>
    </tr>
  `).join("");
}

function renderMemoryAnalysis(summary) {
  const overview = byId("memory-analysis-overview");
  const matrix = byId("memory-plugin-matrix");
  if (!overview || !matrix) return;
  const detail = summary?.memory_analysis_detail;
  if (!detail) {
    overview.innerHTML = valueCard("Memory analysis", "Not available", "No memory analysis detail is available in the executive summary.", "status-warning");
    matrix.innerHTML = `<tr><td colspan="5" class="py-6 text-slate-500">No memory plugin coverage summary is available yet.</td></tr>`;
    return;
  }
  overview.innerHTML = [
    valueCard("Memory layer usefulness", titleize(detail.memory_layer_usefulness || "unknown"), detail.reason || "No reason recorded.", statusTone(detail.memory_layer_usefulness)),
    valueCard("Dumps analyzed", detail.dumps_analyzed || 0, `Dumps total: ${detail.dumps_total || 0}`, statusTone(detail.status)),
    valueCard("Memory dump opened successfully", detail.memory_dump_opened_successfully || "unknown", "Whether the dump could be opened and processed at all.", statusTone(detail.memory_dump_opened_successfully)),
    valueCard("Kernel banner extracted", detail.kernel_banner_extracted || "unknown", "Whether the memory layer successfully extracted kernel banners from the dumps.", statusTone(detail.kernel_banner_extracted)),
    valueCard("Compatible symbols available", detail.compatible_symbols_available || "unknown", "Volatility 3 Linux symbol availability across the analyzed dumps.", statusTone(detail.compatible_symbols_available)),
    valueCard("Useful memory atoms extracted", detail.useful_memory_atoms_extracted || 0, "Completed plugin passes that produced usable memory-layer outputs.", "status-ok"),
  ].join("");
  matrix.innerHTML = (detail.plugins || []).map(plugin => `
    <tr class="border-t border-slate-800/70 align-top">
      <td class="py-4 pr-4 font-semibold">${esc(plugin.label || plugin.plugin_key)}</td>
      <td class="py-4 pr-4 ${statusTone(plugin.status)}">${esc(titleize(plugin.status || "unknown"))}</td>
      <td class="py-4 pr-4">${esc(plugin.completed_dumps ?? 0)}</td>
      <td class="py-4 pr-4">${esc(plugin.partial_dumps ?? 0)}</td>
      <td class="py-4 pr-4">${esc((plugin.failed_dumps ?? 0) + (plugin.blocked_dumps ?? 0))}</td>
    </tr>
  `).join("");
}

function renderAlertTriage(summary) {
  const grid = byId("alert-triage-grid");
  const note = byId("alert-triage-note");
  if (!grid || !note) return;
  const triage = summary?.alert_triage_summary;
  if (!triage) {
    grid.innerHTML = valueCard("Alert triage", "Not available", "No alert triage summary is available in the executive snapshot.", "status-warning");
    note.textContent = "Alert triage and trigger-selection details will appear here once the executive summary is regenerated.";
    return;
  }
  grid.innerHTML = [
    valueCard("Total alerts indexed", triage.total_alerts_indexed ?? "not_available", "Alerts preserved and summarized for this case.", "status-info"),
    valueCard("Alerts inside case window", triage.alerts_inside_selected_case_window ?? "not_available", `Outside selected case window: ${triage.alerts_outside_selected_case_window ?? "not_available"}`, "status-info"),
    valueCard("Correlated alerts", triage.correlated_alerts ?? "not_available", `Uncorrelated alerts: ${triage.uncorrelated_alerts ?? "not_available"}`, "status-ok"),
    valueCard("Trigger candidates evaluated", triage.trigger_candidates_evaluated ?? "not_available", "Candidates evaluated during acquisition-trigger selection.", "status-info"),
    valueCard("Selected trigger", triage.selected_trigger || "not_available", `Rule: ${triage.selected_trigger_rule || "not_available"} · source: ${triage.selected_trigger_source || "not_available"}`, "status-warning"),
    valueCard("Trigger selection score", triage.selected_trigger_score ?? "not_available", `Stronger trigger available: ${triage.stronger_trigger_available ? "yes" : "no"}`, triage.stronger_trigger_available ? "status-warning" : "status-ok"),
  ].join("");
  note.innerHTML = `
    <div><span class="font-black">Reason for selection:</span> ${esc(triage.reason_for_selection || "not_available")}</div>
    <div class="mt-2"><span class="font-black">Rejected candidates summary:</span> ${esc((triage.rejected_candidates_summary || []).join(" | ") || "not_available")}</div>
    <div class="mt-2"><span class="font-black">Noise ratio:</span> ${esc(formatMaybeNumber(triage.noise_ratio, 4))}</div>
  `;
}

function renderCausalAndUncertainty(summary, payload) {
  const causalGrid = byId("causal-summary-grid");
  const causalText = byId("causal-summary-text");
  const uncertaintyGrid = byId("uncertainty-summary-grid");
  const uncertaintyWarning = byId("uncertainty-warning");
  if (!causalGrid || !causalText || !uncertaintyGrid || !uncertaintyWarning) return;
  const causal = summary?.causal_summary;
  const uncertainty = summary?.uncertainty_summary;
  const integrity = summary?.integrity_summary || {};
  if (!causal) {
    causalGrid.innerHTML = valueCard("Causal state", payload.live_status?.causal?.status || "not_available", payload.live_status?.causal?.reason || "Causal reconstruction has not been summarized in this executive view yet.", statusTone(payload.live_status?.causal?.status));
    causalText.textContent = payload.live_status?.causal?.reason || "Causal reconstruction is not yet available for this case.";
  } else {
    const weighted = causal.weighted_cpr_details || {};
    const why = causal.why_expected_relations || {};
    causalGrid.innerHTML = [
      valueCard("CPR", formatMaybeNumber(causal.cpr), "Recovered expected causal relations / expected causal relations.", statusTone(causal.status)),
      valueCard("Weighted CPR", formatMaybeNumber(causal.weighted_cpr), "Weighted causal recoverability using scenario-defined edge weights.", statusTone(causal.status)),
      valueCard("Recovered edges", `${causal.recovered_edges || 0} / ${causal.expected_edges || 0}`, "Expected causal relations fully recovered.", "status-ok"),
      valueCard("Degraded edges", causal.degraded_edges || 0, "Edges with partial support.", "status-warning"),
      valueCard("Ambiguous edges", causal.ambiguous_edges || 0, "Edges limited by temporal uncertainty.", "status-warning"),
      valueCard("Missing edges", causal.missing_edges || 0, "Edges unsupported by the preserved artifact set.", causal.main_limitation || "", statusTone(causal.status)),
    ].join("");
    causalText.innerHTML = `
      <div class="glass-soft rounded-2xl p-4 mb-4 ${statusTone(causal.status)}">
        <div class="text-xs uppercase tracking-[0.16em] font-black">Scientific interpretation</div>
        <div class="mt-2 text-sm">${esc(causal.interpretation_banner || causal.main_limitation || "No causal limitation summary available.")}</div>
      </div>
      <div class="${statusTone(causal.status)} font-black">Status: ${esc(titleize(causal.status || "not_available"))}</div>
      <div class="mt-3">${esc(causal.main_limitation || "No causal limitation summary available.")}</div>
      <div class="mt-4 glass-soft rounded-2xl p-4">
        <div class="font-black text-slate-200">CPR</div>
        <div class="mt-2 text-slate-300">Formula: <span class="mono">${esc(weighted.cpr_formula || "fully recovered expected causal edges / total expected causal edges")}</span></div>
        <div class="mt-3 font-black text-slate-200">Weighted CPR</div>
        <div class="mt-2 text-slate-300">Formula: <span class="mono">${esc(weighted.weighted_cpr_formula || "recovered edge weight / total expected edge weight")}</span></div>
        <div class="mt-2 text-slate-400">${esc(weighted.weighted_cpr_explanation || "Weighted CPR uses scenario-defined edge weights.")}</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3 mt-4 text-xs">
          <div><span class="text-slate-500">total edge weight</span><div class="mono mt-1">${esc(formatMaybeNumber(weighted.total_edge_weight))}</div></div>
          <div><span class="text-slate-500">recovered edge weight</span><div class="mono mt-1">${esc(formatMaybeNumber(weighted.recovered_edge_weight))}</div></div>
          <div><span class="text-slate-500">degraded edge weight</span><div class="mono mt-1">${esc(formatMaybeNumber(weighted.degraded_edge_weight))}</div></div>
          <div><span class="text-slate-500">penalty applied</span><div class="mono mt-1">${esc(formatMaybeNumber(weighted.penalty_applied?.total_penalty))}</div></div>
          <div><span class="text-slate-500">final weighted score</span><div class="mono mt-1">${esc(formatMaybeNumber(weighted.final_weighted_score))}</div></div>
        </div>
      </div>
      <details class="glass-soft rounded-2xl p-4 mt-4">
        <summary class="cursor-pointer font-black text-slate-200">${esc(why.title || "Why expected causal relations?")}</summary>
        <div class="mt-3 text-slate-300">${esc(why.summary || "No explanation available.")}</div>
        <div class="overflow-x-auto mt-4">
          <table class="w-full text-xs text-slate-300">
            <thead><tr class="text-left text-slate-400 uppercase tracking-[0.12em]"><th class="pr-3 py-2">Edge</th><th class="pr-3 py-2">Source event</th><th class="pr-3 py-2">Target event</th><th class="pr-3 py-2">Expected evidence</th><th class="pr-3 py-2">Recovered status</th><th class="pr-3 py-2">Support</th><th class="pr-3 py-2">Degradation reason</th><th class="pr-3 py-2">Temporal resolvability</th></tr></thead>
            <tbody>
              ${(why.relations || []).map(item => `
                <tr class="border-t border-slate-800/70 align-top">
                  <td class="py-3 pr-3 mono">${esc(item.edge_id || "not_available")}</td>
                  <td class="py-3 pr-3">${esc(item.source_event || "not_available")}</td>
                  <td class="py-3 pr-3">${esc(item.target_event || "not_available")}</td>
                  <td class="py-3 pr-3">${esc(item.expected_evidence_source || "not_available")}</td>
                  <td class="py-3 pr-3 ${statusTone(item.recovered_status)}">${esc(titleize(item.recovered_status || "not_available"))}</td>
                  <td class="py-3 pr-3 ${statusTone(item.support_level)}">${esc(titleize(item.support_level || "unknown"))}</td>
                  <td class="py-3 pr-3">${esc(maybeTruncate(item.degradation_reason || "none", 180))}</td>
                  <td class="py-3 pr-3">${esc(titleize(item.temporal_resolvability || "unknown"))}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </details>
      ${causal.is_stale ? `<div class="mt-3 flex items-center justify-between gap-3 flex-wrap status-warning font-black"><span>Causal reconstruction is stale because analysis outputs were modified after causal artifacts were generated.</span><button type="button" class="run-action-btn btn-secondary rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.16em] uppercase" data-run-action="rerun-causal">Regenerate Causal Reconstruction</button></div>` : ""}
    `;
  }
  if (!uncertainty) {
    uncertaintyGrid.innerHTML = valueCard("Uncertainty", "Not generated", "No uncertainty summary is available yet.", "status-warning");
    uncertaintyWarning.textContent = "Temporal and integrity constraints will appear here when the executive summary is generated.";
  } else {
    uncertaintyGrid.innerHTML = [
      valueCard("Clock synchronization", uncertainty.synchronized_status || "unknown", `Source: ${uncertainty.time_sync_source || "not_available"}`, statusTone(uncertainty.synchronized_status)),
      valueCard("Evidence timestamp availability", uncertainty.evidence_timestamp_availability || "unknown", "Whether required artifact timestamps exist at all.", statusTone(uncertainty.evidence_timestamp_availability)),
      valueCard("Available timestamp resolvability", uncertainty.available_timestamp_resolvability || uncertainty.evidence_timestamp_resolvability || "unknown", "Whether the timestamps that do exist can be resolved well enough for ordering.", statusTone(uncertainty.available_timestamp_resolvability || uncertainty.evidence_timestamp_resolvability)),
      valueCard("Causal edge timestamp coverage", uncertainty.causal_edge_timestamp_coverage || "unknown", "Whether the expected causal edges have the timestamps required for causal ordering.", statusTone(uncertainty.causal_edge_timestamp_coverage)),
      valueCard("Causal temporal ordering confidence", uncertainty.causal_temporal_ordering_confidence || "unknown", "Confidence in temporal ordering of the expected causal edges.", statusTone(uncertainty.causal_temporal_ordering_confidence)),
      valueCard("Max clock offset", `${formatMaybeNumber(uncertainty.max_clock_offset_seconds)}s`, uncertainty.time_sync_source || "not_available", statusTone(uncertainty.synchronized_status)),
      valueCard("Uncertainty window", `${formatMaybeNumber(uncertainty.uncertainty_window_seconds)}s`, "Temporal ordering window used by the uncertainty budget.", statusTone(uncertainty.temporal_confidence)),
      valueCard("Integrity validation execution", integrity.validation_execution_status || "unknown", `Validation output: ${integrity.validation_output_status || "unknown"}`, statusTone(integrity.validation_execution_status)),
      valueCard("Case-wide integrity completeness", integrity.case_wide_integrity_completeness || "unknown", `Case-wide integrity ratio: ${formatMaybeNumber(integrity.case_wide_integrity_ratio, 4)}`, statusTone(integrity.case_wide_integrity_completeness)),
      valueCard("Correction applied", uncertainty.correction_applied ? "yes" : "no", `Before: ${uncertainty.before_path || "not_available"} | After: ${uncertainty.after_path || "not_available"}`, uncertainty.correction_applied ? "status-warning" : "status-muted"),
      valueCard("Worst node", uncertainty.worst_node?.name || uncertainty.worst_node?.vm_id || "not_available", uncertainty.worst_node?.ip || "not_available", statusTone(uncertainty.synchronized_status)),
      valueCard("Nodes measured", `${uncertainty.nodes_measured ?? "not_available"} / failed ${uncertainty.nodes_failed ?? "not_available"}`, "Current measurement status.", statusTone(uncertainty.current_measurement_status)),
    ].join("");
    uncertaintyWarning.innerHTML = `
      <div class="font-black text-slate-200">Reason</div>
      <div class="mt-2">${esc(uncertainty.causal_temporal_ordering_reason || uncertainty.main_limitation || "No additional uncertainty warning recorded.")}</div>
      <div class="mt-3 text-slate-300">The integrity and custody validation step can complete successfully while the case-wide integrity assessment still remains partial. These are different scientific questions.</div>
      <div class="mt-3 text-slate-400">${esc(uncertainty.temporal_model_note || "A synchronized infrastructure does not automatically guarantee that every forensic artifact contains usable timestamps for causal ordering.")}</div>
    `;
  }
}

function renderTriggerAndModbus(summary) {
  const triggerPanel = byId("trigger-vs-causal");
  const modbusPanel = byId("modbus-specificity");
  if (!triggerPanel || !modbusPanel) return;
  const causal = summary?.causal_summary;
  const trigger = summary?.trigger_summary;
  if (!summary || !causal) {
    triggerPanel.textContent = "No trigger-versus-causal comparison is available yet.";
    modbusPanel.innerHTML = valueCard("Modbus specificity", "Not available", "Generate the executive summary after causal reconstruction.");
    return;
  }
  const align = causal.trigger_vs_causal_path || {};
  let alignTone = "status-warning";
  let alignText = align.message || "Trigger and causal attack path alignment cannot be confirmed from the current summary.";
  if (align.same_event_family === true) {
    alignTone = "status-ok";
    alignText = "No explicit mismatch was detected between the trigger and the causal attack path.";
  } else if (align.same_event_family === false) {
    alignTone = "status-warning";
  }
  triggerPanel.innerHTML = `
    <div class="space-y-3">
      <div><span class="text-slate-400 uppercase tracking-[0.14em] text-xs font-black">Trigger path</span><div class="mt-2">${esc(align.trigger_path || trigger.trigger || "not_available")}</div></div>
      <div><span class="text-slate-400 uppercase tracking-[0.14em] text-xs font-black">Trigger rule</span><div class="mt-2 mono">${esc(align.trigger_rule_id || trigger.triggering_alert_rule_id || "not_available")}</div></div>
      <div><span class="text-slate-400 uppercase tracking-[0.14em] text-xs font-black">Causal attack path</span><div class="mt-2">${esc(align.causal_attack_path || "not_available")}</div></div>
      <div><span class="text-slate-400 uppercase tracking-[0.14em] text-xs font-black">Status</span><div class="mt-2 ${alignTone} font-black">${esc(titleize(align.status || "unknown"))}</div></div>
      <div><span class="text-slate-400 uppercase tracking-[0.14em] text-xs font-black">Scientific interpretation</span><div class="mt-2">${esc(align.scientific_interpretation || "not_available")}</div></div>
      <div class="${alignTone} font-black mt-2">${esc(alignText)}</div>
    </div>
  `;
  const modbus = causal.modbus_specificity || {};
  modbusPanel.innerHTML = Object.entries(modbus)
    .filter(([key]) => !["message", "interpretation"].includes(key))
    .map(([key, item]) => valueCard(titleize(key), item?.value || "not_available", `Status: ${item?.status || "unknown"}`, statusTone(item?.status)))
    .join("");
  if (modbus.message) {
    modbusPanel.innerHTML += `<div class="md:col-span-2 glass-soft rounded-[24px] p-4 text-sm text-amber-200">${esc(modbus.message)}</div>`;
  }
  if (modbus.interpretation) {
    modbusPanel.innerHTML += `
      <div class="md:col-span-2 glass-soft rounded-[24px] p-4 text-sm text-slate-300">
        <div class="font-black text-slate-200">Confirmed</div>
        <div class="mt-1">${esc(modbus.interpretation.confirmed || "not_available")}</div>
        <div class="font-black text-slate-200 mt-3">Partially supported</div>
        <div class="mt-1">${esc(modbus.interpretation.partially_supported || "not_available")}</div>
        <div class="font-black text-slate-200 mt-3">Not fully claimable</div>
        <div class="mt-1">${esc(modbus.interpretation.not_fully_claimable || "not_available")}</div>
        <div class="mt-3 text-amber-200">${esc(modbus.interpretation.summary || "")}</div>
      </div>
    `;
  }
}

function renderEvidenceStory(summary) {
  const panel = byId("evidence-story-panel");
  if (!panel) return;
  const story = summary?.evidence_based_reconstruction_story;
  if (!story || story.status === "not_available") {
    panel.textContent = "No evidence-based reconstruction story is available yet.";
    return;
  }
  panel.innerHTML = `
    <div class="font-black text-slate-200 mb-3">Evidence-based reconstruction story</div>
    <div>${esc(story.summary_text || "No narrative summary is available.")}</div>
    <div class="mt-4 text-xs text-slate-400">Supported claims: ${esc(story.supported_claim_count ?? 0)} · partially supported: ${esc(story.partially_supported_claim_count ?? 0)} · unsupported: ${esc(story.unsupported_claim_count ?? 0)}</div>
  `;
}

function renderConclusion(summary, payload) {
  const conclusion = summary?.final_forensic_conclusion;
  const summaryBox = byId("final-conclusion-summary");
  const supported = byId("final-supported");
  const degraded = byId("final-degraded");
  const unsupported = byId("final-unsupported");
  if (!summaryBox || !supported || !degraded || !unsupported) return;
  if (!conclusion) {
    summaryBox.textContent = "Final forensic conclusion is not available until the executive summary is generated.";
    supported.innerHTML = listItems([], "No supported claims listed.");
    degraded.innerHTML = listItems([], "No degraded claims listed.");
    unsupported.innerHTML = listItems([], "No unsupported claims listed.");
    return;
  }
  summaryBox.textContent = conclusion.summary_text || "No conclusion summary available.";
  supported.innerHTML = listItems(conclusion.supported, "No supported claims listed.");
  degraded.innerHTML = listItems(conclusion.degraded_or_ambiguous, "No degraded claims listed.");
  unsupported.innerHTML = listItems(conclusion.unsupported_or_not_claimable, "No unsupported claims listed.");
}

function renderReports(summary, payload) {
  const grid = byId("reports-grid");
  if (!grid) return;
  const reports = payload.reports_index || summary?.reports_and_artifacts || [];
  if (!Array.isArray(reports) || !reports.length) {
    grid.innerHTML = `<div class="text-slate-500">No report index is available for this case.</div>`;
    return;
  }
  grid.innerHTML = reports.map(report => {
    const openable = Boolean(report.exists) && report.size_bytes !== null && report.size_bytes !== undefined;
    return `
    <div class="glass-soft rounded-[24px] p-4">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-400 font-black">${esc(report.type)}</div>
      <div class="mono text-xs text-slate-300 mt-3">${esc(report.path || "not_available")}</div>
      <div class="text-xs text-slate-500 mt-2">size=${esc(report.size_bytes ?? "not_available")} bytes · mtime=${esc(report.mtime || "not_available")}</div>
      <div class="mt-4">
        <button class="open-report-btn ${openable ? "btn-secondary" : "btn-secondary opacity-50 cursor-not-allowed"} rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.16em] uppercase" data-report-type="${esc(report.type)}" ${openable ? "" : "disabled"}>Open</button>
      </div>
    </div>
  `;
  }).join("");
}

function renderLists(summary, payload) {
  const limitations = byId("limitations-list");
  const actions = byId("next-actions-list");
  if (!limitations || !actions) return;
  limitations.innerHTML = listItems(summary?.limitations || [], "No explicit limitations were generated.");
  actions.innerHTML = listItems(summary?.next_required_actions || [], "No next actions were generated.");
}

async function runAction(kind) {
  const caseId = DashboardState.selectedCaseId;
  if (!caseId) return;
  if (kind === "run-full" && !window.confirm("Run the full evidence lifecycle? This may take time and will start multiple background phases.")) {
    return;
  }
  if (kind === "fix-time" && !window.confirm("Fix Time Synchronization changes node state and can alter volatile temporal evidence. Continue only in explicit maintenance or laboratory mode.")) {
    return;
  }
  try {
    let payload = null;
    if (kind === "run-multilayer") {
      payload = await postJson(`${API}/lifecycle/run-multilayer-analysis`, { case_id: caseId, force: false });
    } else if (kind === "rerun-multilayer") {
      payload = await postJson(`${API}/lifecycle/run-multilayer-analysis`, { case_id: caseId, force: true });
    } else if (kind === "measure-clock") {
      payload = await postJson(`${API}/time-sync/measure`, { case_id: caseId });
    } else if (kind === "fix-time") {
      payload = await postJson(`${API}/time-sync/fix`, { case_id: caseId });
    } else if (kind === "run-causal") {
      payload = await postJson(`${API}/lifecycle/run-causal`, { case_id: caseId, degraded_ok: true });
    } else if (kind === "rerun-causal") {
      payload = await postJson(`${API}/lifecycle/run-causal`, { case_id: caseId, degraded_ok: true });
    } else if (kind === "run-full") {
      payload = await postJson(`${API}/lifecycle/run-full`, { case_id: caseId, degraded_ok: true });
      DashboardState.trackedJobId = payload.job_id || null;
      await refreshTrackedJob();
    } else if (kind === "generate-summary") {
      payload = await postJson(`${API}/lifecycle/generate-summary`, { case_id: caseId });
      DashboardState.trackedJobId = payload.job_id || null;
      await refreshTrackedJob();
    } else if (kind === "generate-evidence-support") {
      payload = await postJson(`${API}/evidence-support/regenerate`, { case_id: caseId });
      DashboardState.evidenceSupportDetail = null;
      DashboardState.trackedJobId = payload.job_id || null;
      await refreshTrackedJob();
      if (DashboardState.evidenceSupportDetailVisible) {
        await loadEvidenceSupportDetail();
      }
    }
    await loadDashboard(caseId);
  } catch (err) {
    setJobPanel(`<div class="status-error">Action failed: ${esc(err.message)}</div>`);
  }
}

function syncPolling() {
  if (DashboardState.pollTimer) {
    clearInterval(DashboardState.pollTimer);
    DashboardState.pollTimer = null;
  }
  const live = DashboardState.dashboard?.live_status || {};
  const needsPolling =
    DashboardState.trackedJobId ||
    live.analysis?.status === "running" ||
    live.time_sync?.status === "running" ||
    live.causal?.status === "running";
  if (!needsPolling) return;
  DashboardState.pollTimer = setInterval(async () => {
    if (DashboardState.trackedJobId) {
      await refreshTrackedJob();
    }
    if (DashboardState.selectedCaseId) {
      await loadDashboard(DashboardState.selectedCaseId);
    }
  }, 3000);
}

async function openReport(reportType) {
  const caseId = DashboardState.selectedCaseId;
  if (!caseId) return;
  const payload = await fetchJson(`${API}/reports/file?case_id=${encodeURIComponent(caseId)}&type=${encodeURIComponent(reportType)}`);
  byId("report-modal-title").textContent = titleize(payload.report_type || reportType);
  byId("report-modal-path").textContent = payload.path || "not_available";
  byId("report-modal-meta").textContent = `format=${payload.format || "unknown"} · size=${payload.size_bytes ?? "n/a"} bytes${payload.truncated ? " · preview_truncated=true" : ""}`;
  if (payload.format === "json") {
    byId("report-modal-body").textContent = JSON.stringify(payload.content, null, 2);
  } else {
    byId("report-modal-body").textContent = payload.content || "";
  }
  byId("report-modal").classList.add("is-active");
}

function bindEvents() {
  byId("lifecycle-refresh-btn")?.addEventListener("click", () => {
    if (DashboardState.selectedCaseId) loadDashboard(DashboardState.selectedCaseId).catch(() => {});
  });
  byId("lifecycle-open-foc-btn")?.addEventListener("click", () => {
    if (window.parent && typeof window.parent.openView === "function") {
      window.parent.openView("foc_reconstruction");
      return;
    }
    window.location.href = "/foc_reconstruction.html";
  });
  byId("run-multilayer-btn")?.addEventListener("click", () => runAction("run-multilayer"));
  byId("rerun-multilayer-btn")?.addEventListener("click", () => runAction("rerun-multilayer"));
  byId("measure-clock-btn")?.addEventListener("click", () => runAction("measure-clock"));
  byId("fix-time-btn")?.addEventListener("click", () => runAction("fix-time"));
  byId("run-causal-btn")?.addEventListener("click", () => runAction("run-causal"));
  byId("rerun-causal-btn")?.addEventListener("click", () => runAction("rerun-causal"));
  byId("run-full-btn")?.addEventListener("click", () => runAction("run-full"));
  byId("generate-summary-btn")?.addEventListener("click", () => runAction("generate-summary"));
  byId("generate-evidence-support-btn")?.addEventListener("click", () => runAction("generate-evidence-support"));
  byId("view-evidence-support-btn")?.addEventListener("click", () => {
    DashboardState.evidenceSupportDetailVisible = !DashboardState.evidenceSupportDetailVisible;
    const container = byId("evidence-support-details");
    if (!container) return;
    if (!DashboardState.evidenceSupportDetailVisible) {
      container.classList.add("hidden");
      return;
    }
    if (DashboardState.evidenceSupportDetail) {
      renderEvidenceSupportDetailContainer();
    } else {
      loadEvidenceSupportDetail().catch(() => {});
    }
  });
  byId("report-modal-close")?.addEventListener("click", () => byId("report-modal")?.classList.remove("is-active"));
  byId("rail-phase-close")?.addEventListener("click", () => byId("rail-phase-modal")?.classList.remove("is-active"));
  byId("report-modal")?.addEventListener("click", event => {
    if (event.target?.id === "report-modal") {
      byId("report-modal")?.classList.remove("is-active");
    }
  });
  byId("rail-phase-modal")?.addEventListener("click", event => {
    if (event.target?.id === "rail-phase-modal") {
      byId("rail-phase-modal")?.classList.remove("is-active");
    }
  });
  document.addEventListener("click", event => {
    const caseBtn = event.target.closest(".case-item");
    if (caseBtn?.dataset.caseId) {
      loadDashboard(caseBtn.dataset.caseId).catch(() => {});
      return;
    }
    const reportBtn = event.target.closest(".open-report-btn");
    if (reportBtn?.dataset.reportType) {
      openReport(reportBtn.dataset.reportType).catch(err => {
        setJobPanel(`<div class="status-error">Could not open report: ${esc(err.message)}</div>`);
      });
      return;
    }
    const railBtn = event.target.closest(".rail-phase-btn");
    if (railBtn?.dataset.railPhase) {
      openRailPhaseModal(railBtn.dataset.railPhase, DashboardState.dashboard?.summary, DashboardState.dashboard);
      return;
    }
    const jumpBtn = event.target.closest(".rail-jump-btn");
    if (jumpBtn?.dataset.targetSection) {
      byId("rail-phase-modal")?.classList.remove("is-active");
      scrollToDashboardSection(jumpBtn.dataset.targetSection);
      return;
    }
    const storylineBtn = event.target.closest('[data-run-action="view-storyline-step"]');
    if (storylineBtn?.dataset.stepId) {
      document.querySelector(`.evidence-step-atoms[data-step-id="${storylineBtn.dataset.stepId}"]`)?.classList.toggle("hidden");
      return;
    }
    const runActionBtn = event.target.closest(".run-action-btn");
    if (runActionBtn?.dataset.runAction) {
      runAction(runActionBtn.dataset.runAction).catch(() => {});
    }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  try {
    await loadCases();
  } catch (err) {
    setJobPanel(`<div class="status-error">Dashboard load failed: ${esc(err.message)}</div>`);
    const caseList = byId("lifecycle-case-list");
    if (caseList) caseList.innerHTML = `<div class="status-error">${esc(err.message)}</div>`;
  }
});
