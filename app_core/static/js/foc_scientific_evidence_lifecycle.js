const API = "/api/foc";
const DashboardState = {
  cases: [],
  selectedCaseId: null,
  dashboard: null,
  trackedJobId: null,
  pollTimer: null,
  extractDetail: null,
  extractDetailVisible: false,
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
  renderCausalAndUncertainty(summary, payload);
  renderTriggerAndModbus(summary, payload);
  renderExtractSummary(summary, payload);
  renderConclusion(summary, payload);
  renderReports(summary, payload);
  renderLists(summary, payload);
}

function renderExtractSummary(summary, payload) {
  const container = byId("extract-summary");
  if (!container) return;
  const extract = summary?.evidence_support_extract;
  if (!extract || extract.status === "not_available") {
    container.innerHTML = valueCard("Evidence Support Extract", "Not generated", "Generate it after causal reconstruction to obtain a normalized, hypothesis-level forensic support assessment.", "status-warning");
    return;
  }
  const tone = extract.status === "stale" ? "status-warning" : statusTone(extract.global_support_level);
  container.innerHTML = [
    valueCard("Status", titleize(extract.status), extract.path || "not_available", tone),
    valueCard("Global support", titleize(extract.global_support_level || "not_evaluable"), "Aggregated across independent layers.", statusTone(extract.global_support_level)),
    valueCard("Hypotheses", extract.hypothesis_count ?? 0, "Forensic hypotheses evaluated."),
    valueCard("Supporting findings", extract.supporting_findings ?? 0, "Moderate or strong support.", "status-ok"),
    valueCard("Degraded / ambiguous", extract.degraded_or_ambiguous_findings ?? 0, "Weak or indirect support only.", "status-warning"),
    valueCard("Missing / not evaluable", extract.missing_or_not_evaluable_findings ?? 0, `Contradictions: ${extract.contradictions ?? 0}`, (extract.contradictions ?? 0) > 0 ? "status-error" : "status-muted"),
  ].join("");
}

function supportLevelLabel(level) {
  return titleize(level || "not_evaluable");
}

async function loadExtractDetail() {
  const caseId = DashboardState.selectedCaseId;
  if (!caseId) return;
  const container = byId("extract-details");
  if (!container) return;
  container.classList.remove("hidden");
  container.innerHTML = `<div class="text-slate-500 text-sm">Loading evidence support detail…</div>`;
  try {
    const payload = await fetchJson(`${API}/evidence-support-extract?case_id=${encodeURIComponent(caseId)}`);
    DashboardState.extractDetail = payload;
    renderExtractDetail(payload);
  } catch (err) {
    container.innerHTML = `<div class="status-error text-sm">Could not load evidence support extract: ${esc(err.message)}</div>`;
  }
}

function renderExtractDetail(payload) {
  const container = byId("extract-details");
  if (!container) return;
  const extract = payload?.extract;
  if (!payload?.available || !extract) {
    container.innerHTML = `<div class="text-slate-500 text-sm">No Evidence Support Extract has been generated yet for this case.</div>`;
    return;
  }
  const hypotheses = extract.hypotheses || [];
  const layerSupport = extract.layer_support || {};
  const findings = extract.findings || [];
  container.innerHTML = `
    ${extract.is_stale ? `<div class="glass-soft rounded-2xl p-4 text-sm text-amber-200 mb-4">This Evidence Support Extract is stale because causal reconstruction artifacts changed after it was generated. Regenerate it above.</div>` : ""}
    <div class="space-y-4 mb-5">
      ${hypotheses.map(h => `
        <div class="glass-soft rounded-[24px] p-4">
          <div class="flex items-center justify-between gap-3 flex-wrap">
            <div class="font-black">${esc(h.hypothesis_id)}: ${esc(h.attack_family)}</div>
            <div class="text-xs uppercase tracking-[0.14em] font-black ${statusTone(h.global_support_level)}">${esc(supportLevelLabel(h.global_support_level))}</div>
          </div>
          <div class="mt-3 text-sm text-slate-300">${esc(h.hypothesis_text)}</div>
          <div class="mt-2 text-xs text-slate-400">MITRE: <span class="mono">${esc(h.mitre_technique)}</span> · Target: <span class="mono">${esc(h.target_asset)}</span></div>
          <div class="mt-3 text-xs text-slate-300"><strong>Main supporting evidence:</strong> ${listItems(h.main_supporting_evidence, "none")}</div>
          <div class="mt-3 text-xs text-slate-300"><strong>Main limitations:</strong> ${listItems(h.main_limitations, "none")}</div>
        </div>
      `).join("")}
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 mb-5">
      ${Object.entries(layerSupport).map(([layer, item]) => valueCard(titleize(layer), supportLevelLabel(item.support_level), `${item.finding_count || 0} finding(s) · ${maybeTruncate(item.summary, 90)}`, statusTone(item.support_level))).join("")}
    </div>
    <div class="overflow-x-auto">
      <table class="w-full text-xs text-slate-300">
        <thead><tr class="text-left text-slate-400 uppercase tracking-[0.12em]"><th class="pr-3 py-2">Layer</th><th class="pr-3 py-2">Finding</th><th class="pr-3 py-2">Support</th><th class="pr-3 py-2">Causal edges</th><th class="pr-3 py-2">Limitations</th></tr></thead>
        <tbody>
          ${findings.map(f => `
            <tr class="border-t border-slate-800/70 align-top">
              <td class="py-3 pr-3 font-semibold">${esc(titleize(f.layer))}</td>
              <td class="py-3 pr-3">${esc(maybeTruncate(f.summary, 160))}</td>
              <td class="py-3 pr-3 ${statusTone(f.supports_hypothesis)}">${esc(supportLevelLabel(f.supports_hypothesis))}</td>
              <td class="py-3 pr-3 mono">${esc((f.related_causal_edges || []).join(", ") || "none")}</td>
              <td class="py-3 pr-3">${esc(maybeTruncate((f.limitations || []).join(" | ") || "none", 160))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderExecutiveGrid(summary, payload) {
  const container = byId("lifecycle-exec-grid");
  if (!container) return;
  if (!summary) {
    container.innerHTML = [
      valueCard("Summary status", "Not generated", "Generate the executive summary to expose the synthesized scientific lifecycle.", "status-warning"),
      valueCard("Analysis", payload.live_status?.analysis?.status || "not_started", "Live multilayer analysis state from the case pipeline.", statusTone(payload.live_status?.analysis?.status)),
      valueCard("Time sync", payload.live_status?.time_sync?.status || "unknown", "Live time-synchronization state for the case.", statusTone(payload.live_status?.time_sync?.status)),
      valueCard("Causal", payload.live_status?.causal?.status || "not_available", "Live causal reconstruction state.", statusTone(payload.live_status?.causal?.status)),
    ].join("");
    return;
  }
  const exec = summary.execution_summary || {};
  container.innerHTML = [
    valueCard("Case ID", summary.case_id, summary.case_path, "status-info"),
    valueCard("Scenario", summary.scenario_id || "unknown", summary.scenario_name || "unknown", "status-info"),
    valueCard("Evidence lifecycle", exec.evidence_lifecycle_status || "unknown", "Preservation, integrity, and analysis lifecycle state.", statusTone(exec.evidence_lifecycle_status)),
    valueCard("Last multilayer analysis", exec.multilayer_analysis_status || "unknown", "Snapshot baked into the executive summary at generation time, not live pipeline state.", statusTone(exec.multilayer_analysis_status)),
    valueCard("Last causal reconstruction", exec.causal_reconstruction_status || "unknown", "Snapshot baked into the executive summary at generation time, not live pipeline state.", statusTone(exec.causal_reconstruction_status)),
    valueCard("Evidence confidence", exec.evidence_analysis_confidence || "unknown", "Confidence in evidence analysis coverage and usefulness.", statusTone(exec.evidence_analysis_confidence)),
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
      <div class="glass-soft rounded-[22px] p-4 h-full">
        <div class="text-[10px] uppercase tracking-[0.22em] text-slate-400 font-black">${esc(step.label)}</div>
        <div class="text-sm font-black mt-3 ${statusTone(step.status)}">${esc(titleize(step.status))}</div>
      </div>
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
  if (!tags || !overview || !matrix) return;
  const multi = summary?.multilayer_analysis_summary;
  if (!multi) {
    tags.innerHTML = tag("status", payload.live_status?.analysis?.status || "not_started", statusTone(payload.live_status?.analysis?.status));
    overview.innerHTML = valueCard("Summary", "Not generated", "Run or regenerate multilayer analysis and then generate the executive summary.", "status-warning");
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

function renderCausalAndUncertainty(summary, payload) {
  const causalGrid = byId("causal-summary-grid");
  const causalText = byId("causal-summary-text");
  const uncertaintyGrid = byId("uncertainty-summary-grid");
  const uncertaintyWarning = byId("uncertainty-warning");
  if (!causalGrid || !causalText || !uncertaintyGrid || !uncertaintyWarning) return;
  const causal = summary?.causal_summary;
  const uncertainty = summary?.uncertainty_summary;
  if (!causal) {
    causalGrid.innerHTML = valueCard("Causal state", payload.live_status?.causal?.status || "not_available", payload.live_status?.causal?.reason || "Causal reconstruction has not been summarized in this executive view yet.", statusTone(payload.live_status?.causal?.status));
    causalText.textContent = payload.live_status?.causal?.reason || "Causal reconstruction is not yet available for this case.";
  } else {
    causalGrid.innerHTML = [
      valueCard("CPR", formatMaybeNumber(causal.cpr), "Recovered expected causal relations / expected causal relations.", statusTone(causal.status)),
      valueCard("Weighted CPR", formatMaybeNumber(causal.weighted_cpr), "Weighted causal recoverability.", statusTone(causal.status)),
      valueCard("Recovered edges", `${causal.recovered_edges || 0} / ${causal.expected_edges || 0}`, "Expected causal relations fully recovered.", "status-ok"),
      valueCard("Degraded edges", causal.degraded_edges || 0, "Edges with partial support.", "status-warning"),
      valueCard("Ambiguous edges", causal.ambiguous_edges || 0, "Edges limited by temporal uncertainty.", "status-warning"),
      valueCard("Missing edges", causal.missing_edges || 0, "Edges unsupported by the preserved artifact set.", causal.main_limitation || "", statusTone(causal.status)),
    ].join("");
    causalText.innerHTML = `
      <div class="${statusTone(causal.status)} font-black">${esc(titleize(causal.status || "not_available"))}</div>
      <div class="mt-3">${esc(causal.main_limitation || "No causal limitation summary available.")}</div>
      <div class="mt-3 text-slate-400">CPR measures the proportion of expected causal relations that were fully recovered with sufficient evidence.</div>
      ${causal.is_stale ? `<div class="mt-3 flex items-center justify-between gap-3 flex-wrap status-warning font-black"><span>Causal reconstruction is stale because analysis outputs were modified after causal artifacts were generated.</span><button type="button" class="run-action-btn btn-secondary rounded-2xl px-4 py-2 text-xs font-extrabold tracking-[0.16em] uppercase" data-run-action="rerun-causal">Regenerate Causal Reconstruction</button></div>` : ""}
    `;
  }
  if (!uncertainty) {
    uncertaintyGrid.innerHTML = valueCard("Uncertainty", "Not generated", "No uncertainty summary is available yet.", "status-warning");
    uncertaintyWarning.textContent = "Temporal and integrity constraints will appear here when the executive summary is generated.";
  } else {
    uncertaintyGrid.innerHTML = [
      valueCard("Temporal confidence", uncertainty.temporal_confidence || "unknown", "Preserved temporal confidence for causal ordering.", statusTone(uncertainty.temporal_confidence)),
      valueCard("Max clock offset", `${formatMaybeNumber(uncertainty.max_clock_offset_seconds)}s`, uncertainty.time_sync_source || "not_available", statusTone(uncertainty.synchronized_status)),
      valueCard("Uncertainty window", `${formatMaybeNumber(uncertainty.uncertainty_window_seconds)}s`, "Temporal ordering window used by the uncertainty budget.", statusTone(uncertainty.temporal_confidence)),
      valueCard("Sync status", uncertainty.synchronized_status || "unknown", `Nodes measured: ${uncertainty.nodes_measured ?? "not_available"} | failed: ${uncertainty.nodes_failed ?? "not_available"}`, statusTone(uncertainty.synchronized_status)),
      valueCard("Correction applied", uncertainty.correction_applied ? "yes" : "no", `Before: ${uncertainty.before_path || "not_available"} | After: ${uncertainty.after_path || "not_available"}`, uncertainty.correction_applied ? "status-warning" : "status-muted"),
      valueCard("Worst node", uncertainty.worst_node?.name || uncertainty.worst_node?.vm_id || "not_available", uncertainty.worst_node?.ip || "not_available", statusTone(uncertainty.synchronized_status)),
    ].join("");
    uncertaintyWarning.textContent = uncertainty.main_limitation || "No additional uncertainty warning recorded.";
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
      <div class="${alignTone} font-black mt-2">${esc(alignText)}</div>
    </div>
  `;
  const modbus = causal.modbus_specificity || {};
  modbusPanel.innerHTML = Object.entries(modbus)
    .filter(([key]) => key !== "message")
    .map(([key, item]) => valueCard(titleize(key), item?.value || "not_available", `Status: ${item?.status || "unknown"}`, statusTone(item?.status)))
    .join("");
  if (modbus.message) {
    modbusPanel.innerHTML += `<div class="md:col-span-2 glass-soft rounded-[24px] p-4 text-sm text-amber-200">${esc(modbus.message)}</div>`;
  }
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
    } else if (kind === "generate-extract") {
      await postJson(`${API}/lifecycle/generate-evidence-support-extract`, { case_id: caseId });
      DashboardState.extractDetail = null;
      if (DashboardState.extractDetailVisible) {
        await loadExtractDetail();
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
  byId("generate-extract-btn")?.addEventListener("click", () => runAction("generate-extract"));
  byId("view-extract-btn")?.addEventListener("click", () => {
    DashboardState.extractDetailVisible = !DashboardState.extractDetailVisible;
    const container = byId("extract-details");
    if (!container) return;
    if (!DashboardState.extractDetailVisible) {
      container.classList.add("hidden");
      return;
    }
    if (DashboardState.extractDetail) {
      container.classList.remove("hidden");
      renderExtractDetail(DashboardState.extractDetail);
    } else {
      loadExtractDetail().catch(() => {});
    }
  });
  byId("report-modal-close")?.addEventListener("click", () => byId("report-modal")?.classList.remove("is-active"));
  byId("report-modal")?.addEventListener("click", event => {
    if (event.target?.id === "report-modal") {
      byId("report-modal")?.classList.remove("is-active");
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
