(function () {
  "use strict";

  const state = {
    cases: [],
    campaigns: [],
    reports: [],
    tableReconstructionReports: [],
    truthfulEvaluationReports: [],
    cleanupInventory: [],
    cleanupLevelFilter: "ALL",
    selectedCaseId: new URLSearchParams(window.location.search).get("case_id") || "",
    selectedCampaignId: "",
    activeJobId: null,
    activeJobLevel: null,
    lastChildJobId: null,
    lastChildPayload: null,
    pollTimer: null,
    levelBPreflight: null,
  };

  const byId = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  const levelARepetitions = () => Math.max(Number(byId("paper-level-a-repetitions-input")?.value || 6), 1);
  const levelBRepetitions = () => Math.max(Number(byId("paper-level-b-repetitions-input")?.value || 6), 1);
  const levelBNestedLevelARepetitions = () => Math.max(Number(byId("paper-level-b-nested-level-a-repetitions-input")?.value || levelBRepetitions()), 1);

  async function getJson(url, options) {
    const res = await fetch(url, options);
    let payload = {};
    try {
      payload = await res.json();
    } catch (_err) {
      payload = {};
    }
    if (!res.ok) {
      throw new Error(payload.error || `Request failed: ${res.status}`);
    }
    return payload;
  }

  function selectedCase() {
    return state.cases.find((item) => String(item.case_id) === String(state.selectedCaseId)) || null;
  }

  function selectedCampaign() {
    return state.campaigns.find((item) => String(item.campaign_id) === String(state.selectedCampaignId)) || null;
  }

  function isTerminal(status) {
    return ["completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"].includes(String(status || "").toLowerCase());
  }

  function fmtProgress(value) {
    const num = Number(value);
    return Number.isFinite(num) ? `${num.toFixed(1)}%` : "not_available";
  }

  function parseIso(value) {
    const raw = String(value || "").trim();
    if (!raw) return null;
    const date = new Date(raw);
    return Number.isFinite(date.getTime()) ? date : null;
  }

  function formatDurationSeconds(totalSeconds) {
    const num = Number(totalSeconds);
    if (!Number.isFinite(num) || num < 0) return "not_available";
    const rounded = Math.round(num);
    const hours = Math.floor(rounded / 3600);
    const minutes = Math.floor((rounded % 3600) / 60);
    const seconds = rounded % 60;
    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  }

  function jobElapsedSeconds(payload) {
    const started = parseIso(payload?.started_at);
    if (!started) return null;
    const finished = parseIso(payload?.finished_at);
    const end = finished || new Date();
    return Math.max(0, (end.getTime() - started.getTime()) / 1000);
  }

  function lastRepetitionDurationSeconds(childPayload) {
    const rows = Array.isArray(childPayload?.per_repetition_results) ? childPayload.per_repetition_results : [];
    for (let idx = rows.length - 1; idx >= 0; idx -= 1) {
      const timing = rows[idx]?.timing_metrics || {};
      const value = Number(timing.total_repetition_duration_seconds);
      if (Number.isFinite(value) && value >= 0) return value;
    }
    return null;
  }

  function repetitionDurationRows(childPayload) {
    const rows = Array.isArray(childPayload?.per_repetition_results) ? childPayload.per_repetition_results : [];
    return rows
      .map((item) => {
        const value = Number(item?.timing_metrics?.total_repetition_duration_seconds);
        return {
          repetition: item?.repetition_number,
          caseId: item?.case_id || "not_available",
          duration: Number.isFinite(value) && value >= 0 ? value : null,
        };
      })
      .filter((item) => item.duration !== null);
  }

  function isLevelBPaperJob(payload) {
    if (!payload) return false;
    if (String(payload.requested_level || "").toUpperCase() === "B") return true;
    if (String(state.activeJobLevel || "").toUpperCase() === "B") return true;
    if (String(payload.current_phase || "").toLowerCase().includes("level_b")) return true;
    if (String(payload.current_phase_label || "").toLowerCase().includes("level b")) return true;
    if ((payload.nested_phase_statuses || []).length) return true;
    return false;
  }

  function dfirOverlayOpen() {
    const ov = byId("dfir-auto-overlay");
    const term = byId("dfir-auto-terminal");
    const st = byId("dfir-auto-status");
    const meta = byId("dfir-auto-meta");
    const btn = byId("dfir-auto-close");
    if (term) term.textContent = "";
    if (st) st.textContent = "RUNNING";
    if (meta) meta.textContent = "Creating case and preserving artifacts";
    if (btn) btn.disabled = true;
    if (ov) ov.style.display = "flex";
  }

  function dfirOverlaySetSnapshot(payload, childPayload, liveTrace) {
    const st = byId("dfir-auto-status");
    const meta = byId("dfir-auto-meta");
    const term = byId("dfir-auto-terminal");
    if (!st || !meta || !term) return;
    const phases = payload.phase_statuses || [];
    const lastPhase = phases.length ? phases[phases.length - 1] : null;
    const phaseLabel = payload.current_phase_label || lastPhase?.phase_label || payload.current_phase || "queued";
    const phaseStatus = lastPhase?.status || payload.status || "running";
    const hasChildJob = Boolean(String(payload.current_child_job_id || "").trim());
    const childRepCurrent = childPayload?.current_repetition ?? (hasChildJob ? 0 : (payload.current_repetition ?? 0));
    const childRepTotal = childPayload?.requested_repetitions ?? childPayload?.meta?.requested_repetitions ?? (hasChildJob ? 0 : (payload.requested_repetitions ?? payload.meta?.requested_repetitions ?? 0));
    const rep = `${String(childRepCurrent)}/${String(childRepTotal)}`;
    const caseId = childPayload?.current_case_id || (hasChildJob ? "not_available" : (payload.current_case_id || "not_available"));
    st.textContent = String(phaseStatus || "running").toUpperCase().replace(/[_-]+/g, " ");
    meta.textContent = `paper_job=${String(payload.job_id || "not_available")} | level_b_job=${String(childPayload?.job_id || payload.current_child_job_id || "not_available")} | repetition=${rep} | case=${String(caseId)} | paper_progress=${fmtProgress(payload.progress_percent)} | level_b_progress=${fmtProgress(childPayload?.progress_percent)}`;
    term.textContent = levelBConsoleLines(payload, childPayload, liveTrace);
    term.scrollTop = term.scrollHeight;
  }

  function dfirOverlayFinish(ok, payload) {
    const st = byId("dfir-auto-status");
    const meta = byId("dfir-auto-meta");
    const btn = byId("dfir-auto-close");
    if (st) st.textContent = ok ? "DONE" : "ERROR";
    if (meta) meta.textContent = payload && payload.report_output_path ? `Report: ${payload.report_output_path}` : "Finished";
    if (btn) btn.disabled = false;
  }

  function dfirOverlayClose() {
    const ov = byId("dfir-auto-overlay");
    if (ov) ov.style.display = "none";
  }

  function levelBConsoleLines(payload, childPayload, liveTrace) {
    const phases = payload.phase_statuses || [];
    const nested = childPayload?.phase_statuses || payload.nested_phase_statuses || [];
    const lines = [];
    lines.push("[SISTEMA] LEVEL B PAPER EVIDENCE MONITOR");
    lines.push(`[JOB] ${String(payload.job_id || "not_available")}`);
    lines.push(`[STATUS] ${String(payload.status || "running")}`);
    lines.push(`[PROGRESS] ${fmtProgress(payload.progress_percent)}`);
    lines.push(`[CASE] ${String(childPayload?.current_case_id || payload.current_case_id || "not_available")}`);
    lines.push(`[REPORT] ${String(payload.report_output_path || "not_available")}`);
    lines.push("");
    lines.push("[PHASE TRACE]");
    phases.slice(-16).forEach((phase) => {
      const label = phase.phase_label || phase.phase_key || "phase";
      const status = phase.status || "unknown";
      const progress = phase.progress_percent != null ? `${phase.progress_percent}%` : "n/a";
      const detail = String(phase.detail || "No detail available.").replace(/\s+/g, " ").trim();
      lines.push(`- ${label} :: ${status} :: ${progress}`);
      lines.push(`  ${detail}`);
    });
    if (childPayload) {
      lines.push("");
      lines.push("[LEVEL B BATCH]");
      lines.push(`- job=${String(childPayload.job_id || "not_available")} :: status=${String(childPayload.status || "running")} :: progress=${fmtProgress(childPayload.progress_percent)}`);
      lines.push(`  ${String(childPayload.current_phase_label || childPayload.current_phase || "not_available")} :: ${String(childPayload.current_phase_detail || "No detail available.")}`);
      lines.push(`- repetition=${String(childPayload.current_repetition || 0)}/${String(childPayload.requested_repetitions || childPayload.meta?.requested_repetitions || 0)} :: execution=${String(childPayload.current_execution_id || "not_available")} :: case=${String(childPayload.current_case_id || "not_available")}`);
    }
    if (nested.length) {
      lines.push("");
      lines.push("[LEVEL B PHASE TRACE]");
      nested.slice(-12).forEach((phase) => {
        const label = phase.phase_label || phase.phase_key || "phase";
        const status = phase.status || "unknown";
        const progress = phase.progress_percent != null ? `${phase.progress_percent}%` : "n/a";
        const detail = String(phase.detail || "No detail available.").replace(/\s+/g, " ").trim();
        lines.push(`- ${label} :: ${status} :: ${progress}`);
        lines.push(`  ${detail}`);
      });
    }
    if ((liveTrace?.terminal_lines || []).length) {
      lines.push("");
      lines.push("[LIVE CASE PRESERVATION TRACE]");
      (liveTrace.terminal_lines || []).forEach((line) => lines.push(String(line)));
    }
    if ((liveTrace?.analysis_lines || []).length) {
      lines.push("");
      lines.push("[LIVE ANALYSIS SNAPSHOT]");
      (liveTrace.analysis_lines || []).forEach((line) => lines.push(String(line)));
    }
    if ((payload.warnings || []).length) {
      lines.push("");
      lines.push("[WARNINGS]");
      payload.warnings.slice(-8).forEach((item) => lines.push(`- ${String(item)}`));
    }
    if ((payload.errors || []).length) {
      lines.push("");
      lines.push("[BLOCKERS]");
      payload.errors.slice(-8).forEach((item) => lines.push(`- ${String(item?.message || JSON.stringify(item))}`));
    }
    return lines.join("\n");
  }

  function renderCasePicker() {
    const select = byId("paper-case-select");
    if (!select) return;
    if (!state.cases.length) {
      select.innerHTML = '<option value="">No preserved cases available</option>';
      return;
    }
    select.innerHTML = state.cases.map((item) => `
      <option value="${esc(item.case_id)}" ${String(item.case_id) === String(state.selectedCaseId) ? "selected" : ""}>
        ${esc(item.case_id)} · ${esc(item.source_case_name || item.case_id)}
      </option>
    `).join("");
  }

  function renderCaseSummary() {
    const root = byId("paper-case-summary");
    const preflight = byId("paper-preflight");
    const caseItem = selectedCase();
    if (!root || !preflight) return;
    if (!caseItem) {
      root.innerHTML = '<div class="text-amber-300">No preserved case selected.</div>';
      preflight.innerHTML = "Select a preserved case. Level A paper evidence needs a readable sealed case and will not run attacks, acquisition, or redeployment.";
      return;
    }
    root.innerHTML = `
      <div class="space-y-2">
        <div><span class="font-black">Case ID:</span> <span class="mono">${esc(caseItem.case_id)}</span></div>
        <div><span class="font-black">Source case:</span> ${esc(caseItem.source_case_name || "not_available")}</div>
        <div><span class="font-black">Path:</span> <span class="mono break-all">${esc(caseItem.path || "not_available")}</span></div>
        <div><span class="font-black">Manifest:</span> <span class="mono break-all">${esc(caseItem.manifest_path || "not_available")}</span></div>
      </div>
    `;
    preflight.innerHTML = `
      <div class="space-y-2">
        <div><span class="font-black text-cyan-300">Will execute:</span> repeated read-only Level A dry-run analysis and paper package generation.</div>
        <div><span class="font-black text-cyan-300">Will not execute:</span> new attack, new acquisition, or redeployment.</div>
        <div><span class="font-black text-cyan-300">Expected output:</span> one isolated report directory under <span class="mono">app_core/infrastructure/forensics/paper_evidence/</span>.</div>
      </div>
    `;
  }

  function renderCampaignPicker() {
    const select = byId("paper-level-b-campaign-select");
    if (!select) return;
    const levelBCampaigns = state.campaigns.filter((item) => String(item.level || "").toUpperCase() === "B");
    if (!levelBCampaigns.length) {
      select.innerHTML = '<option value="">No Level B campaigns available</option>';
      return;
    }
    if (!state.selectedCampaignId) state.selectedCampaignId = levelBCampaigns[0].campaign_id;
    select.innerHTML = levelBCampaigns.map((item) => `
      <option value="${esc(item.campaign_id)}" ${String(item.campaign_id) === String(state.selectedCampaignId) ? "selected" : ""}>
        ${esc(item.campaign_id)} · ${esc(item.name || item.campaign_id)}
      </option>
    `).join("");
  }

  function renderCampaignSummary() {
    const root = byId("paper-level-b-summary");
    const campaign = selectedCampaign();
    if (!root) return;
    if (!campaign) {
      root.innerHTML = '<div class="text-amber-300">No Level B campaign selected. You can create a temporary Level B campaign from the active scenario and the recommended Modbus attack profile.</div>';
      return;
    }
    root.innerHTML = `
      <div class="space-y-2">
        <div><span class="font-black">Campaign ID:</span> <span class="mono">${esc(campaign.campaign_id)}</span></div>
        <div><span class="font-black">Name:</span> ${esc(campaign.name || "not_available")}</div>
        <div><span class="font-black">Scenario ID:</span> <span class="mono">${esc(campaign.scenario_id || "not_available")}</span></div>
        <div><span class="font-black">Level:</span> ${esc(campaign.level || "not_available")}</div>
        <div><span class="font-black">State:</span> ${esc(campaign.state || "not_available")}</div>
      </div>
    `;
  }

  function renderLevelBPreflight() {
    const root = byId("paper-level-b-preflight");
    const button = byId("paper-run-level-b-btn");
    const payload = state.levelBPreflight;
    if (!root || !button) return;
    if (!payload) {
      root.innerHTML = "Loading Level B disk-acquisition preflight…";
      button.disabled = false;
      button.title = "";
      return;
    }
    const preflight = payload.preflight || {};
    const blockers = Array.isArray(preflight.blockers) ? preflight.blockers : [];
    const warnings = Array.isArray(preflight.warnings) ? preflight.warnings : [];
    const ready = String(payload.status || "") === "ready";
    root.innerHTML = `
      <div class="space-y-2">
        <div><span class="font-black ${ready ? "text-emerald-300" : "text-red-300"}">Level B disk preflight:</span> ${esc(payload.status || "unknown")}</div>
        <div>${esc(payload.message || "No Level B preflight message available.")}</div>
        <div><span class="font-black">Privilege mode:</span> <span class="mono">${esc(preflight.privilege_mode || "not_available")}</span></div>
        <div><span class="font-black">sudo -n available:</span> <span class="mono">${esc(preflight.sudo_noninteractive_ok)}</span></div>
        <div><span class="font-black">NOPASSWD stable:</span> <span class="mono">${esc(preflight.sudo_nopasswd_granted)}</span></div>
        <div><span class="font-black">Docker access:</span> <span class="mono">${esc(preflight.docker_access_ok)}</span></div>
        <div><span class="font-black">qemu-img available:</span> <span class="mono">${esc(preflight.qemu_img_available)}</span></div>
        ${blockers.length ? `<div><span class="font-black text-red-300">Blockers:</span> <span class="mono">${esc(blockers.join(", "))}</span></div>` : ""}
        ${warnings.length ? `<div><span class="font-black text-amber-300">Warnings:</span> ${esc(warnings.join(" | "))}</div>` : ""}
        <div><span class="font-black">Fix path:</span> ${esc(payload.recommended_fix_path || "not_available")}</div>
      </div>
    `;
    button.disabled = !ready;
    button.title = ready ? "" : (payload.message || "Level B launch is blocked by disk-acquisition preflight.");
  }

  function renderJob(payload, childPayload = null, liveTrace = null) {
    const root = byId("paper-job-panel");
    if (!root) return;
    if (!payload) {
      root.innerHTML = "No active paper evidence job.";
      dfirOverlayClose();
      return;
    }
    const phases = payload.phase_statuses || [];
    const nestedPhases = payload.nested_phase_statuses || [];
    const paperElapsed = jobElapsedSeconds(payload);
    const childElapsed = jobElapsedSeconds(childPayload);
    const lastRepDuration = lastRepetitionDurationSeconds(childPayload);
    const repDurations = repetitionDurationRows(childPayload);
    root.innerHTML = `
      <div class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Job ID</div><div class="font-black mt-2 mono">${esc(payload.job_id)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Status</div><div class="font-black mt-2">${esc(payload.status || "unknown")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Current phase</div><div class="font-black mt-2">${esc(payload.current_phase_label || payload.current_phase || "unknown")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</div><div class="font-black mt-2">${esc(payload.progress_percent ?? "0")}%</div></div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Paper Job Elapsed</div>
            <div class="font-black mt-2">${esc(formatDurationSeconds(paperElapsed))}</div>
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Level Repetition Elapsed</div>
            <div class="font-black mt-2">${esc(formatDurationSeconds(childElapsed))}</div>
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Last Repetition Duration</div>
            <div class="font-black mt-2">${esc(formatDurationSeconds(lastRepDuration))}</div>
          </div>
        </div>
        <div><span class="font-black">Detail:</span> ${esc(payload.current_phase_detail || "not_available")}</div>
        <div><span class="font-black">Current case:</span> <span class="mono">${esc(payload.current_case_id || "not_available")}</span></div>
        <div><span class="font-black">Report path:</span> <span class="mono break-all">${esc(payload.report_output_path || "not_available")}</span></div>
        ${repDurations.length ? `
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Completed Repetition Durations</div>
            <div class="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
              ${repDurations.map((item) => `
                <div class="rounded-2xl border border-slate-800/80 bg-slate-900/50 p-3">
                  <div class="font-black">Rep ${esc(item.repetition)}</div>
                  <div class="text-slate-300 mt-1 mono">${esc(item.caseId)}</div>
                  <div class="text-cyan-300 mt-2 font-black">${esc(formatDurationSeconds(item.duration))}</div>
                </div>
              `).join("")}
            </div>
          </div>
        ` : ""}
        ${nestedPhases.length ? `
          <div class="rounded-2xl border border-cyan-500/30 bg-cyan-500/5 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-cyan-300 font-black">Nested Level A Workflow</div>
            <div class="mt-2"><span class="font-black">Current nested phase:</span> ${esc(payload.nested_current_phase_label || "not_available")}</div>
            <div class="mt-2"><span class="font-black">Nested detail:</span> ${esc(payload.nested_current_phase_detail || "not_available")}</div>
            <div class="mt-2"><span class="font-black">Nested progress:</span> ${esc(payload.nested_progress_percent ?? "0")}%</div>
          </div>
        ` : ""}
        ${payload.warnings?.length ? `<div><span class="font-black text-amber-300">Warnings:</span> ${esc(payload.warnings.join(" | "))}</div>` : ""}
        ${payload.errors?.length ? `<div><span class="font-black text-red-300">Errors:</span> ${esc((payload.errors[0] || {}).message || "unknown")}</div>` : ""}
        <div class="space-y-2">
          ${phases.map((phase) => `
            <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-3">
              <div class="flex items-center justify-between gap-3">
                <div class="font-black">${esc(phase.phase_label || phase.phase_key || "phase")}</div>
                <div class="text-xs uppercase tracking-[0.16em]">${esc(phase.status || "unknown")}</div>
              </div>
              <div class="mt-2 text-slate-300">${esc(phase.detail || "No detail available.")}</div>
              <div class="mt-2 text-slate-500 text-xs">${esc(phase.progress_percent ?? "0")}%</div>
            </div>
          `).join("")}
        </div>
        ${nestedPhases.length ? `
          <div class="space-y-2">
            <div class="text-xs uppercase tracking-[0.16em] text-cyan-300 font-black">Nested phase trace</div>
            ${nestedPhases.map((phase) => `
              <div class="rounded-2xl border border-cyan-500/20 bg-cyan-950/20 p-3">
                <div class="flex items-center justify-between gap-3">
                  <div class="font-black">${esc(phase.phase_label || phase.phase_key || "phase")}</div>
                  <div class="text-xs uppercase tracking-[0.16em]">${esc(phase.status || "unknown")}</div>
                </div>
                <div class="mt-2 text-slate-300">${esc(phase.detail || "No detail available.")}</div>
                <div class="mt-2 text-slate-500 text-xs">${esc(phase.progress_percent ?? "0")}%</div>
              </div>
            `).join("")}
          </div>
        ` : ""}
      </div>
    `;
    if (isLevelBPaperJob(payload)) {
      const wasHidden = byId("dfir-auto-overlay")?.style.display === "none" || !byId("dfir-auto-overlay")?.style.display;
      if (wasHidden && !isTerminal(payload.status)) dfirOverlayOpen();
      dfirOverlaySetSnapshot(payload, childPayload, liveTrace);
      if (isTerminal(payload.status)) dfirOverlayFinish(String(payload.status || "").toLowerCase().startsWith("completed"), payload);
    } else {
      dfirOverlayClose();
    }
  }

  function reportActions(report) {
    const zip = report.zip_path ? `<a class="text-cyan-300 underline" href="/api/foc/paper-evidence/export/${encodeURIComponent(report.report_id)}.zip">Download ZIP</a>` : "";
    return `
      <div class="flex gap-3 flex-wrap mt-4">
        <button type="button" class="text-cyan-300 underline paper-report-open-btn" data-report-id="${esc(report.report_id)}">Open report</button>
        ${zip}
      </div>
    `;
  }

  function renderCleanupInventory() {
    const summary = byId("paper-cleanup-summary");
    const root = byId("paper-cleanup-list");
    if (!summary || !root) return;
    const allItems = state.cleanupInventory || [];
    const filter = String(state.cleanupLevelFilter || "ALL").toUpperCase();
    const items = filter === "ALL"
      ? allItems
      : allItems.filter((item) => String(item.evaluation_level || "").toUpperCase() === filter);
    const deletable = items.filter((item) => item.deletable);
    const totalBytes = deletable.reduce((acc, item) => acc + Number(item.size_bytes || 0), 0);
    summary.innerHTML = `
      <div>Inventory items: <span class="mono">${esc(items.length)}</span> <span class="text-slate-500">(filter: ${esc(filter)})</span></div>
      <div class="mt-2">Removable items: <span class="mono">${esc(deletable.length)}</span></div>
      <div class="mt-2">Estimated reclaimable bytes: <span class="mono">${esc(totalBytes)}</span></div>
    `;
    if (!items.length) {
      root.innerHTML = '<div class="glass-soft rounded-2xl p-4">No generated cleanup candidates were found.</div>';
      return;
    }
    root.innerHTML = items.map((item) => `
      <label class="glass-soft rounded-2xl p-4 block ${item.deletable ? "" : "opacity-70"}">
        <div class="flex items-start gap-3">
          <input type="checkbox" class="paper-cleanup-checkbox mt-1" value="${esc(item.item_id)}" ${item.deletable ? "" : "disabled"}>
          <div class="min-w-0 flex-1">
            <div class="font-black">${esc(item.label || item.item_id)}</div>
            <div class="mt-2 text-slate-300 text-xs uppercase tracking-[0.16em]">
              ${esc(item.item_type || "unknown")} · level=${esc(item.evaluation_level || "n/a")}
            </div>
            <div class="mt-2 mono break-all text-xs text-slate-400">${esc(item.path || "not_available")}</div>
            <div class="mt-2 text-sm text-slate-300">Size: <span class="mono">${esc(item.size_human || "not_available")}</span></div>
            ${item.blocked_reason ? `<div class="mt-2 text-amber-300">${esc(item.blocked_reason)}</div>` : ""}
          </div>
        </div>
      </label>
    `).join("");
  }

  function selectVisibleCleanupItems() {
    document.querySelectorAll(".paper-cleanup-checkbox").forEach((node) => {
      if (!node.disabled) node.checked = true;
    });
  }

  function renderCaseCleanupList() {
    const summary = byId("paper-cases-summary");
    const root = byId("paper-cases-list");
    if (!summary || !root) return;
    const items = (state.cleanupInventory || []).filter((item) => item.item_type === "case");
    const deletable = items.filter((item) => item.deletable);
    summary.innerHTML = `
      <div>Full case directories detected: <span class="mono">${esc(items.length)}</span></div>
      <div class="mt-2">Deletable full cases: <span class="mono">${esc(deletable.length)}</span></div>
    `;
    if (!items.length) {
      root.innerHTML = '<div class="glass-soft rounded-2xl p-4">No case directories are currently listed for full deletion.</div>';
      return;
    }
    root.innerHTML = items.map((item) => `
      <label class="glass-soft rounded-2xl p-4 block ${item.deletable ? "" : "opacity-70"}">
        <div class="flex items-start gap-3">
          <input type="checkbox" class="paper-case-checkbox mt-1" value="${esc(item.item_id)}" ${item.deletable ? "" : "disabled"}>
          <div class="min-w-0 flex-1">
            <div class="font-black">${esc(item.label || item.item_id)}</div>
            <div class="mt-2 mono break-all text-xs text-slate-400">${esc(item.path || "not_available")}</div>
            <div class="mt-2 text-sm text-slate-300">Size: <span class="mono">${esc(item.size_human || "not_available")}</span></div>
            ${item.is_active_case ? '<div class="mt-2 text-amber-300">This case is currently marked as active. Cleanup will also clear the active-case pointer before deletion.</div>' : ""}
            ${item.blocked_reason ? `<div class="mt-2 text-amber-300">${esc(item.blocked_reason)}</div>` : ""}
          </div>
        </div>
      </label>
    `).join("");
  }

  function selectAllCases() {
    document.querySelectorAll(".paper-case-checkbox").forEach((node) => {
      if (!node.disabled) node.checked = true;
    });
  }

  function renderReports() {
    const root = byId("paper-reports-list");
    if (!root) return;
    if (!state.reports.length) {
      root.innerHTML = '<div class="glass-soft rounded-2xl p-4">No paper evidence packages were generated yet.</div>';
      return;
    }
    root.innerHTML = state.reports.map((report) => `
      <div class="glass-soft rounded-2xl p-4">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Report ID</div><div class="font-black mt-2 mono">${esc(report.report_id)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Level</div><div class="font-black mt-2">${esc(report.requested_level || "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Status</div><div class="font-black mt-2">${esc(report.status || "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Generated at</div><div class="font-black mt-2">${esc(report.generated_at || "not_available")}</div></div>
        </div>
        <div class="mt-3"><span class="font-black">Source case:</span> <span class="mono">${esc(report.source_case_id || "not_available")}</span></div>
        <div class="mt-2"><span class="font-black">Directory:</span> <span class="mono break-all">${esc(report.report_dir || "not_available")}</span></div>
        ${reportActions(report)}
      </div>
    `).join("");
    document.querySelectorAll(".paper-report-open-btn").forEach((btn) => {
      btn.addEventListener("click", () => openReport(btn.dataset.reportId));
    });
  }

  function renderTableReconstructionReports() {
    const summary = byId("paper-level-b-table-reconstruction-summary");
    const root = byId("paper-level-b-table-reconstruction-list");
    if (!summary || !root) return;
    const reports = state.tableReconstructionReports || [];
    if (!reports.length) {
      summary.innerHTML = "No FORGE-VI Level B table reconstruction reports were generated yet.";
      root.innerHTML = '<div class="glass-soft rounded-2xl p-4">No reconstruction reports available.</div>';
      return;
    }
    summary.innerHTML = `
      <div>Reconstruction reports: <span class="mono">${esc(reports.length)}</span></div>
      <div class="mt-2">Latest conclusion: <span class="font-black">${esc(reports[0]?.conclusion || "not_available")}</span></div>
    `;
    root.innerHTML = reports.map((report) => `
      <div class="glass-soft rounded-2xl p-4">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Report ID</div><div class="font-black mt-2 mono">${esc(report.report_id)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Generated at</div><div class="font-black mt-2">${esc(report.generated_at || "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Accepted Level B Cases</div><div class="font-black mt-2">${esc(report.accepted_level_b_cases ?? "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Conclusion</div><div class="font-black mt-2">${esc(report.conclusion || "not_available")}</div></div>
        </div>
        <div class="mt-3"><span class="font-black">Output dir:</span> <span class="mono break-all">${esc(report.output_dir || "not_available")}</span></div>
        <div class="mt-2"><span class="font-black">Markdown path:</span> <span class="mono break-all">${esc(report.report_markdown_path || "not_available")}</span></div>
        <div class="flex gap-3 flex-wrap mt-4">
          <button type="button" class="text-cyan-300 underline paper-table-reconstruction-open-btn" data-report-id="${esc(report.report_id)}">Open .md Report</button>
        </div>
      </div>
    `).join("");
    document.querySelectorAll(".paper-table-reconstruction-open-btn").forEach((btn) => {
      btn.addEventListener("click", () => openTableReconstructionReport(btn.dataset.reportId));
    });
  }

  function renderTruthfulEvaluationReports() {
    const summary = byId("paper-level-a-level-b-truthful-summary");
    const root = byId("paper-level-a-level-b-truthful-list");
    if (!summary || !root) return;
    const reports = state.truthfulEvaluationReports || [];
    if (!reports.length) {
      summary.innerHTML = "No truthful Level A + Level B evaluation packages were generated yet.";
      root.innerHTML = '<div class="glass-soft rounded-2xl p-4">No truthful evaluation packages available.</div>';
      return;
    }
    summary.innerHTML = `
      <div>Truthful evaluation packages: <span class="mono">${esc(reports.length)}</span></div>
      <div class="mt-2">Latest decision: <span class="font-black">${esc(reports[0]?.decision || "not_available")}</span></div>
      <div class="mt-2">Latest option: <span class="font-black">${esc(reports[0]?.option || "not_available")}</span></div>
    `;
    root.innerHTML = reports.map((report) => `
      <div class="glass-soft rounded-2xl p-4">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Report ID</div><div class="font-black mt-2 mono">${esc(report.report_id)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Generated at</div><div class="font-black mt-2">${esc(report.generated_at || "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Accepted Level B Cases</div><div class="font-black mt-2">${esc(report.accepted_level_b_cases ?? "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Standalone Level A</div><div class="font-black mt-2">${esc(report.standalone_level_a_executions ?? "not_available")}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Decision</div><div class="font-black mt-2">${esc(report.decision || "not_available")}</div></div>
        </div>
        <div class="mt-3"><span class="font-black">Output dir:</span> <span class="mono break-all">${esc(report.output_dir || "not_available")}</span></div>
        <div class="flex gap-3 flex-wrap mt-4">
          <button type="button" class="text-cyan-300 underline paper-truthful-evaluation-open-btn" data-report-id="${esc(report.report_id)}">Open .md Report</button>
        </div>
      </div>
    `).join("");
    document.querySelectorAll(".paper-truthful-evaluation-open-btn").forEach((btn) => {
      btn.addEventListener("click", () => openTruthfulEvaluationReport(btn.dataset.reportId));
    });
  }

  function ensureOverlay() {
    let root = byId("paper-evidence-overlay");
    if (root) return root;
    root = document.createElement("div");
    root.id = "paper-evidence-overlay";
    root.className = "fixed inset-0 z-[1200] bg-slate-950/65 backdrop-blur-sm p-4 md:p-8";
    root.innerHTML = `
      <div class="mx-auto max-w-6xl h-full flex items-center justify-center">
        <div class="glass rounded-[28px] p-6 w-full max-h-[88vh] overflow-auto">
          <div class="flex items-start justify-between gap-4">
            <div>
              <div class="text-[11px] tracking-[0.28em] uppercase text-cyan-300 font-black">Paper Evidence</div>
              <h2 id="paper-evidence-overlay-title" class="text-2xl font-black mt-2"></h2>
            </div>
            <button id="paper-evidence-overlay-close" type="button" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Close</button>
          </div>
          <div id="paper-evidence-overlay-body" class="mt-5"></div>
        </div>
      </div>
    `;
    document.body.appendChild(root);
    byId("paper-evidence-overlay-close").addEventListener("click", () => root.remove());
    root.addEventListener("click", (event) => {
      if (event.target === root) root.remove();
    });
    return root;
  }

  async function openReport(reportId) {
    const payload = await getJson(`/api/foc/paper-evidence/reports/${encodeURIComponent(reportId)}`);
    const root = ensureOverlay();
    byId("paper-evidence-overlay-title").textContent = `Paper Evidence Report · ${reportId}`;
    byId("paper-evidence-overlay-body").innerHTML = `
      <div class="space-y-4">
        <div class="text-sm text-slate-300">
          <div><span class="font-black">Status:</span> ${esc(payload.manifest?.status || "not_available")}</div>
          <div class="mt-2"><span class="font-black">Source case:</span> <span class="mono">${esc(payload.manifest?.source_case_id || "not_available")}</span></div>
          <div class="mt-2"><span class="font-black">Report dir:</span> <span class="mono break-all">${esc(payload.manifest?.paper_reviewer_defense_report_path || "not_available")}</span></div>
        </div>
        <details class="glass-soft rounded-2xl p-4" open>
          <summary class="font-black cursor-pointer">Reviewer-facing Markdown</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.paper_reviewer_defense_report || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">Level A JSON Report</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.level_a_report || {}, null, 2))}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">Level B JSON Report</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.level_b_report || {}, null, 2))}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">Level A Scientific Comparison Markdown</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.level_a_scientific_comparison_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">Level A Scientific Comparison JSON</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.level_a_scientific_comparison_report || {}, null, 2))}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">Paper Table Registry</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.paper_table_registry || {}, null, 2))}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">Limitations Report</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.paper_limitations_report || {}, null, 2))}</pre>
        </details>
      </div>
    `;
    root.style.display = "block";
  }

  async function openTableReconstructionReport(reportId) {
    const payload = await getJson(`/api/foc/paper-evidence/level-b/table-reconstruction/reports/${encodeURIComponent(reportId)}`);
    const root = ensureOverlay();
    byId("paper-evidence-overlay-title").textContent = `FORGE-VI Level B Table Reconstruction · ${reportId}`;
    byId("paper-evidence-overlay-body").innerHTML = `
      <div class="space-y-4">
        <div class="text-sm text-slate-300">
          <div><span class="font-black">Conclusion:</span> ${esc(payload.metadata?.conclusion || "not_available")}</div>
          <div class="mt-2"><span class="font-black">Accepted Level B cases:</span> <span class="mono">${esc(payload.metadata?.accepted_level_b_cases ?? "not_available")}</span></div>
          <div class="mt-2"><span class="font-black">Output dir:</span> <span class="mono break-all">${esc(payload.output_dir || "not_available")}</span></div>
        </div>
        <details class="glass-soft rounded-2xl p-4" open>
          <summary class="font-black cursor-pointer">FORGE-VI_LevelB_Table_Reconstruction_Report.md</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.report_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">FORGE-VI_LevelB_Table_Gap_Report.md</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.gap_report_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">FORGE-VI_LevelB_Table_Values.json</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.values_json || {}, null, 2))}</pre>
        </details>
        <div class="text-xs text-slate-500 mono break-all">
          CSV path: ${esc(payload.availability_matrix_csv_path || "not_available")}
        </div>
      </div>
    `;
    root.style.display = "block";
  }

  async function openTruthfulEvaluationReport(reportId) {
    const payload = await getJson(`/api/foc/paper-evidence/level-a-level-b/truthful-evaluation/reports/${encodeURIComponent(reportId)}`);
    const root = ensureOverlay();
    byId("paper-evidence-overlay-title").textContent = `FORGE-VI Level A + Level B Truthful Evaluation · ${reportId}`;
    byId("paper-evidence-overlay-body").innerHTML = `
      <div class="space-y-4">
        <div class="text-sm text-slate-300">
          <div><span class="font-black">Decision:</span> ${esc(payload.metadata?.decision || "not_available")}</div>
          <div class="mt-2"><span class="font-black">Option:</span> ${esc(payload.metadata?.option || "not_available")}</div>
          <div class="mt-2"><span class="font-black">Output dir:</span> <span class="mono break-all">${esc(payload.output_dir || "not_available")}</span></div>
        </div>
        <details class="glass-soft rounded-2xl p-4" open>
          <summary class="font-black cursor-pointer">FORGE-VI_LevelA_LevelB_Truthful_Evaluation_Report.md</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.evaluation_report_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">FORGE-VI_LevelA_LevelB_Truthful_Paper_Tables.md</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.paper_tables_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">FORGE-VI_LevelA_LevelB_Truthful_Gap_Report.md</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.gap_report_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">FORGE-VI_LevelA_LevelB_Rerun_Readiness_Plan.md</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.rerun_plan_markdown || "not_available")}</pre>
        </details>
        <details class="glass-soft rounded-2xl p-4">
          <summary class="font-black cursor-pointer">FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json</summary>
          <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.values_json || {}, null, 2))}</pre>
        </details>
        <div class="text-xs text-slate-500 mono break-all">
          Provenance CSV path: ${esc(payload.data_provenance_csv_path || "not_available")}<br/>
          Availability CSV path: ${esc(payload.availability_matrix_csv_path || "not_available")}
        </div>
      </div>
    `;
    root.style.display = "block";
  }

  async function loadCases() {
    const payload = await getJson("/api/foc/experimentation/source-cases");
    state.cases = payload.cases || [];
    if (!state.selectedCaseId && state.cases.length) state.selectedCaseId = state.cases[0].case_id;
    renderCasePicker();
    renderCaseSummary();
  }

  async function loadCampaigns() {
    const payload = await getJson("/api/foc/experimentation/campaigns");
    state.campaigns = payload.campaigns || payload.items || [];
    renderCampaignPicker();
    renderCampaignSummary();
  }

  async function loadLevelBPreflight() {
    try {
      state.levelBPreflight = await getJson("/api/foc/paper-evidence/level-b/preflight");
    } catch (error) {
      state.levelBPreflight = {
        status: "error",
        message: error.message || "Could not load Level B preflight.",
        preflight: {},
        recommended_fix_path: "Review backend disk-acquisition prerequisites and retry.",
      };
    }
    renderLevelBPreflight();
  }

  async function ensureLevelBCampaign() {
    let campaign = selectedCampaign();
    if (campaign) return campaign;
    const proposal = await getJson("/api/foc/experimentation/campaigns/proposal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ level: "B" }),
    });
    const attackCatalog = await getJson("/api/foc/experimentation/attack-catalog?target_role=plc");
    const attacks = attackCatalog.attacks || [];
    const preferredAttack = attacks.find((item) => String(item.attack_id || "").toUpperCase() === "T0831_MANIPULATION_OF_CONTROL_MODBUS")
      || attacks.find((item) => String(item.mitre_id || "").toUpperCase() === "T0831")
      || attacks[0];
    if (!preferredAttack) {
      throw new Error("No Level B-compatible attack profile is available for the PLC target.");
    }
    const repetitions = levelBRepetitions();
    const created = await getJson("/api/foc/experimentation/campaigns/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        level: "B",
        name: proposal.campaign_name || `Level B Repetition — ${proposal.scenario_id || "active_scenario"}`,
        description: "Temporary Level B campaign created automatically from the Paper Evidence dashboard.",
        scenario_id: proposal.scenario_id,
        repetitions,
        attack_id: preferredAttack.attack_id,
        analysis_profile_id: proposal.analysis_profile_id || "default_multilayer_analysis_v1",
        foc_profile_id: proposal.foc_profile_id || "default_foc_causal_reconstruction_v1",
        detection_policy_id: proposal.detection_policy_id || "wazuh_suricata_alert_ingestion_v1",
        trigger_policy_id: proposal.trigger_policy_id || "highest_severity_alert_v1",
        acquisition_profile_id: proposal.acquisition_profile_id || "default_kolla_lime_tshark_v1",
        notes: "Auto-created by the Paper Evidence dashboard because no existing Level B campaign was available.",
      }),
    });
    await loadCampaigns();
    state.selectedCampaignId = created?.campaign?.campaign_id || state.selectedCampaignId;
    renderCampaignPicker();
    renderCampaignSummary();
    return selectedCampaign();
  }

  async function loadReports() {
    const payload = await getJson("/api/foc/paper-evidence/reports");
    state.reports = payload.reports || [];
    const root = byId("paper-reports-root");
    if (root && payload.root) root.textContent = payload.root;
    renderReports();
  }

  async function loadTableReconstructionReports() {
    const payload = await getJson("/api/foc/paper-evidence/level-b/table-reconstruction/reports");
    state.tableReconstructionReports = payload.reports || [];
    renderTableReconstructionReports();
  }

  async function loadTruthfulEvaluationReports() {
    const payload = await getJson("/api/foc/paper-evidence/level-a-level-b/truthful-evaluation/reports");
    state.truthfulEvaluationReports = payload.reports || [];
    renderTruthfulEvaluationReports();
  }

  async function runTableReconstruction() {
    const button = byId("paper-run-level-b-table-reconstruction-btn");
    const summary = byId("paper-level-b-table-reconstruction-summary");
    if (button) button.disabled = true;
    if (summary) summary.innerHTML = "Generating FORGE-VI Level B table reconstruction report from existing artifacts…";
    try {
      const payload = await getJson("/api/foc/paper-evidence/level-b/table-reconstruction/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      await loadTableReconstructionReports();
      if (summary) {
        summary.innerHTML = `
          <div class="text-cyan-300 font-black">Reconstruction report generated.</div>
          <div class="mt-2 mono break-all">${esc(payload.output_dir || "not_available")}</div>
          <div class="mt-2">${esc(payload.conclusion || "not_available")}</div>
        `;
      }
      await openTableReconstructionReport(payload.report_id);
    } catch (error) {
      if (summary) summary.innerHTML = `<span class="text-red-300">${esc(error.message || "Could not generate the reconstruction report.")}</span>`;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function runTruthfulEvaluation() {
    const button = byId("paper-run-level-a-level-b-truthful-btn");
    const summary = byId("paper-level-a-level-b-truthful-summary");
    if (button) button.disabled = true;
    if (summary) summary.innerHTML = "Generating truthful Level A + Level B evaluation package from existing artifacts…";
    try {
      const payload = await getJson("/api/foc/paper-evidence/level-a-level-b/truthful-evaluation/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      await loadTruthfulEvaluationReports();
      if (summary) {
        summary.innerHTML = `
          <div class="text-cyan-300 font-black">Truthful evaluation package generated.</div>
          <div class="mt-2 mono break-all">${esc(payload.output_dir || "not_available")}</div>
          <div class="mt-2">${esc(payload.decision || "not_available")}</div>
        `;
      }
      await openTruthfulEvaluationReport(payload.report_id);
    } catch (error) {
      if (summary) summary.innerHTML = `<span class="text-red-300">${esc(error.message || "Could not generate the truthful evaluation package.")}</span>`;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function loadCleanupInventory() {
    const payload = await getJson("/api/foc/experimentation/cleanup/inventory");
    state.cleanupInventory = payload.items || [];
    renderCleanupInventory();
    renderCaseCleanupList();
  }

  async function pollJob() {
    if (!state.activeJobId) return;
    try {
      const payload = await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(state.activeJobId)}`);
      let childPayload = null;
      let liveTrace = null;
      const childJobId = String(payload.current_child_job_id || "").trim();
      if (childJobId !== state.lastChildJobId) {
        state.lastChildJobId = childJobId || null;
        state.lastChildPayload = null;
      }
      if (childJobId) {
        try {
          childPayload = await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(childJobId)}`);
          state.lastChildPayload = childPayload;
        } catch (_err) {
          if (state.lastChildJobId === childJobId && state.lastChildPayload) {
            childPayload = state.lastChildPayload;
          }
        }
      }
      const caseId = String(childPayload?.current_case_id || payload.current_case_id || "").trim();
      if (caseId) {
        try {
          liveTrace = await getJson(`/api/foc/experimentation/cases/${encodeURIComponent(caseId)}/live-trace`);
        } catch (_err) {}
      }
      renderJob(payload, childPayload, liveTrace);
      if (isTerminal(payload.status)) {
        state.activeJobId = null;
        state.activeJobLevel = null;
        state.lastChildJobId = null;
        state.lastChildPayload = null;
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        await loadReports();
      }
    } catch (err) {
      console.error(err);
    }
  }

  function trackJob(jobId) {
    state.activeJobId = jobId;
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(pollJob, 2500);
    pollJob();
  }

  async function runLevelA() {
    const caseItem = selectedCase();
    if (!caseItem) {
      renderCaseSummary();
      return;
    }
    const n = levelARepetitions();
    const payload = {
      case_id: caseItem.case_id,
      level: "A",
      n_repetitions: n,
      generate_latex: !!byId("paper-generate-latex")?.checked,
      generate_zip: !!byId("paper-generate-zip")?.checked,
      dry_run: true,
    };
    const job = await getJson("/api/foc/paper-evidence/level-a/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    state.activeJobLevel = "A";
    trackJob(job.job_id);
  }

  async function runLevelB() {
    const campaign = await ensureLevelBCampaign();
    if (!campaign) {
      renderCampaignSummary();
      return;
    }
    const n = levelBRepetitions();
    const nested = levelBNestedLevelARepetitions();
    const payload = {
      campaign_id: campaign.campaign_id,
      level: "B",
      n_repetitions: n,
      requested_repetitions: n,
      nested_level_a_repetitions: nested,
      cleanup_old_cases: !!byId("paper-level-b-cleanup-old-cases")?.checked,
      generate_latex: !!byId("paper-generate-latex")?.checked,
      generate_zip: !!byId("paper-generate-zip")?.checked,
      dfir_mode_after: "on",
    };
    const job = await getJson("/api/foc/paper-evidence/level-b/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    state.activeJobLevel = "B";
    trackJob(job.job_id);
  }

  async function createTemporaryLevelBCampaign() {
    const button = byId("paper-create-level-b-campaign-btn");
    const summary = byId("paper-level-b-summary");
    if (button) button.disabled = true;
    if (summary) summary.innerHTML = '<div class="text-slate-300">Creating temporary Level B campaign from active scenario and recommended PLC attack profile…</div>';
    try {
      const campaign = await ensureLevelBCampaign();
      if (summary && campaign) {
        summary.innerHTML = `<div class="text-cyan-300">Temporary Level B campaign created: <span class="mono">${esc(campaign.campaign_id)}</span></div>`;
        renderCampaignSummary();
      }
    } catch (err) {
      if (summary) summary.innerHTML = `<div class="text-red-300">${esc(err.message || "Could not create the temporary Level B campaign.")}</div>`;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function deleteSelectedCleanupItems() {
    const checked = Array.from(document.querySelectorAll(".paper-cleanup-checkbox:checked")).map((node) => node.value);
    if (!checked.length) {
      byId("paper-cleanup-summary").innerHTML = '<span class="text-amber-300">Select at least one generated item before deleting.</span>';
      return;
    }
    const confirmation = window.prompt(`Type OK to delete ${checked.length} selected generated item(s). This may remove campaigns, executions, heavy cases, scientific reports, validation bundles, or paper evidence packages.`);
    if (confirmation !== "OK") return;
    const payload = await getJson("/api/foc/experimentation/cleanup/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selected_item_ids: checked, confirmation }),
    });
    byId("paper-cleanup-summary").innerHTML = `
      <div class="text-cyan-300 font-black">${esc(payload.message || "Cleanup completed.")}</div>
      <div class="mt-2 text-xs mono break-all">${esc(payload.cleanup_manifest_path || "not_available")}</div>
    `;
    await loadCleanupInventory();
    await loadReports();
    await loadCampaigns();
    await loadCases();
  }

  async function deleteSelectedCases() {
    const checked = Array.from(document.querySelectorAll(".paper-case-checkbox:checked")).map((node) => node.value);
    if (!checked.length) {
      byId("paper-cases-summary").innerHTML = '<span class="text-amber-300">Select at least one case before deleting.</span>';
      return;
    }
    const confirmation = window.prompt(`Type OK to delete ${checked.length} selected full case director${checked.length === 1 ? "y" : "ies"}. This removes the complete case from evidence_store.`);
    if (confirmation !== "OK") return;
    const payload = await getJson("/api/foc/experimentation/cleanup/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selected_item_ids: checked, confirmation }),
    });
    byId("paper-cases-summary").innerHTML = `
      <div class="text-cyan-300 font-black">${esc(payload.message || "Case cleanup completed.")}</div>
      <div class="mt-2 text-xs mono break-all">${esc(payload.cleanup_manifest_path || "not_available")}</div>
    `;
    await loadCleanupInventory();
    await loadReports();
    await loadCampaigns();
    await loadCases();
  }

  async function init() {
    byId("dfir-auto-close")?.addEventListener("click", dfirOverlayClose);
    byId("paper-case-select")?.addEventListener("change", (event) => {
      state.selectedCaseId = event.target.value || "";
      renderCaseSummary();
    });
    byId("paper-level-b-campaign-select")?.addEventListener("change", (event) => {
      state.selectedCampaignId = event.target.value || "";
      renderCampaignSummary();
    });
    byId("paper-run-level-a-btn")?.addEventListener("click", runLevelA);
    byId("paper-run-level-b-btn")?.addEventListener("click", runLevelB);
    byId("paper-run-level-b-table-reconstruction-btn")?.addEventListener("click", runTableReconstruction);
    byId("paper-level-b-table-reconstruction-refresh-btn")?.addEventListener("click", loadTableReconstructionReports);
    byId("paper-run-level-a-level-b-truthful-btn")?.addEventListener("click", runTruthfulEvaluation);
    byId("paper-level-a-level-b-truthful-refresh-btn")?.addEventListener("click", loadTruthfulEvaluationReports);
    byId("paper-create-level-b-campaign-btn")?.addEventListener("click", createTemporaryLevelBCampaign);
    byId("paper-refresh-btn")?.addEventListener("click", async () => {
      await loadCases();
      await loadCampaigns();
      await loadLevelBPreflight();
      await loadReports();
      await loadTableReconstructionReports();
      await loadTruthfulEvaluationReports();
      await loadCleanupInventory();
    });
    byId("paper-cleanup-refresh-btn")?.addEventListener("click", loadCleanupInventory);
    byId("paper-cleanup-level-filter")?.addEventListener("change", (event) => {
      state.cleanupLevelFilter = event.target.value || "ALL";
      renderCleanupInventory();
    });
    byId("paper-cleanup-select-visible-btn")?.addEventListener("click", selectVisibleCleanupItems);
    byId("paper-cleanup-delete-btn")?.addEventListener("click", deleteSelectedCleanupItems);
    byId("paper-cases-refresh-btn")?.addEventListener("click", loadCleanupInventory);
    byId("paper-cases-select-all-btn")?.addEventListener("click", selectAllCases);
    byId("paper-cases-delete-btn")?.addEventListener("click", deleteSelectedCases);
    await loadCases();
    await loadCampaigns();
    await loadLevelBPreflight();
    await loadReports();
    await loadTableReconstructionReports();
    await loadTruthfulEvaluationReports();
    await loadCleanupInventory();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
