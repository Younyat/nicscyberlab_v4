(function () {
  "use strict";

  const LEVEL_META = {
    A: {
      short: "Level A",
      long: "Level A — Reanalysis Repeatability",
      purpose: "Repeat the analysis and reconstruction pipeline over the same preserved case without modifying the original evidence.",
      sourceMode: "linked_existing_case",
      sourceModeLabel: "Linked existing case",
      stepTwoTitle: "Select source or scenario",
      dashboardActionLabel: "Open Base Case Dashboard",
      baselineLabel: "Not applicable for Level A",
      groundTruthLabel: "Reused from base case if available, otherwise reconstructed from preserved artifacts.",
      notExecuted: [
        "No scenario redeployment",
        "No new attack execution",
        "No new acquisition",
        "No modification of the original preserved case",
      ],
    },
    B: {
      short: "Level B",
      long: "Level B — Controlled Repeated Incident Execution",
      purpose: "Measure stability of forensic reconstruction under equivalent and documented experimental conditions.",
      sourceMode: "new_incident_execution",
      sourceModeLabel: "New incident execution",
      stepTwoTitle: "Select deployed scenario and incident profile",
      dashboardActionLabel: "Open Generated Case Dashboard",
      baselineLabel: "Generated before the controlled attack to measure baseline-noise drift.",
      groundTruthLabel: "Generated before the attack and cryptographically sealed.",
      notExecuted: [],
    },
    C: {
      short: "Level C",
      long: "Level C — Full Environment Redeployment Reproducibility",
      purpose: "Measure platform-level reproducibility across redeployment and environment-level variation.",
      sourceMode: "full_redeployment",
      sourceModeLabel: "Full redeployment",
      stepTwoTitle: "Select deployed scenario and redeployment profile",
      dashboardActionLabel: "Open Generated Case Dashboard",
      baselineLabel: "Generated before the controlled attack to measure baseline-noise drift.",
      groundTruthLabel: "Generated before the attack and cryptographically sealed.",
      notExecuted: [],
    },
  };

  const METHOD_GROUPS = [
    {
      label: "Forensic lifecycle",
      ids: ["nist_sp_800_86"],
      why: "Justifies preserved-evidence examination, analysis, and reporting logic.",
    },
    {
      label: "Incident response",
      ids: ["nist_sp_800_61_r3"],
      why: "Justifies trigger, triage, acquisition, and incident-handling sequencing.",
    },
    {
      label: "OT context",
      ids: ["nist_sp_800_82_r3"],
      why: "Justifies OT, PLC, SCADA, and Modbus-specific interpretation boundaries.",
    },
    {
      label: "Logs and alerts",
      ids: ["nist_sp_800_92"],
      why: "Justifies alert triage, timeline use, and log-centric comparability.",
    },
    {
      label: "Evidence preservation",
      ids: ["nist_ir_8387", "swgde_collection"],
      why: "Justifies read-only linkage, preservation constraints, and custody-aware profiles.",
    },
    {
      label: "Repeatability and reproducibility",
      ids: ["iso_5725_1", "iso_5725_2", "vim_repeatability", "vim_reproducibility", "vim_uncertainty", "acm_artifact_review"],
      why: "Justifies Level A/B/C semantics, degradation-aware comparability, and artifact-centric reporting.",
    },
    {
      label: "Attack vocabulary",
      ids: ["mitre_attack"],
      why: "Justifies normalized scenario and attack-path interpretation.",
    },
    {
      label: "Equivalence margins",
      ids: ["lakens_equivalence_testing"],
      why: "Justifies explicit delta thresholds instead of vague similarity claims.",
    },
  ];

  const state = {
    campaigns: [],
    sourceCases: [],
    selectedCampaignId: null,
    activeJobId: null,
    pollTimer: null,
    guidedMode: true,
    proposal: null,
    preflight: null,
    currentCaseId: new URLSearchParams(window.location.search).get("case_id") || "",
    executionCache: new Map(),
    dirtyFields: new Set(),
    methodBasis: null,
    storyMode: true,
    selectedCampaignDetail: null,
    recommendedFamily: null,
    attackCatalog: [],
    lastRecommendation: null,
    justCreatedCampaignId: null,
    levelAReportOverlayJobId: null,
    levelBOverlayJobId: null,
  };
  const ACTIVE_JOB_STORAGE_KEY = "nics-foc-experimentation-active-job";

  const byId = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  const truthy = (value) => !!value && value !== "not_available";
  const ANALYSIS_PHASE_META = {
    preflight_validation: { label: "Multilayer analysis preflight", layer: "multilayer" },
    evidence_inventory: { label: "Preserved evidence inventory", layer: "verification" },
    integrity_custody_validation: { label: "Chain of custody verification", layer: "verification" },
    temporal_validation: { label: "Time synchronization and timestamp quality assessment", layer: "time_sync" },
    network_analysis: { label: "Network analysis", layer: "network" },
    memory_analysis: { label: "Memory analysis", layer: "memory" },
    disk_analysis: { label: "Disk analysis", layer: "disk" },
    ot_export_analysis: { label: "OT and industrial artifacts analysis", layer: "ot" },
    alerts_detection_analysis: { label: "Alerts analysis", layer: "alerts" },
    pipeline_custody_analysis: { label: "Pipeline and custody analysis", layer: "pipeline_custody" },
    unified_forensic_timeline: { label: "Unified timeline generation", layer: "timeline" },
    cross_layer_findings: { label: "Cross-layer findings generation", layer: "cross_layer" },
    forensic_analysis_report_generation: { label: "Multilayer analysis finalization", layer: "multilayer" },
    foc_readiness_update: { label: "FOC readiness update", layer: "foc" },
  };
  const ANALYSIS_PHASE_ORDER = [
    "preflight_validation",
    "evidence_inventory",
    "integrity_custody_validation",
    "temporal_validation",
    "network_analysis",
    "memory_analysis",
    "disk_analysis",
    "ot_export_analysis",
    "alerts_detection_analysis",
    "pipeline_custody_analysis",
    "unified_forensic_timeline",
    "cross_layer_findings",
    "forensic_analysis_report_generation",
    "foc_readiness_update",
  ];
  const PARAM_HELP = {
    cpr: {
      label: "CPR",
      meaning: "Causal Path Recoverability.",
      formula: "CPR = fully recovered expected causal edges / total expected causal edges.",
      represents: "It represents how much of the expected causal model was fully recovered from preserved evidence.",
    },
    weighted_cpr: {
      label: "Weighted CPR",
      meaning: "Weighted causal recoverability.",
      formula: "Weighted CPR = recovered expected edge weight / total expected edge weight.",
      represents: "It represents recoverability after accounting for the relative importance of the expected causal edges.",
    },
    delta_wcpr_allowed: {
      label: "Delta WCPR allowed",
      meaning: "Accepted Weighted CPR drift between executions.",
      formula: "The comparison passes this rule when Max |ΔWCPR| stays at or below this threshold.",
      represents: "It represents how much weighted causal recoverability variation is still accepted across repeated executions.",
    },
    baseline_threshold: {
      label: "Baseline threshold",
      meaning: "Accepted baseline-noise drift between executions.",
      formula: "Relative difference = abs(value_i - value_j) / max(value_i, value_j, epsilon).",
      represents: "It represents the maximum accepted baseline variation before the system raises a comparability warning.",
    },
    technical_outcome: {
      label: "Technical execution",
      meaning: "Whether the campaign finished technically.",
      formula: "It is aggregated from execution status, missing required profiles, failed stages, and other blocking technical conditions.",
      represents: "It represents whether the module completed its orchestration work without technical failure.",
    },
    scientific_outcome: {
      label: "Scientific outcome",
      meaning: "Whether usable outputs still carry scientific limitations.",
      formula: "It is aggregated from completed outputs plus inherited or generated scientific limitations such as degraded causal edges or partial integrity.",
      represents: "It represents whether the campaign is scientifically clean or completed with limitations.",
    },
    comparison_readiness: {
      label: "Comparison readiness",
      meaning: "Whether enough execution profiles exist for comparability analysis.",
      formula: "Ready usually requires at least two executions with forensic_comparison_profile.json available.",
      represents: "It represents whether the campaign can already be consumed by the Comparability View.",
    },
    campaign_status: {
      label: "Campaign status",
      meaning: "Aggregated campaign-level state.",
      formula: "The backend combines technical completion, scientific limitations, and profile availability to derive the campaign status.",
      represents: "It represents whether the campaign is completed, degraded, partial, insufficient, or technically failed.",
    },
  };

  function infoTip(key, overrideLabel, currentValue) {
    const meta = PARAM_HELP[key];
    const label = overrideLabel || meta?.label || key;
    if (!meta) return `<span>${esc(label)}</span>`;
    return `
      <span class="info-tip" tabindex="0">
        <span>${esc(label)}</span>
        <span class="info-badge">i</span>
        <span class="tip-panel">
          <div><strong>${esc(meta.label)}</strong></div>
          <div class="tip-line">${esc(meta.meaning)}</div>
          <div class="tip-line"><strong>How it is calculated:</strong> ${esc(meta.formula)}</div>
          <div class="tip-line"><strong>What it represents:</strong> ${esc(meta.represents)}</div>
          ${currentValue == null ? "" : `<div class="tip-line"><strong>Current value:</strong> ${esc(currentValue)}</div>`}
        </span>
      </span>
    `;
  }

  async function getJson(url, options) {
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.message || data.error || `${res.status} ${res.statusText}`);
    return data;
  }

  function titleCaseStatus(value) {
    return String(value || "unknown")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (ch) => ch.toUpperCase());
  }

  function isTerminalJobStatus(status) {
    return ["completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped", "blocked_before_attack", "failed_detection"].includes(String(status || "").toLowerCase());
  }

  function formatDetail(value) {
    if (value == null) return "";
    if (typeof value === "string") return value;
    if (typeof value === "object") {
      if (value.message && value.phase) return `${value.phase}: ${value.message}`;
      try {
        return JSON.stringify(value);
      } catch {
        return String(value);
      }
    }
    return String(value);
  }

  function isRunningLikeStatus(status) {
    return ["queued", "running"].includes(String(status || "").toLowerCase());
  }

  function formatElapsedDuration(startedAtIso, finishedAtIso) {
    if (!startedAtIso) return "not_available";
    const started = new Date(startedAtIso);
    if (Number.isNaN(started.getTime())) return "not_available";
    const end = finishedAtIso ? new Date(finishedAtIso) : new Date();
    const seconds = Math.max(0, Math.round((end.getTime() - started.getTime()) / 1000));
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
    if (minutes > 0) return `${minutes}m ${secs}s`;
    return `${secs}s`;
  }

  function isLevelAReportJob(payload) {
    return String(payload?.job_type || "").toLowerCase() === "level_a_scientific_report";
  }

  function isLevelBRepetitionJob(payload) {
    return String(payload?.job_type || "").toLowerCase() === "level_b_repetitions";
  }

  function getBrowserDfirMode() {
    try {
      return (localStorage.getItem("nics_dfir_auto") || "0") === "1" ? "on" : "off";
    } catch {
      return "unknown";
    }
  }

  function setBrowserDfirModeOn() {
    try {
      localStorage.setItem("nics_dfir_auto", "1");
      return "on";
    } catch {
      return "unknown";
    }
  }

  function analysisPhaseLabel(phaseKey) {
    return ANALYSIS_PHASE_META[phaseKey]?.label || titleCaseStatus(phaseKey || "analysis");
  }

  function analysisPhaseLayer(phaseKey) {
    return ANALYSIS_PHASE_META[phaseKey]?.layer || "analysis";
  }

  function mapAnalysisProgressToLifecycle(progressPercent) {
    if (progressPercent == null || Number.isNaN(Number(progressPercent))) return null;
    return Math.min(88, Math.max(74, Math.round((74 + (Number(progressPercent) * 0.14)) * 10) / 10));
  }

  function mapLifecycleProgressToWrapper(progressPercent) {
    if (progressPercent == null || Number.isNaN(Number(progressPercent))) return null;
    return Math.min(88, Math.max(74, Math.round((74 + (Number(progressPercent) * 0.14)) * 10) / 10));
  }

  function orderedAnalysisPhaseEntries(phases) {
    const map = phases || {};
    return ANALYSIS_PHASE_ORDER
      .filter((phaseKey) => map[phaseKey])
      .map((phaseKey) => [phaseKey, map[phaseKey]]);
  }

  function buildAnalysisTraceFromStatus(analysis) {
    const phases = analysis?.phases || {};
    return orderedAnalysisPhaseEntries(phases).map(([phaseId, payload]) => ({
      case_id: analysis.case_id || null,
      phase_id: `analysis_${phaseId}`,
      parent_phase_id: "run_multilayer_analysis",
      phase_label: analysisPhaseLabel(phaseId),
      layer: analysisPhaseLayer(phaseId),
      status: payload?.status || "unknown",
      utc_start_time: payload?.started_at || null,
      utc_end_time: payload?.finished_at || null,
      duration_ms: null,
      input_artifacts_used: [],
      output_artifacts_generated: payload?.output_path ? [payload.output_path] : [],
      number_of_artifacts_processed: null,
      number_of_findings_generated: null,
      warnings: payload?.limitations || [],
      blockers: payload?.errors || [],
      scientific_limitation_reason: (payload?.limitations || [])[0] || null,
      detail: payload?.errors?.[0] || payload?.limitations?.[0] || `${analysisPhaseLabel(phaseId)} is ${titleCaseStatus(payload?.status || "pending").toLowerCase()}.`,
    }));
  }

  function analysisPhaseQueueReason(entries, index) {
    if (index <= 0) return "Queued. This phase has not started yet.";
    const prev = entries[index - 1];
    return `Queued. This phase will start only after ${analysisPhaseLabel(prev?.[0])} completes.`;
  }

  function mergeLifecycleTrace(baseTrace, analysis) {
    const trace = Array.isArray(baseTrace) ? [...baseTrace] : [];
    const existing = new Set(trace.map((item) => String(item.phase_id || "")));
    if (analysis?.phases && !existing.has("run_full_evidence_lifecycle")) {
      trace.push({
        case_id: analysis.case_id || null,
        phase_id: "run_full_evidence_lifecycle",
        parent_phase_id: null,
        phase_label: "Run Full Evidence Lifecycle",
        layer: "lifecycle",
        status: analysis.status || "running",
        utc_start_time: analysis.started_at || null,
        utc_end_time: analysis.finished_at || null,
        duration_ms: null,
        input_artifacts_used: [],
        output_artifacts_generated: [],
        number_of_artifacts_processed: null,
        number_of_findings_generated: null,
        warnings: analysis.warnings || [],
        blockers: analysis.errors || [],
        scientific_limitation_reason: null,
        detail: "Running the preserved-case lifecycle from the Repetition Manager.",
      });
      existing.add("run_full_evidence_lifecycle");
    }
    if (analysis?.phases && !existing.has("run_multilayer_analysis")) {
      trace.push({
        case_id: analysis.case_id || null,
        phase_id: "run_multilayer_analysis",
        parent_phase_id: "run_full_evidence_lifecycle",
        phase_label: "Run multilayer forensic analysis",
        layer: "multilayer",
        status: analysis.status || "running",
        utc_start_time: analysis.started_at || null,
        utc_end_time: analysis.finished_at || null,
        duration_ms: null,
        input_artifacts_used: [],
        output_artifacts_generated: analysis.output_files || [],
        number_of_artifacts_processed: null,
        number_of_findings_generated: null,
        warnings: analysis.warnings || [],
        blockers: analysis.errors || [],
        scientific_limitation_reason: null,
        detail: "Executing the same multilayer forensic analysis backend used by the reconstruction dashboards.",
      });
      existing.add("run_multilayer_analysis");
    }
    buildAnalysisTraceFromStatus(analysis).forEach((item) => {
      if (!existing.has(String(item.phase_id))) trace.push(item);
    });
    return trace;
  }

  async function loadLifecycleJob(jobId) {
    if (!jobId) return null;
    try {
      return await getJson(`/api/foc/lifecycle/job-status?job_id=${encodeURIComponent(jobId)}`);
    } catch {
      return null;
    }
  }

  async function loadLiveAnalysisStatus(caseId) {
    if (!caseId) return null;
    try {
      return await getJson(`/api/foc/cases/${encodeURIComponent(caseId)}/analysis-status`);
    } catch {
      return null;
    }
  }

  async function hydrateExperimentationJob(payload) {
    const lifecycleJobId = payload.lifecycle_job_id || (payload.meta || {}).lifecycle_job_id || null;
    const lifecycle = await loadLifecycleJob(lifecycleJobId);
    const caseId = lifecycle?.case_id
      || payload.reference_case_id
      || payload.source_case_id
      || (payload.meta || {}).reference_case_id
      || (payload.meta || {}).source_case_id
      || null;
    const analysis = await loadLiveAnalysisStatus(caseId);
    const lifecycleActive = isRunningLikeStatus(lifecycle?.status);
    const analysisActive = String(analysis?.status || "").toLowerCase() === "running";
    const continuePolling = !isTerminalJobStatus(payload.status) || lifecycleActive || analysisActive;
    const nestedTrace = mergeLifecycleTrace(lifecycle?.phase_trace || payload.lifecycle_phase_trace || payload.phase_trace || [], analysis);
    const display = {
      ...payload,
      live_lifecycle_status: lifecycle,
      live_analysis_status: analysis,
      lifecycle_phase_trace: nestedTrace,
    };
    if (lifecycleActive || analysisActive) {
      const livePhaseLabel = analysisActive
        ? analysisPhaseLabel(analysis.current_phase)
        : (lifecycle?.current_phase_label || titleCaseStatus(lifecycle?.current_phase || "running"));
      const livePhaseDetail = analysisActive
        ? `The full evidence lifecycle is still running. Current multilayer phase: ${analysisPhaseLabel(analysis.current_phase)}.${analysis.progress_percent != null ? ` Multilayer analysis progress: ${analysis.progress_percent}%.` : ""}`
        : formatDetail(lifecycle?.current_phase_detail) || "The full evidence lifecycle is still running.";
      display.status = "running";
      display.finished_at = null;
      display.last_error = null;
      display.current_phase = analysisActive ? String(analysis.current_phase || "run_multilayer_analysis") : (lifecycle?.current_phase || payload.current_phase || "running");
      display.current_phase_label = `Run Full Evidence Lifecycle · ${livePhaseLabel}`;
      display.current_phase_detail = livePhaseDetail;
      // Both mappers clamp into the same [74, 88] "nested phase" band on the outer
      // wrapper's progress bar. Falling back to the raw payload.progress_percent
      // here was wrong: that's the OUTER job's own last phase progress (any
      // value 0-100), not scaled to this nested band, so the displayed percent
      // would jump erratically between e.g. 20% and 80% depending on which of
      // lifecycle/analysis happened to report a number on a given poll.
      display.progress_percent = mapLifecycleProgressToWrapper(lifecycle?.progress_percent) ?? mapAnalysisProgressToLifecycle(analysis?.progress_percent) ?? 74;
      if (isTerminalJobStatus(payload.status)) {
        display.live_recovery_note = "The experimentation wrapper reached a terminal state, but the underlying lifecycle or multilayer analysis is still active. Live child progress is shown below until the scientific backend really finishes.";
      }
    }
    return { payload: display, continuePolling };
  }

  function currentAttackProfile() {
    const attackId = String(byId("attack-profile-select")?.value || "").trim();
    return state.attackCatalog.find((item) => item.attack_id === attackId) || null;
  }

  function builderRequiresAttack(level) {
    return ["B", "C"].includes(String(level || currentLevel()).toUpperCase());
  }

  function builderHasAttackSelection(level) {
    if (!builderRequiresAttack(level)) return true;
    return !!(currentAttackProfile() || state.recommendedFamily?.attack_profile_id);
  }

  function builderCreateBlockedReason() {
    const level = currentLevel();
    if (builderRequiresAttack(level) && !builderHasAttackSelection(level)) {
      return `This Level ${level} campaign is not ready because no attack profile has been selected. Select an attack profile or start a new comparison family before creating executable repetitions.`;
    }
    return "";
  }

  function statusClass(status) {
    const raw = String(status || "").toLowerCase();
    if (raw.includes("fail") || raw.includes("missing")) return "text-red-300";
    if (raw.includes("pause") || raw.includes("degradation") || raw.includes("partial") || raw.includes("warning")) return "text-amber-300";
    if (raw.includes("complete") || raw.includes("running") || raw.includes("available") || raw.includes("ok")) return "text-cyan-300";
    return "text-slate-300";
  }

  function statusExplanation(status, scope) {
    const normalized = String(status || "").toLowerCase();
    const map = {
      campaign: {
        completed_with_degradation: "The campaign completed and generated usable executions, but one or more scientific limitations remain. This is not a technical failure.",
        completed_with_failures: "The campaign finished, but at least one execution failed or did not complete all required stages.",
        completed: "The campaign finished and its registered executions completed within the expected workflow.",
        partial: "Some execution outputs exist, but the campaign is not complete enough yet for a full scientific reading.",
        insufficient_data: "The campaign workspace exists, but there are not enough generated profiles yet for comparison-ready interpretation.",
        running: "The campaign currently has an active execution job in progress.",
        paused: "The campaign is paused. No new execution will start until resumed.",
        stopped: "The campaign was stopped explicitly. Existing execution workspaces remain preserved.",
        not_started: "The campaign configuration exists, but no execution has been launched yet.",
        failed: "The campaign failed at the orchestration level and needs inspection before further runs.",
      },
      execution: {
        completed_with_degradation: "The execution produced usable outputs, but at least one scientific limitation remains.",
        completed: "The execution completed and produced the expected outputs for its configured scope.",
        partial: "The execution workspace was created, but some expected scientific profiles could not be populated.",
        failed: "The execution failed before generating the minimum expected outputs.",
        running: "The execution is currently generating or updating scientific profiles.",
        cancelled: "The execution was cancelled before completion.",
        queued: "The execution has been registered and is waiting for orchestration.",
      },
      generic: {
        completed_with_degradation: "The step produced output, but one or more scientific limitations remain visible.",
        completed: "The step completed and produced output.",
        not_applicable: "This step is not applicable to the selected evaluation level.",
        missing: "This requirement is currently missing.",
        ok: "This requirement is satisfied.",
      },
    };
    return (map[scope] && map[scope][normalized]) || map.generic[normalized] || "No additional explanation is currently available for this status.";
  }

  function campaignScientificLimitationStatus(campaign) {
    return (campaign?.scientific_limitations || []).length ? "Present" : "None recorded";
  }

  function campaignTechnicalReason(campaign, level) {
    const technicalFailures = campaign?.technical_failures || [];
    const scientificLimitations = campaign?.scientific_limitations || [];
    const normalized = String(campaign?.status || "").toLowerCase();
    if (normalized === "completed_with_degradation") {
      return level === "A"
        ? "All Level A executions completed and generated usable profiles, but they inherit limitations from the base case."
        : "All executions completed and generated usable profiles, but one or more scientific limitations remain in the reconstructed outputs.";
    }
    if (normalized === "completed_with_failures") {
      return technicalFailures[0] || "At least one execution failed or a required profile could not be generated.";
    }
    if (normalized === "partial") {
      return "Some execution outputs exist, but the campaign is not complete enough yet for a full comparison.";
    }
    if (normalized === "insufficient_data") {
      return "The campaign finished technically, but there are not enough generated comparison profiles yet.";
    }
    if (normalized === "completed" && scientificLimitations.length) {
      return "The campaign completed technically and recorded limitations, but they did not degrade the aggregated campaign status.";
    }
    if (normalized === "completed") {
      return "All registered executions completed and generated the expected outputs.";
    }
    return statusExplanation(normalized, "campaign");
  }

  function campaignComparisonReadinessLabel(value) {
    const normalized = String(value || "").toLowerCase();
    if (normalized === "ready") return "Ready";
    if (normalized === "partial") return "Partial";
    if (normalized === "insufficient_data") return "Insufficient Data";
    return titleCaseStatus(normalized || "unknown");
  }

  function updateCampaignNameFromSelection() {
    const nameNode = byId("campaign-name-input");
    if (!nameNode || state.dirtyFields.has("campaign-name-input")) return;
    const level = currentLevel();
    const scenarioId = currentScenarioId() || state.proposal?.scenario_id || "not_available";
    const attack = currentAttackProfile();
    if (level === "A") {
      const caseId = currentSourceCaseId() || state.proposal?.linked_source_case || "preserved_case";
      nameNode.value = `Level A Reanalysis — ${caseId}`;
      return;
    }
    if (level === "B") {
      nameNode.value = attack?.mitre_id
        ? `Level B ${attack.mitre_id} Repetition — ${scenarioId}`
        : `Level B Repetition — ${scenarioId}`;
      return;
    }
    if (level === "C") {
      nameNode.value = attack?.mitre_id
        ? `Level C ${attack.mitre_id} Redeployment — ${scenarioId}`
        : `Level C Full Redeployment — ${scenarioId}`;
    }
  }

  function renderBuilderSelectedCampaignNote() {
    const root = byId("builder-selected-separation-note");
    if (!root) return;
    const selected = state.selectedCampaignDetail?.campaign || selectedCampaign();
    const builderLevel = currentLevel();
    if (!selected) {
      root.innerHTML = "";
      return;
    }
    const selectedLevel = String(selected.level || "A").toUpperCase();
    if (builderLevel !== selectedLevel) {
      root.innerHTML = `You are configuring a new ${esc(LEVEL_META[builderLevel]?.long || `Level ${builderLevel}`)} campaign. The selected campaign below is an existing ${esc(LEVEL_META[selectedLevel]?.long || `Level ${selectedLevel}`)} campaign and is independent from the builder state.`;
      return;
    }
    root.innerHTML = `The builder above defines a new ${esc(LEVEL_META[builderLevel]?.long || `Level ${builderLevel}`)} campaign. The detail below shows the currently selected saved campaign and its registered executions.`;
  }

  function currentScenarioActionCampaign() {
    const selected = state.selectedCampaignDetail?.campaign || selectedCampaign();
    if (selected && String(selected.level || "").toUpperCase() === "C") return selected;
    return null;
  }

  function normalizeCampaignLimitation(text, level) {
    const raw = String(text || "");
    if (/ground_truth_sealed -> ground truth seal was reconstructed/i.test(raw) || /ground truth is reused rather than freshly sealed/i.test(raw)) {
      return {
        reason: "Ground truth context reused or reconstructed from preserved case artifacts",
        classification: level === "A" ? "expected Level A limitation" : "scientific limitation",
        interpretation: "Level A does not execute a new attack and therefore cannot generate a new pre-attack ground truth seal. The ground truth context is reused or reconstructed from the preserved case.",
      };
    }
    if (/causal_reconstruction_generated -> .*causal edge is degraded/i.test(raw) || /degraded edges/i.test(raw)) {
      return {
        reason: "Causal reconstruction contains degraded edges",
        classification: level === "A" ? "inherited from base case or stable across Level A reanalysis" : "stable scientific limitation",
        interpretation: "The degradation is stable across reanalysis and limits scientific strength, but does not indicate analysis instability.",
      };
    }
    if (/trigger.*aligned/i.test(raw)) {
      return {
        reason: "Trigger and reconstructed attack path are not aligned",
        classification: level === "A" ? "inherited from base case" : "trigger-alignment limitation",
        interpretation: "The acquisition trigger is host/FIM-oriented while the reconstructed path is OT/Modbus-oriented.",
      };
    }
    if (/integrity/i.test(raw) && /partial/i.test(raw)) {
      return {
        reason: "Case-wide integrity remains partial",
        classification: level === "A" ? "inherited from base case" : "integrity limitation",
        interpretation: "The comparison can proceed, but scientific confidence must remain limited.",
      };
    }
    if (/execution completed with scientific degradation/i.test(raw)) {
      return {
        reason: "Execution completed with scientific degradation",
        classification: "execution summary status",
        interpretation: "The execution produced usable outputs, but one or more scientific limitations remain visible.",
      };
    }
    return {
      reason: raw.includes(": ") ? raw.split(": ").slice(1).join(": ") : raw,
      classification: "scientific limitation",
      interpretation: "This limitation remains scientifically relevant and should be inspected before drawing stronger conclusions.",
    };
  }

  function groupCampaignScientificLimitations(limitations, level, executionCount) {
    const groups = new Map();
    for (const raw of limitations || []) {
      const parts = String(raw || "").split(": ");
      const executionId = parts.length > 1 ? parts[0] : "unknown";
      const normalized = normalizeCampaignLimitation(raw, level);
      const entry = groups.get(normalized.reason) || { ...normalized, executions: [] };
      if (!entry.executions.includes(executionId)) entry.executions.push(executionId);
      groups.set(normalized.reason, entry);
    }
    return [...groups.values()].map((item) => ({
      ...item,
      affectedLabel: `${item.executions.length} / ${executionCount || item.executions.length}`,
    }));
  }

  function stageNarrative(status, context) {
    const normalized = String(status || "unknown").toLowerCase();
    if (normalized === "completed") return "The stage finished and produced the expected output.";
    if (normalized === "completed_with_degradation") return "The stage produced usable output, but one or more scientific limitations remain.";
    if (normalized === "completed_with_failures") return "The campaign ended, but at least one execution failed or did not complete all required stages.";
    if (normalized === "partial") return "Some outputs exist, but the execution is not complete enough for a full comparison.";
    if (normalized === "failed") return "A technical failure prevented the expected output.";
    if (normalized === "not_applicable") {
      if (context === "attack") return "Level A reuses preserved evidence. No new attack is executed.";
      if (context === "baseline") return "Baseline noise is not measured in Level A because the experiment does not execute a new incident.";
      if (context === "ground_truth") return "The campaign reuses the ground truth or reconstructed expectation associated with the base case.";
      return "This stage is not required for the selected level.";
    }
    if (normalized === "running") return "The stage is currently running.";
    if (normalized === "missing") return "This requirement is still missing.";
    return "This stage has not produced a final interpretable result yet.";
  }

  function saveActiveJob(payload) {
    try {
      localStorage.setItem(ACTIVE_JOB_STORAGE_KEY, JSON.stringify(payload || null));
    } catch {}
  }

  function loadActiveJob() {
    try {
      return JSON.parse(localStorage.getItem(ACTIVE_JOB_STORAGE_KEY) || "null");
    } catch {
      return null;
    }
  }

  function clearActiveJob() {
    try {
      localStorage.removeItem(ACTIVE_JOB_STORAGE_KEY);
    } catch {}
  }

  function sourceModeLabel(mode) {
    const labels = {
      linked_existing_case: "Linked existing case",
      new_incident_execution: "New incident execution",
      full_redeployment: "Full redeployment",
      planned_campaign: "Planned campaign",
    };
    return labels[String(mode || "")] || String(mode || "unknown");
  }

  function sourceModeExplanation(mode) {
    const explanations = {
      linked_existing_case: "The campaign is linked to an existing preserved forensic case. This is normally used for Level A.",
      new_incident_execution: "The campaign will execute a new incident in an already deployed scenario. This is normally used for Level B.",
      full_redeployment: "The campaign will redeploy the environment before executing the incident. This is normally used for Level C.",
      planned_campaign: "The campaign was registered without a concrete source case yet. Additional configuration may still be required before execution.",
    };
    return explanations[String(mode || "")] || "No source-mode explanation is currently available.";
  }

  function selectedCampaign() {
    return state.campaigns.find((item) => item.campaign_id === state.selectedCampaignId) || null;
  }

  function currentLevel() {
    return String(byId("level-hidden")?.value || state.proposal?.default_level || "A").toUpperCase();
  }

  function currentSourceCaseId() {
    return String(byId("source-case-select")?.value || "").trim();
  }

  function currentScenarioId() {
    return String(byId("scenario-id-input")?.value || "").trim();
  }

  function isGuidedMode() {
    return !!state.guidedMode;
  }

  function markFieldDirty(event) {
    if (event?.target?.id) state.dirtyFields.add(event.target.id);
  }

  function setFieldValue(id, value, options) {
    const node = byId(id);
    if (!node) return;
    const force = !!(options && options.force);
    if (!force && state.dirtyFields.has(id)) return;
    if (node.tagName === "SELECT" || node.tagName === "INPUT" || node.tagName === "TEXTAREA") {
      node.value = value ?? "";
    }
  }

  function renderModeButtons() {
    byId("guided-mode-btn")?.classList.toggle("is-active", state.guidedMode);
    byId("advanced-mode-btn")?.classList.toggle("is-active", !state.guidedMode);
    byId("advanced-panel")?.classList.toggle("hidden", state.guidedMode);
  }

  function renderViewModeButtons() {
    byId("story-mode-btn")?.classList.toggle("is-active", state.storyMode);
    byId("technical-mode-btn")?.classList.toggle("is-active", !state.storyMode);
    ["rm-story-mode-panel", "rm-level-story-panel", "rm-storyline-panel", "rm-campaign-story-panel"].forEach((id) => {
      const node = byId(id);
      if (!node) return;
      node.closest(".glass, .glass-soft")?.classList.toggle("opacity-100", state.storyMode);
    });
    byId("rm-story-mode-panel")?.parentElement?.classList.toggle("hidden", !state.storyMode);
    byId("rm-level-story-panel")?.parentElement?.classList.toggle("hidden", !state.storyMode);
    byId("rm-storyline-panel")?.parentElement?.classList.toggle("hidden", !state.storyMode);
  }

  function renderStoryIntro() {
    const root = byId("rm-story-mode-panel");
    if (!root) return;
    root.innerHTML = `
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What are we trying to test?</div>
        <div class="mt-3 text-slate-300">This view prepares repeated forensic executions. It does not judge the case yet. Its purpose is to create controlled execution workspaces that can later be compared. Each execution stores its own artifacts, logs, ground truth seal, baseline noise profile, and forensic comparison profile.</div>
      </div>
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What will this view produce?</div>
        <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
          <li>a repetition campaign</li>
          <li>one or more executions</li>
          <li>isolated execution workspaces</li>
          <li>execution manifests</li>
          <li>ground truth seals when applicable</li>
          <li>baseline noise profiles when applicable</li>
          <li>forensic comparison profiles</li>
          <li>links to the individual Scientific Lifecycle dashboard</li>
          <li>inputs for the Comparability View</li>
        </ul>
      </div>
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What this view does not do</div>
        <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
          <li>it does not compare executions</li>
          <li>it does not replace the Scientific Lifecycle dashboard</li>
          <li>it does not modify preserved evidence</li>
          <li>it does not silently overwrite previous cases</li>
          <li>it does not make degraded evidence stronger</li>
        </ul>
      </div>
    `;
  }

  function renderLevelStory() {
    const root = byId("rm-level-story-panel");
    if (!root) return;
    const level = currentLevel();
    const story = {
      A: {
        title: "Level A story — Can the analysis be repeated over the same evidence?",
        narrative: "You are not creating a new incident. You are reusing one preserved case in read-only mode. The goal is to check whether the analysis, FOC, causal reconstruction, uncertainty assessment, hypothesis support, and executive summary remain stable when the same evidence is processed again.",
        success: `The repeated executions produce the same or equivalent ${infoTip("cpr")}, ${infoTip("weighted_cpr")}, uncertainty class, hypothesis support, and conclusion class.`,
        limits: "It cannot prove attack repeatability, trigger repeatability, acquisition repeatability, or environment reproducibility.",
        interpretation: `If ${infoTip("cpr")} and ${infoTip("weighted_cpr")} do not vary, the analytical pipeline is repeatable. If the result is degraded, the degradation is probably inherited from the base case.`,
      },
      B: {
        title: "Level B story — Can repeated incidents recover comparable forensic reconstructions?",
        narrative: "You keep the same scenario and repeat the incident under documented conditions. Each execution captures baseline noise, seals the ground truth, executes the automated attack, observes detection, selects a trigger, acquires and preserves evidence, runs forensic analysis, runs FOC, reconstructs causality, evaluates uncertainty, and generates a comparison profile.",
        success: "Different executions do not produce identical artifacts, but they recover comparable causal structures, evidence coverage, uncertainty classes, hypothesis support, and final conclusions.",
        limits: "This level still depends on controlled conditions, sensor consistency, and scenario discipline.",
        interpretation: "This is the main scientific level for forensic reconstruction comparability.",
      },
      C: {
        title: "Level C story — Can the platform reproduce the experiment after redeployment?",
        narrative: "You redeploy the environment and repeat the experiment. This includes infrastructure, tools, sensors, IDS/SIEM configuration, PLC/SCADA context, attack execution, acquisition, preservation, analysis, FOC, and reconstruction.",
        success: "After redeployment, the platform can still recover comparable forensic reconstructions.",
        limits: "This level introduces deployment and configuration variability. It is useful as complementary platform-level reproducibility evidence, but it should not be the only measure of forensic reconstruction quality.",
        interpretation: "A Level C success supports platform-level reproducibility, not only pipeline-level repeatability.",
      },
    }[level];
    root.innerHTML = `
      <div class="font-black text-cyan-300">${esc(story.title)}</div>
      <div class="mt-3"><span class="font-black">Narrative:</span> ${esc(story.narrative)}</div>
      <div class="mt-3"><span class="font-black">What success looks like:</span> ${story.success}</div>
      <div class="mt-3"><span class="font-black">${level === "B" ? "What this level proves" : "What this level cannot prove"}:</span> ${esc(story.limits)}</div>
      <div class="mt-3"><span class="font-black">Typical interpretation:</span> ${story.interpretation}</div>
    `;
  }

  function renderStoryline() {
    const root = byId("rm-storyline-panel");
    if (!root) return;
    const level = currentLevel();
    const campaign = state.selectedCampaignDetail?.campaign || selectedCampaign();
    const executions = state.selectedCampaignDetail?.executions || [];
    const profilesAvailable = executions.filter((item) => item.artifacts?.forensic_comparison_profile).length;
    const runningJob = state.selectedCampaignDetail?.running_job || null;
    const sourceReady = level === "A" ? !!currentSourceCaseId() : truthy(currentScenarioId());
    const stages = [
      {
        name: "Select level",
        status: level ? "completed" : "missing",
        explanation: "What kind of repetition are we creating?",
        artifact: "campaign_config.json",
        next: "Confirm whether the objective is Level A, B or C.",
        problem: "The methodological objective is still undefined.",
        fix: "Select one evaluation level before creating the campaign.",
      },
      {
        name: "Link source or scenario",
        status: sourceReady ? "completed" : "missing",
        explanation: "What evidence or scenario will this campaign use?",
        artifact: level === "A" ? "linked base case reference" : "scenario_id",
        next: level === "A" ? "Select the preserved base case." : "Provide or confirm the scenario context.",
        problem: "The campaign does not yet know what source or scenario to use.",
        fix: level === "A" ? "Select a preserved case." : "Provide a valid scenario_id before execution.",
      },
      {
        name: "Seal or reuse ground truth",
        status: level === "A" ? (currentSourceCaseId() ? "completed_with_degradation" : "missing") : (sourceReady ? "completed" : "missing"),
        explanation: "What is the expected causal truth before analysis?",
        artifact: "ground_truth_seal.json",
        next: "Review whether the ground truth will be reused or sealed before execution.",
        problem: "Without a defined ground truth context, later causal comparison is weaker.",
        fix: level === "A" ? "Reuse the base-case expectation or verify the linked case context." : "Keep ground truth sealing enabled.",
      },
      {
        name: "Prepare execution workspace",
        status: campaign ? "completed" : "not_started",
        explanation: "Where will this execution store its artifacts?",
        artifact: "execution workspace",
        next: "Create the campaign if it does not exist yet.",
        problem: "No isolated experimental workspace exists yet.",
        fix: "Create the campaign to allocate campaign and execution directories.",
      },
      {
        name: "Run execution",
        status: runningJob ? "running" : (executions.length ? "completed_with_degradation" : "not_started"),
        explanation: "What process will be executed depending on Level A, B or C?",
        artifact: "execution_manifest.json",
        next: executions.length ? "Inspect the generated execution and its warnings." : "Start the campaign or run the next execution.",
        problem: "No execution exists yet, or a job is still in progress.",
        fix: runningJob ? "Wait until the current job finishes." : "Launch the first execution.",
      },
      {
        name: "Generate comparison profile",
        status: profilesAvailable ? "completed" : (executions.length ? "partial" : "not_started"),
        explanation: "What normalized profile will be used later for comparison?",
        artifact: "forensic_comparison_profile.json",
        next: profilesAvailable ? "Generate another execution or open Comparability View." : "Inspect the execution workspace and regenerate if the profile is missing.",
        problem: "Without a comparison profile, the execution cannot participate in comparability analysis.",
        fix: "Open the execution workspace and verify the generated scientific profiles.",
      },
      {
        name: "Open Comparability View",
        status: profilesAvailable >= 2 ? "completed" : "not_started",
        explanation: "How will the generated executions be evaluated?",
        artifact: "comparability_result.json",
        next: profilesAvailable >= 2 ? "Compare the generated executions." : "Generate at least two executions first.",
        problem: "Comparability cannot be decided with fewer than two valid profiles.",
        fix: "Generate at least two executions with forensic_comparison_profile.json.",
      },
    ];
    root.innerHTML = stages.map((item, idx) => `
      <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4 ${idx ? "mt-3" : ""}">
        <div class="flex items-center justify-between gap-3">
          <div class="font-black">${idx + 1}. ${esc(item.name)}</div>
          <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status))}</div>
        </div>
        <div class="mt-3"><span class="font-black">Plain-language explanation:</span> ${esc(item.explanation)}</div>
        <div class="mt-2"><span class="font-black">Technical artifact:</span> ${esc(item.artifact)}</div>
        <div class="mt-2"><span class="font-black">Next action:</span> ${esc(item.next)}</div>
        <div class="mt-2"><span class="font-black">Possible problem:</span> ${esc(item.problem)}</div>
        <div class="mt-2"><span class="font-black">How to fix it:</span> ${esc(item.fix)}</div>
      </div>
    `).join("");
  }

  function renderCampaignStoryPanel() {
    const root = byId("rm-campaign-story-panel");
    if (!root) return;
    const detail = state.selectedCampaignDetail;
    const campaign = detail?.campaign || selectedCampaign();
    if (!campaign) {
      root.innerHTML = `
        <div class="font-black text-cyan-300">Beginner Summary</div>
        <div class="mt-3">Create or select a campaign first. Then generate at least one execution. After at least two executions have generated forensic comparison profiles, open the Comparability View.</div>
        <div class="mt-4 font-black text-cyan-300">Expert Summary</div>
        <div class="mt-3">This module creates isolated execution workspaces and normalizes them into forensic_comparison_profile.json artifacts. No execution-to-execution judgement is performed here.</div>
      `;
      return;
    }
    const execs = detail?.executions || [];
    const executionDetails = detail?.executionDetails || [];
    const profilesAvailable = executionDetails.length
      ? executionDetails.filter((item) => hasComparisonProfile(item)).length
      : execs.filter((item) => item.artifacts?.forensic_comparison_profile).length;
    const level = String(campaign.level || "A").toUpperCase();
    root.innerHTML = `
      <div class="font-black text-cyan-300">Beginner Summary</div>
      <div class="mt-3">This campaign has ${execs.length} execution(s), and ${profilesAvailable} of them have forensic comparison profiles available for comparability analysis. This view is preparing the comparison material for ${esc(LEVEL_META[level].long)} and does not judge comparability by itself.</div>
      <div class="mt-4 font-black text-cyan-300">Expert Summary</div>
      <div class="mt-3">Campaign <span class="mono">${esc(campaign.campaign_id)}</span> is scoped to ${esc(LEVEL_META[level].long)} with source mode <span class="mono">${esc(sourceModeLabel(campaign.source_mode || LEVEL_META[level].sourceMode))}</span>. The current objective is to generate stable execution workspaces, manifests, seals, noise profiles when applicable, and <span class="mono">forensic_comparison_profile.json</span> for later execution-to-execution evaluation.</div>
    `;
  }

  function renderCampaignResourceActions(campaign, executionDetails) {
    const root = byId("campaign-resource-actions");
    if (!root) return;
    const level = String(campaign?.level || "").toUpperCase();
    if (!campaign || !["B", "C"].includes(level)) {
      root.classList.add("hidden");
      root.innerHTML = "";
      return;
    }
    const generatedCases = (executionDetails || []).filter((item) => executionCleanupState(item).canDelete);
    root.classList.remove("hidden");
    root.innerHTML = `
      <div class="text-[11px] tracking-[0.28em] uppercase text-slate-400 font-black">Resource Release</div>
      <h3 class="text-xl font-black mt-2">Generated Case Cleanup</h3>
      <div class="mt-3 text-slate-300">Because only one heavy forensic case may be kept at a time, this module can delete heavy generated-case artifacts while preserving scientific comparison memory.</div>
      <div class="mt-3 text-slate-400">Deleting a generated case must delete only heavy artifacts, not scientific comparison memory.</div>
      <div class="mt-4 text-sm ${generatedCases.length ? "text-cyan-300" : "text-amber-300"}">${generatedCases.length ? `${generatedCases.length} generated case(s) are currently eligible for cleanup actions in the execution registry below.` : "No generated heavy case is currently available for cleanup in this campaign."}</div>
      ${generatedCases.length ? `
        <div class="space-y-3 mt-4">
          ${generatedCases.map((item) => `
            <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
              <div class="flex items-start justify-between gap-3">
                <div>
                  <div class="font-black">Execution <span class="mono">${esc(item.execution_id)}</span></div>
                  <div class="text-slate-400 mt-2">Generated case: <span class="mono">${esc(item.run_case_id || "not_available")}</span></div>
                </div>
                <button type="button" class="btn-danger rounded-2xl px-4 py-3 text-xs font-extrabold tracking-[0.16em] uppercase generated-case-cleanup-btn" data-campaign-id="${esc(campaign.campaign_id)}" data-execution-id="${esc(item.execution_id)}" data-case-id="${esc(item.run_case_id || "")}" data-origin="campaign-panel">Delete Generated Case Artifacts</button>
              </div>
              <div id="cleanup-status-${esc(item.execution_id)}-campaign-panel" class="mt-3 text-sm text-slate-300"></div>
            </div>
          `).join("")}
        </div>
      ` : ""}
    `;
    bindGeneratedCaseCleanupButtons();
  }

  function renderScenarioRedeploymentActions() {
    const root = byId("scenario-redeployment-actions");
    if (!root) return;
    const builderLevel = currentLevel();
    const selected = currentScenarioActionCampaign();
    const visible = builderLevel === "C" || !!selected;
    if (!visible) {
      root.classList.add("hidden");
      root.innerHTML = "";
      return;
    }
    const scenarioId = (selected && (selected.scenario_id || state.selectedCampaignDetail?.config?.scenario_id)) || currentScenarioId() || state.proposal?.scenario_id || "not_available";
    root.classList.remove("hidden");
    root.innerHTML = `
      <div class="text-[11px] tracking-[0.28em] uppercase text-slate-400 font-black">Scenario Redeployment Actions</div>
      <h3 class="text-xl font-black mt-2">Destroy Full Scenario For Level C Redeployment</h3>
      <div class="mt-3 text-slate-300">This action destroys the active IT/OT scenario before a Level C redeployment. It does not delete scientific comparison memory, scenario cards, result cards, comparison profiles, registries, or reconstruction blueprints.</div>
      <div class="mt-3 text-slate-400">Destroying a scenario must not delete the scientific memory needed to compare scenarios, cases, executions, or results.</div>
      <div class="mt-4"><span class="font-black">Scenario context:</span> <span class="mono">${esc(scenarioId)}</span></div>
      <div class="mt-5 flex gap-3 flex-wrap items-center">
        <button type="button" id="destroy-scenario-btn" class="btn-danger rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Destroy Full Scenario For Level C Redeployment</button>
      </div>
      <div id="destroy-scenario-result" class="mt-4 text-sm text-slate-300"></div>
    `;
    byId("destroy-scenario-btn")?.addEventListener("click", () => validateAndPromptScenarioDestroy(scenarioId, selected?.campaign_id || state.selectedCampaignId || null));
  }

  function executionCleanupState(item) {
    const level = String(item?.level || "").toUpperCase();
    if (!["B", "C"].includes(level)) {
      return { visible: false, canDelete: false, label: "Not applicable", reason: "Level A does not generate a new heavy forensic case." };
    }
    if (item?.cleanup_status === "completed" || item?.heavy_artifacts_retained === false) {
      return {
        visible: true,
        canDelete: false,
        label: "Already cleaned up",
        reason: "Heavy generated-case artifacts were already deleted or archived. Lightweight scientific comparison memory remains preserved.",
      };
    }
    if (item?.dry_run || !item?.run_case_id || String(item.run_case_id).startsWith("CASE-PLANNED-") || !item?.run_case_path) {
      return {
        visible: true,
        canDelete: false,
        label: "Not created yet",
        reason: "No heavy generated case exists yet for this execution.",
      };
    }
    return {
      visible: true,
      canDelete: true,
      label: item.run_case_id,
      reason: "A generated heavy forensic case exists and can be cleaned up after validating that lightweight scientific memory is complete.",
    };
  }

  function renderValidationList(checks) {
    const items = Array.isArray(checks) ? checks : [];
    if (!items.length) return '<div class="text-slate-400">No validation checklist is available.</div>';
    return `
      <div class="space-y-3 mt-4">
        ${items.map((item) => `
          <div class="rounded-2xl border ${item.status === "ok" ? "border-cyan-500/30 bg-cyan-500/5" : "border-amber-500/30 bg-amber-500/5"} p-4">
            <div class="flex items-start justify-between gap-3">
              <div class="font-black">${esc(titleCaseStatus(item.key || item.requirement || "requirement"))}</div>
              <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status || "unknown"))}</div>
            </div>
            <div class="mt-3"><span class="font-black">Why it matters:</span> ${esc(item.why_it_matters || "No explanation available.")}</div>
            <div class="mt-2"><span class="font-black">How to fix it:</span> ${esc(item.how_to_fix || "No fix guidance available.")}</div>
            <div class="mt-2"><span class="font-black">Can be auto-generated:</span> ${item.can_be_auto_generated ? "yes" : "no"}</div>
          </div>
        `).join("")}
      </div>
    `;
  }

  function setInlineActionResult(nodeId, html) {
    const node = byId(nodeId);
    if (node) node.innerHTML = html;
  }

  function renderCampaigns() {
    const root = byId("campaign-list");
    if (!root) return;
    if (!state.campaigns.length) {
      root.innerHTML = `
        <div class="glass-soft rounded-2xl p-4">
          <div class="font-black">No campaigns registered yet.</div>
          <div class="text-slate-400 mt-2">Create a campaign to start generating comparable forensic executions.</div>
        </div>
      `;
      return;
    }
    root.innerHTML = state.campaigns.map((item) => `
      <button type="button" data-campaign-id="${esc(item.campaign_id)}" class="campaign-select-btn w-full text-left glass-soft rounded-2xl p-4 hover:border-cyan-400/50 ${item.campaign_id === state.selectedCampaignId ? "ring-1 ring-cyan-400/60" : ""}">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="font-black">${esc(item.name || item.campaign_id)}</div>
            <div class="text-xs text-slate-400 mt-2">${esc(item.campaign_id)} · ${esc(item.level || "A")} · executions ${esc(item.execution_count || 0)}</div>
          </div>
          <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status))}</div>
        </div>
      </button>
    `).join("");
    root.querySelectorAll(".campaign-select-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        state.selectedCampaignId = btn.dataset.campaignId;
        renderCampaigns();
        await renderSelectedCampaign();
      });
    });
  }

  function renderSourceCases() {
    const select = byId("source-case-select");
    if (select) {
      const current = select.value;
      select.innerHTML = '<option value="">No linked case</option>' + state.sourceCases.map((item) => `
        <option value="${esc(item.case_id)}">${esc(item.case_id)} · ${esc(item.source_case_name || item.case_dir_name || item.path || "preserved case")}</option>
      `).join("");
      const preferred = state.currentCaseId || current;
      if ([...select.options].some((opt) => opt.value === preferred)) {
        select.value = preferred;
      }
    }
    const registerSelect = byId("register-case-select");
    if (registerSelect) {
      const current = registerSelect.value;
      registerSelect.innerHTML = '<option value="">Select a case…</option>' + state.sourceCases.map((item) => `
        <option value="${esc(item.case_id)}">${esc(item.case_id)} · ${esc(item.source_case_name || item.case_dir_name || item.path || "preserved case")}</option>
      `).join("");
      if ([...registerSelect.options].some((opt) => opt.value === current)) {
        registerSelect.value = current;
      }
    }
  }

  async function registerExistingCaseAsResultCard() {
    const resultNode = byId("register-case-result");
    const caseId = String(byId("register-case-select")?.value || "").trim();
    if (!resultNode) return;
    if (!caseId) {
      resultNode.innerHTML = '<div class="text-amber-300">Select a case before registering it as a result card.</div>';
      return;
    }
    resultNode.innerHTML = '<div class="text-slate-400">Registering case…</div>';
    try {
      const card = await getJson("/api/foc/experimentation/comparison-registry/register-case", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: caseId }),
      });
      resultNode.innerHTML = `
        <div class="text-cyan-300">This comparison uses lightweight forensic result profiles, not full duplicated cases.</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-3">
          <div><div class="text-xs text-slate-400">Result card</div><div class="font-black mt-1 mono">${esc(card.result_card_id)}</div></div>
          <div><div class="text-xs text-slate-400">Comparison family</div><div class="font-black mt-1 mono">${esc(card.comparison_family_id)}</div></div>
          <div><div class="text-xs text-slate-400">Original case</div><div class="font-black mt-1 mono">${esc(card.original_case_id)}</div></div>
          <div><div class="text-xs text-slate-400">Retention policy</div><div class="font-black mt-1">${esc(card.retention_policy)}</div></div>
        </div>
      `;
    } catch (err) {
      resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
    }
  }

  function renderMethodBasis(payload) {
    state.methodBasis = payload || { references: [] };
    const root = byId("method-basis-list");
    if (!root) return;
    const refs = state.methodBasis.references || [];
    const byIdRef = new Map(refs.map((item) => [item.id, item]));
    root.innerHTML = METHOD_GROUPS.map((group) => {
      const groupRefs = group.ids.map((id) => byIdRef.get(id)).filter(Boolean);
      return `
        <details class="glass-soft rounded-2xl p-4 helper-details">
          <summary class="flex items-center justify-between gap-3">
            <div>
              <div class="font-black">${esc(group.label)}</div>
              <div class="text-xs text-slate-400 mt-2">${esc(group.why)}</div>
            </div>
            <span class="help-chip">Reference Basis</span>
          </summary>
          <div class="mt-4 space-y-3">
            ${groupRefs.map((item) => `
              <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-3">
                <div class="font-black">${esc(item.title)}</div>
                <div class="text-xs text-slate-400 mt-2">${esc(item.why_applies || "")}</div>
                <div class="text-xs text-slate-500 mt-2">${esc((item.justifies || []).join(" · "))}</div>
                <div class="mt-2"><a class="text-cyan-300 underline" href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">Open official reference</a></div>
              </div>
            `).join("") || '<div class="text-slate-400">No reference loaded for this group.</div>'}
          </div>
        </details>
      `;
    }).join("");
  }

  function syncLevelButtons() {
    const level = currentLevel();
    document.querySelectorAll(".level-btn").forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.level === level);
    });
  }

  function syncStepTwoTitle() {
    const level = currentLevel();
    const title = byId("step-two-title");
    if (title) title.textContent = LEVEL_META[level]?.stepTwoTitle || "Select source or scenario";
  }

  // "Linked source case" is mandatory and visible only for Level A. For
  // Level B/C it is relocated into the Advanced Mode panel as an optional
  // reference case -- it copies defaults/thresholds only, it is never
  // reused as evidence, and it is not required to create the campaign.
  function syncLinkedCaseField() {
    const level = currentLevel();
    const field = byId("linked-case-field");
    const labelSpan = byId("linked-case-field-label");
    const helpDiv = byId("linked-case-field-help");
    const guidedGrid = byId("step-two-source-grid");
    const advancedGrid = byId("advanced-panel-grid");
    if (!field || !guidedGrid || !advancedGrid) return;
    if (level === "A") {
      if (field.parentElement !== guidedGrid) guidedGrid.insertBefore(field, guidedGrid.firstChild);
      if (labelSpan) labelSpan.textContent = "Linked source case";
      if (helpDiv) helpDiv.textContent = "Required. Level A reuses this preserved case in read-only mode and repeats analysis over the same evidence.";
    } else {
      if (field.parentElement !== advancedGrid) advancedGrid.appendChild(field);
      if (labelSpan) labelSpan.textContent = "Optional reference case";
      if (helpDiv) helpDiv.textContent = "Optional. This case is only used to copy defaults, thresholds, expected causal model, or comparison-family settings. It is not reused as evidence and is not required for Level B/C.";
    }
  }

  function syncNestedLevelAField() {
    const field = byId("nested-level-a-repetitions-field");
    const input = byId("nested-level-a-repetitions-input");
    if (!field || !input) return;
    const level = currentLevel();
    const show = level === "B";
    field.classList.toggle("hidden", !show);
    if (!show) {
      input.value = "";
      return;
    }
    if (!String(input.value || "").trim()) {
      input.value = String(
        state.selectedCampaignDetail?.config?.nested_level_a_repetitions
        || state.proposal?.nested_level_a_repetitions
        || state.proposal?.number_of_repetitions
        || byId("repetitions-input")?.value
        || 3
      );
    }
  }

  function renderLevelExplanation() {
    const panel = byId("level-explanation-panel");
    if (!panel) return;
    const explanation = state.proposal?.level_explanation;
    const level = currentLevel();
    const meta = LEVEL_META[level];
    if (!explanation || !meta) {
      panel.innerHTML = "No level explanation is currently available.";
      return;
    }
    panel.innerHTML = `
      <div class="font-black text-cyan-300">${esc(explanation.title || meta.long)}</div>
      <div class="mt-3"><span class="font-black">Meaning:</span> ${esc(explanation.meaning || meta.purpose)}</div>
      ${explanation.does_not_do ? `
        <div class="mt-3"><span class="font-black">What it does not do:</span></div>
        <ul class="mt-2 list-disc pl-5 text-slate-400 space-y-1">${explanation.does_not_do.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      ` : ""}
      ${explanation.used_for ? `<div class="mt-3"><span class="font-black">Used for:</span> ${esc(explanation.used_for)}</div>` : ""}
      ${explanation.required_input ? `<div class="mt-3"><span class="font-black">Required input:</span> ${esc(explanation.required_input)}</div>` : ""}
      ${explanation.important ? `<div class="mt-3 text-amber-300"><span class="font-black">Important:</span> ${esc(explanation.important)}</div>` : ""}
      ${explanation.source_note ? `<div class="mt-3 text-amber-300"><span class="font-black">Source note:</span> ${esc(explanation.source_note)}</div>` : ""}
      <div class="mt-3"><span class="font-black">Automatically generated:</span></div>
      <ul class="mt-2 list-disc pl-5 text-slate-400 space-y-1">${(explanation.auto_generated || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
    `;
    syncStepTwoTitle();
    syncLinkedCaseField();
    syncScenarioIdHelp();
    syncAttackProfileField();
    syncNestedLevelAField();
    renderLevelStory();
    renderStoryline();
    renderCampaignStoryPanel();
    renderRecommendedExperiment();
    renderPreCreateNote();
    renderScenarioRedeploymentActions();
  }

  function syncScenarioIdHelp() {
    const help = byId("scenario-id-help");
    if (!help) return;
    const level = currentLevel();
    if (level === "A") {
      help.textContent = "The identifier of the scenario used by the campaign. If possible, this is extracted automatically from the linked case or preserved FOC artifacts.";
    } else {
      help.textContent = "Scenario ID identifies the active deployed scenario where the new incident execution will run. Level B requires a deployed scenario because each execution launches a new attack, waits for detection, creates a new forensic case, preserves evidence, and generates a new comparison profile.";
    }
  }

  function renderSourceSummary() {
    const panel = byId("source-summary-panel");
    if (!panel) return;
    const level = currentLevel();
    const caseId = currentSourceCaseId();
    const scenarioId = currentScenarioId() || "not_available";
    const sourceMode = LEVEL_META[level]?.sourceMode || state.proposal?.source_mode || "linked_existing_case";
    const sourceCase = state.sourceCases.find((item) => item.case_id === caseId);
    const cfg = state.proposal || {};
    panel.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Source mode</div>
          <div class="font-black mt-2">${esc(sourceModeLabel(sourceMode))}</div>
          <div class="text-slate-400 mt-2">${esc(sourceModeExplanation(sourceMode))}</div>
        </div>
        <div>
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Scenario and source context</div>
          ${level === "A" ? `<div class="mt-2"><span class="font-black">Linked source case:</span> ${esc(caseId || "not_selected")}</div>` : ""}
          <div class="mt-2"><span class="font-black">Scenario ID:</span> ${esc(scenarioId)}</div>
          ${!truthy(scenarioId) ? `<div class="mt-2 text-amber-300">Scenario ID could not be extracted automatically. For Level A this is allowed, but the comparison profile will be weaker. For Level B and Level C, scenario ID should be provided before execution.</div>` : ""}
          ${level === "A" && sourceCase ? `<div class="mt-2 text-slate-400">Selected case path: <span class="mono">${esc(sourceCase.path || sourceCase.case_path || "not_available")}</span></div>` : ""}
          ${level !== "A" && caseId && sourceCase ? `
            <div class="mt-2"><span class="font-black">Scenario context source:</span> <span class="mono">${esc(sourceCase.path || sourceCase.case_path || "not_available")}</span></div>
            <div class="mt-2 text-slate-400">Scenario context was inferred from a previous case, but this case will not be reused as evidence. Level ${esc(level)} will create a new forensic case for each execution.</div>
          ` : ""}
          ${level !== "A" && !caseId ? `<div class="mt-2 text-slate-400">No optional reference case selected. This is valid for Level ${esc(level)}.</div>` : ""}
        </div>
      </div>
      ${level !== "A" ? `
        <div class="mt-5">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Deployed scenario and incident profile</div>
          <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-3">
            <div><div class="text-xs text-slate-400">Active deployed scenario</div><div class="font-black mt-1">${esc(truthy(scenarioId) ? scenarioId : "Not selected yet")}</div></div>
            <div><div class="text-xs text-slate-400">Scenario health</div><div class="font-black mt-1">Not available in this phase</div></div>
            <div>
              <div class="text-xs text-slate-400">Detection policy</div>
              <div class="font-black mt-1 mono">${esc(cfg.detection_policy_id || "wazuh_suricata_alert_ingestion_v1")}</div>
              <div class="text-xs text-slate-500 mt-1">Which detection source is listened to and which alert is expected.</div>
            </div>
            <div>
              <div class="text-xs text-slate-400">Trigger policy</div>
              <div class="font-black mt-1 mono">${esc(cfg.trigger_policy_id || "highest_severity_alert_v1")}</div>
              <div class="text-xs text-slate-500 mt-1">Which condition fires forensic acquisition.</div>
            </div>
            <div>
              <div class="text-xs text-slate-400">Acquisition policy</div>
              <div class="font-black mt-1 mono">${esc(cfg.acquisition_profile_id || "default_kolla_lime_tshark_v1")}</div>
              <div class="text-xs text-slate-500 mt-1">Which evidence is preserved after the trigger fires.</div>
            </div>
            <div><div class="text-xs text-slate-400">New case creation policy</div><div class="font-black mt-1">A new forensic case will be created for every execution after detection-triggered acquisition.</div></div>
          </div>
        </div>
      ` : ""}
      ${level === "A" && !caseId ? `<div class="mt-4 text-red-300">A linked source case is required for Level A. Select a preserved case or open the manager from the Scientific Lifecycle dashboard.</div>` : ""}
    `;
    renderStoryline();
  }

  function syncRecommendUseButtonState() {
    const btn = byId("recommend-use-btn");
    const reason = byId("recommend-use-disabled-reason");
    if (!btn) return;
    const hasRecommendation = !!state.lastRecommendation?.has_recommendation;
    btn.disabled = !hasRecommendation;
    btn.classList.toggle("opacity-50", !hasRecommendation);
    btn.classList.toggle("cursor-not-allowed", !hasRecommendation);
    if (reason) {
      reason.textContent = hasRecommendation ? "" : "No previous comparable result exists for this scenario family.";
    }
  }

  async function renderRecommendedExperiment() {
    const panel = byId("recommended-experiment-panel");
    const content = byId("recommended-experiment-content");
    const choiceNode = byId("recommended-experiment-choice");
    if (!panel || !content) return;
    const level = currentLevel();
    const scenarioId = currentScenarioId();
    if (level === "A" || !truthy(scenarioId)) {
      panel.classList.add("hidden");
      state.lastRecommendation = null;
      syncRecommendUseButtonState();
      return;
    }
    panel.classList.remove("hidden");
    content.innerHTML = '<div class="text-slate-400">Checking the comparison registry for previous comparable results…</div>';
    if (choiceNode) choiceNode.innerHTML = "";
    let payload;
    try {
      const attackProfileId = String(byId("attack-profile-select")?.value || "").trim();
      const triggerPolicy = state.proposal?.trigger_policy_id || "highest_severity_alert_v1";
      const acquisitionProfileId = state.proposal?.acquisition_profile_id || "default_kolla_lime_tshark_v1";
      payload = await getJson(`/api/foc/experimentation/comparison-registry/recommend?scenario_id=${encodeURIComponent(scenarioId)}&level=${encodeURIComponent(level)}&attack_profile_id=${encodeURIComponent(attackProfileId)}&trigger_policy=${encodeURIComponent(triggerPolicy)}&acquisition_profile_id=${encodeURIComponent(acquisitionProfileId)}`);
    } catch (err) {
      content.innerHTML = `<div class="text-amber-300">Could not query the comparison registry: ${esc(err.message)}</div>`;
      state.lastRecommendation = null;
      syncRecommendUseButtonState();
      return;
    }
    state.lastRecommendation = payload;
    syncRecommendUseButtonState();
    if (!payload.has_recommendation) {
      content.innerHTML = `<div class="text-slate-300">No previous comparable result was found. You can start a new comparison family. Future executions using the same scenario, attack profile, trigger policy, acquisition policy, and FOC profile will be directly comparable with this one.</div>`;
      state.recommendedFamily = null;
      return;
    }
    const rec = payload.recommended;
    content.innerHTML = `
      <div>${esc(payload.message)}</div>
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
        <div><div class="text-xs text-slate-400">Previous result card</div><div class="font-black mt-1 mono">${esc(rec.result_card_id)}</div></div>
        <div><div class="text-xs text-slate-400">Previous case</div><div class="font-black mt-1 mono">${esc(rec.original_case_id || rec.case_id || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Previous campaign</div><div class="font-black mt-1 mono">${esc(rec.campaign_id || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Comparison family</div><div class="font-black mt-1 mono">${esc(rec.comparison_family_id)}</div></div>
        <div><div class="text-xs text-slate-400">Scenario fingerprint</div><div class="font-black mt-1 mono">${esc(rec.scenario_fingerprint)}</div></div>
        <div><div class="text-xs text-slate-400">Attack profile</div><div class="font-black mt-1 mono">${esc(rec.attack_profile_id)}</div></div>
        <div><div class="text-xs text-slate-400">MITRE technique</div><div class="font-black mt-1 mono">${esc(rec.mitre_technique || rec.mitre_technique_id || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Attack script</div><div class="font-black mt-1 mono break-all">${esc(rec.attack_script)}</div></div>
        <div><div class="text-xs text-slate-400">Attack script SHA-256</div><div class="font-black mt-1 mono break-all">${esc(rec.attack_script_sha256)}</div></div>
        <div><div class="text-xs text-slate-400">Attack parameters hash</div><div class="font-black mt-1 mono break-all">${esc(rec.attack_parameters_hash)}</div></div>
        <div><div class="text-xs text-slate-400">Expected causal edges</div><div class="font-black mt-1">${esc((rec.expected_causal_edges || []).length)}</div></div>
        <div><div class="text-xs text-slate-400">Trigger policy</div><div class="font-black mt-1 mono">${esc(rec.trigger_policy_id || rec.trigger_policy || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Acquisition profile</div><div class="font-black mt-1 mono">${esc(rec.acquisition_profile_id)}</div></div>
        <div><div class="text-xs text-slate-400">Analysis profile</div><div class="font-black mt-1 mono">${esc(rec.analysis_profile_id)}</div></div>
        <div><div class="text-xs text-slate-400">FOC profile</div><div class="font-black mt-1 mono">${esc(rec.foc_profile_id)}</div></div>
        <div><div class="text-xs text-slate-400">Reason</div><div class="font-black mt-1">This matches the saved comparison family used by the previous forensic result.</div></div>
      </div>
    `;
  }

  function bindRecommendedExperimentButtons() {
    byId("recommend-use-btn")?.addEventListener("click", async () => {
      const rec = state.lastRecommendation?.recommended;
      const choiceNode = byId("recommended-experiment-choice");
      if (!rec) {
        if (choiceNode) choiceNode.innerHTML = '<div class="text-amber-300">No recommendation is available yet.</div>';
        return;
      }
      state.recommendedFamily = rec;
      const select = byId("attack-profile-select");
      if (select && rec.attack_profile_id && [...select.options].some((opt) => opt.value === rec.attack_profile_id)) {
        select.value = rec.attack_profile_id;
        renderAttackProfileDetail();
      }
      updateCampaignNameFromSelection();
      await refreshProposalAndPreflight({ force: false });
      if (choiceNode) choiceNode.innerHTML = '<div class="text-cyan-300">To compare with this previous result, use this attack profile.</div>';
    });
    byId("recommend-new-family-btn")?.addEventListener("click", async () => {
      state.recommendedFamily = null;
      const choiceNode = byId("recommended-experiment-choice");
      if (choiceNode) choiceNode.innerHTML = '<div class="text-slate-300">This execution will create a new comparison family. It can be compared with future executions using the same scenario, attack profile, trigger policy, acquisition profile, and FOC profile.</div>';
      await refreshProposalAndPreflight({ force: false });
    });
  }

  function renderGuidedDefaults() {
    const panel = byId("guided-defaults-panel");
    if (!panel) return;
    const p = state.proposal || {};
    const level = currentLevel();
    panel.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Default repetitions</div><div class="font-black mt-2">${esc(p.number_of_repetitions ?? "not_available")}</div></div>
        ${level === "B" ? `<div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Nested Level A repetitions</div><div class="font-black mt-2">${esc(p.nested_level_a_repetitions ?? p.number_of_repetitions ?? "not_available")}</div></div>` : ""}
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Baseline threshold</div><div class="font-black mt-2">${esc(p.baseline_threshold ?? "0.15")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Delta WCPR allowed</div><div class="font-black mt-2">${esc(p.delta_wcpr_allowed ?? "0.10")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Baseline window</div><div class="font-black mt-2">${esc(p.baseline_window_seconds ?? "60")}s</div></div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div><span class="font-black">Retention policy:</span> ${esc(p.retention_policy || "not_available")}</div>
        <div><span class="font-black">Dry-run default:</span> ${p.dry_run_default ? "yes" : "no"}</div>
      </div>
      <div class="mt-4"><span class="font-black">Ground truth seal:</span> ${esc(p.ground_truth_seal_mode || LEVEL_META[level]?.groundTruthLabel || "not_available")}</div>
      <div class="mt-2"><span class="font-black">Comparison profile after each run:</span> ${p.comparison_profile_after_each_run ? "enabled by default" : "disabled"}</div>
      <div class="mt-2 text-slate-400">${esc(p.methodological_notes || "")}</div>
    `;
  }

  const OPERATIONAL_FLOW = {
    B: [
      "Validate deployed scenario",
      "Capture baseline noise",
      "Seal ground truth before attack",
      "Launch selected automated attack",
      "Wait for detection",
      "Evaluate severity and forensic recommendation",
      "Select trigger",
      "Create new forensic case",
      "Run acquisition",
      "Preserve evidence",
      "Run multilayer analysis",
      "Run FOC and causal reconstruction",
      "Generate executive lifecycle outputs",
      "Generate forensic comparison profile",
      "Register forensic result card",
    ],
    C: [
      "Redeploy scenario and environment",
      "Validate deployed scenario",
      "Capture baseline noise",
      "Seal ground truth before attack",
      "Launch selected automated attack",
      "Wait for detection",
      "Evaluate severity and forensic recommendation",
      "Select trigger",
      "Create new forensic case",
      "Run acquisition",
      "Preserve evidence",
      "Run multilayer analysis",
      "Run FOC and causal reconstruction",
      "Generate executive lifecycle outputs",
      "Generate forensic comparison profile",
      "Register forensic result card",
    ],
  };

  function renderExecutionPlan() {
    const panel = byId("execution-plan-panel");
    if (!panel) return;
    const level = currentLevel();
    const explanation = state.proposal?.level_explanation || {};
    const meta = LEVEL_META[level];
    const sourceMode = LEVEL_META[level]?.sourceMode || "linked_existing_case";
    const flow = OPERATIONAL_FLOW[level];
    panel.innerHTML = `
      <div class="font-black text-cyan-300">${esc(meta?.long || `Level ${level}`)}</div>
      <div class="mt-3">${esc(meta?.purpose || explanation.meaning || "No execution-plan summary is currently available.")}</div>
      <div class="mt-4"><span class="font-black">Source mode:</span> ${esc(sourceModeLabel(sourceMode))}</div>
      <div class="mt-2"><span class="font-black">What will be generated automatically:</span></div>
      <ul class="mt-2 list-disc pl-5 text-slate-400 space-y-1">${(explanation.auto_generated || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      ${meta?.notExecuted?.length ? `
        <div class="mt-4"><span class="font-black">What will not be executed:</span></div>
        <ul class="mt-2 list-disc pl-5 text-slate-400 space-y-1">${meta.notExecuted.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      ` : ""}
      ${flow ? `
        <div class="mt-4"><span class="font-black">Operational flow for each Level ${esc(level)} execution:</span></div>
        <ol class="mt-2 list-decimal pl-5 text-slate-300 space-y-1">${flow.map((item) => `<li>${esc(item)}</li>`).join("")}</ol>
      ` : ""}
      <div class="mt-4 text-slate-400">The generated artifacts will later be consumed by the Forensic Reconstruction Comparability View, especially <span class="mono">forensic_comparison_profile.json</span>.</div>
    `;
    renderStoryline();
  }

  function renderPreCreateNote() {
    const note = byId("pre-create-note");
    if (!note) return;
    const level = currentLevel();
    const blockedReason = builderCreateBlockedReason();
    if (blockedReason) {
      note.innerHTML = `<div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">${esc(blockedReason)}</div>`;
      return;
    }
    if (level === "A") {
      note.innerHTML = "";
      return;
    }
    note.innerHTML = `<div class="rounded-2xl border border-cyan-500/30 bg-cyan-500/5 p-4 text-cyan-200">This Level ${esc(level)} campaign will not reuse an old forensic case. It will create a new forensic case for each execution after attack detection and forensic acquisition.</div>`;
  }

  function renderPreflight(payload) {
    state.preflight = payload || null;
    const root = byId("preflight-panel");
    if (!root) return;
    if (!payload) {
      root.innerHTML = "Pre-flight validation is not available.";
      return;
    }
    root.innerHTML = `
      <div class="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <div class="font-black text-cyan-300">Pre-flight checklist</div>
          <div class="text-slate-400 mt-2">Review required inputs before creating the campaign. Missing requirements are not hidden.</div>
        </div>
        <div class="text-sm">
          <span class="font-black ${payload.ready ? "text-cyan-300" : "text-amber-300"}">${payload.ready ? "Ready" : "Needs review"}</span>
          <span class="text-slate-400 ml-2">ok ${esc(payload.ok_count)} · missing ${esc(payload.missing_count)}</span>
        </div>
      </div>
      ${(payload.info_notes || []).length ? `
        <div class="mt-4 space-y-2">
          ${payload.info_notes.map((item) => `<div class="text-cyan-300">${esc(item)}</div>`).join("")}
        </div>
      ` : ""}
      <div class="space-y-3 mt-5">
        ${(payload.items || []).map((item) => `
          <div class="rounded-2xl border ${item.status === "ok" ? "border-cyan-500/30 bg-cyan-500/5" : "border-amber-500/30 bg-amber-500/5"} p-4">
            <div class="flex items-start justify-between gap-3">
              <div class="font-black">${esc(titleCaseStatus(item.requirement))}</div>
              <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status))}</div>
            </div>
            <div class="mt-3"><span class="font-black">Why it matters:</span> ${esc(item.why_it_matters)}</div>
            <div class="mt-2"><span class="font-black">How to fix it:</span> ${esc(item.how_to_fix)}</div>
            <div class="mt-2"><span class="font-black">Can be auto-generated:</span> ${item.can_be_auto_generated ? "yes" : "no"}</div>
          </div>
        `).join("")}
      </div>
    `;
    applyBuilderCreateState();
    renderStoryline();
  }

  function applyBuilderCreateState() {
    const btn = byId("campaign-create-btn");
    if (!btn) return;
    const blockedReason = builderCreateBlockedReason();
    const disabled = !!blockedReason;
    btn.disabled = disabled;
    btn.classList.toggle("opacity-50", disabled);
    btn.classList.toggle("cursor-not-allowed", disabled);
    btn.title = blockedReason;
    renderPreCreateNote();
  }

  async function loadProposal(options) {
    const payload = await getJson("/api/foc/experimentation/campaigns/proposal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: options?.caseId ?? (currentSourceCaseId() || state.currentCaseId || ""),
        level: options?.level ?? currentLevel(),
        scenario_id: options?.scenarioId ?? currentScenarioId(),
      }),
    });
    state.proposal = payload;
    return payload;
  }

  function applyProposal(proposal, options) {
    if (!proposal) return;
    const force = !!(options && options.force);
    const level = String(proposal.default_level || "A").toUpperCase();
    byId("level-hidden").value = level;
    syncLevelButtons();
    setFieldValue("campaign-name-input", proposal.campaign_name, { force });
    setFieldValue("scenario-id-input", proposal.scenario_id === "not_available" ? "" : proposal.scenario_id, { force });
    setFieldValue("repetitions-input", proposal.number_of_repetitions, { force });
    setFieldValue("nested-level-a-repetitions-input", proposal.nested_level_a_repetitions ?? proposal.number_of_repetitions, { force });
    setFieldValue("notes-input", proposal.methodological_notes, { force });
    setFieldValue("baseline-threshold-input", proposal.baseline_threshold, { force });
    setFieldValue("delta-wcpr-input", proposal.delta_wcpr_allowed, { force });
    setFieldValue("baseline-window-input", proposal.baseline_window_seconds, { force });
    setFieldValue("description-input", proposal.methodological_notes, { force });
    if (proposal.linked_source_case) {
      setFieldValue("source-case-select", proposal.linked_source_case, { force });
    }
    renderLevelExplanation();
    renderSourceSummary();
    renderGuidedDefaults();
    renderExecutionPlan();
    updateCampaignNameFromSelection();
    renderBuilderSelectedCampaignNote();
    applyBuilderCreateState();
  }

  function buildFormPayload() {
    const level = currentLevel();
    const baseCaseId = currentSourceCaseId();
    return {
      level,
      name: String(byId("campaign-name-input")?.value || "").trim() || state.proposal?.campaign_name || `Level ${level} Campaign`,
      description: String(byId("description-input")?.value || "").trim() || String(byId("notes-input")?.value || "").trim(),
      notes: String(byId("notes-input")?.value || "").trim(),
      scenario_id: String(byId("scenario-id-input")?.value || "").trim() || "not_available",
      base_case_id: baseCaseId || undefined,
      run_case_id: baseCaseId || undefined,
      baseline_noise_threshold: Number(byId("baseline-threshold-input")?.value || state.proposal?.baseline_threshold || 0.15),
      baseline_window_seconds: Number(byId("baseline-window-input")?.value || state.proposal?.baseline_window_seconds || 60),
      delta_wcpr_allowed: Number(byId("delta-wcpr-input")?.value || state.proposal?.delta_wcpr_allowed || 0.10),
      repetitions: Number(byId("repetitions-input")?.value || state.proposal?.number_of_repetitions || 3),
      nested_level_a_repetitions: level === "B"
        ? Number(
          byId("nested-level-a-repetitions-input")?.value
          || state.selectedCampaignDetail?.config?.nested_level_a_repetitions
          || state.proposal?.nested_level_a_repetitions
          || byId("repetitions-input")?.value
          || state.proposal?.number_of_repetitions
          || 3
        )
        : undefined,
      source_mode: LEVEL_META[level]?.sourceMode,
      requested_comparison_family_id: state.recommendedFamily?.comparison_family_id || undefined,
      attack_id: String(byId("attack-profile-select")?.value || "").trim() || state.recommendedFamily?.attack_profile_id || undefined,
      trigger_policy_id: state.proposal?.trigger_policy_id || "highest_severity_alert_v1",
      acquisition_profile_id: state.proposal?.acquisition_profile_id || "default_kolla_lime_tshark_v1",
      retention_policy: state.proposal?.retention_policy || (level === "A" ? "original_case_retained" : "profiles_only_after_archive"),
      dry_run: level !== "A",
    };
  }

  async function refreshProposalAndPreflight(options) {
    const proposal = await loadProposal(options);
    applyProposal(proposal, { force: !!(options && options.force) });
    const preflight = await getJson("/api/foc/experimentation/campaigns/preflight", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildFormPayload()),
    });
    renderPreflight(preflight);
  }

  async function getExecutionDetail(executionId) {
    if (state.executionCache.has(executionId)) return state.executionCache.get(executionId);
    const payload = await getJson(`/api/foc/experimentation/executions/${encodeURIComponent(executionId)}`);
    state.executionCache.set(executionId, payload);
    return payload;
  }

  function hasComparisonProfile(execution) {
    return !!(execution && execution.artifacts && execution.artifacts.forensic_comparison_profile);
  }

  async function renderSelectedCampaign() {
    const root = byId("campaign-detail");
    const execRoot = byId("execution-list");
    const execNote = byId("execution-registry-note");
    const jobRoot = byId("job-panel");
    if (!root || !execRoot || !execNote || !jobRoot) return;
    const selected = selectedCampaign();
    if (!selected) {
      root.textContent = "Select a campaign to inspect its configuration, execution list, and job activity.";
      execRoot.innerHTML = "No campaign selected.";
      execNote.textContent = "";
      applyCampaignActionState(null, null);
      renderCampaignResourceActions(null, []);
      renderScenarioRedeploymentActions();
      renderBuilderSelectedCampaignNote();
      if (!state.activeJobId) renderJob(null);
      return;
    }
    root.innerHTML = '<div class="text-slate-400">Loading campaign detail…</div>';
    execRoot.innerHTML = '<div class="text-slate-400">Loading execution registry…</div>';
    const payload = await getJson(`/api/foc/experimentation/campaigns/${encodeURIComponent(selected.campaign_id)}`);
    state.selectedCampaignDetail = payload;
    const campaign = payload.campaign || selected;
    state.campaigns = state.campaigns.map((item) => item.campaign_id === campaign.campaign_id ? { ...item, ...campaign } : item);
    renderCampaigns();
    const cfg = payload.config || {};
    const execs = payload.executions || [];
    const level = String(campaign.level || cfg.level || "A").toUpperCase();
    const meta = LEVEL_META[level] || LEVEL_META.A;
    const sourceMode = campaign.source_mode || meta.sourceMode;
    const executionDetails = await Promise.all(execs.map((item) => getExecutionDetail(item.execution_id).catch(() => null)));
    state.selectedCampaignDetail.executionDetails = executionDetails.filter(Boolean);
    const comparableCount = executionDetails.filter((item) => hasComparisonProfile(item)).length;
    const runningJob = payload.running_job || null;
    const scenarioId = cfg.scenario_id || campaign.scenario_id || "not_available";
    const technicalFailures = campaign.technical_failures || [];
    const scientificLimitations = campaign.scientific_limitations || [];
    const technicalOutcome = campaign.technical_outcome || (campaign.status === "completed_with_failures" ? "completed_with_failures" : "completed");
    const scientificOutcome = campaign.scientific_outcome || (campaign.status === "completed_with_degradation" ? "completed_with_degradation" : "completed");
    const comparisonReadiness = campaign.comparison_readiness || (comparableCount >= 2 ? "ready" : (comparableCount === 1 ? "partial" : "insufficient_data"));
    root.innerHTML = `
      <div class="space-y-5">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Campaign</div><div class="font-black mt-2">${esc(campaign.name || campaign.campaign_id)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Campaign ID</div><div class="font-black mt-2 mono">${esc(campaign.campaign_id)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Evaluation level</div><div class="font-black mt-2">${esc(meta.long)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("campaign_status", "Campaign status", campaign.status)}</div><div class="font-black mt-2 ${statusClass(campaign.status)}">${infoTip("campaign_status", titleCaseStatus(campaign.status), campaign.status)}</div></div>
        </div>
        <div><span class="font-black">Scientific purpose:</span> ${esc(meta.purpose)}</div>
        <div><span class="font-black">Status explanation:</span> ${esc(campaignTechnicalReason(campaign, level))}</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div>
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("technical_outcome", "Technical execution", technicalOutcome)}</div>
            <div class="font-black mt-2 ${statusClass(technicalOutcome)}">${infoTip("technical_outcome", titleCaseStatus(technicalOutcome), technicalOutcome)}</div>
          </div>
          <div>
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Scientific limitations</div>
            <div class="font-black mt-2 ${scientificLimitations.length ? "text-amber-300" : "text-cyan-300"}">${esc(campaignScientificLimitationStatus(campaign))}</div>
          </div>
          <div>
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("scientific_outcome", "Scientific outcome", scientificOutcome)}</div>
            <div class="font-black mt-2 ${statusClass(scientificOutcome)}">${infoTip("scientific_outcome", titleCaseStatus(scientificOutcome), scientificOutcome)}</div>
          </div>
          <div>
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("comparison_readiness", "Comparison readiness", comparisonReadiness)}</div>
            <div class="font-black mt-2 ${statusClass(comparisonReadiness)}">${infoTip("comparison_readiness", campaignComparisonReadinessLabel(comparisonReadiness), comparisonReadiness)}</div>
          </div>
        </div>
        <div><span class="font-black">Reason:</span> ${esc(campaignTechnicalReason(campaign, level))}</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            ${level === "A" ? `
              <div><span class="font-black">Source:</span> ${esc(sourceModeLabel(sourceMode))}</div>
              <div class="mt-2"><span class="font-black">Linked base case:</span> ${esc(cfg.base_case_id || cfg.run_case_id || cfg.base_case_path || cfg.run_case_path || "not_configured")}</div>
              <div class="mt-2"><span class="font-black">Source case policy:</span> Read-only. The original case will not be modified.</div>
            ` : `
              <div><span class="font-black">Source:</span> Active deployed scenario</div>
              <div class="mt-2"><span class="font-black">New case policy:</span> A new forensic case will be created for every execution after detection-triggered acquisition.</div>
              <div class="mt-2"><span class="font-black">Reference case:</span> ${esc(cfg.base_case_id || cfg.run_case_id ? (cfg.base_case_id || cfg.run_case_id) : "Not selected, not required.")}</div>
            `}
          </div>
          <div>
            <div><span class="font-black">Scenario:</span> ${esc(scenarioId)}</div>
            <div class="mt-2"><span class="font-black">Scenario explanation:</span> ${scenarioId === "not_available" ? "Scenario ID could not be extracted automatically from the linked case. This does not block Level A reanalysis, but it may reduce the metadata quality of the comparison profile." : "Scenario metadata is available for the campaign profile."}</div>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("baseline_threshold", "Baseline threshold", cfg.baseline_noise_threshold)}</div><div class="font-black mt-2">${infoTip("baseline_threshold", cfg.baseline_noise_threshold, cfg.baseline_noise_threshold)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("delta_wcpr_allowed", "Weighted CPR tolerance", cfg.delta_wcpr_allowed)}</div><div class="font-black mt-2">${infoTip("delta_wcpr_allowed", cfg.delta_wcpr_allowed, cfg.delta_wcpr_allowed)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Registered executions</div><div class="font-black mt-2">${esc(execs.length)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Artifacts root</div><div class="font-black mt-2 mono text-[12px] break-all">${esc(campaign.campaign_path || "not_available")}</div></div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Retention policy</div><div class="font-black mt-2">${esc(cfg.retention_policy || (level === "A" ? "original_case_retained" : "profiles_only_after_archive"))}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Heavy case policy</div><div class="font-black mt-2">${esc(cfg.heavy_case_policy || (level === "A" ? "reuse_original_case" : "new_case_per_execution"))}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Dry-run default</div><div class="font-black mt-2">${cfg.dry_run ? "yes" : "no"}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Requested comparison family</div><div class="font-black mt-2 mono">${esc(cfg.requested_comparison_family_id || "new family unless recommendation is applied")}</div></div>
        </div>
        ${level === "B" ? renderLatestLevelBReportSection(campaign) : ""}
        ${technicalFailures.length ? `
          <div>
            <div class="font-black text-red-300">Technical failures</div>
            <ul class="mt-2 list-disc pl-5 text-slate-300 space-y-1">${technicalFailures.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
          </div>
        ` : ""}
        ${scientificLimitations.length ? `
          <div>
            <div class="font-black text-amber-300">Scientific limitations</div>
            <div class="mt-3 space-y-3">
              ${groupCampaignScientificLimitations(scientificLimitations, level, execs.length).map((item) => `
                <div class="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4">
                  <div class="font-black">${esc(item.reason)}</div>
                  <div class="text-slate-400 mt-1">Affected executions: ${esc(item.affectedLabel)}</div>
                  <div class="text-slate-400 mt-1">Classification: ${esc(item.classification)}</div>
                  <div class="text-slate-300 mt-1">Interpretation: ${esc(item.interpretation)}</div>
                </div>
              `).join("")}
            </div>
          </div>
        ` : ""}
      </div>
    `;

    renderCampaignResourceActions(campaign, executionDetails.filter(Boolean));
    renderScenarioRedeploymentActions();
    root.querySelectorAll("[data-open-level-b-report]").forEach((btn) => {
      btn.addEventListener("click", () => openLevelBReport(btn.dataset.openLevelBReport));
    });

    applyCampaignActionState(campaign, runningJob, cfg);

    if (!execs.length) {
      execNote.innerHTML = "No executions registered for this campaign. Run the first execution to generate an execution workspace.";
      execRoot.innerHTML = '<div class="glass-soft rounded-2xl p-4">No executions registered for this campaign.</div>';
    } else if (execs.length === 1) {
      execNote.innerHTML = "Only one execution is available. At least two executions are required for comparability analysis.";
    } else if (comparableCount < 2) {
      execNote.innerHTML = "Comparison requires at least two executions with generated forensic comparison profiles.";
    } else {
      execNote.innerHTML = `${comparableCount} execution profiles are available for comparability analysis.`;
    }

    execRoot.innerHTML = execs.length ? executionDetails.map((item, idx) => renderExecutionCard(item || execs[idx], comparableCount)).join("") : execRoot.innerHTML;
    bindExecutionActions(executionDetails.filter(Boolean), comparableCount, campaign.campaign_id);

    if (!state.activeJobId) {
      renderJob(runningJob || (payload.latest_job ? { ...payload.latest_job, summary_mode: true } : null));
    }
    renderCampaignStoryPanel();
    renderStoryline();
    renderBuilderSelectedCampaignNote();
  }

  function applyCampaignActionState(campaign, runningJob, cfg) {
    const busy = !!runningJob || !!state.activeJobId;
    const noCampaign = !campaign;
    const level = String(campaign?.level || cfg?.level || "").toUpperCase();
    const isLevelB = level === "B";
    const attackId = cfg?.attack_id || campaign?.attack_id || null;
    const startBtn = byId("campaign-start-btn");
    const runNextBtn = byId("campaign-run-next-btn");
    const levelAReportBtn = byId("campaign-level-a-report-btn");
    const paperLevelABtn = byId("campaign-paper-level-a-btn");
    const paperLevelBBtn = byId("campaign-paper-level-b-btn");
    const paperLevelCBtn = byId("campaign-paper-level-c-btn");
    const runRealBtn = byId("campaign-run-real-btn");
    const runBatchBtn = byId("campaign-run-level-b-repetitions-btn");
    const pauseBtn = byId("campaign-pause-btn");
    const stopBtn = byId("campaign-stop-btn");
    const note = byId("campaign-action-note");
    const dryRunBanner = byId("level-b-dry-run-banner");
    if (startBtn) {
      startBtn.disabled = busy || noCampaign;
      startBtn.classList.toggle("opacity-50", busy || noCampaign);
      startBtn.classList.toggle("cursor-not-allowed", busy || noCampaign);
      startBtn.textContent = busy ? "Campaign Queue Busy" : "Queue Selected Campaign";
      startBtn.title = isLevelB
        ? "Start Selected Campaign always runs dry-run executions for Level B. It never chains real attacks unattended."
        : (busy ? "A campaign job is already running for this workspace." : (noCampaign ? "Select or create a campaign first." : ""));
    }
    if (runNextBtn) {
      runNextBtn.disabled = busy || noCampaign;
      runNextBtn.classList.toggle("opacity-50", busy || noCampaign);
      runNextBtn.classList.toggle("cursor-not-allowed", busy || noCampaign);
      runNextBtn.textContent = busy ? "Dry-Run In Progress" : "Run Next Dry-Run Execution";
      runNextBtn.title = busy ? "Wait until the current experimentation job finishes." : (noCampaign ? "Select or create a campaign first." : "");
    }
    if (levelAReportBtn) {
      const blocked = busy || noCampaign || level !== "A";
      levelAReportBtn.classList.toggle("hidden", level !== "A");
      levelAReportBtn.disabled = blocked;
      levelAReportBtn.classList.toggle("opacity-50", blocked);
      levelAReportBtn.classList.toggle("cursor-not-allowed", blocked);
      levelAReportBtn.textContent = busy ? "Consolidated Report In Progress" : "Generate Consolidated Level A Report";
      levelAReportBtn.title = busy
        ? "Wait until the current experimentation job finishes."
        : (noCampaign ? "Select or create a campaign first." : "Run the same Level A dry-run execution path several times over the preserved case, then generate one consolidated auditable scientific report from those fresh repetitions.");
    }
    if (paperLevelABtn) {
      const blocked = busy || noCampaign || level !== "A";
      paperLevelABtn.classList.toggle("hidden", level !== "A");
      paperLevelABtn.disabled = blocked;
      paperLevelABtn.classList.toggle("opacity-50", blocked);
      paperLevelABtn.classList.toggle("cursor-not-allowed", blocked);
      paperLevelABtn.textContent = busy ? "Paper Evidence In Progress" : "Generate Level A Paper Evidence Report";
      paperLevelABtn.title = busy
        ? "Wait until the current experimentation job finishes."
        : (noCampaign ? "Select or create a campaign first." : "Run the current Level A read-only scientific workflow, then package the resulting metrics, limitations, table registry, and reviewer-facing interpretation for the paper.");
    }
    if (paperLevelBBtn) {
      const blocked = busy || noCampaign || level !== "B";
      paperLevelBBtn.classList.toggle("hidden", level !== "B");
      paperLevelBBtn.disabled = blocked;
      paperLevelBBtn.classList.toggle("opacity-50", blocked);
      paperLevelBBtn.classList.toggle("cursor-not-allowed", blocked);
      paperLevelBBtn.textContent = busy ? "Paper Evidence In Progress" : "Generate Level B Paper Evidence Report";
      paperLevelBBtn.title = busy
        ? "Wait until the current experimentation job finishes."
        : (noCampaign ? "Select or create a campaign first." : "Prepare the Level B paper evidence package and its table registry. Runtime Level B paper metrics remain explicitly unsupported until the dedicated paper-grade execution path is completed.");
    }
    if (paperLevelCBtn) {
      const blocked = busy || noCampaign || level !== "C";
      paperLevelCBtn.classList.toggle("hidden", level !== "C");
      paperLevelCBtn.disabled = blocked;
      paperLevelCBtn.classList.toggle("opacity-50", blocked);
      paperLevelCBtn.classList.toggle("cursor-not-allowed", blocked);
      paperLevelCBtn.textContent = busy ? "Paper Evidence In Progress" : "Generate Level C Paper Evidence Report";
      paperLevelCBtn.title = busy
        ? "Wait until the current experimentation job finishes."
        : (noCampaign ? "Select or create a campaign first." : "Prepare the Level C paper evidence package and record the current redeployment evidence gap explicitly.");
    }
    if (runRealBtn) {
      runRealBtn.classList.toggle("hidden", !isLevelB);
      const noAttack = isLevelB && !attackId;
      const blocked = busy || noCampaign || !isLevelB || noAttack;
      runRealBtn.disabled = blocked;
      runRealBtn.classList.toggle("opacity-50", blocked);
      runRealBtn.classList.toggle("cursor-not-allowed", blocked);
      runRealBtn.textContent = busy ? "Execution In Progress" : "Run Real Level B Execution";
      runRealBtn.title = busy
        ? "Wait until the current experimentation job finishes."
        : (noCampaign ? "Select or create a campaign first." : (noAttack ? "Select an attack profile for this campaign before running a real execution." : "This launches a real attack, waits for a real alert, and creates a new forensic case. A confirmation step will ask you to type OK."));
    }
    if (runBatchBtn) {
      runBatchBtn.classList.toggle("hidden", !isLevelB);
      const noAttack = isLevelB && !attackId;
      const blocked = busy || noCampaign || !isLevelB || noAttack;
      runBatchBtn.disabled = blocked;
      runBatchBtn.classList.toggle("opacity-50", blocked);
      runBatchBtn.classList.toggle("cursor-not-allowed", blocked);
      runBatchBtn.textContent = busy ? "Batch In Progress" : "Run Level B Repetitions";
      runBatchBtn.title = busy
        ? "Wait until the current experimentation job finishes."
        : (noCampaign ? "Select or create a campaign first." : (noAttack ? "Select an attack profile for this campaign before running the configured Level B repetitions." : "Run the configured Level B repetitions with optional cleanup, one new case per execution, and nested Level A comparability reports."));
    }
    if (pauseBtn) {
      pauseBtn.disabled = noCampaign;
      pauseBtn.classList.toggle("opacity-50", noCampaign);
      pauseBtn.classList.toggle("cursor-not-allowed", noCampaign);
    }
    if (stopBtn) {
      stopBtn.disabled = noCampaign;
      stopBtn.classList.toggle("opacity-50", noCampaign);
      stopBtn.classList.toggle("cursor-not-allowed", noCampaign);
    }
    if (note) {
      note.innerHTML = noCampaign
        ? '<span class="text-amber-300">No campaign selected. Create or select a campaign before running executions.</span>'
        : "";
    }
    if (dryRunBanner) {
      dryRunBanner.classList.toggle("hidden", noCampaign || level === "A");
      if (!noCampaign && level !== "A") {
        dryRunBanner.innerHTML = isLevelB
          ? "<span class=\"font-black text-amber-300\">Run Dry-Run Execution:</span> This reuses existing scientific functions over a preserved reference case or the active preserved case: Bootstrap FOC, Regenerate Reconstruction, Run Causal Reconstruction, and Run Full Evidence Lifecycle. It does not launch a real attack, wait for a real alert, create a heavy forensic case, or execute real acquisition. Use <span class=\"font-black\">Run Real Level B Execution</span> for a real controlled incident execution."
          : "<span class=\"font-black text-amber-300\">Run Dry-Run Execution:</span> This reuses existing scientific functions over a preserved reference case or the active preserved case: Bootstrap FOC, Regenerate Reconstruction, Run Causal Reconstruction, and Run Full Evidence Lifecycle. It does not launch a real attack, wait for a real alert, create a heavy forensic case, or execute real acquisition.";
      }
    }
  }

  function renderExecutionCard(item, comparableCount) {
    const level = String(item.level || "A").toUpperCase();
    const meta = LEVEL_META[level] || LEVEL_META.A;
    const profileAvailable = hasComparisonProfile(item);
    const cleanupState = executionCleanupState(item);
    const sealState = level === "A"
      ? (item.artifacts?.ground_truth_seal ? "Reused from base case or reconstructed from preserved artifacts." : "Missing")
      : (item.artifacts?.ground_truth_seal ? "Available" : "Missing");
    const baselineState = level === "A"
      ? "Not applicable for Level A"
      : (item.artifacts?.baseline_noise_profile ? "Available" : "Missing");
    const sourceCase = item.source_case_id || item.base_case_id || item.run_case_id || "not_available";
    const generatedCase = cleanupState.canDelete
      ? (item.run_case_id || "not_available")
      : (cleanupState.label === "Already cleaned up" ? "cleaned_up" : (item.planned_case_id || "not_created_yet"));
    const caseFieldLabel = level === "A"
      ? (item.base_case_id || item.source_case_id ? "Reanalyzed preserved case" : "Base case")
      : (item.run_case_id ? "Generated case" : (item.planned_case_id ? "Planned case" : "Generated case"));
    const caseFieldValue = level === "A" ? sourceCase : generatedCase;
    const retentionPolicy = item.retention_policy || (level === "A" ? "original_case_retained" : "profiles_only_after_archive");
    const latestLevelAReport = item.scientific_reports?.latest_level_a || item.scientific_reports?.latest_level_a_report || null;
    return `
      <div class="glass-soft rounded-2xl p-4 space-y-4">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Execution</div>
            <div class="font-black mt-2">${esc(item.execution_id)}</div>
          </div>
          <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status || "unknown"))}</div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Level</div><div class="font-black mt-2">${esc(meta.long)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Source</div><div class="font-black mt-2">${level === "A" ? `Base case ${esc(sourceCase)}` : `Scenario execution ${esc(item.scenario_id || "not_available")}`}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Generated profile</div><div class="font-black mt-2 ${profileAvailable ? "text-cyan-300" : "text-red-300"}">${profileAvailable ? "Available" : "Missing"}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Ground truth seal</div><div class="font-black mt-2">${esc(sealState)}</div></div>
        </div>
        <div><span class="font-black">Status explanation:</span> ${esc(statusExplanation(item.status, "execution"))}</div>
        <div><span class="font-black">Baseline noise:</span> ${esc(baselineState)}</div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        <div><span class="font-black">${esc(caseFieldLabel)}:</span> <span class="mono">${esc(caseFieldValue)}</span></div>
        <div><span class="font-black">Retention policy:</span> ${esc(retentionPolicy)}</div>
        <div><span class="font-black">Dry-run:</span> ${item.dry_run ? "yes" : "no"}</div>
      </div>
      ${cleanupState.visible ? `<div class="text-slate-400"><span class="font-black">Cleanup state:</span> ${esc(cleanupState.reason)}</div>` : ""}
      ${item.warnings?.length ? `<div class="text-amber-300"><span class="font-black">Warnings:</span> ${esc(item.warnings.join(" | "))}</div>` : ""}
      ${level !== "A" && item.dry_run ? `<div class="text-slate-400">This Level ${esc(level)} execution currently preserves the experimental design, planned case ID, and normalized profiles as a dry-run scaffold. It does not yet prove that a heavy case was acquired.</div>` : ""}
      <div class="flex gap-3 flex-wrap">
          ${level === "A" || (item.run_case_id && truthy(item.run_case_id)) ? `<a class="text-cyan-300 underline" href="/foc_scientific_evidence_lifecycle.html?case_id=${encodeURIComponent(level === "A" ? sourceCase : item.run_case_id)}">${esc(meta.dashboardActionLabel)}</a>` : ""}
          <button type="button" class="text-cyan-300 underline execution-workspace-btn" data-execution-id="${esc(item.execution_id)}">Open Execution Workspace</button>
          <button type="button" class="text-cyan-300 underline execution-profile-btn" data-execution-id="${esc(item.execution_id)}" ${profileAvailable ? "" : "disabled"}>Open Comparison Profile</button>
          ${level === "A" && latestLevelAReport ? `<button type="button" class="text-cyan-300 underline execution-level-a-report-btn" data-execution-id="${esc(item.execution_id)}" data-campaign-id="${esc(item.campaign_id || "")}">Open Level A Scientific Report</button>` : ""}
          <button type="button" class="text-cyan-300 underline execution-compare-btn ${comparableCount >= 2 && profileAvailable ? "" : "opacity-50 cursor-not-allowed"}" data-execution-id="${esc(item.execution_id)}" ${comparableCount >= 2 && profileAvailable ? "" : "disabled"}>Compare with other executions</button>
          ${cleanupState.visible ? `<button type="button" class="text-amber-300 underline generated-case-cleanup-btn ${cleanupState.canDelete ? "" : "opacity-50 cursor-not-allowed"}" data-campaign-id="${esc(item.campaign_id || "")}" data-execution-id="${esc(item.execution_id)}" data-case-id="${esc(item.run_case_id || "")}" data-origin="execution-card" ${cleanupState.canDelete ? "" : "disabled"}>Delete Generated Case Artifacts</button>` : ""}
        </div>
        ${cleanupState.visible ? `<div id="cleanup-status-${esc(item.execution_id)}-execution-card" class="text-sm text-slate-300"></div>` : ""}
      </div>
    `;
  }

  function bindExecutionActions(executions, comparableCount, campaignId) {
    document.querySelectorAll(".execution-workspace-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const executionId = btn.dataset.executionId;
        const payload = await getJson(`/api/foc/experimentation/executions/${encodeURIComponent(executionId)}/artifacts`);
        const artifacts = payload.artifacts || [];
        openOverlay(`Execution Workspace · ${executionId}`, `
          <div class="space-y-3">
            <div class="text-slate-300">Each execution keeps its own isolated workspace, artifacts and logs.</div>
            ${artifacts.length ? artifacts.map((item) => `
              <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-3">
                <div class="font-black">${esc(item.name)}</div>
                <div class="mono text-xs text-slate-400 mt-2">${esc(item.path)}</div>
                <div class="text-xs text-slate-500 mt-2">${esc(item.size_bytes)} bytes</div>
              </div>
            `).join("") : '<div class="text-slate-400">No execution artifacts were listed.</div>'}
          </div>
        `);
      });
    });
    document.querySelectorAll(".execution-profile-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const executionId = btn.dataset.executionId;
        const payload = await getJson(`/api/foc/experimentation/comparability/profile/${encodeURIComponent(executionId)}`);
        openOverlay(`Forensic Comparison Profile · ${executionId}`, `<pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono">${esc(JSON.stringify(payload, null, 2))}</pre>`);
      });
    });
    document.querySelectorAll(".execution-level-a-report-btn").forEach((btn) => {
      btn.addEventListener("click", () => openLevelAReport(btn.dataset.executionId, btn.dataset.campaignId || campaignId || null));
    });
    document.querySelectorAll(".execution-compare-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.disabled || comparableCount < 2) return;
        const executionId = btn.dataset.executionId;
        window.location.href = `/foc_reconstruction_comparability.html?campaign_id=${encodeURIComponent(campaignId)}&execution_id=${encodeURIComponent(executionId)}`;
      });
    });
    bindGeneratedCaseCleanupButtons();
  }

  function bindGeneratedCaseCleanupButtons() {
    document.querySelectorAll(".generated-case-cleanup-btn").forEach((btn) => {
      if (btn.dataset.boundCleanup === "true") return;
      btn.dataset.boundCleanup = "true";
      btn.addEventListener("click", () => {
        if (btn.disabled) return;
        validateAndPromptCaseCleanup(
          btn.dataset.executionId,
          btn.dataset.campaignId || null,
          btn.dataset.caseId || null,
          btn.dataset.origin || "execution-card",
        );
      });
    });
  }

  function openInteractiveOverlay(title, html, onReady) {
    let root = byId("foc-experimentation-overlay");
    if (!root) {
      root = document.createElement("div");
      root.id = "foc-experimentation-overlay";
      root.className = "fixed inset-0 z-[1000] bg-slate-950/65 backdrop-blur-sm p-4 md:p-8";
      root.innerHTML = `
        <div class="mx-auto max-w-5xl h-full flex items-center justify-center">
          <div class="glass rounded-[28px] p-6 w-full max-h-[88vh] overflow-auto">
            <div class="flex items-start justify-between gap-4">
              <div>
                <div class="text-[11px] tracking-[0.28em] uppercase text-slate-400 font-black">Execution Detail</div>
                <h2 id="foc-experimentation-overlay-title" class="text-2xl font-black mt-2"></h2>
              </div>
              <button id="foc-experimentation-overlay-close" type="button" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Close</button>
            </div>
            <div id="foc-experimentation-overlay-body" class="mt-5"></div>
          </div>
        </div>
      `;
      document.body.appendChild(root);
      byId("foc-experimentation-overlay-close").addEventListener("click", () => root.remove());
      root.addEventListener("click", (event) => {
        if (event.target === root) root.remove();
      });
    }
    byId("foc-experimentation-overlay-title").textContent = title;
    byId("foc-experimentation-overlay-body").innerHTML = html;
    if (typeof onReady === "function") onReady(root);
    return root;
  }

  function openOverlay(title, html) {
    openInteractiveOverlay(title, html);
  }

  function ensureLevelAReportOverlay() {
    let root = byId("foc-level-a-report-overlay");
    if (root) return root;
    root = document.createElement("div");
    root.id = "foc-level-a-report-overlay";
    root.className = "fixed inset-0 z-[1200] bg-slate-950/55 backdrop-blur-sm p-4 md:p-8";
    root.innerHTML = `
      <div class="mx-auto max-w-3xl h-full flex items-center justify-center">
        <div class="glass rounded-[30px] p-6 w-full shadow-2xl border border-cyan-500/20">
          <div class="text-center">
            <div class="text-[11px] tracking-[0.28em] uppercase text-cyan-300 font-black">Level A Scientific Report</div>
            <h2 class="text-2xl font-black mt-3">Scientific Report Generation</h2>
          </div>
          <div id="foc-level-a-report-overlay-body" class="mt-6"></div>
          <div class="mt-6 flex items-center justify-center gap-3 flex-wrap">
            <button id="foc-level-a-report-stop-btn" type="button" class="btn-danger rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Stop Current Job</button>
            <button id="foc-level-a-report-force-stop-btn" type="button" class="btn-danger rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Force Stop</button>
            <button id="foc-level-a-report-open-btn" type="button" class="btn-primary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase hidden">Open Report</button>
            <button id="foc-level-a-report-close-btn" type="button" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Close Window</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(root);
    byId("foc-level-a-report-stop-btn")?.addEventListener("click", async () => {
      const jobId = state.levelAReportOverlayJobId;
      if (!jobId) return;
      await cancelExperimentationJob(jobId, "Level A scientific report generation");
    });
    byId("foc-level-a-report-force-stop-btn")?.addEventListener("click", async () => {
      const jobId = state.levelAReportOverlayJobId;
      if (!jobId) return;
      await confirmForceStopExperimentationJob(jobId, "Level A scientific report generation");
    });
    byId("foc-level-a-report-close-btn")?.addEventListener("click", () => {
      state.levelAReportOverlayJobId = null;
      root.remove();
    });
    return root;
  }

  function renderLevelAReportOverlay(payload) {
    const root = byId("foc-level-a-report-overlay");
    if (!root) return;
    const body = byId("foc-level-a-report-overlay-body");
    const closeBtn = byId("foc-level-a-report-close-btn");
    const openBtn = byId("foc-level-a-report-open-btn");
    const stopBtn = byId("foc-level-a-report-stop-btn");
    const forceStopBtn = byId("foc-level-a-report-force-stop-btn");
    if (!body || !closeBtn || !openBtn || !stopBtn || !forceStopBtn) return;
    if (!payload || !isLevelAReportJob(payload) || state.levelAReportOverlayJobId !== payload.job_id) {
      return;
    }
    const terminal = isTerminalJobStatus(payload.status);
    const phaseStatuses = payload.phase_statuses || [];
    const lastPhase = phaseStatuses.length ? phaseStatuses[phaseStatuses.length - 1] : null;
    const phaseLabel = payload.current_phase_label || lastPhase?.phase_label || titleCaseStatus(payload.current_phase || "queued");
    const phaseDetail = formatDetail(payload.current_phase_detail || lastPhase?.detail || "No scientific detail available.");
    const warnings = payload.warnings || [];
    body.innerHTML = `
      <div class="space-y-5 text-sm text-slate-200">
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Current phase</div>
            <div class="font-black mt-2">${esc(phaseLabel)}</div>
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Current phase status</div>
            <div class="font-black mt-2 ${statusClass(payload.status)}">${esc(titleCaseStatus(payload.status || "running"))}</div>
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Exact progress</div>
            <div class="font-black mt-2">${esc(payload.progress_percent ?? "not_available")}${payload.progress_percent != null ? "%" : ""}</div>
          </div>
        </div>
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Detailed message</div>
          <div class="mt-2">${esc(phaseDetail)}</div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Current case ID</div>
            <div class="font-black mt-2 mono">${esc(payload.current_case_id || "not_available")}</div>
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Repetition / execution ID</div>
            <div class="font-black mt-2 mono">${esc(payload.current_execution_id || "not_available")}</div>
          </div>
        </div>
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Report output path</div>
          <div class="font-black mt-2 mono break-all">${esc(payload.report_output_path || "not_available")}</div>
        </div>
        ${warnings.length ? `
          <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
            <div class="font-black">Warnings or degraded states</div>
            <div class="mt-2 space-y-1">${warnings.map((item) => `<div>${esc(item)}</div>`).join("")}</div>
          </div>
        ` : ""}
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Final status</div>
          <div class="font-black mt-2 ${statusClass(payload.status)}">${esc(titleCaseStatus(payload.status || "running"))}</div>
        </div>
      </div>
    `;
    stopBtn.classList.toggle("hidden", terminal);
    stopBtn.disabled = String(payload.status || "").toLowerCase() === "cancel_requested";
    stopBtn.classList.toggle("opacity-50", stopBtn.disabled);
    stopBtn.classList.toggle("cursor-not-allowed", stopBtn.disabled);
    forceStopBtn.classList.toggle("hidden", terminal);
    forceStopBtn.disabled = ["stopped", "force_stop_requested"].includes(String(payload.status || "").toLowerCase());
    forceStopBtn.classList.toggle("opacity-50", forceStopBtn.disabled);
    forceStopBtn.classList.toggle("cursor-not-allowed", forceStopBtn.disabled);
    const reportExecutionId = payload.level_a_report?.execution_id || null;
    const reportCampaignId = payload.level_a_report?.campaign_id || payload.meta?.campaign_id || null;
    openBtn.classList.toggle("hidden", !terminal || !reportExecutionId || !payload.level_a_report?.report_markdown_path);
    openBtn.onclick = () => openLevelAReport(reportExecutionId, reportCampaignId);
  }

  function openLevelAReportProgressOverlay(jobId) {
    state.levelAReportOverlayJobId = jobId;
    ensureLevelAReportOverlay();
  }

  function ensureLevelBOverlay() {
    let root = byId("foc-level-b-overlay");
    if (root) return root;
    root = document.createElement("div");
    root.id = "foc-level-b-overlay";
    root.className = "fixed inset-0 z-[1200] bg-black/55 backdrop-blur-md p-4 md:p-8 flex items-center justify-center";
    root.innerHTML = `
      <div class="mx-auto max-w-5xl w-full">
        <div class="w-full max-h-[84vh] overflow-hidden rounded-[32px] border border-slate-900/10 bg-white/95 shadow-[0_40px_120px_rgba(0,0,0,0.45)]">
          <div class="flex items-center justify-between gap-4 border-b border-slate-900/10 px-5 py-4">
            <div>
              <div class="text-[10px] font-black uppercase tracking-[0.22em] text-slate-900/85">Level B Repetitions</div>
              <div class="mt-1 text-lg font-black text-slate-900">DFIR Preservation And Scientific Execution Monitor</div>
            </div>
            <div id="foc-level-b-overlay-status" class="text-[10px] font-black uppercase tracking-[0.18em] text-slate-900/70">Running</div>
          </div>
          <div id="foc-level-b-overlay-body" class="px-5 py-4"></div>
          <div class="flex flex-wrap justify-end gap-3 border-t border-slate-900/10 px-5 py-4">
            <button id="foc-level-b-stop-btn" type="button" class="btn-danger rounded-full px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Stop Current Job</button>
            <button id="foc-level-b-force-stop-btn" type="button" class="btn-danger rounded-full px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Force Stop</button>
            <button id="foc-level-b-cleanup-btn" type="button" class="btn-danger rounded-full px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Force Stop And Clean Batch</button>
            <button id="foc-level-b-open-report-btn" type="button" class="btn-primary rounded-full px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase hidden">Open Report</button>
            <button id="foc-level-b-close-btn" type="button" class="btn-secondary rounded-full px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Close Window</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(root);
    byId("foc-level-b-stop-btn")?.addEventListener("click", async () => {
      const jobId = state.levelBOverlayJobId;
      if (!jobId) return;
      await cancelExperimentationJob(jobId, "Level B repetition batch");
    });
    byId("foc-level-b-force-stop-btn")?.addEventListener("click", async () => {
      const jobId = state.levelBOverlayJobId;
      if (!jobId) return;
      await confirmForceStopExperimentationJob(jobId, "Level B repetition batch");
    });
    byId("foc-level-b-cleanup-btn")?.addEventListener("click", async () => {
      const jobId = state.levelBOverlayJobId;
      if (!jobId) return;
      await confirmCleanupLevelBJob(jobId);
    });
    byId("foc-level-b-close-btn")?.addEventListener("click", () => {
      state.levelBOverlayJobId = null;
      root.remove();
    });
    return root;
  }

  function levelBTerminalLines(payload, phaseStatuses, nestedTrace) {
    const lines = [];
    lines.push("[SISTEMA] LEVEL B REAL EXECUTION MONITOR");
    lines.push(`[JOB] ${String(payload.job_id || "not_available")}`);
    lines.push(`[STATUS] ${String(payload.status || "running")}`);
    lines.push(`[PROGRESS] ${payload.progress_percent != null ? `${payload.progress_percent}%` : "not_available"}`);
    lines.push(`[REPETITION] ${String(payload.current_repetition || 0)} / ${String(payload.requested_repetitions || payload.meta?.requested_repetitions || 0)}`);
    lines.push(`[CASE] ${String(payload.current_case_id || "not_available")}`);
    lines.push(`[EXECUTION] ${String(payload.current_execution_id || "not_available")}`);
    lines.push("");
    lines.push("[PHASE TRACE]");
    (phaseStatuses || []).slice(-14).forEach((item) => {
      const label = item?.phase_label || item?.phase_key || "phase";
      const status = item?.status || "unknown";
      const progress = item?.progress_percent != null ? `${item.progress_percent}%` : "n/a";
      const detail = formatDetail(item?.detail || "No detail available.");
      lines.push(`- ${label} :: ${status} :: ${progress}`);
      lines.push(`  ${detail}`);
    });
    if ((nestedTrace || []).length) {
      lines.push("");
      lines.push("[NESTED FULL EVIDENCE LIFECYCLE]");
      nestedTrace.slice(-12).forEach((item) => {
        const label = item?.phase_label || item?.phase_id || "phase";
        const layer = item?.layer || "lifecycle";
        const status = item?.status || "unknown";
        const detail = formatDetail(item?.detail || "No detail available.");
        lines.push(`- ${layer} :: ${label} :: ${status}`);
        lines.push(`  ${detail}`);
      });
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

  function renderLevelBOverlay(payload) {
    const root = byId("foc-level-b-overlay");
    if (!root) return;
    const body = byId("foc-level-b-overlay-body");
    const statusBadge = byId("foc-level-b-overlay-status");
    const closeBtn = byId("foc-level-b-close-btn");
    const openBtn = byId("foc-level-b-open-report-btn");
    const stopBtn = byId("foc-level-b-stop-btn");
    const forceStopBtn = byId("foc-level-b-force-stop-btn");
    const cleanupBtn = byId("foc-level-b-cleanup-btn");
    if (!body || !statusBadge || !closeBtn || !openBtn || !stopBtn || !forceStopBtn || !cleanupBtn) return;
    if (!payload || !isLevelBRepetitionJob(payload) || state.levelBOverlayJobId !== payload.job_id) return;
    const terminal = isTerminalJobStatus(payload.status);
    const phaseStatuses = payload.phase_statuses || [];
    const lastPhase = phaseStatuses.length ? phaseStatuses[phaseStatuses.length - 1] : null;
    const nestedTrace = payload.lifecycle_phase_trace || payload.phase_trace || [];
    const phaseLabel = payload.current_phase_label || lastPhase?.phase_label || titleCaseStatus(payload.current_phase || "queued");
    const phaseDetail = formatDetail(payload.current_phase_detail || lastPhase?.detail || "No detail available.");
    const phaseStatus = lastPhase?.status || payload.status || "running";
    const warnings = payload.warnings || [];
    const blockers = (payload.errors || []).map((item) => item?.message || JSON.stringify(item));
    const terminalLog = levelBTerminalLines(payload, phaseStatuses, nestedTrace);
    statusBadge.textContent = titleCaseStatus(payload.status || phaseStatus || "running");
    const elapsed = formatElapsedDuration(payload.started_at || payload.requested_at, payload.finished_at);
    body.innerHTML = `
      <div class="space-y-4 text-sm text-slate-900">
        <div class="rounded-2xl border border-slate-900/10 bg-white px-4 py-3 font-mono text-[11px] text-slate-700">
          job=${esc(payload.job_id || "not_available")} | repetition=${esc(payload.current_repetition || 0)}/${esc(payload.requested_repetitions || payload.meta?.requested_repetitions || 0)} | case=${esc(payload.current_case_id || "not_available")} | execution=${esc(payload.current_execution_id || "not_available")} | progress=${esc(payload.progress_percent ?? "not_available")}${payload.progress_percent != null ? "%" : ""} | elapsed=${esc(elapsed)}
        </div>
        <div class="rounded-2xl border border-slate-900/10 bg-black shadow-[inset_0_0_0_1px_rgba(16,185,129,0.10)]">
          <div class="border-b border-slate-800/80 px-4 py-3 text-[10px] font-black uppercase tracking-[0.18em] text-emerald-300">Live Preservation Console</div>
          <div class="px-4 py-2 font-mono text-[11px] text-slate-400">phase=${esc(phaseLabel)} | status=${esc(titleCaseStatus(phaseStatus))}</div>
          <pre class="max-h-[420px] overflow-auto whitespace-pre-wrap px-4 pb-4 text-[12px] leading-relaxed text-emerald-400">${esc(terminalLog)}</pre>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Current case ID</div><div class="mt-2 font-black mono text-slate-900">${esc(payload.current_case_id || "not_available")}</div></div>
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Execution ID</div><div class="mt-2 font-black mono text-slate-900">${esc(payload.current_execution_id || "not_available")}</div></div>
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Report output path</div><div class="mt-2 font-black mono break-all text-slate-900">${esc(payload.report_output_path || "not_available")}</div></div>
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Attack status</div><div class="mt-2 font-black text-slate-900">${esc(titleCaseStatus(payload.current_attack_status || "queued"))}</div></div>
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Preservation status</div><div class="mt-2 font-black text-slate-900">${esc(titleCaseStatus(payload.current_preservation_status || "queued"))}</div></div>
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Analysis status</div><div class="mt-2 font-black text-slate-900">${esc(titleCaseStatus(payload.current_analysis_status || "queued"))}</div></div>
          <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4"><div class="text-xs uppercase tracking-[0.16em] text-slate-500">Elapsed</div><div class="mt-2 font-black text-slate-900">${esc(elapsed)}</div></div>
        </div>
        <div class="rounded-2xl border border-slate-900/10 bg-slate-50 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-500">Detailed message</div>
          <div class="mt-2 text-slate-800">${esc(phaseDetail)}</div>
        </div>
        ${warnings.length ? `<div class="rounded-2xl border border-amber-500/30 bg-amber-50 p-4 text-amber-900"><div class="font-black">Warnings</div><div class="mt-2 space-y-1">${warnings.slice(-8).map((item) => `<div>${esc(item)}</div>`).join("")}</div></div>` : ""}
        ${blockers.length ? `<div class="rounded-2xl border border-red-500/30 bg-red-50 p-4 text-red-900"><div class="font-black">Blockers</div><div class="mt-2 space-y-1">${blockers.slice(-8).map((item) => `<div>${esc(item)}</div>`).join("")}</div></div>` : ""}
      </div>
    `;
    stopBtn.classList.toggle("hidden", terminal);
    stopBtn.disabled = String(payload.status || "").toLowerCase() === "cancel_requested";
    stopBtn.classList.toggle("opacity-50", stopBtn.disabled);
    stopBtn.classList.toggle("cursor-not-allowed", stopBtn.disabled);
    forceStopBtn.classList.toggle("hidden", terminal);
    forceStopBtn.disabled = ["stopped", "force_stop_requested"].includes(String(payload.status || "").toLowerCase());
    forceStopBtn.classList.toggle("opacity-50", forceStopBtn.disabled);
    forceStopBtn.classList.toggle("cursor-not-allowed", forceStopBtn.disabled);
    cleanupBtn.classList.toggle("hidden", false);
    cleanupBtn.disabled = false;
    cleanupBtn.classList.remove("opacity-50", "cursor-not-allowed");
    openBtn.classList.toggle("hidden", !terminal || !payload.level_b_report_path);
    openBtn.onclick = () => openLevelBReport(payload.job_id);
  }

  async function cancelExperimentationJob(jobId, label) {
    try {
      await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" });
    } catch (err) {
      openOverlay("Job cancellation", `<div class="text-red-300 text-sm">${esc(err.message)}</div>`);
      return;
    }
    openOverlay(
      "Job cancellation requested",
      `<div class="space-y-3 text-sm text-slate-300">
        <div>A cancellation request was sent for <span class="mono">${esc(jobId)}</span>.</div>
        <div>${esc(label)} will stop cooperatively as soon as the current backend phase reaches a safe checkpoint. If an underlying scientific subsystem does not support hard interruption, some nested work may still finish in the background.</div>
      </div>`
    );
    await pollJob();
  }

  async function confirmForceStopExperimentationJob(jobId, label) {
    openOkConfirmDialog({
      title: "Force Stop Job",
      bodyIntro: `You are about to force-stop ${label}. This immediately releases the experimentation wrapper and also asks the nested lifecycle and preserved-case analysis to stop.`,
      bodyHtml: `
        <div class="rounded-2xl border border-red-500/30 bg-red-500/5 p-4 text-red-200">
          Use this only when normal cancellation is not being honored. Some backend scientific threads may still need a short time to acknowledge the stop request, but the dashboard job will be closed immediately.
        </div>
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div><span class="font-black">Job ID:</span> <span class="mono">${esc(jobId)}</span></div>
        </div>
      `,
      confirmLabel: "Force Stop Job",
      onConfirm: async (resultNode, overlay) => {
        try {
          const payload = await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(jobId)}/force-stop`, { method: "POST" });
          if (resultNode) {
            resultNode.innerHTML = `<div class="text-amber-200">${esc(payload.note || "Force stop was requested.")}</div>`;
          }
          await pollJob();
          setTimeout(() => overlay?.remove(), 900);
        } catch (err) {
          if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
        }
      },
    });
  }

  async function confirmCleanupLevelBJob(jobId) {
    openOkConfirmDialog({
      title: "Force Stop And Clean Level B Batch",
      bodyIntro: "This action force-stops the Level B batch and then deletes everything that was created by that batch as far as possible.",
      bodyHtml: `
        <div class="rounded-2xl border border-red-500/30 bg-red-500/5 p-4 text-red-200">
          The cleanup targets the Level B batch runtime directory, the fresh forensic cases created by the batch, the execution workspaces registered for that batch, nested Level A child campaigns created from those cases, and the Level B report bundle if it already exists.
        </div>
        <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
          Use this when Stop and Force Stop are not enough and you want to abandon this Level B batch completely without touching the active scenario definition.
        </div>
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div><span class="font-black">Job ID:</span> <span class="mono">${esc(jobId)}</span></div>
        </div>
      `,
      confirmLabel: "Force Stop And Clean",
      onConfirm: async (resultNode, overlay) => {
        try {
          const payload = await getJson(`/api/foc/repetitions/level-b/cleanup/${encodeURIComponent(jobId)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ confirmation: "OK" }),
          });
          if (resultNode) {
            resultNode.innerHTML = `
              <div class="text-cyan-300">${esc(payload.message || "Cleanup completed.")}</div>
              <div class="mt-2 text-xs text-slate-400">Deleted cases: ${esc((payload.deleted_cases || []).length)}</div>
              <div class="mt-1 text-xs text-slate-400">Deleted executions: ${esc((payload.deleted_executions || []).length)}</div>
              <div class="mt-1 text-xs text-slate-400">Deleted nested Level A campaigns: ${esc((payload.deleted_nested_campaigns || []).length)}</div>
            `;
          }
          clearActiveJob();
          state.activeJobId = null;
          state.levelBOverlayJobId = null;
          if (state.pollTimer) {
            clearInterval(state.pollTimer);
            state.pollTimer = null;
          }
          byId("foc-level-b-overlay")?.remove();
          await loadCampaigns();
          await loadSourceCases();
          setTimeout(() => overlay?.remove(), 900);
        } catch (err) {
          if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
        }
      },
    });
  }

  async function openGlobalCleaner() {
    let inventory;
    try {
      inventory = await getJson("/api/foc/experimentation/cleanup/inventory");
    } catch (err) {
      openOverlay("Global Cleaner", `<div class="text-red-300 text-sm">${esc(err.message)}</div>`);
      return;
    }
    const items = inventory.items || [];
    const removable = items.filter((item) => item.deletable);
    openInteractiveOverlay(
      "Global Cleaner",
      `
        <div class="space-y-4 text-sm text-slate-300">
          <div>This cleaner removes selected campaigns, executions, forensic cases, analyses, and report bundles across the repetition, comparison, reconstruction, and evidence lifecycle surfaces. It does not touch the active scenario definition.</div>
          <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
            Select exactly what you want to remove. You can choose complete campaigns, individual executions, full forensic cases, scientific report bundles, validation reports, and scientific memory registries. Type <span class="mono">OK</span> to execute deletion.
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div><span class="font-black">Removable items:</span> ${esc(removable.length)}</div>
            <div class="mt-2"><span class="font-black">Estimated reclaimable space:</span> ${esc(inventory.summary?.estimated_reclaimable_human || "not_available")}</div>
          </div>
          <div class="flex gap-3 flex-wrap">
            <button type="button" id="global-cleaner-select-all" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Select All Removable</button>
            <button type="button" id="global-cleaner-clear" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Clear Selection</button>
          </div>
          <div class="max-h-[44vh] overflow-auto space-y-3 pr-1">
            ${items.map((item) => `
              <label class="block rounded-2xl border ${item.deletable ? "border-slate-700/60 bg-slate-950/30" : "border-red-500/25 bg-red-500/5"} p-4">
                <div class="flex items-start gap-3">
                  <input type="checkbox" class="global-cleaner-check mt-1" value="${esc(item.item_id)}" ${item.deletable ? "" : "disabled"}>
                  <div class="min-w-0">
                    <div class="font-black">${esc(item.label)}</div>
                    <div class="text-xs uppercase tracking-[0.16em] text-slate-400 mt-1">${esc(item.item_type)}</div>
                    <div class="mono text-xs text-slate-500 mt-2 break-all">${esc(item.path)}</div>
                    <div class="text-xs text-slate-400 mt-2">Estimated size: ${esc(item.size_human || "not_available")}</div>
                    ${item.blocked_reason ? `<div class="text-xs text-red-300 mt-2">${esc(item.blocked_reason)}</div>` : ""}
                  </div>
                </div>
              </label>
            `).join("")}
          </div>
          <label class="block">
            <span class="font-black">Confirmation</span>
            <input id="global-cleaner-confirm" class="w-full mt-3 rounded-xl bg-slate-950/60 border border-slate-700 px-3 py-2 text-slate-100" placeholder="Type OK">
          </label>
          <div class="flex gap-3 flex-wrap">
            <button type="button" id="global-cleaner-submit" class="btn-danger rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase opacity-50 cursor-not-allowed" disabled>Delete Selected Items</button>
            <button type="button" id="global-cleaner-cancel" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Cancel</button>
          </div>
          <div id="global-cleaner-result" class="text-sm text-slate-300"></div>
        </div>
      `,
      () => {
        const overlay = byId("foc-experimentation-overlay");
        const confirmInput = byId("global-cleaner-confirm");
        const submit = byId("global-cleaner-submit");
        const resultNode = byId("global-cleaner-result");
        const sync = () => {
          const anySelected = [...document.querySelectorAll(".global-cleaner-check:checked")].length > 0;
          const enabled = anySelected && String(confirmInput?.value || "") === "OK";
          submit.disabled = !enabled;
          submit.classList.toggle("opacity-50", !enabled);
          submit.classList.toggle("cursor-not-allowed", !enabled);
        };
        byId("global-cleaner-select-all")?.addEventListener("click", () => {
          document.querySelectorAll(".global-cleaner-check:not([disabled])").forEach((node) => { node.checked = true; });
          sync();
        });
        byId("global-cleaner-clear")?.addEventListener("click", () => {
          document.querySelectorAll(".global-cleaner-check").forEach((node) => { node.checked = false; });
          sync();
        });
        document.querySelectorAll(".global-cleaner-check").forEach((node) => node.addEventListener("change", sync));
        confirmInput?.addEventListener("input", sync);
        byId("global-cleaner-cancel")?.addEventListener("click", () => overlay?.remove());
        submit?.addEventListener("click", async () => {
          if (submit.disabled) return;
          const selectedIds = [...document.querySelectorAll(".global-cleaner-check:checked")].map((node) => node.value);
          submit.disabled = true;
          submit.classList.add("opacity-50", "cursor-not-allowed");
          if (resultNode) resultNode.innerHTML = '<div class="text-slate-400">Deleting selected items…</div>';
          try {
            const payload = await getJson("/api/foc/experimentation/cleanup/delete", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ selected_item_ids: selectedIds, confirmation: "OK" }),
            });
            if (resultNode) resultNode.innerHTML = `
              <div class="text-cyan-300">${esc(payload.message || "Cleanup completed.")}</div>
              <div class="mt-2 text-xs text-slate-400 mono break-all">${esc(payload.cleanup_manifest_path || "not_available")}</div>
            `;
            clearActiveJob();
            state.activeJobId = null;
            if (state.pollTimer) {
              clearInterval(state.pollTimer);
              state.pollTimer = null;
            }
            await loadCampaigns();
            await loadSourceCases();
            setTimeout(() => overlay?.remove(), 900);
          } catch (err) {
            if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
            sync();
          }
        });
        sync();
      }
    );
  }

  function openLevelBOverlay(jobId) {
    state.levelBOverlayJobId = jobId;
    ensureLevelBOverlay();
  }

  function originStatusNodeId(origin, executionId) {
    return origin === "campaign-panel"
      ? `cleanup-status-${executionId}-campaign-panel`
      : `cleanup-status-${executionId}-execution-card`;
  }

  function openOkConfirmDialog({ title, bodyIntro, bodyHtml, confirmLabel, onConfirm }) {
    openInteractiveOverlay(title, `
      <div class="space-y-4 text-sm text-slate-300">
        <div>${bodyIntro}</div>
        ${bodyHtml || ""}
        <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
          Type <span class="mono">OK</span> to confirm. If you close this modal or type a different value, nothing will be deleted or destroyed.
        </div>
        <label class="block">
          <span class="font-black">Confirmation</span>
          <input id="confirm-ok-input" class="w-full mt-3 rounded-xl bg-slate-950/60 border border-slate-700 px-3 py-2 text-slate-100" placeholder="Type OK">
        </label>
        <div class="flex gap-3 flex-wrap">
          <button type="button" id="confirm-ok-submit" class="btn-danger rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase opacity-50 cursor-not-allowed" disabled>${esc(confirmLabel)}</button>
          <button type="button" id="confirm-ok-cancel" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Cancel</button>
        </div>
        <div id="confirm-ok-result" class="text-sm text-slate-300"></div>
      </div>
    `, () => {
      const input = byId("confirm-ok-input");
      const submit = byId("confirm-ok-submit");
      const cancel = byId("confirm-ok-cancel");
      const overlay = byId("foc-experimentation-overlay");
      const sync = () => {
        const enabled = String(input?.value || "") === "OK";
        submit.disabled = !enabled;
        submit.classList.toggle("opacity-50", !enabled);
        submit.classList.toggle("cursor-not-allowed", !enabled);
      };
      input?.addEventListener("input", sync);
      cancel?.addEventListener("click", () => overlay?.remove());
      submit?.addEventListener("click", async () => {
        if (submit.disabled || typeof onConfirm !== "function") return;
        const resultNode = byId("confirm-ok-result");
        submit.disabled = true;
        submit.classList.add("opacity-50", "cursor-not-allowed");
        if (resultNode) resultNode.innerHTML = '<div class="text-slate-400">Executing action…</div>';
        await onConfirm(resultNode, overlay, submit);
      });
      sync();
    });
  }

  async function validateAndPromptCaseCleanup(executionId, campaignId, caseId, origin) {
    const statusNodeId = originStatusNodeId(origin, executionId);
    setInlineActionResult(statusNodeId, '<div class="text-slate-400">Validating cleanup requirements…</div>');
    let validation;
    try {
      validation = await getJson("/api/foc/experimentation/case-cleanup/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          campaign_id: campaignId,
          execution_id: executionId,
          case_id: caseId,
          action_type: "delete_case_directory",
        }),
      });
    } catch (err) {
      setInlineActionResult(statusNodeId, `<div class="text-red-300">${esc(err.message)}</div>`);
      return;
    }
    if (!validation.ready) {
      setInlineActionResult(statusNodeId, `<div class="text-amber-300">${esc(validation.message || "Cleanup validation failed.")}</div>`);
      openOverlay("Generated Case Cleanup Validation", `
        <div class="space-y-4 text-sm text-slate-300">
          <div>${esc(validation.message || "Cleanup validation failed.")}</div>
          ${renderValidationList(validation.checks)}
        </div>
      `);
      return;
    }
    openOkConfirmDialog({
      title: `Delete Generated Case Artifacts · ${executionId}`,
      bodyIntro: "This action will delete or archive heavy forensic artifacts for the generated case. Lightweight scientific comparison data will be preserved. Future comparisons will use result cards, comparison profiles, summaries, hashes, and registry entries, not full memory dumps, disk images, or PCAP equality.",
      bodyHtml: `
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div><span class="font-black">Execution:</span> <span class="mono">${esc(executionId)}</span></div>
          <div class="mt-2"><span class="font-black">Generated case:</span> <span class="mono">${esc(validation.case_id || caseId || "not_available")}</span></div>
          <div class="mt-2"><span class="font-black">Action type:</span> delete heavy case directory artifacts</div>
        </div>
        ${renderValidationList(validation.checks)}
      `,
      confirmLabel: "Delete Generated Case Artifacts",
      onConfirm: async (resultNode, overlay) => {
        try {
          const payload = await getJson("/api/foc/experimentation/case-cleanup/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              campaign_id: campaignId,
              execution_id: executionId,
              case_id: validation.case_id || caseId,
              action_type: "delete_case_directory",
              confirmation: "OK",
            }),
          });
          if (resultNode) resultNode.innerHTML = `<div class="text-cyan-300">${esc(payload.message || "Cleanup completed.")}</div>`;
          setInlineActionResult(statusNodeId, `<div class="text-cyan-300">${esc(payload.message || "Cleanup completed.")}</div>`);
          await loadCampaigns();
          setTimeout(() => overlay?.remove(), 600);
        } catch (err) {
          if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
        }
      },
    });
  }

  async function validateAndPromptScenarioDestroy(scenarioId, campaignId) {
    const resultNodeId = "destroy-scenario-result";
    setInlineActionResult(resultNodeId, '<div class="text-slate-400">Validating scenario destruction requirements…</div>');
    let validation;
    try {
      validation = await getJson("/api/foc/experimentation/scenario-destruction/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario_id: scenarioId,
          campaign_id: campaignId,
          action_type: "destroy_full_scenario",
        }),
      });
    } catch (err) {
      setInlineActionResult(resultNodeId, `<div class="text-red-300">${esc(err.message)}</div>`);
      return;
    }
    if (!validation.ready) {
      setInlineActionResult(resultNodeId, `<div class="text-amber-300">${esc(validation.message || "Scenario destruction validation failed.")}</div>`);
      openOverlay("Scenario Destruction Validation", `
        <div class="space-y-4 text-sm text-slate-300">
          <div>${esc(validation.message || "Scenario destruction validation failed.")}</div>
          ${renderValidationList(validation.checks)}
        </div>
      `);
      return;
    }
    openOkConfirmDialog({
      title: "Destroy Full Scenario For Level C Redeployment",
      bodyIntro: "You are about to destroy the active IT/OT scenario for Level C redeployment. This will remove active scenario resources but will not delete scientific comparison memory, scenario registry entries, result cards, comparison profiles, or reconstruction blueprints. Type OK to confirm.",
      bodyHtml: `
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div><span class="font-black">Scenario:</span> <span class="mono">${esc(validation.scenario_id || scenarioId || "not_available")}</span></div>
          <div class="mt-2"><span class="font-black">Scenario fingerprint:</span> <span class="mono">${esc(validation.scenario_fingerprint || "not_available")}</span></div>
          <div class="mt-2"><span class="font-black">Blueprint:</span> <span class="mono">${esc(validation.blueprint_path || "not_available")}</span></div>
        </div>
        ${renderValidationList(validation.checks)}
      `,
      confirmLabel: "Destroy Full Scenario",
      onConfirm: async (resultNode, overlay) => {
        try {
          const payload = await getJson("/api/foc/experimentation/scenario-destruction/destroy", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              scenario_id: validation.scenario_id || scenarioId,
              campaign_id: campaignId,
              action_type: "destroy_full_scenario",
              confirmation: "OK",
            }),
          });
          if (resultNode) resultNode.innerHTML = `<div class="text-cyan-300">${esc(payload.message || "Scenario destruction completed.")}</div>`;
          setInlineActionResult(resultNodeId, `<div class="text-cyan-300">${esc(payload.message || "Scenario destruction completed.")}</div>`);
          await loadCampaigns();
          await refreshProposalAndPreflight({ force: false });
          setTimeout(() => overlay?.remove(), 600);
        } catch (err) {
          if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
        }
      },
    });
  }

  async function loadHealth() {
    const payload = await getJson("/api/foc/experimentation/health");
    const root = byId("campaign-health");
    if (root) root.innerHTML = `Module: <span class="font-black text-cyan-300">${esc(payload.status)}</span> · root <span class="mono text-slate-400">${esc(payload.campaigns_root)}</span>`;
  }

  async function loadCampaigns() {
    state.executionCache.clear();
    const payload = await getJson("/api/foc/experimentation/campaigns");
    // Backend lists campaigns oldest-first (sorted CMP-* dir glob); reverse so the
    // most recently created campaign is what gets shown/selected by default, not the
    // oldest one (was pinning selection to the very first campaign ever created).
    state.campaigns = (payload.campaigns || []).slice().reverse();
    if (!state.campaigns.some((item) => item.campaign_id === state.selectedCampaignId)) {
      state.selectedCampaignId = state.campaigns.length ? state.campaigns[0].campaign_id : null;
    }
    renderCampaigns();
    await renderSelectedCampaign();
  }

  async function loadSourceCases() {
    const payload = await getJson("/api/foc/experimentation/source-cases");
    state.sourceCases = payload.cases || [];
    renderSourceCases();
  }

  async function loadAttackCatalog() {
    try {
      const payload = await getJson("/api/foc/experimentation/attack-catalog");
      state.attackCatalog = payload.attacks || [];
    } catch {
      state.attackCatalog = [];
    }
    renderAttackProfileOptions();
  }

  function renderAttackProfileOptions() {
    const select = byId("attack-profile-select");
    if (!select) return;
    const current = select.value;
    select.innerHTML = '<option value="">Select an attack profile…</option>' + state.attackCatalog.map((item) => `
      <option value="${esc(item.attack_id)}">${esc(item.display_name)} (${esc(item.mitre_id)})</option>
    `).join("");
    if ([...select.options].some((opt) => opt.value === current)) select.value = current;
  }

  function renderAttackProfileDetail() {
    const detail = byId("attack-profile-detail");
    if (!detail) return;
    const attackId = String(byId("attack-profile-select")?.value || "").trim();
    const attack = state.attackCatalog.find((item) => item.attack_id === attackId);
    if (!attack) {
      detail.innerHTML = '<div class="text-slate-400">No attack profile selected yet. The campaign will not specify a planned attack until one is selected here.</div>';
      return;
    }
    detail.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        <div><div class="text-xs text-slate-400">Attack profile</div><div class="font-black mt-1">${esc(attack.display_name)}</div></div>
        <div><div class="text-xs text-slate-400">MITRE</div><div class="font-black mt-1 mono">${esc(attack.mitre_id)} — ${esc(attack.mitre_technique)}</div></div>
        <div><div class="text-xs text-slate-400">Tactic / domain</div><div class="font-black mt-1">${esc(attack.tactic)} (${esc(attack.mitre_domain)})</div></div>
        <div><div class="text-xs text-slate-400">Script</div><div class="font-black mt-1 mono break-all">${esc(attack.script || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Severity</div><div class="font-black mt-1">${esc(attack.severity)}</div></div>
        <div><div class="text-xs text-slate-400">Detection engine</div><div class="font-black mt-1">${esc(attack.detection_engine || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Expected alerts</div><div class="font-black mt-1">${esc((attack.expected_alerts || []).join(", ") || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Expected artifacts</div><div class="font-black mt-1">${esc((attack.expected_artifacts || []).join(", ") || "not_available")}</div></div>
        <div><div class="text-xs text-slate-400">Rollback required</div><div class="font-black mt-1">${attack.rollback_required ? "Yes" : "No"}</div></div>
        <div><div class="text-xs text-slate-400">DFIR escalation expectation</div><div class="font-black mt-1">${attack.dfir_escalation ? "Yes — high/critical severity is treated as an escalation candidate." : "No"}</div></div>
      </div>
      <div class="mt-3 text-slate-400">${esc(attack.description || "")}</div>
      <div class="mt-3 text-cyan-200">This attack profile is used to define the experimental design and the comparison family. Changing it will normally create a new comparison family instead of preserving direct comparability with previous results.</div>
    `;
  }

  function syncAttackProfileField() {
    const field = byId("attack-profile-field");
    if (!field) return;
    const level = currentLevel();
    field.classList.toggle("hidden", level === "A");
    if (level !== "A") renderAttackProfileDetail();
  }

  async function loadMethodBasis() {
    renderMethodBasis(await getJson("/api/foc/experimentation/methodological-basis"));
  }

  function renderJob(payload) {
    const root = byId("job-panel");
    if (!root) return;
    if (payload && isLevelAReportJob(payload) && state.levelAReportOverlayJobId === payload.job_id) {
      renderLevelAReportOverlay(payload);
    }
    if (!payload) {
      root.innerHTML = `
        <div class="font-black">No active background job.</div>
        <div class="text-slate-400 mt-2">Campaign execution runs as background jobs. When a campaign or execution is started, this panel will show the active stage, job ID, progress, logs and errors.</div>
      `;
      return;
    }
    const isSummary = !!payload.summary_mode;
    const phaseStatuses = payload.phase_statuses || [];
    const lastPhase = phaseStatuses.length ? phaseStatuses[phaseStatuses.length - 1] : null;
    const terminal = isTerminalJobStatus(payload.status);
    const nestedTrace = payload.lifecycle_phase_trace || payload.phase_trace || [];
    const phaseLabel = terminal
      ? (lastPhase?.phase_label || payload.current_phase_label || titleCaseStatus(payload.current_phase || "completed"))
      : (payload.current_phase_label || titleCaseStatus(payload.current_phase || "queued"));
    const phaseDetail = terminal
      ? formatDetail(lastPhase?.detail || payload.current_phase_detail || "The job has already completed.")
      : formatDetail(payload.current_phase_detail || "No additional execution detail is currently available.");
    const phaseHeading = terminal ? "Last phase" : "Current phase";
    root.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${isSummary ? "Last job" : "Job ID"}</div><div class="font-black mt-2 mono">${esc(payload.job_id || "not_available")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Status</div><div class="font-black mt-2 ${statusClass(payload.status)}">${esc(titleCaseStatus(payload.status || "unknown"))}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${esc(phaseHeading)}</div><div class="font-black mt-2">${esc(phaseLabel)}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</div><div class="font-black mt-2">${esc(payload.progress_percent ?? "not_available")}${payload.progress_percent != null ? "%" : ""}</div></div>
      </div>
      ${payload.live_recovery_note ? `<div class="mt-4 rounded-2xl border border-cyan-500/30 bg-cyan-500/5 p-4 text-cyan-200">${esc(payload.live_recovery_note)}</div>` : ""}
      <div class="mt-4"><span class="font-black">Exact activity now:</span> ${esc(phaseDetail)}</div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <div><span class="font-black">Started at:</span> ${esc(payload.started_at || payload.requested_at || "not_available")}</div>
        <div><span class="font-black">Completed at:</span> ${esc(payload.finished_at || "not_available")}</div>
      </div>
      ${phaseStatuses.length ? `
        <div class="mt-4">
          <div class="font-black">Phase trace</div>
          <div class="space-y-2 mt-3">
            ${phaseStatuses.slice(-8).map((item) => `
              <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-3">
                <div class="flex items-center justify-between gap-3">
                  <div class="font-black">${esc(item.phase_label || item.phase_key)}</div>
                  <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status || "running"))}</div>
                </div>
                <div class="text-slate-400 mt-2">${esc(formatDetail(item.detail || "No detail available."))}</div>
                <div class="text-xs text-slate-500 mt-2">${esc(item.progress_percent)}% · ${esc(item.updated_at || "not_available")}</div>
              </div>
            `).join("")}
          </div>
        </div>
      ` : ""}
      ${payload.live_analysis_status?.phases ? `
        <div class="mt-5">
          <div class="font-black">Live multilayer execution order</div>
          <div class="text-slate-400 mt-2">These layers run in sequence, not in parallel. Only one layer should be actively running at a time; the rest remain queued until their turn.</div>
          <div class="space-y-3 mt-3">
            ${orderedAnalysisPhaseEntries(payload.live_analysis_status.phases || {}).map(([phaseKey, phase], index, entries) => {
              const phaseStatus = String(phase?.status || "pending").toLowerCase();
              const detail = phaseStatus === "pending"
                ? analysisPhaseQueueReason(entries, index)
                : (phase?.errors?.[0] || phase?.limitations?.[0] || `${analysisPhaseLabel(phaseKey)} is ${titleCaseStatus(phase?.status || "pending").toLowerCase()}.`);
              const timing = phaseStatus === "pending"
                ? "not_started · queued"
                : `${phase?.started_at || "not_started"} · ${phase?.finished_at || (phaseStatus === "running" ? "running" : "not_finished")}`;
              return `
              <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-3">
                <div class="flex items-center justify-between gap-3">
                  <div class="font-black">${index + 1}. ${esc(analysisPhaseLabel(phaseKey))}</div>
                  <div class="text-xs uppercase tracking-[0.16em] ${statusClass(phase?.status)}">${esc(titleCaseStatus(phase?.status || "pending"))}</div>
                </div>
                <div class="text-slate-400 mt-2">${esc(formatDetail(detail))}</div>
                <div class="text-xs text-slate-500 mt-2">${esc(timing)}</div>
              </div>
            `;
            }).join("")}
          </div>
        </div>
      ` : ""}
      ${nestedTrace.length ? `
        <div class="mt-5">
          <div class="font-black">Full Evidence Lifecycle nested trace</div>
          <div class="space-y-2 mt-3">
            ${renderNestedLifecycleTrace(nestedTrace)}
          </div>
        </div>
      ` : ""}
      ${payload.last_error ? `<div class="mt-4 text-red-300"><span class="font-black">Last error:</span> ${esc(formatDetail(payload.last_error))}</div>` : ""}
      ${(payload.generated_artifacts || []).length ? `<div class="mt-4"><span class="font-black">Generated artifacts:</span><div class="mt-2 space-y-1">${payload.generated_artifacts.map((item) => `<div class="mono text-slate-400">${esc(item)}</div>`).join("")}</div></div>` : ""}
      ${(payload.errors || []).length ? `<div class="mt-4 text-red-300"><span class="font-black">Errors:</span><div class="mt-2 space-y-1">${payload.errors.map((item) => `<div>${esc(item.message || JSON.stringify(item))}</div>`).join("")}</div></div>` : ""}
    `;
  }

  function renderNestedLifecycleTrace(trace) {
    const byParent = new Map();
    const roots = [];
    (trace || []).forEach((item) => {
      const key = item.parent_phase_id || "__root__";
      if (!byParent.has(key)) byParent.set(key, []);
      byParent.get(key).push(item);
      if (!item.parent_phase_id) roots.push(item);
    });
    const renderNode = (item, depth = 0) => {
      const children = byParent.get(item.phase_id) || [];
      const margin = depth * 18;
      const warnings = item.warnings || [];
      const blockers = item.blockers || [];
      return `
        <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-3" style="margin-left:${margin}px">
          <div class="flex items-center justify-between gap-3">
            <div>
              <div class="font-black">${esc(item.phase_label || item.phase_id || "phase")}</div>
          <div class="text-[11px] uppercase tracking-[0.16em] text-slate-500 mt-1">${esc(item.layer || "lifecycle")}</div>
            </div>
            <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCaseStatus(item.status || "unknown"))}</div>
          </div>
          <div class="text-slate-300 mt-2">${esc(formatDetail(item.detail || "No detail available."))}</div>
          <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2 mt-3 text-xs text-slate-400">
            <div><span class="font-black text-slate-300">Started:</span> ${esc(item.utc_start_time || "not_available")}</div>
            <div><span class="font-black text-slate-300">Finished:</span> ${esc(item.utc_end_time || "not_available")}</div>
            <div><span class="font-black text-slate-300">Duration:</span> ${item.duration_ms != null ? `${esc(item.duration_ms)} ms` : "not_available"}</div>
            <div><span class="font-black text-slate-300">Artifacts / findings:</span> ${esc(item.number_of_artifacts_processed ?? "n/a")} / ${esc(item.number_of_findings_generated ?? "n/a")}</div>
          </div>
          ${(item.input_artifacts_used || []).length ? `<div class="mt-3 text-xs"><span class="font-black text-slate-300">Input artifacts:</span><div class="mt-1 space-y-1">${item.input_artifacts_used.map((v) => `<div class="mono text-slate-500">${esc(v)}</div>`).join("")}</div></div>` : ""}
          ${(item.output_artifacts_generated || []).length ? `<div class="mt-3 text-xs"><span class="font-black text-slate-300">Output artifacts:</span><div class="mt-1 space-y-1">${item.output_artifacts_generated.map((v) => `<div class="mono text-slate-500">${esc(v)}</div>`).join("")}</div></div>` : ""}
          ${warnings.length ? `<div class="mt-3 text-amber-300 text-xs"><span class="font-black">Warnings:</span><div class="mt-1 space-y-1">${warnings.map((v) => `<div>${esc(v)}</div>`).join("")}</div></div>` : ""}
          ${blockers.length ? `<div class="mt-3 text-red-300 text-xs"><span class="font-black">Blockers:</span><div class="mt-1 space-y-1">${blockers.map((v) => `<div>${esc(v)}</div>`).join("")}</div></div>` : ""}
          ${item.scientific_limitation_reason ? `<div class="mt-3 text-xs text-amber-200"><span class="font-black">Scientific limitation:</span> ${esc(item.scientific_limitation_reason)}</div>` : ""}
        </div>
        ${children.map((child) => renderNode(child, depth + 1)).join("")}
      `;
    };
    return roots.map((item) => renderNode(item)).join("");
  }

  async function pollJob() {
    if (!state.activeJobId) return;
    try {
      const rawPayload = await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(state.activeJobId)}`);
      const hydrated = await hydrateExperimentationJob(rawPayload);
      const payload = hydrated.payload;
      if (isLevelAReportJob(payload) && !state.levelAReportOverlayJobId) {
        openLevelAReportProgressOverlay(payload.job_id);
      }
      if (isLevelBRepetitionJob(payload) && !state.levelBOverlayJobId) {
        openLevelBOverlay(payload.job_id);
      }
      renderJob(payload);
      renderLevelAReportOverlay(payload);
      renderLevelBOverlay(payload);
      saveActiveJob({
        job_id: payload.job_id,
        campaign_id: (payload.meta || {}).campaign_id || null,
        title: payload.title || "",
      });
      if (!hydrated.continuePolling) {
        state.activeJobId = null;
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        clearActiveJob();
        await loadCampaigns();
        return;
      }
    } catch (err) {
      console.error(err);
    }
  }

  function trackJob(jobId) {
    state.activeJobId = jobId;
    const campaign = selectedCampaign();
    saveActiveJob({ job_id: jobId, campaign_id: campaign?.campaign_id || null, title: "Experimentation job" });
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(pollJob, 2500);
    pollJob();
  }

  async function createCampaignFromForm(event) {
    event.preventDefault();
    const blockedReason = builderCreateBlockedReason();
    const successNode = byId("campaign-create-success");
    if (blockedReason) {
      if (successNode) successNode.innerHTML = `<div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">${esc(blockedReason)}</div>`;
      return;
    }
    const payload = buildFormPayload();
    if (state.preflight && !state.preflight.ready) {
      const proceed = window.confirm("Pre-flight validation still shows missing requirements. Create the campaign anyway as a scaffolded experimental container?");
      if (!proceed) return;
    }
    let res;
    try {
      res = await getJson("/api/foc/experimentation/campaigns/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      if (successNode) successNode.innerHTML = `<div class="rounded-2xl border border-red-500/30 bg-red-500/5 p-4 text-red-300">${esc(err.message)}</div>`;
      return;
    }
    state.selectedCampaignId = res.campaign.campaign_id;
    state.dirtyFields.clear();
    await loadCampaigns();
    renderBuilderSelectedCampaignNote();
    if (successNode) {
      const level = String(res.campaign.level || "A").toUpperCase();
      successNode.innerHTML = `
        <div class="rounded-2xl border border-cyan-500/30 bg-cyan-500/5 p-4 text-cyan-200">
          <div class="font-black">Campaign created successfully.</div>
          <div class="mt-2"><span class="font-black">Next action:</span> Run first Level ${esc(level)} execution.</div>
        </div>
      `;
    }
  }

  async function changeCampaignState(targetState) {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const payload = await getJson(`/api/foc/experimentation/campaigns/${encodeURIComponent(campaign.campaign_id)}/${targetState}`, { method: "POST" });
    if (targetState === "start" && payload.job?.job_id) {
      trackJob(payload.job.job_id);
    }
    await loadCampaigns();
  }

  async function runNextExecution() {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const res = await getJson(`/api/foc/experimentation/campaigns/${encodeURIComponent(campaign.campaign_id)}/run-next`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    trackJob(res.job_id);
  }

  async function generateLevelAScientificReport() {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const level = String(campaign.level || state.selectedCampaignDetail?.config?.level || "A").toUpperCase();
    if (level !== "A") return;
    const res = await getJson("/api/foc/repetitions/level-a/report/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ campaign_id: campaign.campaign_id }),
    });
    openLevelAReportProgressOverlay(res.job_id);
    trackJob(res.job_id);
  }

  async function generatePaperEvidence(level) {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const cfg = state.selectedCampaignDetail?.config || {};
    const requestedLevel = String(level || campaign.level || "A").toUpperCase();
    const requestedRepetitions = Math.max(Number(byId("repetitions-input")?.value || cfg.repetitions || state.proposal?.number_of_repetitions || 6), 1);
    const nestedLevelARepetitions = requestedLevel === "B"
      ? Math.max(Number(byId("nested-level-a-repetitions-input")?.value || cfg.nested_level_a_repetitions || state.proposal?.nested_level_a_repetitions || requestedRepetitions), 1)
      : undefined;
    const payload = {
      level: requestedLevel,
      case_id: cfg.base_case_id || cfg.run_case_id || null,
      scenario_id: cfg.scenario_id || campaign.scenario_id || null,
      attack_profile_id: cfg.attack_id || null,
      acquisition_profile_id: cfg.acquisition_profile_id || null,
      trigger_policy_id: cfg.trigger_policy_id || null,
      n_repetitions: requestedRepetitions,
      nested_level_a_repetitions: nestedLevelARepetitions,
      dry_run: true,
      generate_latex: true,
      generate_zip: true,
    };
    const endpoint = requestedLevel === "A"
      ? "/api/foc/paper-evidence/level-a/run"
      : requestedLevel === "B"
        ? "/api/foc/paper-evidence/level-b/run"
        : "/api/foc/paper-evidence/level-c/run";
    const res = await getJson(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    trackJob(res.job_id);
  }

  async function openLevelAReport(executionId, campaignId = null) {
    if (!executionId) return;
    const suffix = campaignId ? `?campaign_id=${encodeURIComponent(campaignId)}` : "";
    const payload = await getJson(`/api/foc/repetitions/level-a/report/open/${encodeURIComponent(executionId)}${suffix}`);
    openOverlay(
      `Level A Scientific Report · ${executionId}`,
      `
        <div class="space-y-4">
          <div class="text-sm text-slate-300">
            <div><span class="font-black">Case ID:</span> <span class="mono">${esc(payload.case_id || "not_available")}</span></div>
            <div class="mt-2"><span class="font-black">Report path:</span> <span class="mono break-all">${esc(payload.report_path || payload.report_output_path || "not_available")}</span></div>
            <div class="mt-2"><span class="font-black">Generated at:</span> ${esc(payload.generated_at || "not_available")}</div>
            <div class="mt-2"><span class="font-black">Status:</span> ${esc(titleCaseStatus(payload.status || "unknown"))}</div>
          </div>
          <details class="helper-details" open>
            <summary class="help-chip">Scientific Markdown Report</summary>
            <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.report_markdown || "Report markdown not available.")}</pre>
          </details>
          <details class="helper-details">
            <summary class="help-chip">Evidence-To-Claim Map</summary>
            <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.evidence_to_claim_map || {}, null, 2))}</pre>
          </details>
          <details class="helper-details">
            <summary class="help-chip">Source Files Index</summary>
            <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.source_files_index || {}, null, 2))}</pre>
          </details>
        </div>
      `
    );
  }

  async function openLevelBReport(jobId) {
    if (!jobId) return;
    const payload = await getJson(`/api/foc/repetitions/level-b/report/${encodeURIComponent(jobId)}`);
    openOverlay(
      `Level B Repetition Report · ${jobId}`,
      `
        <div class="space-y-4">
          <div class="text-sm text-slate-300">
            <div><span class="font-black">Status:</span> ${esc(titleCaseStatus(payload.status || "unknown"))}</div>
            <div class="mt-2"><span class="font-black">Report path:</span> <span class="mono break-all">${esc(payload.report_path || "not_available")}</span></div>
            <div class="mt-2"><span class="font-black">Report directory:</span> <span class="mono break-all">${esc(payload.report_dir || "not_available")}</span></div>
            <div class="mt-2"><span class="font-black">Generated at:</span> ${esc(payload.generated_at || "not_available")}</div>
          </div>
          <details class="helper-details" open>
            <summary class="help-chip">Markdown Summary</summary>
            <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(payload.summary_markdown || "Summary markdown not available.")}</pre>
          </details>
          <details class="helper-details">
            <summary class="help-chip">Main JSON Report</summary>
            <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.report_json || {}, null, 2))}</pre>
          </details>
          <details class="helper-details">
            <summary class="help-chip">Cleanup Manifest</summary>
            <pre class="whitespace-pre-wrap break-words text-xs text-slate-200 mono mt-4">${esc(JSON.stringify(payload.cleanup_manifest || {}, null, 2))}</pre>
          </details>
        </div>
      `
    );
  }

  function renderLatestLevelBReportSection(campaign) {
    const reports = campaign?.validation_reports || {};
    const latest = reports.latest_level_b || null;
    if (!latest) return "";
    return `
      <div class="rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-4">
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <div class="font-black text-cyan-200">Latest Level B Report</div>
            <div class="text-slate-400 mt-1">Generated at ${esc(latest.generated_at || "not_available")}.</div>
            <div class="text-slate-400 mt-1 mono break-all">${esc(latest.report_dir || latest.main_report_path || "not_available")}</div>
          </div>
          ${latest.job_id ? `<button type="button" class="btn-primary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase" data-open-level-b-report="${esc(latest.job_id)}">Open Latest Report</button>` : ""}
        </div>
      </div>
    `;
  }

  async function runLevelBRepetitions() {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const requestedRepetitions = Math.max(Number(byId("repetitions-input")?.value || state.selectedCampaignDetail?.config?.repetitions || state.proposal?.number_of_repetitions || 3), 1);
    const nestedLevelARepetitions = Math.max(Number(byId("nested-level-a-repetitions-input")?.value || state.selectedCampaignDetail?.config?.nested_level_a_repetitions || state.proposal?.nested_level_a_repetitions || requestedRepetitions), 1);
    let preview;
    try {
      preview = await getJson("/api/foc/repetitions/level-b/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          campaign_id: campaign.campaign_id,
          requested_repetitions: requestedRepetitions,
          nested_level_a_repetitions: nestedLevelARepetitions,
          preview_only: true,
        }),
      });
    } catch (err) {
      openOverlay("Level B Repetition Preview", `<div class="text-red-300 text-sm">${esc(err.message)}</div>`);
      return;
    }
    if (!preview.ready) {
      openOverlay(
        "Level B Repetition Preview",
        `
          <div class="space-y-4 text-sm text-slate-300">
            <div>${esc(preview.message || "The Level B repetition batch is not ready.")}</div>
            <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
              <div><span class="font-black">Campaign:</span> <span class="mono">${esc(campaign.campaign_id)}</span></div>
              <div class="mt-2"><span class="font-black">Scenario:</span> <span class="mono">${esc(preview.scenario_id || "not_available")}</span></div>
              <div class="mt-2"><span class="font-black">Attack profile:</span> <span class="mono">${esc(preview.attack_profile_id || "not_available")}</span></div>
            </div>
          </div>
        `
      );
      return;
    }
    const cleanup = preview.cleanup_preview || {};
    const dfirBefore = getBrowserDfirMode();
    openInteractiveOverlay(
      `Run Level B Repetitions · ${campaign.campaign_id}`,
      `
        <div class="space-y-4 text-sm text-slate-300">
          <div>This workflow will run ${esc(preview.requested_repetitions || requestedRepetitions)} independent repetitions of the same OT register-modification attack in the same deployed scenario. After each new Level B case is preserved and analyzed, it will also launch ${esc(preview.nested_level_a_repetitions || nestedLevelARepetitions)} nested Level A dry-run repetitions over that preserved case and include both levels of comparability in the final report.</div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div><span class="font-black">Scenario:</span> <span class="mono">${esc(preview.scenario_id || "not_available")}</span></div>
            <div class="mt-2"><span class="font-black">Attack:</span> <span class="mono">${esc(preview.attack_profile_id || "not_available")}</span> · ${esc(preview.attack_name || "not_available")}</div>
            <div class="mt-2"><span class="font-black">Target verified:</span> <span class="mono">${esc(preview.resolved_target?.vm_name || "not_available")}</span> (${esc(preview.resolved_target?.vm_ip || "not_available")})</div>
            <div class="mt-2"><span class="font-black">Monitor:</span> <span class="mono">${esc(preview.resolved_monitor?.vm_name || "not_available")}</span> (${esc(preview.resolved_monitor?.vm_ip || "not_available")})</div>
            <div class="mt-2"><span class="font-black">Requested Level B repetitions:</span> <span class="mono">${esc(preview.requested_repetitions || requestedRepetitions)}</span></div>
            <div class="mt-2"><span class="font-black">Nested Level A repetitions per new case:</span> <span class="mono">${esc(preview.nested_level_a_repetitions || nestedLevelARepetitions)}</span></div>
          </div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div class="font-black">Safe cleanup before run</div>
            <div class="mt-2">Removable heavy cases detected: <span class="mono">${esc(cleanup.count || 0)}</span></div>
            <div class="mt-2">Estimated freed disk space: <span class="mono">${esc(cleanup.freed_human_estimated || "0 B")}</span></div>
            <label class="mt-3 flex items-start gap-3">
              <input id="level-b-cleanup-checkbox" type="checkbox" class="mt-1">
              <span>Delete old removable heavy forensic cases before launching the ${esc(preview.requested_repetitions || requestedRepetitions)} repetitions. Only preserved case directories are removed. Scenario configuration, attack profiles, acquisition profiles, validation reports, code, and dashboards are kept.</span>
            </label>
          </div>
          <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
            Browser DFIR mode before this action: <span class="mono">${esc(dfirBefore)}</span>. If it is OFF, this dialog will switch the same platform DFIR browser mode to ON before starting the batch, and the backend will block the attack if the resulting mode is not ON.
          </div>
          <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
            Type <span class="mono">OK</span> to confirm. If you close this modal or type a different value, nothing will be launched or deleted.
          </div>
          <label class="block">
            <span class="font-black">Confirmation</span>
            <input id="confirm-ok-input" class="w-full mt-3 rounded-xl bg-slate-950/60 border border-slate-700 px-3 py-2 text-slate-100" placeholder="Type OK">
          </label>
          <div class="flex gap-3 flex-wrap">
            <button type="button" id="confirm-ok-submit" class="btn-danger rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase opacity-50 cursor-not-allowed" disabled>Run Level B Repetitions</button>
            <button type="button" id="confirm-ok-cancel" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Cancel</button>
          </div>
          <div id="confirm-ok-result" class="text-sm text-slate-300"></div>
        </div>
      `,
      () => {
        const input = byId("confirm-ok-input");
        const submit = byId("confirm-ok-submit");
        const cancel = byId("confirm-ok-cancel");
        const overlay = byId("foc-experimentation-overlay");
        const cleanupBox = byId("level-b-cleanup-checkbox");
        const sync = () => {
          const enabled = String(input?.value || "") === "OK";
          submit.disabled = !enabled;
          submit.classList.toggle("opacity-50", !enabled);
          submit.classList.toggle("cursor-not-allowed", !enabled);
        };
        input?.addEventListener("input", sync);
        cancel?.addEventListener("click", () => overlay?.remove());
        submit?.addEventListener("click", async () => {
          if (submit.disabled) return;
          const resultNode = byId("confirm-ok-result");
          submit.disabled = true;
          submit.classList.add("opacity-50", "cursor-not-allowed");
          if (resultNode) resultNode.innerHTML = '<div class="text-slate-400">Starting Level B batch…</div>';
          const before = getBrowserDfirMode();
          const after = before === "on" ? before : setBrowserDfirModeOn();
          try {
            const res = await getJson("/api/foc/repetitions/level-b/run", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                campaign_id: campaign.campaign_id,
                requested_repetitions: requestedRepetitions,
                nested_level_a_repetitions: nestedLevelARepetitions,
                cleanup_old_cases: !!cleanupBox?.checked,
                confirmation: "OK",
                dfir_mode_before: before,
                dfir_mode_after: after,
              }),
            });
            if (resultNode) resultNode.innerHTML = `<div class="text-cyan-300">Level B batch started. Job ID: <span class="mono">${esc(res.job_id || "not_available")}</span></div>`;
            openLevelBOverlay(res.job_id);
            trackJob(res.job_id);
            setTimeout(() => overlay?.remove(), 900);
          } catch (err) {
            if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
          }
        });
        sync();
      }
    );
  }

  function runRealLevelBExecution() {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const cfg = state.selectedCampaignDetail?.config || {};
    openOkConfirmDialog({
      title: `Run Real Level B Execution · ${campaign.campaign_id}`,
      bodyIntro: "Level B is not only a campaign metadata generator. It must orchestrate a real controlled incident execution: arm DFIR auto, launch the selected attack, wait for detection, create a new case, acquire evidence, analyze it, and register comparable results. This will launch a real attack against real lab infrastructure, wait for a real alert, and create a new forensic case. It does not reuse or modify any previous case.",
      bodyHtml: `
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div><span class="font-black">Campaign:</span> <span class="mono">${esc(campaign.campaign_id)}</span></div>
          <div class="mt-2"><span class="font-black">Scenario:</span> <span class="mono">${esc(cfg.scenario_id || campaign.scenario_id || "not_available")}</span></div>
          <div class="mt-2"><span class="font-black">Attack profile:</span> <span class="mono">${esc(cfg.attack_id || "not_available")}</span></div>
        </div>
        <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
          If no alert matching this attack's detection criteria is observed within the configured timeout, the execution is marked <span class="mono">failed_detection</span> and no forensic case is created. It is never marked successful without a real detection and real acquisition.
        </div>
      `,
      confirmLabel: "Run Real Level B Execution",
      onConfirm: async (resultNode, overlay) => {
        try {
          const res = await getJson(`/api/foc/experimentation/campaigns/${encodeURIComponent(campaign.campaign_id)}/run-real`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ confirmation: "OK" }),
          });
          if (resultNode) resultNode.innerHTML = `<div class="text-cyan-300">Real Level B execution started. Job ID: <span class="mono">${esc(res.job_id || "not_available")}</span></div>`;
          trackJob(res.job_id);
          setTimeout(() => overlay?.remove(), 900);
        } catch (err) {
          if (resultNode) resultNode.innerHTML = `<div class="text-red-300">${esc(err.message)}</div>`;
        }
      },
    });
  }

  function bindFieldListeners() {
    ["source-case-select", "scenario-id-input", "campaign-name-input", "repetitions-input", "nested-level-a-repetitions-input", "notes-input", "baseline-threshold-input", "delta-wcpr-input", "baseline-window-input", "description-input", "attack-profile-select"].forEach((id) => {
      const node = byId(id);
      if (!node) return;
      node.addEventListener("input", markFieldDirty);
      node.addEventListener("change", async (event) => {
        markFieldDirty(event);
        if (id === "source-case-select") {
          state.currentCaseId = currentSourceCaseId();
        }
        if (id === "attack-profile-select") {
          renderAttackProfileDetail();
          if (!state.lastRecommendation?.has_recommendation) state.recommendedFamily = null;
          updateCampaignNameFromSelection();
          await refreshProposalAndPreflight({ force: false });
        } else if (id === "source-case-select" || id === "scenario-id-input") {
          await refreshProposalAndPreflight({ force: false });
        } else {
          const preflight = await getJson("/api/foc/experimentation/campaigns/preflight", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(buildFormPayload()),
          });
          renderPreflight(preflight);
          renderSourceSummary();
          renderExecutionPlan();
          applyBuilderCreateState();
        }
      });
    });
    document.querySelectorAll(".level-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const level = btn.dataset.level;
        byId("level-hidden").value = level;
        syncLevelButtons();
        state.dirtyFields.delete("campaign-name-input");
        await refreshProposalAndPreflight({ level, force: true });
      });
    });
    byId("guided-mode-btn")?.addEventListener("click", async () => {
      state.guidedMode = true;
      renderModeButtons();
      await refreshProposalAndPreflight({ force: false });
    });
    byId("advanced-mode-btn")?.addEventListener("click", () => {
      state.guidedMode = false;
      renderModeButtons();
    });
  }

  async function init() {
    byId("campaign-create-form")?.addEventListener("submit", createCampaignFromForm);
    byId("campaign-refresh-btn")?.addEventListener("click", async () => {
      await loadCampaigns();
      await loadSourceCases();
      await refreshProposalAndPreflight({ force: false });
    });
    byId("campaign-start-btn")?.addEventListener("click", () => changeCampaignState("start"));
    byId("campaign-pause-btn")?.addEventListener("click", () => changeCampaignState("pause"));
    byId("campaign-stop-btn")?.addEventListener("click", () => changeCampaignState("stop"));
    byId("campaign-run-next-btn")?.addEventListener("click", runNextExecution);
    byId("campaign-level-a-report-btn")?.addEventListener("click", generateLevelAScientificReport);
    byId("campaign-paper-level-a-btn")?.addEventListener("click", () => generatePaperEvidence("A"));
    byId("campaign-paper-level-b-btn")?.addEventListener("click", () => generatePaperEvidence("B"));
    byId("campaign-paper-level-c-btn")?.addEventListener("click", () => generatePaperEvidence("C"));
    byId("campaign-run-real-btn")?.addEventListener("click", runRealLevelBExecution);
    byId("campaign-run-level-b-repetitions-btn")?.addEventListener("click", runLevelBRepetitions);
    byId("register-case-btn")?.addEventListener("click", registerExistingCaseAsResultCard);
    byId("global-cleaner-btn")?.addEventListener("click", openGlobalCleaner);
    bindRecommendedExperimentButtons();
    bindFieldListeners();
    renderModeButtons();
    renderViewModeButtons();
    renderStoryIntro();
    const restored = loadActiveJob();
    if (restored?.job_id) {
      state.activeJobId = restored.job_id;
      if (state.pollTimer) clearInterval(state.pollTimer);
      state.pollTimer = setInterval(pollJob, 2500);
    }
    await loadHealth();
    await loadSourceCases();
    await loadAttackCatalog();
    await loadMethodBasis();
    await refreshProposalAndPreflight({ caseId: state.currentCaseId || currentSourceCaseId(), force: true });
    await loadCampaigns();
    renderStoryIntro();
    renderLevelStory();
    renderStoryline();
    renderCampaignStoryPanel();
    if (state.activeJobId) {
      pollJob();
    }
    byId("story-mode-btn")?.addEventListener("click", () => {
      state.storyMode = true;
      renderViewModeButtons();
    });
    byId("technical-mode-btn")?.addEventListener("click", () => {
      state.storyMode = false;
      renderViewModeButtons();
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
