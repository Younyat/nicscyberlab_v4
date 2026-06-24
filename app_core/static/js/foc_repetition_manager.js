(function () {
  "use strict";

  const LEVEL_META = {
    A: {
      short: "Level A",
      long: "Level A — Reanalysis Repeatability",
      purpose: "Repeat the analysis and reconstruction pipeline over the same preserved case without modifying the original evidence.",
      sourceMode: "linked_existing_case",
      sourceModeLabel: "Linked existing case",
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
      dashboardActionLabel: "Open Execution Dashboard",
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
      dashboardActionLabel: "Open Execution Dashboard",
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
  };
  const ACTIVE_JOB_STORAGE_KEY = "nics-foc-experimentation-active-job";

  const byId = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  const truthy = (value) => !!value && value !== "not_available";
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
    if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
    return data;
  }

  function titleCaseStatus(value) {
    return String(value || "unknown")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (ch) => ch.toUpperCase());
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
    const profilesAvailable = execs.filter((item) => item.artifacts?.forensic_comparison_profile).length;
    const level = String(campaign.level || "A").toUpperCase();
    root.innerHTML = `
      <div class="font-black text-cyan-300">Beginner Summary</div>
      <div class="mt-3">This campaign is creating controlled executions for ${esc(LEVEL_META[level].long)}. Right now it has ${execs.length} execution(s), and ${profilesAvailable} of them already have a forensic comparison profile. This view is preparing the comparison material, not judging comparability yet.</div>
      <div class="mt-4 font-black text-cyan-300">Expert Summary</div>
      <div class="mt-3">Campaign <span class="mono">${esc(campaign.campaign_id)}</span> is scoped to ${esc(LEVEL_META[level].long)} with source mode <span class="mono">${esc(sourceModeLabel(campaign.source_mode || LEVEL_META[level].sourceMode))}</span>. The current objective is to generate stable execution workspaces, manifests, seals, noise profiles when applicable, and <span class="mono">forensic_comparison_profile.json</span> for later execution-to-execution evaluation.</div>
    `;
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
    if (!select) return;
    const current = select.value;
    select.innerHTML = '<option value="">No linked case</option>' + state.sourceCases.map((item) => `
      <option value="${esc(item.case_id)}">${esc(item.case_id)} · ${esc(item.source_case_name || item.case_dir_name || item.path || "preserved case")}</option>
    `).join("");
    const preferred = state.currentCaseId || current;
    if ([...select.options].some((opt) => opt.value === preferred)) {
      select.value = preferred;
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
      <div class="mt-3"><span class="font-black">Automatically generated:</span></div>
      <ul class="mt-2 list-disc pl-5 text-slate-400 space-y-1">${(explanation.auto_generated || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
    `;
    renderLevelStory();
    renderStoryline();
    renderCampaignStoryPanel();
  }

  function renderSourceSummary() {
    const panel = byId("source-summary-panel");
    if (!panel) return;
    const level = currentLevel();
    const caseId = currentSourceCaseId();
    const scenarioId = currentScenarioId() || "not_available";
    const sourceMode = LEVEL_META[level]?.sourceMode || state.proposal?.source_mode || "linked_existing_case";
    const sourceCase = state.sourceCases.find((item) => item.case_id === caseId);
    panel.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Source mode</div>
          <div class="font-black mt-2">${esc(sourceModeLabel(sourceMode))}</div>
          <div class="text-slate-400 mt-2">${esc(sourceModeExplanation(sourceMode))}</div>
        </div>
        <div>
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">Scenario and source context</div>
          <div class="mt-2"><span class="font-black">Linked source case:</span> ${esc(caseId || "not_selected")}</div>
          <div class="mt-2"><span class="font-black">Scenario ID:</span> ${esc(scenarioId)}</div>
          ${!truthy(scenarioId) ? `<div class="mt-2 text-amber-300">Scenario ID could not be extracted automatically. For Level A this is allowed, but the comparison profile will be weaker. For Level B and Level C, scenario ID should be provided before execution.</div>` : ""}
          ${sourceCase ? `<div class="mt-2 text-slate-400">Selected case path: <span class="mono">${esc(sourceCase.path || sourceCase.case_path || "not_available")}</span></div>` : ""}
        </div>
      </div>
      ${level === "A" && !caseId ? `<div class="mt-4 text-red-300">A linked source case is required for Level A. Select a preserved case or open the manager from the Scientific Lifecycle dashboard.</div>` : ""}
    `;
    renderStoryline();
  }

  function renderGuidedDefaults() {
    const panel = byId("guided-defaults-panel");
    if (!panel) return;
    const p = state.proposal || {};
    const level = currentLevel();
    panel.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Default repetitions</div><div class="font-black mt-2">${esc(p.number_of_repetitions ?? "not_available")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Baseline threshold</div><div class="font-black mt-2">${esc(p.baseline_threshold ?? "0.15")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Delta WCPR allowed</div><div class="font-black mt-2">${esc(p.delta_wcpr_allowed ?? "0.10")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Baseline window</div><div class="font-black mt-2">${esc(p.baseline_window_seconds ?? "60")}s</div></div>
      </div>
      <div class="mt-4"><span class="font-black">Ground truth seal:</span> ${esc(p.ground_truth_seal_mode || LEVEL_META[level]?.groundTruthLabel || "not_available")}</div>
      <div class="mt-2"><span class="font-black">Comparison profile after each run:</span> ${p.comparison_profile_after_each_run ? "enabled by default" : "disabled"}</div>
      <div class="mt-2 text-slate-400">${esc(p.methodological_notes || "")}</div>
    `;
  }

  function renderExecutionPlan() {
    const panel = byId("execution-plan-panel");
    if (!panel) return;
    const level = currentLevel();
    const explanation = state.proposal?.level_explanation || {};
    const meta = LEVEL_META[level];
    const sourceMode = LEVEL_META[level]?.sourceMode || "linked_existing_case";
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
      <div class="mt-4 text-slate-400">The generated artifacts will later be consumed by the Forensic Reconstruction Comparability View, especially <span class="mono">forensic_comparison_profile.json</span>.</div>
    `;
    renderStoryline();
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
    renderStoryline();
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
      source_mode: LEVEL_META[level]?.sourceMode,
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
            <div><span class="font-black">Source:</span> ${esc(sourceModeLabel(sourceMode))}</div>
            <div class="mt-2"><span class="font-black">Linked base case:</span> ${esc(cfg.base_case_id || cfg.run_case_id || cfg.base_case_path || cfg.run_case_path || "not_configured")}</div>
            <div class="mt-2"><span class="font-black">Source case policy:</span> ${level === "A" ? "Read-only. The original case will not be modified." : "Campaign workspaces remain isolated from the original evidence store."}</div>
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
        ${technicalFailures.length ? `
          <div>
            <div class="font-black text-red-300">Technical failures</div>
            <ul class="mt-2 list-disc pl-5 text-slate-300 space-y-1">${technicalFailures.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
          </div>
        ` : ""}
        ${scientificLimitations.length ? `
          <div>
            <div class="font-black text-amber-300">Scientific limitations</div>
            <ul class="mt-2 list-disc pl-5 text-slate-300 space-y-1">${scientificLimitations.slice(0, 8).map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
            ${scientificLimitations.length > 8 ? `<div class="text-xs text-slate-500 mt-2">Showing 8 of ${esc(scientificLimitations.length)} recorded scientific limitations.</div>` : ""}
          </div>
        ` : ""}
      </div>
    `;

    applyCampaignActionState(campaign, runningJob);

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
  }

  function applyCampaignActionState(campaign, runningJob) {
    const busy = !!runningJob || !!state.activeJobId;
    const startBtn = byId("campaign-start-btn");
    const runNextBtn = byId("campaign-run-next-btn");
    const pauseBtn = byId("campaign-pause-btn");
    const stopBtn = byId("campaign-stop-btn");
    if (startBtn) {
      startBtn.disabled = busy;
      startBtn.classList.toggle("opacity-50", busy);
      startBtn.classList.toggle("cursor-not-allowed", busy);
      startBtn.textContent = busy ? "Campaign Running" : "Start Campaign";
      startBtn.title = busy ? "A campaign job is already running for this workspace." : "";
    }
    if (runNextBtn) {
      runNextBtn.disabled = busy;
      runNextBtn.classList.toggle("opacity-50", busy);
      runNextBtn.classList.toggle("cursor-not-allowed", busy);
      runNextBtn.textContent = busy ? "Execution In Progress" : "Run Next Execution";
      runNextBtn.title = busy ? "Wait until the current experimentation job finishes." : "";
    }
    if (pauseBtn) pauseBtn.disabled = !campaign;
    if (stopBtn) stopBtn.disabled = !campaign;
  }

  function renderExecutionCard(item, comparableCount) {
    const level = String(item.level || "A").toUpperCase();
    const meta = LEVEL_META[level] || LEVEL_META.A;
    const profileAvailable = hasComparisonProfile(item);
    const sealState = level === "A"
      ? (item.artifacts?.ground_truth_seal ? "Reused from base case or reconstructed from preserved artifacts." : "Missing")
      : (item.artifacts?.ground_truth_seal ? "Available" : "Missing");
    const baselineState = level === "A"
      ? "Not applicable for Level A"
      : (item.artifacts?.baseline_noise_profile ? "Available" : "Missing");
    const sourceCase = item.source_case_id || item.base_case_id || item.run_case_id || "not_available";
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
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Source</div><div class="font-black mt-2">Base case ${esc(sourceCase)}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Generated profile</div><div class="font-black mt-2 ${profileAvailable ? "text-cyan-300" : "text-red-300"}">${profileAvailable ? "Available" : "Missing"}</div></div>
          <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Ground truth seal</div><div class="font-black mt-2">${esc(sealState)}</div></div>
        </div>
        <div><span class="font-black">Status explanation:</span> ${esc(statusExplanation(item.status, "execution"))}</div>
        <div><span class="font-black">Baseline noise:</span> ${esc(baselineState)}</div>
        ${item.warnings?.length ? `<div class="text-amber-300"><span class="font-black">Warnings:</span> ${esc(item.warnings.join(" | "))}</div>` : ""}
        <div class="flex gap-3 flex-wrap">
          <a class="text-cyan-300 underline" href="/foc_scientific_evidence_lifecycle.html?case_id=${encodeURIComponent(sourceCase)}">${esc(meta.dashboardActionLabel)}</a>
          <button type="button" class="text-cyan-300 underline execution-workspace-btn" data-execution-id="${esc(item.execution_id)}">Open Execution Workspace</button>
          <button type="button" class="text-cyan-300 underline execution-profile-btn" data-execution-id="${esc(item.execution_id)}" ${profileAvailable ? "" : "disabled"}>Open Comparison Profile</button>
          <button type="button" class="text-cyan-300 underline execution-compare-btn ${comparableCount >= 2 && profileAvailable ? "" : "opacity-50 cursor-not-allowed"}" data-execution-id="${esc(item.execution_id)}" ${comparableCount >= 2 && profileAvailable ? "" : "disabled"}>Compare with other executions</button>
        </div>
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
    document.querySelectorAll(".execution-compare-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.disabled || comparableCount < 2) return;
        const executionId = btn.dataset.executionId;
        window.location.href = `/foc_reconstruction_comparability.html?campaign_id=${encodeURIComponent(campaignId)}&execution_id=${encodeURIComponent(executionId)}`;
      });
    });
  }

  function openOverlay(title, html) {
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
  }

  async function loadHealth() {
    const payload = await getJson("/api/foc/experimentation/health");
    const root = byId("campaign-health");
    if (root) root.innerHTML = `Module: <span class="font-black text-cyan-300">${esc(payload.status)}</span> · root <span class="mono text-slate-400">${esc(payload.campaigns_root)}</span>`;
  }

  async function loadCampaigns() {
    const payload = await getJson("/api/foc/experimentation/campaigns");
    state.campaigns = payload.campaigns || [];
    if (!state.selectedCampaignId && state.campaigns.length) state.selectedCampaignId = state.campaigns[0].campaign_id;
    renderCampaigns();
    await renderSelectedCampaign();
  }

  async function loadSourceCases() {
    const payload = await getJson("/api/foc/experimentation/source-cases");
    state.sourceCases = payload.cases || [];
    renderSourceCases();
  }

  async function loadMethodBasis() {
    renderMethodBasis(await getJson("/api/foc/experimentation/methodological-basis"));
  }

  function renderJob(payload) {
    const root = byId("job-panel");
    if (!root) return;
    if (!payload) {
      root.innerHTML = `
        <div class="font-black">No active background job.</div>
        <div class="text-slate-400 mt-2">Campaign execution runs as background jobs. When a campaign or execution is started, this panel will show the active stage, job ID, progress, logs and errors.</div>
      `;
      return;
    }
    const isSummary = !!payload.summary_mode;
    const phaseLabel = payload.current_phase_label || titleCaseStatus(payload.current_phase || "queued");
    const phaseDetail = payload.current_phase_detail || "No additional execution detail is currently available.";
    const phaseStatuses = payload.phase_statuses || [];
    root.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${isSummary ? "Last job" : "Job ID"}</div><div class="font-black mt-2 mono">${esc(payload.job_id || "not_available")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Status</div><div class="font-black mt-2 ${statusClass(payload.status)}">${esc(titleCaseStatus(payload.status || "unknown"))}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Current phase</div><div class="font-black mt-2">${esc(phaseLabel)}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</div><div class="font-black mt-2">${esc(payload.progress_percent ?? "not_available")}${payload.progress_percent != null ? "%" : ""}</div></div>
      </div>
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
                <div class="text-slate-400 mt-2">${esc(item.detail || "No detail available.")}</div>
                <div class="text-xs text-slate-500 mt-2">${esc(item.progress_percent)}% · ${esc(item.updated_at || "not_available")}</div>
              </div>
            `).join("")}
          </div>
        </div>
      ` : ""}
      ${payload.last_error ? `<div class="mt-4 text-red-300"><span class="font-black">Last error:</span> ${esc(payload.last_error)}</div>` : ""}
      ${(payload.generated_artifacts || []).length ? `<div class="mt-4"><span class="font-black">Generated artifacts:</span><div class="mt-2 space-y-1">${payload.generated_artifacts.map((item) => `<div class="mono text-slate-400">${esc(item)}</div>`).join("")}</div></div>` : ""}
      ${(payload.errors || []).length ? `<div class="mt-4 text-red-300"><span class="font-black">Errors:</span><div class="mt-2 space-y-1">${payload.errors.map((item) => `<div>${esc(item.message || JSON.stringify(item))}</div>`).join("")}</div></div>` : ""}
    `;
  }

  async function pollJob() {
    if (!state.activeJobId) return;
    try {
      const payload = await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(state.activeJobId)}`);
      renderJob(payload);
      saveActiveJob({
        job_id: payload.job_id,
        campaign_id: (payload.meta || {}).campaign_id || null,
        title: payload.title || "",
      });
      if (["completed", "completed_with_degradation", "failed", "cancelled"].includes(String(payload.status))) {
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
    const payload = buildFormPayload();
    if (state.preflight && !state.preflight.ready) {
      const proceed = window.confirm("Pre-flight validation still shows missing requirements. Create the campaign anyway as a scaffolded experimental container?");
      if (!proceed) return;
    }
    const res = await getJson("/api/foc/experimentation/campaigns/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    state.selectedCampaignId = res.campaign.campaign_id;
    state.dirtyFields.clear();
    await loadCampaigns();
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

  function bindFieldListeners() {
    ["source-case-select", "scenario-id-input", "campaign-name-input", "repetitions-input", "notes-input", "baseline-threshold-input", "delta-wcpr-input", "baseline-window-input", "description-input"].forEach((id) => {
      const node = byId(id);
      if (!node) return;
      node.addEventListener("input", markFieldDirty);
      node.addEventListener("change", async (event) => {
        markFieldDirty(event);
        if (id === "source-case-select") {
          state.currentCaseId = currentSourceCaseId();
        }
        if (id === "source-case-select" || id === "scenario-id-input") {
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
