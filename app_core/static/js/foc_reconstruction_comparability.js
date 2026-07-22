(function () {
  "use strict";

  const state = {
    campaigns: [],
    selectedCampaignId: null,
    activeJobId: null,
    pollTimer: null,
    storyMode: true,
    selectedExecutionIds: new Set(),
    comparisonResult: null,
    comparisonProfiles: new Map(),
  };

  const params = new URLSearchParams(window.location.search);
  const byId = (id) => document.getElementById(id);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
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
      represents: "It represents recoverability after accounting for that some expected causal edges matter more than others in the scenario model.",
    },
    max_delta_cpr: {
      label: "Max |ΔCPR|",
      meaning: "Maximum absolute CPR difference across the selected executions.",
      formula: "Max |ΔCPR| = max over all selected execution pairs of |CPR_i - CPR_j|.",
      represents: "It represents the largest observed variation in causal recoverability across the compared executions.",
    },
    max_delta_wcpr: {
      label: "Max |ΔWCPR|",
      meaning: "Maximum absolute Weighted CPR difference across the selected executions.",
      formula: "Max |ΔWCPR| = max over all selected execution pairs of |WCPR_i - WCPR_j|.",
      represents: "It represents the largest weighted recoverability variation across the compared executions.",
    },
    delta_cpr_allowed: {
      label: "ΔCPR allowed",
      meaning: "Allowed CPR equivalence margin.",
      formula: "The comparison passes this rule when Max |ΔCPR| stays at or below the configured CPR margin.",
      represents: "It represents how much CPR variation is still accepted before executions stop being considered equivalent under the selected rule.",
    },
    delta_wcpr_allowed: {
      label: "ΔWCPR allowed",
      meaning: "Allowed Weighted CPR equivalence margin.",
      formula: "The comparison passes this rule when Max |ΔWCPR| stays at or below the configured Weighted CPR margin.",
      represents: "It represents the maximum acceptable weighted causal recoverability drift across the compared executions.",
    },
    comparable_status: {
      label: "Comparability status",
      meaning: "Final comparison decision.",
      formula: "The backend combines metric margins, degradation logic, hard failures, and readiness rules to classify the result.",
      represents: "It represents whether the executions can be treated as comparable, comparable with degradation, not comparable, or insufficient data.",
    },
    support_rank_shift: {
      label: "Support rank shift",
      meaning: "Change in hypothesis-support class across executions.",
      formula: "A shift of 0 means the same support class was preserved across all selected executions.",
      represents: "It represents whether hypothesis support remained stable or moved to a stronger or weaker class.",
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

  function titleCase(value) {
    return String(value || "unknown").replace(/_/g, " ").replace(/\b\w/g, (ch) => ch.toUpperCase());
  }

  function statusClass(status) {
    const raw = String(status || "").toLowerCase();
    if (raw.includes("not comparable") || raw.includes("fail")) return "text-red-300";
    if (raw.includes("degradation") || raw.includes("insufficient") || raw.includes("partial") || raw.includes("warning")) return "text-amber-300";
    if (raw.includes("comparable") || raw.includes("running") || raw.includes("completed") || raw.includes("available")) return "text-cyan-300";
    return "text-slate-300";
  }

  // 2026-07-21: campaigns previously showed no time information at all -- with 40+
  // accumulated, telling two "Level B Repetition — industrial_file" entries apart meant
  // reading raw campaign_id timestamps by hand. Absolute + relative, both real (no
  // rounding tricks beyond simple bucketing), never invented.
  function fmtCampaignTimestamp(iso) {
    if (!iso) return "not_available";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "not_available";
    const diffMs = Date.now() - d.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    let rel;
    if (diffMin < 1) rel = "just now";
    else if (diffMin < 60) rel = `${diffMin}m ago`;
    else if (diffMin < 1440) rel = `${Math.floor(diffMin / 60)}h ago`;
    else rel = `${Math.floor(diffMin / 1440)}d ago`;
    return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC · ${rel}`;
  }

  function openInteractiveOverlay(title, html, onReady) {
    let root = byId("cmp-overlay");
    if (!root) {
      root = document.createElement("div");
      root.id = "cmp-overlay";
      root.className = "fixed inset-0 z-[1200] bg-slate-950/65 backdrop-blur-sm p-4 md:p-8";
      root.innerHTML = `
        <div class="mx-auto max-w-5xl h-full flex items-center justify-center">
          <div class="glass rounded-[28px] p-6 w-full max-h-[88vh] overflow-auto">
            <div class="flex items-start justify-between gap-4">
              <div>
                <div class="text-[11px] tracking-[0.28em] uppercase text-slate-400 font-black">Comparability Detail</div>
                <h2 id="cmp-overlay-title" class="text-2xl font-black mt-2"></h2>
              </div>
              <button id="cmp-overlay-close" type="button" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Close</button>
            </div>
            <div id="cmp-overlay-body" class="mt-5"></div>
          </div>
        </div>
      `;
      document.body.appendChild(root);
      byId("cmp-overlay-close")?.addEventListener("click", () => root.remove());
      root.addEventListener("click", (event) => {
        if (event.target === root) root.remove();
      });
    }
    byId("cmp-overlay-title").textContent = title;
    byId("cmp-overlay-body").innerHTML = html;
    if (typeof onReady === "function") onReady(root);
    return root;
  }

  function openOverlay(title, html) {
    openInteractiveOverlay(title, html);
  }

  // comparison_type is an independent axis from status: it answers "are these
  // executions even the same experiment by design?" (family grouping),
  // separate from "did the numbers come out close?" (status).
  function comparisonTypeLabel(value) {
    const labels = {
      direct_family_comparison: "Direct family comparison",
      direct_level_a_repeatability_comparison: "Direct Level A repeatability comparison",
      direct_level_a_repeatability_family_metadata_incomplete: "Direct Level A repeatability comparison, family metadata incomplete",
      exploratory_comparison_only: "Exploratory comparison only",
      platform_level_comparison: "Platform-level comparison",
      platform_level_comparison_with_scenario_drift: "Platform-level comparison with scenario drift",
      insufficient_data: "Insufficient data",
    };
    return labels[String(value || "insufficient_data")] || titleCase(value);
  }

  function comparisonTypeClass(value) {
    const normalized = String(value || "insufficient_data");
    if (["direct_family_comparison", "direct_level_a_repeatability_comparison", "direct_level_a_repeatability_family_metadata_incomplete"].includes(normalized)) return "text-cyan-300";
    if (normalized === "exploratory_comparison_only" || normalized === "platform_level_comparison" || normalized === "platform_level_comparison_with_scenario_drift") return "text-amber-300";
    return "text-slate-300";
  }

  function isDirectComparisonType(value) {
    return ["direct_family_comparison", "direct_level_a_repeatability_comparison", "direct_level_a_repeatability_family_metadata_incomplete"].includes(String(value || ""));
  }

  function selectedCampaign() {
    return state.campaigns.find((item) => item.campaign_id === state.selectedCampaignId) || null;
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
    openInteractiveOverlay(
      "Global Cleaner",
      `
        <div class="space-y-4 text-sm text-slate-300">
          <div>This cleaner removes selected campaigns, executions, preserved forensic cases, analyses, and report bundles without touching the active scenario definition.</div>
          <div class="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">Type <span class="mono">OK</span> to execute deletion. Non-removable items stay blocked.</div>
          <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
            <div><span class="font-black">Estimated reclaimable space:</span> ${esc(inventory.summary?.estimated_reclaimable_human || "not_available")}</div>
            <div class="mt-2"><span class="font-black">Removable items:</span> ${esc(inventory.summary?.removable_items || 0)}</div>
          </div>
          <div class="flex gap-3 flex-wrap">
            <button type="button" id="cmp-cleaner-select-all" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Select All Removable</button>
            <button type="button" id="cmp-cleaner-clear" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Clear Selection</button>
          </div>
          <div class="max-h-[44vh] overflow-auto space-y-3 pr-1">
            ${items.map((item) => `
              <label class="block rounded-2xl border ${item.deletable ? "border-slate-700/60 bg-slate-950/30" : "border-red-500/25 bg-red-500/5"} p-4">
                <div class="flex items-start gap-3">
                  <input type="checkbox" class="cmp-cleaner-check mt-1" value="${esc(item.item_id)}" ${item.deletable ? "" : "disabled"}>
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
            <input id="cmp-cleaner-confirm" class="w-full mt-3 rounded-xl bg-slate-950/60 border border-slate-700 px-3 py-2 text-slate-100" placeholder="Type OK">
          </label>
          <div class="flex gap-3 flex-wrap">
            <button type="button" id="cmp-cleaner-submit" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase opacity-50 cursor-not-allowed" disabled>Delete Selected Items</button>
            <button type="button" id="cmp-cleaner-cancel" class="btn-secondary rounded-2xl px-4 py-3 text-sm font-extrabold tracking-[0.16em] uppercase">Cancel</button>
          </div>
          <div id="cmp-cleaner-result" class="text-sm text-slate-300"></div>
        </div>
      `,
      () => {
        const overlay = byId("cmp-overlay");
        const confirmInput = byId("cmp-cleaner-confirm");
        const submit = byId("cmp-cleaner-submit");
        const resultNode = byId("cmp-cleaner-result");
        const sync = () => {
          const anySelected = [...document.querySelectorAll(".cmp-cleaner-check:checked")].length > 0;
          const enabled = anySelected && String(confirmInput?.value || "") === "OK";
          submit.disabled = !enabled;
          submit.classList.toggle("opacity-50", !enabled);
          submit.classList.toggle("cursor-not-allowed", !enabled);
        };
        byId("cmp-cleaner-select-all")?.addEventListener("click", () => {
          document.querySelectorAll(".cmp-cleaner-check:not([disabled])").forEach((node) => { node.checked = true; });
          sync();
        });
        byId("cmp-cleaner-clear")?.addEventListener("click", () => {
          document.querySelectorAll(".cmp-cleaner-check").forEach((node) => { node.checked = false; });
          sync();
        });
        document.querySelectorAll(".cmp-cleaner-check").forEach((node) => node.addEventListener("change", sync));
        confirmInput?.addEventListener("input", sync);
        byId("cmp-cleaner-cancel")?.addEventListener("click", () => overlay?.remove());
        submit?.addEventListener("click", async () => {
          if (submit.disabled) return;
          const selectedIds = [...document.querySelectorAll(".cmp-cleaner-check:checked")].map((node) => node.value);
          submit.disabled = true;
          if (resultNode) resultNode.innerHTML = '<div class="text-slate-400">Deleting selected items…</div>';
          try {
            const payload = await getJson("/api/foc/experimentation/cleanup/delete", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ selected_item_ids: selectedIds, confirmation: "OK" }),
            });
            if (resultNode) resultNode.innerHTML = `<div class="text-cyan-300">${esc(payload.message || "Cleanup completed.")}</div>`;
            await loadCampaigns();
            renderResult(null);
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

  function renderViewModeButtons() {
    byId("cmp-story-mode-btn")?.classList.toggle("is-active", state.storyMode);
    byId("cmp-technical-mode-btn")?.classList.toggle("is-active", !state.storyMode);
    ["cmp-story-intro", "cmp-storyline-panel", "cmp-result-story-panel", "cmp-beginner-expert-panel", "cmp-passed-limited-panel"].forEach((id) => {
      const node = byId(id);
      if (!node) return;
      node.closest(".glass, .glass-soft")?.classList.toggle("opacity-100", state.storyMode);
    });
  }

  function renderStoryIntro() {
    const root = byId("cmp-story-intro");
    if (!root) return;
    root.innerHTML = `
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What are we trying to decide?</div>
        <div class="mt-3 text-slate-300">This view decides whether already generated executions produced comparable forensic reconstructions. It does not create new executions. It compares execution profiles, ground truth seals, baseline noise, causal metrics, uncertainty, hypothesis support, and final conclusions.</div>
      </div>
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What does comparable mean here?</div>
        <div class="mt-3 text-slate-300">Comparable does not mean identical artifacts. It means that the executions recover equivalent forensic explanations within predefined causal, evidential, uncertainty, and conclusion-stability margins.</div>
      </div>
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What this view checks</div>
        <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
          <li>are there at least two execution profiles?</li>
          <li>do the executions belong to the selected campaign?</li>
          <li>is ground truth available or correctly marked as reused?</li>
          <li>are ${infoTip("cpr")} and ${infoTip("weighted_cpr")} available?</li>
          <li>are ${infoTip("cpr")} and ${infoTip("weighted_cpr")} within margins?</li>
          <li>is uncertainty stable?</li>
          <li>is hypothesis support stable?</li>
          <li>is the final conclusion stable enough for the configured comparison rule?</li>
        </ul>
      </div>
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-cyan-300">What is being compared?</div>
        <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
          <li>attack profile</li>
          <li>scenario fingerprint</li>
          <li>trigger policy</li>
          <li>acquisition profile</li>
          <li>causal metrics</li>
          <li>uncertainty</li>
          <li>hypothesis support</li>
          <li>final conclusion</li>
          <li>scientific limitations</li>
        </ul>
      </div>
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black text-amber-300">What is not being compared?</div>
        <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
          <li>full memory dumps</li>
          <li>full disk images</li>
          <li>full PCAP equality</li>
          <li>byte-level artifact equality</li>
          <li>complete raw case equality</li>
        </ul>
      </div>
    `;
  }

  function renderCampaigns() {
    const root = byId("cmp-campaign-list");
    if (!root) return;
    if (!state.campaigns.length) {
      root.innerHTML = '<div class="glass-soft rounded-2xl p-4">No campaigns registered yet.</div>';
      return;
    }
    // 2026-07-21: "running_job" comes straight from list_campaigns() (backend, one disk
    // scan of every job file, not per-campaign) -- a campaign with a repetition genuinely
    // in progress right now is marked here, distinct from its aggregate technical/scientific
    // outcome (item.status), which only describes what already finished.
    root.innerHTML = state.campaigns.map((item) => {
      const running = item.running_job;
      const activeBadge = running
        ? `<div class="mt-2 text-xs font-black uppercase tracking-[0.14em]" style="color:#22c55e;">● Active now — ${esc(titleCase(running.current_phase_label || running.job_type || "running"))}</div>
           ${running.current_phase_detail ? `<div class="mt-1 text-xs text-slate-400">${esc(running.current_phase_detail)}</div>` : ""}`
        : "";
      return `
      <button type="button" data-campaign-id="${esc(item.campaign_id)}" class="cmp-campaign-btn w-full text-left glass-soft rounded-2xl p-4 hover:border-cyan-400/50 ${item.campaign_id === state.selectedCampaignId ? "ring-1 ring-cyan-400/60" : ""} ${running ? "ring-1 ring-emerald-400/40" : ""}">
        <div class="flex items-center justify-between gap-3">
          <div class="font-black">${esc(item.name || item.campaign_id)}</div>
          <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCase(item.status || "unknown"))}</div>
        </div>
        <div class="text-xs text-slate-400 mt-2">${esc(item.campaign_id)} · executions ${esc(item.execution_count || 0)} · ${esc(fmtCampaignTimestamp(item.created_at))}</div>
        ${activeBadge}
      </button>
    `;
    }).join("");
    root.querySelectorAll(".cmp-campaign-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedCampaignId = btn.dataset.campaignId;
        state.selectedExecutionIds.clear();
        renderCampaigns();
        renderExecutions();
        renderReadiness();
        renderStoryline();
        renderResultStory();
      });
    });
  }

  function renderExecutions() {
    const root = byId("cmp-execution-list");
    if (!root) return;
    const campaign = selectedCampaign();
    if (!campaign) {
      root.textContent = "Select a campaign to see its executions.";
      return;
    }
    const executions = campaign.executions || [];
    if (!state.selectedExecutionIds.size && params.get("execution_id")) {
      state.selectedExecutionIds.add(params.get("execution_id"));
    }
    // 2026-07-21: user asked for a simple "I launched a repetition, compare its rounds"
    // path instead of hand-checking boxes one by one, especially once a campaign has many
    // executions. Purely a selection shortcut -- still goes through the exact same
    // readiness/compare flow as manual selection, nothing bypassed.
    const selectAllBtn = executions.length > 1
      ? `<button type="button" id="cmp-select-all-execs" class="btn-secondary rounded-xl px-3 py-2 mb-3 text-xs font-extrabold tracking-[0.1em] uppercase">Select all ${executions.length} executions</button>`
      : "";
    root.innerHTML = selectAllBtn + (executions.length ? executions.map((item) => `
      <label class="glass-soft rounded-2xl p-4 block cursor-pointer">
        <div class="flex items-center justify-between gap-3">
          <div class="flex items-center gap-3">
            <input type="checkbox" class="cmp-execution-check" value="${esc(item.execution_id)}" ${state.selectedExecutionIds.has(item.execution_id) ? "checked" : ""}>
            <div class="font-black">${esc(item.execution_id)}</div>
          </div>
          <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item.status)}">${esc(titleCase(item.status || "unknown"))}</div>
        </div>
        <div class="text-xs text-slate-400 mt-2">${esc(item.level || "")} · source case ${esc(item.source_case_id || "not_available")}</div>
      </label>
    `).join("") : '<div class="glass-soft rounded-2xl p-4">No executions registered for this campaign.</div>');
    root.querySelectorAll(".cmp-execution-check").forEach((node) => {
      node.addEventListener("change", () => {
        if (node.checked) state.selectedExecutionIds.add(node.value);
        else state.selectedExecutionIds.delete(node.value);
        renderReadiness();
        renderStoryline();
        renderResultStory();
      });
    });
    byId("cmp-select-all-execs")?.addEventListener("click", () => {
      executions.forEach((item) => state.selectedExecutionIds.add(item.execution_id));
      renderExecutions();
      renderReadiness();
      renderStoryline();
      renderResultStory();
    });
  }

  function renderMethodBasis(payload) {
    const root = byId("cmp-method-basis");
    if (!root) return;
    const refs = (payload && payload.references) || [];
    root.innerHTML = refs.slice(0, 5).map((item) => `
      <div class="glass-soft rounded-2xl p-4">
        <div class="font-black">${esc(item.title)}</div>
        <div class="text-xs text-slate-400 mt-2">${esc(item.why_applies || "")}</div>
      </div>
    `).join("") || '<div class="glass-soft rounded-2xl p-4">No methodological references were loaded.</div>';
  }

  async function getProfile(executionId) {
    if (state.comparisonProfiles.has(executionId)) return state.comparisonProfiles.get(executionId);
    try {
      const payload = await getJson(`/api/foc/experimentation/comparability/profile/${encodeURIComponent(executionId)}`);
      state.comparisonProfiles.set(executionId, payload);
      return payload;
    } catch {
      return null;
    }
  }

  async function selectedProfiles() {
    const ids = [...state.selectedExecutionIds];
    const items = await Promise.all(ids.map((id) => getProfile(id)));
    return items.filter(Boolean);
  }

  async function renderReadiness() {
    const root = byId("cmp-readiness-panel");
    if (!root) return;
    const campaign = selectedCampaign();
    if (!campaign) {
      root.innerHTML = "Select a campaign first.";
      return;
    }
    const selected = [...state.selectedExecutionIds];
    const profiles = await selectedProfiles();
    const allGroundTruth = profiles.every((p) => p?.ground_truth_seal && p.ground_truth_seal.seal_valid !== undefined);
    const allMetrics = profiles.every((p) => p?.causal_reconstruction && p.causal_reconstruction.cpr != null && p.causal_reconstruction.weighted_cpr != null);
    const checks = [
      { label: "Select campaign", ok: !!campaign, meta: "Comparison scope must be defined." },
      { label: "Select at least two executions", ok: selected.length >= 2, meta: "Comparability requires two or more executions." },
      { label: "Execution profiles available", ok: profiles.length >= 2 && profiles.length === selected.length, meta: "Each selected execution must expose forensic_comparison_profile.json." },
      { label: "Ground truth available or reused", ok: allGroundTruth, meta: "Each execution must expose ground-truth context or a valid reused seal." },
      { label: `${infoTip("cpr")} and ${infoTip("weighted_cpr")} available`, ok: allMetrics, meta: "The comparison cannot be decided without causal metrics." },
    ];
    root.innerHTML = checks.map((item) => `
      <div class="rounded-2xl border ${item.ok ? "border-cyan-500/30 bg-cyan-500/5" : "border-amber-500/30 bg-amber-500/5"} p-4 ${item === checks[0] ? "" : "mt-3"}">
        <div class="flex items-center justify-between gap-3">
          <div class="font-black">${item.label}</div>
          <div class="text-xs uppercase tracking-[0.16em] ${item.ok ? "text-cyan-300" : "text-amber-300"}">${item.ok ? "Passed" : "Pending"}</div>
        </div>
        <div class="mt-2 text-slate-400">${esc(item.meta)}</div>
      </div>
    `).join("");
  }

  function renderJob(payload) {
    const root = byId("cmp-job-panel");
    if (!root) return;
    if (!payload) {
      root.textContent = "No comparison job tracked yet.";
      return;
    }
    root.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Job ID</div><div class="font-black mt-2">${esc(payload.job_id)}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Status</div><div class="font-black mt-2 ${statusClass(payload.status)}">${esc(titleCase(payload.status))}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Phase</div><div class="font-black mt-2">${esc(payload.current_phase_label || payload.current_phase || "queued")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</div><div class="font-black mt-2">${esc(payload.progress_percent || 0)}%</div></div>
      </div>
      <div class="mt-4 text-slate-300"><span class="font-black">Exact activity:</span> ${esc(payload.current_phase_detail || "No detail available.")}</div>
    `;
  }

  function groupedDegradations(payload) {
    const items = payload?.degradation_reasons || [];
    const affectedTotal = (payload?.execution_ids || []).length || 0;
    const groups = new Map();
    for (const raw of items) {
      const text = String(raw || "");
      const parts = text.split(": ");
      const executionId = parts.length > 1 ? parts[0] : "unknown";
      const reason = parts.length > 1 ? parts.slice(1).join(": ") : text;
      const entry = groups.get(reason) || { reason, executions: [] };
      entry.executions.push(executionId);
      groups.set(reason, entry);
    }
    return [...groups.values()].map((item) => {
      let classification = "execution-specific degradation";
      if (item.executions.length === affectedTotal) {
        classification = "stable across compared executions";
        const campaign = selectedCampaign();
        if (String(campaign?.level || "").toUpperCase() === "A") classification = "inherited from base case or stable across Level A reanalysis";
      }
      let interpretation = "This limitation remains scientifically relevant and should be inspected before drawing stronger conclusions.";
      if (/degraded edges/i.test(item.reason)) interpretation = "The causal degradation is consistent across executions. This supports repeatability but limits the scientific strength of the case.";
      if (/ground truth/i.test(item.reason) && /reused|reconstructed/i.test(item.reason)) interpretation = "Level A does not generate a new pre-attack ground truth seal. The ground truth context is reused or reconstructed from the preserved case.";
      if (/attack path are not aligned/i.test(item.reason)) interpretation = "The acquisition trigger is host/FIM-oriented while the reconstructed path is OT/Modbus-oriented.";
      if (/integrity remains partial/i.test(item.reason)) interpretation = "The comparison can proceed, but scientific confidence must remain limited.";
      return { ...item, classification, interpretation };
    });
  }

  function statusNarrative(status) {
    const normalized = String(status || "").toLowerCase();
    if (normalized === "comparable") return "The executions are comparable under the selected metrics and thresholds. The causal reconstruction, evidence coverage, uncertainty class, hypothesis support, and final conclusion remain stable.";
    if (normalized === "comparable with degradation") return "The executions are comparable, but the comparable result still carries scientific limitations. The comparison passed the stability criteria, but at least one limitation remains in the evidence, causal reconstruction, trigger alignment, timestamp coverage, or integrity state.";
    if (normalized === "not comparable") return "The executions are not comparable under the selected criteria. At least one mandatory causal relation, CPR/WCPR margin, evidence coverage requirement, uncertainty constraint, hypothesis support condition, or conclusion-stability rule failed.";
    if (normalized === "insufficient data") return "The comparison cannot be decided because required profiles or metrics are missing. Generate or repair the missing execution profiles before comparing.";
    return "No comparability decision is available yet.";
  }

  function comparisonTypeNarrative(result) {
    const comparisonType = String(result?.comparison_type || "insufficient_data");
    if (comparisonType === "direct_family_comparison") return "The selected executions belong to the same comparison family. Direct forensic comparability is scientifically valid under the configured thresholds.";
    if (comparisonType === "direct_level_a_repeatability_comparison") return "The selected executions reanalyze the same preserved case under the same Level A analysis configuration. This is a direct Level A repeatability comparison.";
    if (comparisonType === "direct_level_a_repeatability_family_metadata_incomplete") return "The selected executions reanalyze the same preserved case under the same Level A analysis configuration. The comparison is scientifically valid, but comparison_family_id should still be generated and stored consistently in the lightweight registry.";
    if (comparisonType === "exploratory_comparison_only") return "The selected executions belong to different comparison families. This is an exploratory comparison only, not direct reproducibility evidence.";
    if (comparisonType === "platform_level_comparison_with_scenario_drift") return "The selected executions include Level C redeployment outputs with scenario drift. This supports platform-level interpretation, not direct family equivalence.";
    if (comparisonType === "platform_level_comparison") return "The selected executions include Level C redeployment outputs under a compatible scenario family. This supports platform-level reproducibility interpretation.";
    return "The comparison family could not be validated from the available lightweight result cards.";
  }

  async function renderResultStory() {
    const root = byId("cmp-result-story-panel");
    if (!root) return;
    const campaign = selectedCampaign();
    const selected = [...state.selectedExecutionIds];
    const result = state.comparisonResult;
    if (!campaign) {
      root.innerHTML = "Step 1: Select campaign. Step 2: Select at least two executions. Step 3: Compare them.";
      return;
    }
    if (!selected.length) {
      root.innerHTML = "Select executions to prepare the comparison story.";
      return;
    }
    if (!result) {
      root.innerHTML = `This view is ready to decide whether the selected executions produced comparable forensic reconstructions. It will compare execution profiles, ground truth seals, baseline noise, causal metrics, uncertainty, hypothesis support, and final conclusions.`;
      return;
    }
    const level = String(campaign.level || "A").toUpperCase();
    let story = "";
    if (String(result.status) === "Comparable With Degradation") {
      story = level === "A"
        ? `The selected executions are comparable at Level A. ${infoTip("cpr")} and ${infoTip("weighted_cpr")} did not vary across the selected executions, which indicates repeatable analytical behavior over the same preserved evidence. The result is still marked as ${infoTip("comparable_status", "Comparable With Degradation", "Comparable With Degradation")} because the compared executions preserve inherited scientific limitations such as degraded causal edges, trigger and attack-path mismatch, partial integrity, or other evidence constraints from the base case. This is not a comparison failure. It means the pipeline is stable, but the underlying case remains scientifically limited.`
        : `The selected executions are comparable at Level ${esc(level)}. ${infoTip("cpr")} and ${infoTip("weighted_cpr")} remained within the allowed margins, which indicates stable analytical behavior for the chosen repetition level. The result is still marked as ${infoTip("comparable_status", "Comparable With Degradation", "Comparable With Degradation")} because the compared executions preserve scientific limitations such as degraded causal edges, trigger and attack-path mismatch, partial integrity, or other inherited evidence constraints. This is not a comparison failure. It means the pipeline is stable, but the underlying case remains scientifically limited.`;
    } else if (String(result.status) === "Comparable") {
      story = `The selected executions are comparable at Level ${esc(level)}. ${infoTip("cpr")} and ${infoTip("weighted_cpr")} remained within the configured margins. This means the repeated executions produced stable forensic reconstructions under the selected criteria.`;
    } else if (String(result.status) === "Not Comparable") {
      story = `The selected executions are not comparable under the configured criteria. At least one mandatory metric, support condition, or stability rule fell outside the allowed margins, so the repeated executions cannot be treated as equivalent forensic reconstructions.`;
    } else {
      story = `The comparison cannot be decided yet because one or more required execution profiles or metrics are missing. Repair or regenerate the missing artifacts before comparing.`;
    }
    root.innerHTML = `
      <div class="font-black text-cyan-300">Result Story</div>
      <div class="mt-3">${story}</div>
      <div class="mt-4"><span class="font-black">Comparison family interpretation:</span> ${esc(comparisonTypeNarrative(result))}</div>
      <div class="mt-4"><span class="font-black">Interpretation by state:</span> ${esc(statusNarrative(result.status))}</div>
    `;
    await renderBeginnerExpert(result);
    await renderPassedLimited(result);
  }

  async function renderBeginnerExpert(payload) {
    const root = byId("cmp-beginner-expert-panel");
    if (!root) return;
    const summary = payload?.summary || {};
    const grouped = groupedDegradations(payload);
    const beginner = payload?.status === "Comparable"
      ? "The repeated executions gave an equivalent result. This means the analysis is stable under the selected comparison rules."
      : payload?.status === "Comparable With Degradation"
        ? "The repeated executions gave the same general result. This means the analysis is stable, but the original case still has limitations, so the final result cannot be considered strong."
        : payload?.status === "Not Comparable"
          ? "The repeated executions did not stay within the allowed comparison margins. The result is not stable enough to be treated as the same forensic reconstruction."
          : "The comparison is not ready because required profiles or metrics are still missing.";
    const expert = payload?.status
      ? `The selected executions produced ${infoTip("max_delta_cpr", "Max |ΔCPR|", summary.max_abs_cpr_difference ?? "n/a")} = <span class="font-black ${statusClass(summary.max_abs_cpr_difference != null && summary.max_abs_cpr_difference <= Number(payload.delta_cpr_allowed || 0) ? "completed" : "partial")}">${esc(summary.max_abs_cpr_difference ?? "n/a")}</span> and ${infoTip("max_delta_wcpr", "Max |ΔWCPR|", summary.max_abs_weighted_cpr_difference ?? "n/a")} = <span class="font-black ${statusClass(summary.max_abs_weighted_cpr_difference != null && summary.max_abs_weighted_cpr_difference <= Number(payload.delta_wcpr_allowed || 0) ? "completed" : "partial")}">${esc(summary.max_abs_weighted_cpr_difference ?? "n/a")}</span>. The ${infoTip("comparable_status", "comparability status", payload.status)} is <span class="font-black ${statusClass(payload.status)}">${esc(payload.status)}</span>${grouped.length ? ` due to stable limitations such as ${grouped.map((item) => esc(item.reason)).join("; ")}` : ""}.`
      : "No expert comparison summary is available yet.";
    root.innerHTML = `
      <div class="font-black text-cyan-300">Beginner Summary</div>
      <div class="mt-3">${esc(beginner)}</div>
      <div class="mt-4 font-black text-cyan-300">Expert Summary</div>
      <div class="mt-3">${expert}</div>
    `;
  }

  async function renderPassedLimited(payload) {
    const root = byId("cmp-passed-limited-panel");
    if (!root) return;
    const summary = payload?.summary || {};
    const grouped = groupedDegradations(payload);
    const passed = [];
    if ((payload?.execution_ids || []).length >= 2) passed.push("comparison profiles available");
    if (summary.max_abs_cpr_difference != null && summary.max_abs_cpr_difference <= Number(payload.delta_cpr_allowed || 0)) passed.push(`${PARAM_HELP.cpr.label} variation within margin`);
    if (summary.max_abs_weighted_cpr_difference != null && summary.max_abs_weighted_cpr_difference <= Number(payload.delta_wcpr_allowed || 0)) passed.push(`${PARAM_HELP.weighted_cpr.label} variation within margin`);
    if (summary.max_support_rank_shift === 0) passed.push("same support class preserved");
    const nextActions = [];
    grouped.forEach((item) => {
      if (/degraded edges/i.test(item.reason)) nextActions.push("Open causal graph, inspect degraded edges, inspect missing evidence, and regenerate causal reconstruction only if new evidence exists.");
      else if (/attack path are not aligned/i.test(item.reason)) nextActions.push("Run a Level B campaign with an OT-specific trigger, or document the current case as host/FIM-triggered and OT-reconstructed.");
      else if (/integrity remains partial/i.test(item.reason)) nextActions.push("Open the integrity report, inspect missing hashes, and generate an integrity supplement if possible without modifying original evidence.");
      else nextActions.push("Inspect the affected execution profiles and execution workspace before drawing stronger conclusions.");
    });
    if (payload?.status === "Insufficient Data") nextActions.push("Generate the missing forensic_comparison_profile.json, open the execution workspace, inspect job logs, and regenerate the missing profile.");
    if (payload?.comparison_type === "exploratory_comparison_only") nextActions.push("Treat this as exploratory only. Use the same attack profile, trigger policy, acquisition profile, and FOC profile to return to a direct comparison family.");
    if (payload?.comparison_type === "platform_level_comparison_with_scenario_drift") nextActions.push("Inspect scenario drift. Confirm whether the redeployed topology and scenario fingerprint still satisfy your equivalence criteria before claiming reproducibility.");
    root.innerHTML = `
      <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div class="glass-soft rounded-2xl p-4">
          <div class="font-black text-cyan-300">What passed?</div>
          <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
            ${passed.length ? passed.map((item) => `<li>${esc(item)}</li>`).join("") : "<li>No stable comparison condition has passed yet.</li>"}
          </ul>
        </div>
        <div class="glass-soft rounded-2xl p-4">
          <div class="font-black text-amber-300">What remains limited?</div>
          ${grouped.length ? grouped.map((item) => `
            <div class="mt-3">
              <div class="font-black">${esc(item.reason)}</div>
              <div class="text-slate-400 mt-1">Affected executions: ${esc(item.executions.length)} / ${esc((payload.execution_ids || []).length)}</div>
              <div class="text-slate-400 mt-1">Classification: ${esc(item.classification)}</div>
              <div class="text-slate-300 mt-1">Interpretation: ${esc(item.interpretation)}</div>
            </div>
          `).join("") : '<div class="mt-3 text-slate-300">No degradation groups are currently recorded.</div>'}
        </div>
        <div class="glass-soft rounded-2xl p-4">
          <div class="font-black text-cyan-300">What this means</div>
          <div class="mt-3 text-slate-300">${esc(statusNarrative(payload.status))}</div>
          <div class="mt-3 text-slate-300">${esc(comparisonTypeNarrative(payload))}</div>
          <div class="mt-4 text-slate-300">
            <span class="font-black">${infoTip("comparable_status", "Result meaning", payload.status)}</span>
          </div>
          <div class="mt-4 font-black text-cyan-300">What to do next</div>
          <ul class="mt-3 list-disc pl-5 text-slate-300 space-y-1">
            ${[...new Set(nextActions)].length ? [...new Set(nextActions)].map((item) => `<li>${esc(item)}</li>`).join("") : "<li>Run the comparison after selecting at least two valid execution profiles.</li>"}
          </ul>
        </div>
      </div>
    `;
  }

  function renderResult(payload) {
    state.comparisonResult = payload || null;
    const root = byId("cmp-result-panel");
    if (!root) return;
    if (!payload) {
      root.textContent = "Run a comparison to generate matrix, result, and report artifacts.";
      renderResultStory();
      return;
    }
    const summary = payload.summary || {};
    const comparisonType = payload.comparison_type || "insufficient_data";
    root.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("comparable_status", "Status", payload.status)}</div><div class="font-black mt-2 ${statusClass(payload.status)}">${infoTip("comparable_status", payload.status, payload.status)}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Comparison type</div><div class="font-black mt-2 ${comparisonTypeClass(comparisonType)}">${esc(comparisonTypeLabel(comparisonType))}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">Reference execution</div><div class="font-black mt-2">${esc(payload.reference_execution_id || "not_available")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("max_delta_cpr", "Max |ΔCPR|", summary.max_abs_cpr_difference ?? "n/a")}</div><div class="font-black mt-2">${infoTip("max_delta_cpr", summary.max_abs_cpr_difference ?? "n/a", summary.max_abs_cpr_difference ?? "n/a")}</div></div>
        <div><div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("max_delta_wcpr", "Max |ΔWCPR|", summary.max_abs_weighted_cpr_difference ?? "n/a")}</div><div class="font-black mt-2">${infoTip("max_delta_wcpr", summary.max_abs_weighted_cpr_difference ?? "n/a", summary.max_abs_weighted_cpr_difference ?? "n/a")}</div></div>
      </div>
      ${!isDirectComparisonType(comparisonType) ? `
        <div class="mt-5 rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 text-amber-200">
          The selected executions belong to different comparison families. They can be inspected together, but they should not be used as direct forensic reconstruction comparability evidence unless the difference is explicitly accepted as exploratory or platform-level comparison.
        </div>
      ` : ""}
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("delta_cpr_allowed", "Allowed |ΔCPR| margin", payload.delta_cpr_allowed ?? "n/a")}</div>
          <div class="font-black mt-2">${infoTip("delta_cpr_allowed", payload.delta_cpr_allowed ?? "n/a", payload.delta_cpr_allowed ?? "n/a")}</div>
        </div>
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("delta_wcpr_allowed", "Allowed |ΔWCPR| margin", payload.delta_wcpr_allowed ?? "n/a")}</div>
          <div class="font-black mt-2">${infoTip("delta_wcpr_allowed", payload.delta_wcpr_allowed ?? "n/a", payload.delta_wcpr_allowed ?? "n/a")}</div>
        </div>
        <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4">
          <div class="text-xs uppercase tracking-[0.16em] text-slate-400">${infoTip("support_rank_shift", "Max support-rank shift", summary.max_support_rank_shift ?? "n/a")}</div>
          <div class="font-black mt-2">${infoTip("support_rank_shift", summary.max_support_rank_shift ?? "n/a", summary.max_support_rank_shift ?? "n/a")}</div>
        </div>
      </div>
      ${(payload.hard_failures || []).length ? `<div class="mt-5"><div class="font-black text-red-300">Hard failures</div><div class="mt-2 space-y-2">${payload.hard_failures.map((item) => `<div>${esc(item)}</div>`).join("")}</div></div>` : ""}
      ${(payload.degradation_reasons || []).length ? `<div class="mt-5"><div class="font-black text-amber-300">Degradation reasons</div><div class="mt-2 space-y-2">${payload.degradation_reasons.map((item) => `<div>${esc(item)}</div>`).join("")}</div></div>` : ""}
      ${(payload.artifacts || {}).comparability_result ? `<div class="mt-5 text-sm text-slate-300"><span class="font-black">Artifacts:</span><div class="mt-2 space-y-1">${Object.entries(payload.artifacts).map(([k,v]) => `<div><span class="font-black">${esc(k)}:</span> <span class="mono text-slate-400">${esc(v)}</span></div>`).join("")}</div></div>` : ""}
      <details class="mt-5">
        <summary class="cursor-pointer font-black text-cyan-300">Raw JSON / advanced details</summary>
        <pre class="mt-3 whitespace-pre-wrap break-words text-xs text-slate-200">${esc(JSON.stringify(payload, null, 2))}</pre>
      </details>
    `;
    renderResultStory();
  }

  function renderStoryline() {
    const root = byId("cmp-storyline-panel");
    if (!root) return;
    const campaign = selectedCampaign();
    const selectedCount = state.selectedExecutionIds.size;
    const hasResult = !!state.comparisonResult;
    const stages = [
      ["Select campaign", campaign ? "completed" : "not_started", "Choose the comparison scope.", "campaign_manifest.json", "Select one campaign.", "No campaign is selected.", "Select a campaign from the left panel."],
      ["Select at least two executions", selectedCount >= 2 ? "completed" : "not_started", "Pick the executions to compare.", "execution_manifest.json", "Mark at least two executions.", "One execution is not enough to decide comparability.", "Select two or more executions."],
      ["Check readiness", selectedCount >= 2 ? "completed_with_degradation" : "not_started", "Verify profiles, metrics, and seals before comparing.", "forensic_comparison_profile.json", "Confirm that all selected executions have profiles.", "Missing profiles or metrics lead to insufficient data.", "Generate or repair the missing profiles."],
      ["Compare selected executions", state.activeJobId ? "running" : (hasResult ? "completed" : "not_started"), "Run the comparison job without rerunning analysis.", "comparability_result.json", "Launch the comparison when readiness is satisfied.", "No comparison result exists yet.", "Click Compare Selected Executions."],
      ["Read result story", hasResult ? "completed" : "not_started", "Interpret whether the result passed, degraded, failed, or is insufficient.", "comparability_report.md", "Read the narrative summary.", "A label alone is not enough.", "Open the result story and beginner/expert summary."],
      ["Open degraded evidence if needed", hasResult && String(state.comparisonResult?.status || "").includes("Degradation") ? "completed_with_degradation" : (hasResult ? "completed" : "not_started"), "Inspect degraded evidence, trigger alignment, uncertainty, or integrity if the result is limited.", "execution workspace / lifecycle dashboard", "Open the affected execution or lifecycle dashboard when limitations remain.", "Limitations may be inherited or new.", "Inspect grouped degradations and follow the suggested next actions."],
    ];
    root.innerHTML = stages.map((item, idx) => `
      <div class="rounded-2xl border border-slate-700/60 bg-slate-950/30 p-4 ${idx ? "mt-3" : ""}">
        <div class="flex items-center justify-between gap-3">
          <div class="font-black">${idx + 1}. ${esc(item[0])}</div>
          <div class="text-xs uppercase tracking-[0.16em] ${statusClass(item[1])}">${esc(titleCase(item[1]))}</div>
        </div>
        <div class="mt-3"><span class="font-black">Plain-language explanation:</span> ${esc(item[2])}</div>
        <div class="mt-2"><span class="font-black">Technical artifact:</span> ${esc(item[3])}</div>
        <div class="mt-2"><span class="font-black">Next action:</span> ${esc(item[4])}</div>
        <div class="mt-2"><span class="font-black">Possible problem:</span> ${esc(item[5])}</div>
        <div class="mt-2"><span class="font-black">How to fix it:</span> ${esc(item[6])}</div>
      </div>
    `).join("");
  }

  async function pollJob() {
    if (!state.activeJobId) return;
    const payload = await getJson(`/api/foc/experimentation/jobs/${encodeURIComponent(state.activeJobId)}`);
    renderJob(payload);
    if (["completed", "failed", "cancelled", "completed_with_degradation"].includes(String(payload.status))) {
      state.activeJobId = null;
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      const meta = payload.meta || {};
      if (meta.comparison_id) {
        renderResult(await getJson(`/api/foc/experimentation/comparability/results/${encodeURIComponent(meta.comparison_id)}`));
      }
    }
  }

  function trackJob(jobId) {
    state.activeJobId = jobId;
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(pollJob, 2500);
    pollJob();
    renderStoryline();
  }

  async function loadCampaigns() {
    const payload = await getJson("/api/foc/experimentation/campaigns");
    // 2026-07-21: backend list_campaigns() sorts CMP-* directories alphabetically, which
    // for CMP-YYYYMMDD-HHMMSS-XXXX ids is also chronological -- oldest first. With 40+
    // campaigns accumulated, the one the user actually launched minutes ago (possibly
    // still with a repetition in progress) was buried at the very bottom of the list and
    // never the default selection. Reversed here so the most recent campaign is both
    // first in the list and the default -- same fix already applied to the Level B/C
    // campaign pickers elsewhere in this codebase.
    state.campaigns = (payload.campaigns || []).slice().reverse();
    if (!state.campaigns.some((item) => item.campaign_id === state.selectedCampaignId)) {
      // 2026-07-21 correction: defaulting to campaigns[0] (now the single most recent
      // campaign of ANY level) surfaced a tiny auto-created "Nested Level A" campaign as
      // the default far more often than not -- one gets created per Level B repetition,
      // so they're the most frequent campaign type by far and constantly outrank the
      // actual Level B/C campaign the user launched. Caught live: right after this fix,
      // the default became "Nested Level A · EXEC-0001" (1 execution) instead of the real
      // Level B campaign created 12 seconds earlier (2 executions). Default now skips
      // level="A" campaigns specifically -- they're still fully visible/selectable in the
      // list, just never the silent default.
      const primary = state.campaigns.find((item) => String(item.level || "").toUpperCase() !== "A");
      state.selectedCampaignId = params.get("campaign_id") || (primary || state.campaigns[0])?.campaign_id || null;
    }
    renderCampaigns();
    renderExecutions();
    await renderReadiness();
    renderStoryline();
  }

  async function runComparison() {
    const campaign = selectedCampaign();
    if (!campaign) return;
    const executionIds = [...state.selectedExecutionIds];
    if (executionIds.length < 2) {
      alert("Select at least two executions.");
      return;
    }
    const payload = await getJson("/api/foc/experimentation/comparability/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ campaign_id: campaign.campaign_id, execution_ids: executionIds }),
    });
    trackJob(payload.job_id);
  }

  async function init() {
    byId("cmp-run-btn")?.addEventListener("click", runComparison);
    byId("cmp-refresh-btn")?.addEventListener("click", async () => { await loadCampaigns(); renderResultStory(); });
    byId("cmp-global-cleaner-btn")?.addEventListener("click", openGlobalCleaner);
    byId("cmp-story-mode-btn")?.addEventListener("click", () => {
      state.storyMode = true;
      renderViewModeButtons();
    });
    byId("cmp-technical-mode-btn")?.addEventListener("click", () => {
      state.storyMode = false;
      renderViewModeButtons();
    });
    renderViewModeButtons();
    renderStoryIntro();
    renderMethodBasis(await getJson("/api/foc/experimentation/methodological-basis"));
    await loadCampaigns();
    renderResultStory();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
