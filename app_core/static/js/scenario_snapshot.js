"use strict";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let currentSnapshot = null;
let currentSnapshotId = null;
let pollTimer = null;
let isCapturing = false;

const API = {
  capture:     "/api/scenario-snapshot/capture",
  status:      "/api/scenario-snapshot/status",
  snapshots:   "/api/scenario-snapshot/snapshots",
  current:     "/api/scenario-snapshot/current",
  get:         (id) => `/api/scenario-snapshot/snapshots/${id}`,
  validate:    (id) => `/api/scenario-snapshot/snapshots/${id}/validate`,
  seal:        (id) => `/api/scenario-snapshot/snapshots/${id}/seal`,
  export:      (id) => `/api/scenario-snapshot/snapshots/${id}/export`,
  diff:        (id, other) => `/api/scenario-snapshot/snapshots/${id}/diff?compare_with=${other}`,
  verifyNodes: (id) => `/api/scenario-snapshot/snapshots/${id}/verify-nodes`,
};

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", async () => {
  await loadSnapshotList();
  await loadLatest();
});

// ---------------------------------------------------------------------------
// Capture flow
// ---------------------------------------------------------------------------
async function startCapture() {
  if (isCapturing) return;
  isCapturing = true;
  setBtn(true, "Capturing…");
  showProgress(true);
  setBadge("COLLECTING", "badge-info");
  animateProgress();

  try {
    const res = await fetch(API.capture, { method: "POST" });
    const data = await res.json();
    if (res.status === 409) {
      // Already running — just start polling
    } else if (!res.ok) {
      throw new Error(data.error || "Capture failed to start.");
    }
    startPolling();
  } catch (err) {
    showError(`Capture error: ${err.message}`);
    finishCapture(null);
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollStatus, 1800);
}

async function pollStatus() {
  try {
    const res = await fetch(API.status);
    const data = await res.json();
    if (data.status === "COLLECTING") return;  // still running

    clearInterval(pollTimer);
    pollTimer = null;

    if (data.status === "FAILED") {
      showError(`Capture failed: ${data.result?.error || "unknown error"}`);
      finishCapture(null);
      return;
    }

    // Use in-memory result or fall back to latest saved snapshot
    const snap = data.result || data.latest_snapshot_full;
    if (snap) {
      finishCapture(snap);
      renderSnapshot(snap);
      await loadSnapshotList(snap.snapshot_id);
      return;
    }

    // If only summary is available, load the full snapshot by id
    const latestId = data.latest_snapshot?.snapshot_id;
    if (latestId) {
      try {
        const r2 = await fetch(API.get(latestId));
        const full = await r2.json();
        if (full?.snapshot_id) {
          finishCapture(full);
          renderSnapshot(full);
          await loadSnapshotList(full.snapshot_id);
          return;
        }
      } catch {}
    }

    // Nothing to show — reset to idle
    finishCapture(null);
    await loadLatest();
  } catch {}
}

function finishCapture(snap) {
  isCapturing = false;
  showProgress(false);
  if (snap) {
    setBadge(snap.status, statusToBadgeClass(snap.status));
    setBtn(false, "Refresh Scenario Snapshot");
  } else {
    setBadge("FAILED", "badge-fail");
    setBtn(false, "Generate Scenario Snapshot");
  }
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------
async function loadLatest() {
  try {
    const res = await fetch(API.current);
    const data = await res.json();
    if (data.snapshot) {
      renderSnapshot(data.snapshot);
      setBtn(false, "Refresh Scenario Snapshot");
    } else {
      showEmptyState(true);
    }
  } catch {
    showEmptyState(true);
  }
}

async function loadSnapshotList(selectId) {
  try {
    const res = await fetch(API.snapshots);
    const data = await res.json();
    const snaps = data.snapshots || [];
    const sel = document.getElementById("snapshotSelect");
    sel.innerHTML = snaps.length
      ? snaps.map(s => `<option value="${esc(s.snapshot_id)}" ${s.snapshot_id === (selectId || currentSnapshotId) ? "selected" : ""}>
          ${esc(s.snapshot_id)} — ${esc(s.status || "")} — ${esc((s.captured_at_utc || "").slice(0, 16))}
        </option>`).join("")
      : '<option value="">— No snapshots yet —</option>';
  } catch {}
}

async function loadSnapshot(id) {
  if (!id) return;
  try {
    const res = await fetch(API.get(id));
    const snap = await res.json();
    renderSnapshot(snap);
  } catch (err) {
    showError(`Could not load snapshot: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------
function renderSnapshot(snap) {
  currentSnapshot = snap;
  currentSnapshotId = snap.snapshot_id;
  showEmptyState(false);
  document.getElementById("mainContent").style.display = "block";

  setBadge(snap.status, statusToBadgeClass(snap.status));
  setBtn(false, "Refresh Scenario Snapshot");

  const metaEl = document.getElementById("metaStatus");
  metaEl.textContent = `${snap.snapshot_id} · ${(snap.captured_at_utc || "").slice(0,16)} UTC · ${snap.status}${snap.sealed ? " · SEALED" : ""}`;

  renderOverview(snap);
  renderReadiness(snap.validation || {});
  renderScenario(snap.scenario || {});
  renderInfrastructure(snap.infrastructure || {});
  renderNetwork(snap.network_config || {});
  renderTools(snap.tools || {});
  renderNodeVerification(snap.node_verification || {});
  renderAttacks(snap.attacks || {});
  renderChains(snap.relationships || {});
  renderForensics(snap.forensics || {});
  renderCampaigns(snap.campaigns || {});
  renderFoc(snap.foc || {});
  renderProcedures(snap.procedures || {});
  renderAudit(snap);
  renderProvenance(snap);
}

// OVERVIEW
function renderOverview(snap) {
  const sc = snap.scenario || {};
  const infra = snap.infrastructure || {};
  const atk = snap.attacks || {};
  const for_ = snap.forensics || {};
  const val = snap.validation || {};
  const camps = snap.campaigns || {};
  const prov = snap.provenance || {};

  const metrics = [
    { label: "Snapshot ID",     value: (snap.snapshot_id || "").slice(-8), sub: snap.snapshot_id },
    { label: "Status",          value: snap.status || "—",              cls: statusToCls(snap.status) },
    { label: "Captured At",     value: (snap.captured_at_utc || "").slice(0,16), sub: "UTC" },
    { label: "Sealed",          value: snap.sealed ? "YES" : "NO",     cls: snap.sealed ? "ri-pass" : "ri-warn" },
    { label: "Scenario",        value: sc.scenario_name || "—",         sub: sc.scenario_type || "" },
    { label: "Declared Nodes",  value: (sc.nodes_declared || []).length },
    { label: "Runtime Instances",value: (infra.instances || []).length },
    { label: "OT Nodes",        value: (sc.ot_nodes || []).length },
    { label: "Attack Executions",value: atk.total || 0 },
    { label: "Forensic Cases",  value: for_.total || 0 },
    { label: "Campaigns",       value: camps.total || 0 },
    { label: "Level B Runs",    value: (camps.level_b || []).length },
    { label: "Validation Checks",value: (val.summary || {}).total || 0 },
    { label: "Passed",          value: (val.summary || {}).passed || 0, cls: "ri-pass" },
    { label: "Warnings",        value: (val.summary || {}).warnings || 0, cls: "ri-warn" },
    { label: "Failed",          value: (val.summary || {}).failed || 0, cls: (val.summary || {}).failed ? "ri-fail" : "" },
    { label: "Warnings",        value: prov.warning_count || 0 },
    { label: "Errors",          value: prov.error_count || 0, cls: (prov.error_count || 0) > 0 ? "ri-fail" : "" },
  ];

  document.getElementById("overviewContent").innerHTML = metrics.map(m => `
    <div class="readiness-item">
      <div class="ri-label">${esc(m.label)}</div>
      <div class="ri-val ${m.cls || ""}">${esc(String(m.value ?? "—"))}</div>
      ${m.sub ? `<div class="text-xs text-slate-500 mt-1">${esc(m.sub)}</div>` : ""}
    </div>
  `).join("");
}

// READINESS
function renderReadiness(val) {
  const flags = [
    { label: "Snapshot Capture",       key: "snapshot_capture_ready" },
    { label: "Incident Replay",         key: "incident_replay_ready" },
    { label: "DFIR Replay",             key: "dfir_replay_ready" },
    { label: "Campaign Replay",         key: "campaign_replay_ready" },
    { label: "Paper Traceability",      key: "paper_traceability_ready" },
    { label: "Scenario Redeployment",   key: "scenario_redeployment_ready" },
    { label: "Overall Reproduction",    key: "overall_reproduction_ready" },
  ];

  document.getElementById("readinessFlags").innerHTML = flags.map(f => {
    const v = val[f.key];
    const cls = v === true ? "ri-pass" : v === false ? "ri-fail" : "ri-warn";
    return `<div class="readiness-item">
      <div class="ri-label">${esc(f.label)}</div>
      <div class="ri-val ${cls}">${v === true ? "READY" : v === false ? "NOT READY" : "UNKNOWN"}</div>
    </div>`;
  }).join("");

  const checks = val.checks || [];
  const grouped = {};
  for (const c of checks) {
    const d = c.domain || "other";
    if (!grouped[d]) grouped[d] = [];
    grouped[d].push(c);
  }

  document.getElementById("validationChecks").innerHTML = Object.entries(grouped).map(([domain, items]) => `
    <details class="mt-3">
      <summary>${esc(domain.replace(/_/g," ").toUpperCase())} — ${items.length} check(s)</summary>
      <table class="ss-table mt-2">
        <thead><tr>
          <th>Status</th><th>Requirement</th><th>Reason</th><th>Recommended Action</th>
        </tr></thead>
        <tbody>${items.map(c => `<tr>
          <td>${statusBadge(c.status)}</td>
          <td>${esc(c.requirement || "")}</td>
          <td class="text-slate-400">${esc(c.reason || "")}</td>
          <td class="text-slate-500 italic">${esc(c.recommended_action || "")}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>
  `).join("");
}

// SCENARIO
function renderScenario(sc) {
  const meta = `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
    ${[
      ["Scenario ID",   sc.scenario_id],
      ["Name",          sc.scenario_name],
      ["Type",          sc.scenario_type],
      ["Source File",   sc.source_file],
      ["IT Nodes",      (sc.it_nodes || []).length],
      ["OT Nodes",      (sc.ot_nodes || []).length],
      ["Edges",         (sc.edges || []).length],
      ["Collector",     sc.collector_status],
    ].map(([l, v]) => `<div class="readiness-item"><div class="ri-label">${esc(l)}</div>
      <div class="text-sm font-semibold text-slate-300">${esc(String(v ?? "—"))}</div></div>`).join("")}
  </div>`;
  document.getElementById("scenarioMeta").innerHTML = meta;

  const nodes = sc.nodes_declared || [];
  document.getElementById("nodeCount").textContent = nodes.length;
  document.getElementById("nodeTable").innerHTML = nodeTable(nodes);

  const otNodes = sc.ot_nodes || [];
  document.getElementById("otNodeCount").textContent = otNodes.length;
  document.getElementById("otNodeTable").innerHTML = otNodes.length
    ? nodeTable(otNodes)
    : '<p class="empty-note">No OT nodes declared.</p>';
}

function nodeTable(nodes) {
  if (!nodes.length) return '<p class="empty-note">No nodes.</p>';
  return `<table class="ss-table">
    <thead><tr><th>Name</th><th>Type / Role</th><th>Image</th><th>Flavor</th><th>Tools Declared</th></tr></thead>
    <tbody>${nodes.map(n => `<tr>
      <td class="font-semibold">${esc(n.name || "—")}</td>
      <td>${esc(n.type || n.role || "—")}</td>
      <td class="text-slate-400 text-xs">${esc(n.image || "—")}</td>
      <td class="text-slate-400 text-xs">${esc(n.flavor || "—")}</td>
      <td class="text-xs">${(n.tools || []).map(t => `<span class="badge badge-na">${esc(t)}</span>`).join(" ")}</td>
    </tr>`).join("")}</tbody>
  </table>`;
}

// INFRASTRUCTURE
function renderInfrastructure(infra) {
  const statusEl = document.getElementById("infraStatus");
  statusEl.innerHTML = `<div class="flex items-center gap-3">
    ${statusBadge(infra.collector_status)}
    <span class="text-slate-400 text-xs">${infra.error ? esc(infra.error) : `${(infra.instances||[]).length} runtime instance(s) found.`}</span>
  </div>`;

  const instances = infra.instances || [];
  document.getElementById("instanceCount").textContent = instances.length;
  document.getElementById("instanceTable").innerHTML = instances.length
    ? `<table class="ss-table">
        <thead><tr><th>Name</th><th>Status</th><th>IP</th><th>Flavor</th><th>Created</th></tr></thead>
        <tbody>${instances.map(i => `<tr>
          <td class="font-semibold">${esc(i.name || "—")}</td>
          <td>${statusBadge(i.status)}</td>
          <td class="font-mono text-xs">${esc(i.ip || "—")}</td>
          <td class="text-slate-400 text-xs">${esc(i.flavor_name || i.flavor_id || "—")}</td>
          <td class="text-slate-500 text-xs">${esc((i.created_at || "").slice(0,16))}</td>
        </tr>`).join("")}</tbody>
      </table>`
    : '<p class="empty-note">No runtime instances found.</p>';

  const mapping = infra.node_mapping || [];
  document.getElementById("mappingTable").innerHTML = mapping.length
    ? `<table class="ss-table">
        <thead><tr><th>Logical Name</th><th>Type</th><th>Runtime Instance</th><th>IP</th><th>Match</th></tr></thead>
        <tbody>${mapping.map(m => `<tr>
          <td class="font-semibold">${esc(m.logical_name || "—")}</td>
          <td class="text-slate-400 text-xs">${esc(m.logical_type || "—")}</td>
          <td class="font-mono text-xs">${esc(m.runtime_instance_id?.slice(-8) || "—")}</td>
          <td class="font-mono text-xs">${esc(m.runtime_ip || "—")}</td>
          <td>${relBadge(m.match_status)}</td>
        </tr>`).join("")}</tbody>
      </table>`
    : '<p class="empty-note">No node mapping available.</p>';
}

// TOOLS
function renderTools(tools) {
  const byNode = tools.by_node || {};
  const nodes = Object.values(byNode);
  document.getElementById("toolsContent").innerHTML = nodes.length
    ? nodes.map(node => `
      <details class="mb-3">
        <summary>${esc(node.instance_name || node.instance_id || "—")}
          — <span class="text-indigo-400">${node.installed_count} installed</span>
          ${node.failed_count > 0 ? `· <span class="text-red-400">${node.failed_count} failed</span>` : ""}
          ${node.pending_count > 0 ? `· <span class="text-yellow-400">${node.pending_count} pending</span>` : ""}
        </summary>
        <table class="ss-table mt-2">
          <thead><tr><th>Tool</th><th>Status</th><th>Installed At</th></tr></thead>
          <tbody>${(node.tools || []).map(t => `<tr>
            <td class="font-semibold">${esc(t.tool_name)}</td>
            <td>${toolBadge(t.status)}</td>
            <td class="text-slate-500 text-xs">${esc(t.installed_at || "—")}</td>
          </tr>`).join("")}</tbody>
        </table>
      </details>
    `).join("")
    : '<p class="empty-note">No tools state data available.</p>';
}

// ATTACKS
function renderAttacks(attacks) {
  const catalog = attacks.profiles || [];
  const execs = attacks.executions || [];

  document.getElementById("catalogCount").textContent = catalog.length;
  document.getElementById("catalogTable").innerHTML = catalog.length
    ? `<table class="ss-table">
        <thead><tr><th>ID</th><th>Name</th><th>MITRE</th><th>Severity</th><th>Detection Engine</th><th>Target Roles</th></tr></thead>
        <tbody>${catalog.map(a => `<tr>
          <td class="font-mono text-xs">${esc(a.attack_id || "")}</td>
          <td class="font-semibold">${esc(a.display_name || "")}</td>
          <td class="text-slate-400">${esc(a.mitre_id || "")} ${esc(a.tactic || "")}</td>
          <td>${sevBadge(a.severity)}</td>
          <td class="text-xs text-slate-400">${esc(a.detection_engine || "")}</td>
          <td class="text-xs">${(a.target_roles||[]).map(r => `<span class="badge badge-na">${esc(r)}</span>`).join(" ")}</td>
        </tr>`).join("")}</tbody>
      </table>`
    : '<p class="empty-note">Attack catalog not available.</p>';

  document.getElementById("execCount").textContent = execs.length;
  document.getElementById("execTable").innerHTML = execs.length
    ? `<table class="ss-table">
        <thead><tr><th>Execution</th><th>Attack</th><th>Severity</th><th>Status</th><th>Target</th><th>Started</th><th>Case</th></tr></thead>
        <tbody>${execs.map(e => `<tr>
          <td class="font-mono text-xs">${esc((e.attack_execution_id || "").slice(-12))}</td>
          <td class="font-semibold text-xs">${esc(e.display_name || e.attack_id || "—")}</td>
          <td>${sevBadge(e.severity)}</td>
          <td>${statusBadge(e.status)}</td>
          <td class="font-mono text-xs">${esc(e.target_ip || "—")} <span class="text-slate-500">${esc(e.target_role || "")}</span></td>
          <td class="text-slate-500 text-xs">${esc((e.started_at || "").slice(0,16))}</td>
          <td class="text-xs text-slate-400">${esc(e.case_dir ? e.case_dir.split("/").pop() : "—")}</td>
        </tr>`).join("")}</tbody>
      </table>`
    : '<p class="empty-note">No attack executions recorded.</p>';
}

// CHAINS
function renderChains(rel) {
  const chains = rel.attack_case_chains || [];
  const summary = rel.summary || {};

  document.getElementById("chainSummary").innerHTML = `
    <div class="flex gap-4 flex-wrap">
      <div class="readiness-item"><div class="ri-label">Total Executions</div><div class="ri-val">${summary.total_executions ?? 0}</div></div>
      <div class="readiness-item"><div class="ri-label">Confirmed Case Links</div><div class="ri-val ri-pass">${summary.confirmed_case_links ?? 0}</div></div>
      <div class="readiness-item"><div class="ri-label">Missing Case Links</div><div class="ri-val ${summary.missing_case_links > 0 ? 'ri-fail' : ''}">${summary.missing_case_links ?? 0}</div></div>
      <div class="readiness-item"><div class="ri-label">Ambiguous</div><div class="ri-val ri-warn">${summary.ambiguous_case_links ?? 0}</div></div>
    </div>`;

  document.getElementById("chainList").innerHTML = chains.length
    ? chains.map(c => `
      <div class="chain-row flex-wrap gap-2">
        <div class="chain-node">
          <div class="chain-box cb-attack">${esc((c.attack_id || "ATTACK").replace("T1","T1").slice(-12))}</div>
          <div class="text-xs text-slate-500 mt-1">${esc(c.severity || "")}</div>
          <div class="text-xs text-slate-600">${esc((c.started_at||"").slice(0,10))}</div>
        </div>
        <div class="chain-arrow">→</div>
        <div class="chain-node">
          ${c.alert_signature
            ? `<div class="chain-box cb-alert" title="${esc(c.alert_signature)}">${esc(c.alert_signature.slice(0,28))}${c.alert_signature.length > 28 ? "…" : ""}</div>
               <div class="text-xs text-slate-500 mt-1">${esc(c.alert_severity || "")}</div>`
            : `<div class="chain-box cb-missing">No alert linked</div>`}
        </div>
        <div class="chain-arrow">→</div>
        <div class="chain-node">
          ${c.forensic_case_id
            ? `<div class="chain-box cb-case">${esc(c.forensic_case_id)}</div>
               <div class="text-xs text-slate-500 mt-1">${esc(c.case_match_method || "")}</div>
               <div class="text-xs mt-1">${relBadge(c.case_match_status)}</div>`
            : `<div class="chain-box cb-missing">No case</div>`}
        </div>
        <div class="ml-auto flex flex-col text-right gap-1 text-xs text-slate-500">
          <span>${c.evidence_count || 0} artifact(s)</span>
          ${c.custody_chain ? '<span class="text-indigo-400">✓ Custody</span>' : ''}
          ${c.sealed ? '<span class="text-purple-400">✓ Sealed</span>' : ''}
        </div>
      </div>
    `).join("")
    : '<p class="empty-note">No attack-case chains available.</p>';
}

// FORENSICS — enhanced with full case analysis
function renderForensics(forensics) {
  const cases = forensics.cases || [];
  if (!cases.length) {
    document.getElementById("forensicsContent").innerHTML = '<p class="empty-note">No forensic cases found.</p>';
    return;
  }
  document.getElementById("forensicsContent").innerHTML = `
    <div class="mb-3 text-xs text-slate-400">${cases.length} case(s) total · ${forensics.active_case_id ? "Last: " + forensics.active_case_id : ""}</div>
    ${cases.map(c => `
    <details class="mb-3">
      <summary>
        <span class="font-mono">${esc(c.case_id)}</span>
        &nbsp;${c.sealed ? '<span class="badge badge-sealed">SEALED</span>' : '<span class="badge badge-na">OPEN</span>'}
        ${c.campaign_id ? `&nbsp;<span class="badge badge-info">Campaign</span>` : ""}
        ${c.lightweight_bundle_present ? `&nbsp;<span class="badge badge-pass">Bundle ✓</span>` : ""}
        &nbsp;<span class="text-slate-500 text-xs">${esc((c.created_at || "").slice(0,16))}</span>
      </summary>
      <div class="pl-4 pt-2 space-y-2">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
          ${[
            ["Alert",        c.alert_signature || "—"],
            ["Severity",     c.trigger_severity || "—"],
            ["Artifacts",    `${c.artifact_count ?? 0} (${c.hash_count ?? 0} hashed)`],
            ["Custody Chain",c.custody_chain_present ? "YES" : "NO"],
            ["Campaign",     c.campaign_id || "—"],
            ["Execution",    c.execution_id || "—"],
            ["Status",       c.case_status || "—"],
            ["Analysis",     c.analysis_present ? "YES" : "NO"],
          ].map(([l,v]) => `<div class="readiness-item" style="padding:8px 10px">
            <div class="ri-label">${esc(l)}</div>
            <div class="text-xs text-slate-200 font-semibold mt-1">${esc(String(v))}</div>
          </div>`).join("")}
        </div>
        ${c.analysis_report ? `
        <details>
          <summary>Analysis Report</summary>
          <div class="pl-3 mt-2 text-xs text-slate-300 space-y-1">
            ${c.analysis_report.summary ? `<p><strong>Summary:</strong> ${esc(c.analysis_report.summary)}</p>` : ""}
            ${(c.analysis_report.findings || []).length ? `
              <p class="font-semibold text-slate-400 mt-2">Findings:</p>
              <ul class="list-disc pl-4">${c.analysis_report.findings.map(f => `<li>${esc(String(f))}</li>`).join("")}</ul>` : ""}
            ${c.analysis_report.conclusion ? `<p class="mt-1"><strong>Conclusion:</strong> ${esc(c.analysis_report.conclusion)}</p>` : ""}
          </div>
        </details>` : ""}
        ${c.custody_log_tail?.length ? `
        <details>
          <summary>Chain of Custody (last ${c.custody_log_tail.length} entries)</summary>
          <pre class="text-xs text-slate-400 mt-2 bg-slate-900 rounded p-3 overflow-x-auto max-h-40">${esc(c.custody_log_tail.join("\n"))}</pre>
        </details>` : ""}
      </div>
    </details>`).join("")}`;
}

// CAMPAIGNS — enhanced with CPR/WCPR metrics per execution
function renderCampaigns(camps) {
  const stats = camps.level_b_statistics || {};
  const statBar = stats.execution_count ? `
    <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-5">
      ${[
        ["Level B Runs",  stats.execution_count,           ""],
        ["CPR Mean",      stats.cpr_mean !== undefined ? (stats.cpr_mean*100).toFixed(1)+"%" : "—", ""],
        ["CPR Min",       stats.cpr_min !== undefined ? (stats.cpr_min*100).toFixed(1)+"%" : "—",  "ri-warn"],
        ["CPR Max",       stats.cpr_max !== undefined ? (stats.cpr_max*100).toFixed(1)+"%" : "—",  "ri-pass"],
        ["WCPR Mean",     stats.wcpr_mean !== undefined ? (stats.wcpr_mean*100).toFixed(1)+"%" : "—", ""],
      ].map(([l,v,c]) => `<div class="readiness-item"><div class="ri-label">${esc(l)}</div>
        <div class="ri-val ${c}">${esc(String(v))}</div></div>`).join("")}
    </div>` : "";

  const byLevel = [
    { label: "Level A — Ground Truth", key: "level_a", open: true },
    { label: "Level B — Statistical Repetitions", key: "level_b", open: true },
    { label: "Level C — Scenario Redeployment", key: "level_c", open: false },
  ];

  document.getElementById("campaignsContent").innerHTML = statBar + byLevel.map(({ label, key, open }) => {
    const items = camps[key] || [];
    return `<details class="mb-4" ${open ? "open" : ""}>
      <summary>${esc(label)} (${items.length})</summary>
      ${items.map(c => {
        const detail = c.execution_detail || {};
        const levelKey = key.replace("level_", "").toUpperCase();
        const execs = (detail[levelKey] || {}).executions || [];
        const comparisons = detail["_comparisons"] || [];
        return `<div class="pl-2 mb-3 border-l-2 border-slate-700">
          <div class="flex items-center gap-2 py-2">
            <span class="font-mono text-xs text-slate-300">${esc(c.campaign_id || "—")}</span>
            ${statusBadge(c.status)}
            <span class="text-xs text-slate-500">${c.completed_executions ?? 0}/${c.execution_count ?? 0} exec · ${esc((c.created_at||"").slice(0,16))}</span>
            ${c.comparison_readiness === "ready" ? '<span class="badge badge-pass">Comparable</span>' : ""}
          </div>
          ${c.scientific_limitations?.length ? `
          <details class="mb-2">
            <summary class="text-yellow-400">Scientific Limitations (${c.scientific_limitations.length})</summary>
            <ul class="mt-1 space-y-0.5">${c.scientific_limitations.slice(0,5).map(l =>
              `<li class="text-xs text-yellow-300">⚠ ${esc(l)}</li>`).join("")}
            ${c.scientific_limitations.length > 5 ? `<li class="text-xs text-slate-500">… ${c.scientific_limitations.length-5} more</li>` : ""}
            </ul>
          </details>` : ""}
          ${execs.length ? `
          <details ${key === "level_b" ? "open" : ""}>
            <summary>Executions (${execs.length}) — CPR/WCPR</summary>
            <table class="ss-table mt-2">
              <thead><tr><th>Exec ID</th><th>Case</th><th>Status</th><th>CPR</th><th>WCPR</th><th>Ground Truth</th><th>Trigger</th></tr></thead>
              <tbody>${execs.map(e => `<tr>
                <td class="font-mono text-xs">${esc(e.execution_id)}</td>
                <td class="font-mono text-xs text-slate-400">${esc((e.case_id||"—").slice(0,12))}</td>
                <td>${statusBadge(e.status)}</td>
                <td class="font-bold ${(e.cpr||0) >= 0.7 ? "ri-pass" : (e.cpr||0) >= 0.4 ? "ri-warn" : "ri-fail"}">${e.cpr !== undefined ? (e.cpr*100).toFixed(1)+"%" : "—"}</td>
                <td class="font-bold ${(e.wcpr||0) >= 0.7 ? "ri-pass" : "ri-warn"}">${e.wcpr !== undefined ? (e.wcpr*100).toFixed(1)+"%" : "—"}</td>
                <td>${e.ground_truth_sealed ? '<span class="badge badge-pass">Sealed</span>' : '<span class="badge badge-na">—</span>'}</td>
                <td class="text-xs text-slate-400 max-w-[180px] truncate" title="${esc(e.selected_trigger||"")}">${esc(e.selected_trigger||"—")}</td>
              </tr>`).join("")}</tbody>
            </table>
          </details>` : ""}
          ${comparisons.length ? `
          <details>
            <summary>Comparisons (${comparisons.length})</summary>
            ${comparisons.map(cp => `<div class="pl-3 mt-1 text-xs text-slate-400">
              <span class="font-mono">${esc(cp.comparison_id)}</span>
              · ${(cp.execution_ids||[]).length} execs
              · Result: <strong class="${cp.overall_result === 'pass' ? 'ri-pass' : 'ri-warn'}">${esc(cp.overall_result||"—")}</strong>
              · ΔWCPR allowed: ${cp.delta_wcpr_allowed ?? "—"}
            </div>`).join("")}
          </details>` : ""}
        </div>`;
      }).join("") || `<p class="empty-note pl-4">No ${label} campaigns found.</p>`}
    </details>`;
  }).join("");
}

// FOC
function renderFoc(foc) {
  const paper = foc.paper_repetitions || {};
  const paperResults = paper.results || [];

  document.getElementById("focContent").innerHTML = `
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
      ${[
        ["Initialized",       foc.initialized ? "YES" : "NO",   foc.initialized ? "ri-pass" : "ri-fail"],
        ["Quality Status",    foc.quality_status || "—",         ""],
        ["Completeness",      foc.completeness || "—", ""],
        ["Reproducibility",   foc.reproducibility_score !== undefined ? Math.min(100, Math.round(foc.reproducibility_score||0))+"%" : "—", ""],
        ["Scenario BOM",      foc.scenario_bom?.present ? "PRESENT" : "MISSING", foc.scenario_bom?.present ? "ri-pass" : "ri-fail"],
        ["Tools BOM",         foc.tools_bom?.present ? "PRESENT" : "MISSING",    foc.tools_bom?.present ? "ri-pass" : "ri-fail"],
        ["Attack Attestation",foc.attack_attestation?.present ? "PRESENT" : "MISSING", foc.attack_attestation?.present ? "ri-pass" : "ri-fail"],
        ["Forensic Intervention", foc.forensic_intervention?.present ? "PRESENT" : "MISSING", foc.forensic_intervention?.present ? "ri-pass" : "ri-fail"],
      ].map(([l, v, cls]) => `<div class="readiness-item"><div class="ri-label">${esc(l)}</div>
        <div class="ri-val ${cls}">${esc(String(v))}</div></div>`).join("")}
    </div>
    <details>
      <summary>Paper Repetition Results (${paperResults.length})</summary>
      ${paperResults.length
        ? `<table class="ss-table mt-2">
            <thead><tr><th>Result ID</th><th>Campaign</th><th>Level</th><th>CPR</th><th>WCPR</th><th>In Paper</th></tr></thead>
            <tbody>${paperResults.map(r => `<tr>
              <td class="font-mono text-xs">${esc(r.result_id || "")}</td>
              <td class="text-xs">${esc(r.campaign_id || "—")}</td>
              <td>${esc(r.level || "—")}</td>
              <td>${r.cpr !== undefined ? (r.cpr * 100).toFixed(1) + "%" : "—"}</td>
              <td>${r.wcpr !== undefined ? (r.wcpr * 100).toFixed(1) + "%" : "—"}</td>
              <td>${r.included_in_paper ? '<span class="badge badge-pass">YES</span>'
                : (r.exclusion_reason ? `<span class="badge badge-warn" title="${esc(r.exclusion_reason)}">EXCLUDED</span>`
                : '<span class="badge badge-na">—</span>')}</td>
            </tr>`).join("")}</tbody>
          </table>`
        : '<p class="empty-note mt-2">No paper results recorded in result_registry.</p>'}
    </details>`;
}

// NETWORK CONFIG
function renderNetwork(nc) {
  const st = nc.summary || {};
  if (nc.collector_status !== "AVAILABLE") {
    document.getElementById("networkContent").innerHTML = `<p class="empty-note">Network config not available: ${esc(nc.error || nc.collector_status || "—")}</p>`;
    return;
  }
  document.getElementById("networkContent").innerHTML = `
    <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-5">
      ${[["Networks", st.network_count||0], ["Subnets", st.subnet_count||0], ["Routers", st.router_count||0],
         ["Security Groups", st.security_group_count||0], ["Floating IPs", st.floating_ip_count||0]]
        .map(([l,v]) => `<div class="readiness-item"><div class="ri-label">${esc(l)}</div><div class="ri-val">${v}</div></div>`).join("")}
    </div>
    <details open>
      <summary>Subnets & CIDRs (${(nc.subnets||[]).length})</summary>
      <table class="ss-table mt-2">
        <thead><tr><th>Name</th><th>CIDR</th><th>Gateway</th><th>DNS</th><th>DHCP</th></tr></thead>
        <tbody>${(nc.subnets||[]).map(s => `<tr>
          <td class="font-mono text-xs">${esc(s.name||"—")}</td>
          <td class="font-bold text-indigo-300">${esc(s.cidr||"—")}</td>
          <td class="text-slate-400 text-xs">${esc(s.gateway_ip||"—")}</td>
          <td class="text-slate-400 text-xs">${esc((s.dns_nameservers||[]).join(", ")||"—")}</td>
          <td>${s.enable_dhcp ? '<span class="badge badge-pass">ON</span>' : '<span class="badge badge-na">OFF</span>'}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>
    <details class="mt-3">
      <summary>Security Groups (${(nc.security_groups||[]).length})</summary>
      ${(nc.security_groups||[]).map(sg => `
        <details class="mt-2 pl-2 border-l border-slate-700">
          <summary class="font-semibold text-xs text-slate-300">${esc(sg.name)} — ${sg.rule_count} rules</summary>
          <table class="ss-table mt-2">
            <thead><tr><th>Dir</th><th>Protocol</th><th>Port Range</th><th>Remote IP</th><th>Ethertype</th></tr></thead>
            <tbody>${(sg.rules||[]).map(r => `<tr>
              <td class="${r.direction==="ingress" ? "text-green-400" : "text-orange-400"} font-semibold text-xs">${esc(r.direction||"—")}</td>
              <td class="text-xs">${esc(r.protocol||"any")}</td>
              <td class="text-xs">${r.port_range_min !== null && r.port_range_min !== undefined ? esc(r.port_range_min + (r.port_range_max !== r.port_range_min ? "-"+r.port_range_max : "")) : "any"}</td>
              <td class="font-mono text-xs text-slate-400">${esc(r.remote_ip_prefix||"—")}</td>
              <td class="text-xs text-slate-500">${esc(r.ethertype||"—")}</td>
            </tr>`).join("")}</tbody>
          </table>
        </details>`).join("")}
    </details>
    <details class="mt-3">
      <summary>Floating IPs (${(nc.floating_ips||[]).length})</summary>
      <table class="ss-table mt-2">
        <thead><tr><th>Floating IP</th><th>Fixed IP</th><th>Status</th></tr></thead>
        <tbody>${(nc.floating_ips||[]).map(f => `<tr>
          <td class="font-mono text-xs text-green-300">${esc(f.floating_ip||"—")}</td>
          <td class="font-mono text-xs text-slate-400">${esc(f.fixed_ip||"—")}</td>
          <td>${statusBadge(f.status)}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>`;
}

// NODE VERIFICATION
function renderNodeVerification(nv) {
  const byNode = nv.by_node || {};
  const nodes = Object.values(byNode);
  if (!nodes.length) {
    document.getElementById("nodeVerifyContent").innerHTML =
      '<p class="empty-note">No node health cache available. Run a node health probe from the Node Health view first.</p>';
    return;
  }

  const svcBadge = (v) => {
    if (!v || v === "NOT_AVAILABLE") return '<span class="badge badge-warn">?</span>';
    if (String(v).startsWith("active")) return `<span class="badge badge-pass" title="${esc(v)}">${esc(v)}</span>`;
    if (v === "inactive") return '<span class="badge badge-na">inactive</span>';
    return `<span class="badge badge-na">${esc(v)}</span>`;
  };

  // Render a "config" sub-block vs a "roles" sub-block
  // config = main yaml/conf key settings
  // roles  = detection rule files, FIM directories, decoders
  const cfgBlock = (label, lines, color) => {
    if (!lines || !lines.length) return "";
    const filtered = lines.filter(l => l && !l.startsWith("#") && l.trim());
    if (!filtered.length) return "";
    return `<div class="mb-2">
      <div class="text-[10px] uppercase tracking-[0.2em] font-black mb-1" style="color:${color}">${esc(label)}</div>
      <pre class="text-[11px] text-slate-300 bg-black/30 rounded-xl p-3 overflow-auto" style="max-height:180px;font-family:ui-monospace,monospace;">${esc(filtered.join("\n"))}</pre>
    </div>`;
  };

  const fileItem = (name, meta) =>
    `<div class="flex items-center gap-2 py-1 border-b border-slate-800/40">
      <span class="font-mono text-xs text-slate-200">${esc(name)}</span>
      ${meta ? `<span class="text-[10px] text-slate-500">${esc(meta)}</span>` : ""}
    </div>`;

  const parseInventoryLines = (lines) => lines.map(l => {
    const parts = l.split(" | ");
    const path = (parts[0] || "").trim();
    const name = path.split("/").pop() || path;
    const meta = parts.slice(1).join(" | ").trim();
    return { name, path, meta };
  });

  const ruleBadge = (r) => {
    const msg = r.interpretation || "";
    const isModbus = /modbus|register|coil/i.test(msg);
    const isPing = /ping|icmp/i.test(msg);
    const isWazuh = /wazuh|syscheck|fim/i.test(msg);
    if (isModbus) return '<span class="badge" style="background:rgba(239,68,68,0.18);color:#fca5a5;border-color:rgba(239,68,68,0.3)">ICS/Modbus</span>';
    if (isPing) return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#fcd34d;border-color:rgba(245,158,11,0.3)">ICMP</span>';
    return '<span class="badge badge-info">Detection</span>';
  };

  document.getElementById("nodeVerifyContent").innerHTML = `
    ${nv.live_verified
      ? `<div class="mb-4 text-xs text-green-400 font-semibold">✓ Live SSH verification performed at ${esc(nv.live_verified_at||"")}</div>`
      : `<div class="mb-4 text-xs text-yellow-400">⚠ Showing cached probe data only. Click <strong>Verify Nodes</strong> to run live SSH verification that captures configuration files and rules.</div>`}
    ${nodes.map(n => {
      const sv = n.services || {};
      const lv = n.live_verification || {};
      const suricata = lv.suricata || {};
      const wazuh = lv.wazuh || {};
      const tools = lv.tools || [];
      const hasLive = lv.status === "VERIFIED" || lv.status === "PARTIAL";

      // ── Suricata config (from config_summary) vs roles (rule files)
      const surConfig = suricata.config_summary || [];
      const surRuleFiles = suricata.active_rule_files || [];
      const surInventory = parseInventoryLines(suricata.rule_inventory || []);
      const surCustomSigs = suricata.custom_signatures || [];
      const surRules = suricata.rules || [];

      // ── Wazuh config (from config_summary) vs roles (rule/decoder files + FIM)
      const wazConfig = wazuh.config_summary || [];
      const wazRuleFiles = wazuh.local_rules || [];
      const wazDecoders = wazuh.local_decoders || [];
      const wazInventory = parseInventoryLines(wazuh.rule_inventory || []);
      const wazFim = wazuh.fim_paths || [];
      const wazContents = wazuh.rule_contents || [];

      const hasSuricata = String(sv.suricata || "").startsWith("active") || hasLive && surConfig.length;
      const hasWazuh = String(sv.wazuh_agent || "").startsWith("active") ||
                       String(sv.wazuh_manager || "").startsWith("active") ||
                       (hasLive && wazConfig.length);

      return `<details class="mb-4" open>
        <summary class="cursor-pointer flex items-center gap-2 py-1">
          <span class="font-bold text-sm">${esc(n.instance_name||n.instance_id)}</span>
          ${n.status === "CACHE_AVAILABLE" ? '<span class="badge badge-info">Cached</span>' : '<span class="badge badge-warn">No Cache</span>'}
          ${lv.status === "VERIFIED" ? '<span class="badge badge-pass">SSH Verified</span>'
            : lv.status === "FAILED" ? '<span class="badge badge-fail">SSH Failed</span>'
            : lv.status === "PARTIAL" ? '<span class="badge badge-warn">Partial</span>' : ""}
          <span class="text-slate-500 text-xs ml-1">${esc(n.cached_at ? "cached: " + n.cached_at.slice(0,16) : "")}</span>
        </summary>

        <div class="pl-3 pt-3 space-y-4">
          ${n.identity ? `<div class="text-xs text-slate-400">${esc(n.identity.os||"")} · ${esc(n.identity.kernel||"")} · ${esc(n.identity.hostname||"")}</div>` : ""}

          <!-- SERVICES -->
          <div>
            <div class="text-[10px] uppercase tracking-[0.25em] font-black text-slate-500 mb-2">Services (cached)</div>
            <div class="flex flex-wrap gap-3">
              ${Object.entries(sv).map(([k,v]) => `
                <div class="flex items-center gap-1">
                  <span class="text-[11px] text-slate-400">${esc(k)}</span>
                  ${svcBadge(v)}
                </div>`).join("")}
            </div>
          </div>

          <!-- TOOLS (only after live verification) -->
          ${tools.length ? `
          <details>
            <summary class="text-[10px] uppercase tracking-[0.25em] font-black text-slate-500 cursor-pointer">Tools — Live Verified (${tools.length})</summary>
            <table class="ss-table mt-2">
              <thead><tr><th>Tool</th><th>Declared</th><th>Present</th><th>Running</th><th>Version</th></tr></thead>
              <tbody>${tools.map(t => `<tr>
                <td class="font-semibold text-xs">${esc(t.name||t.id)}</td>
                <td>${statusBadge(t.declared_status)}</td>
                <td>${t.runtime_presence === "yes" ? '<span class="badge badge-pass">YES</span>'
                    : t.runtime_presence === "no" ? '<span class="badge badge-fail">NO</span>'
                    : '<span class="badge badge-warn">?</span>'}</td>
                <td>${svcBadge(t.runtime_status)}</td>
                <td class="text-xs text-slate-500 font-mono">${esc(t.runtime_version||"—")}</td>
              </tr>`).join("")}</tbody>
            </table>
          </details>` : ""}

          <!-- CONFIGURATION FILES SECTION -->
          ${hasSuricata || hasWazuh ? `
          <div>
            <div class="text-[10px] uppercase tracking-[0.25em] font-black text-slate-400 mb-3">Configuration Files</div>

            ${hasSuricata ? `
            <!-- SURICATA -->
            <details class="mb-3" open>
              <summary class="text-xs font-bold cursor-pointer flex items-center gap-2">
                <span style="color:#f97316">Suricata</span>
                <span class="text-slate-500 font-normal">/etc/suricata/</span>
                ${surRules.length ? `<span class="badge badge-info">${surRules.length} rules active</span>` : ""}
                ${!hasLive ? '<span class="badge badge-warn text-[10px]">verify nodes for config details</span>' : ""}
              </summary>
              <div class="pl-3 mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">

                <!-- config -->
                <div>
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-sky-400 mb-2">config — suricata.yaml</div>
                  ${surConfig.length
                    ? cfgBlock("", surConfig.filter(l => !l.startsWith("config_file=")), "#94a3b8")
                    : `<p class="text-[11px] text-slate-500 italic">${hasLive ? "No config captured" : "Run Verify Nodes to capture"}</p>`}
                  ${surConfig.filter(l => l.startsWith("config_file=")).map(l =>
                    `<div class="text-[10px] text-slate-600 font-mono mt-1">${esc(l)}</div>`
                  ).join("")}
                </div>

                <!-- roles -->
                <div>
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-orange-400 mb-2">roles — rule files</div>
                  ${surRuleFiles.length
                    ? `<div class="space-y-1">${surRuleFiles.map(f => fileItem(f, "")).join("")}</div>`
                    : `<p class="text-[11px] text-slate-500 italic">${hasLive ? "No rule files declared" : "Run Verify Nodes"}</p>`}
                  ${surInventory.length ? `
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-slate-500 mt-3 mb-1">Rule file inventory</div>
                  <div class="space-y-1">${surInventory.map(f => fileItem(f.name, f.meta)).join("")}</div>` : ""}
                  ${surCustomSigs.length ? `
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-red-400 mt-3 mb-1">Custom NICS signatures (${surCustomSigs.length})</div>
                  <div class="space-y-1">${surCustomSigs.map(s => {
                    const parts = s.split(" | ");
                    return `<div class="text-[11px] font-mono text-slate-300 py-0.5">${esc(parts[1]||"")} <span class="text-slate-500">${esc(parts[2]||"")}</span></div>`;
                  }).join("")}</div>` : ""}
                  ${surRules.length ? `
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-amber-400 mt-3 mb-1">Active parsed rules (${surRules.length})</div>
                  <table class="ss-table">
                    <thead><tr><th>Rule / SID</th><th>Type</th><th>Interpretation</th></tr></thead>
                    <tbody>${surRules.slice(0, 30).map(r => `<tr>
                      <td class="font-mono text-[10px]">${esc(r.raw?.match(/sid:\d+/)?.[0] || r.raw?.split("(")[0]?.trim().slice(0,50) || "—")}</td>
                      <td>${ruleBadge(r)}</td>
                      <td class="text-[11px] text-slate-400">${esc(r.interpretation||"—")}</td>
                    </tr>`).join("")}
                    ${surRules.length > 30 ? `<tr><td colspan="3" class="text-slate-500 text-[11px] italic">… and ${surRules.length - 30} more</td></tr>` : ""}
                    </tbody>
                  </table>` : ""}
                </div>
              </div>
            </details>` : ""}

            ${hasWazuh ? `
            <!-- WAZUH -->
            <details class="mb-3" open>
              <summary class="text-xs font-bold cursor-pointer flex items-center gap-2">
                <span style="color:#22c55e">Wazuh</span>
                <span class="text-slate-500 font-normal">/var/ossec/etc/</span>
                ${wazFim.length ? `<span class="badge badge-info">${wazFim.length} FIM path(s)</span>` : ""}
                ${!hasLive ? '<span class="badge badge-warn text-[10px]">verify nodes for config details</span>' : ""}
              </summary>
              <div class="pl-3 mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">

                <!-- config -->
                <div>
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-sky-400 mb-2">config — ossec.conf</div>
                  ${wazConfig.length
                    ? cfgBlock("", wazConfig.filter(l => !l.startsWith("config_file=")), "#94a3b8")
                    : `<p class="text-[11px] text-slate-500 italic">${hasLive ? "No config captured" : "Run Verify Nodes to capture"}</p>`}
                  ${wazConfig.filter(l => l.startsWith("config_file=")).map(l =>
                    `<div class="text-[10px] text-slate-600 font-mono mt-1">${esc(l)}</div>`
                  ).join("")}
                </div>

                <!-- roles -->
                <div>
                  <div class="text-[10px] uppercase tracking-[0.2em] font-black text-green-400 mb-2">roles — rules & decoders</div>

                  ${wazFim.length ? `
                  <div class="text-[10px] uppercase tracking-[0.18em] font-black text-purple-400 mb-1">FIM monitored paths</div>
                  <div class="space-y-1 mb-3">${wazFim.map(p => {
                    const realtime = /realtime.*yes|check_all/i.test(p);
                    const whodata = /whodata.*yes/i.test(p);
                    const pathMatch = p.match(/>([^<]+)</);
                    const pathStr = pathMatch ? pathMatch[1] : p.replace(/<[^>]+>/g, "").trim();
                    return `<div class="flex items-start gap-2 text-[11px]">
                      <span class="font-mono text-slate-300 break-all">${esc(pathStr)}</span>
                      ${realtime ? '<span class="badge" style="background:rgba(168,85,247,0.15);color:#d8b4fe;border-color:rgba(168,85,247,0.3);font-size:9px">realtime</span>' : ""}
                      ${whodata ? '<span class="badge" style="background:rgba(59,130,246,0.15);color:#93c5fd;border-color:rgba(59,130,246,0.3);font-size:9px">whodata</span>' : ""}
                    </div>`;
                  }).join("")}</div>` : ""}

                  ${wazRuleFiles.length ? `
                  <div class="text-[10px] uppercase tracking-[0.18em] font-black text-green-500 mb-1">Rule files</div>
                  <div class="space-y-1 mb-3">${wazRuleFiles.map(f => fileItem(f, "rules")).join("")}</div>` : ""}

                  ${wazDecoders.length ? `
                  <div class="text-[10px] uppercase tracking-[0.18em] font-black text-blue-400 mb-1">Decoder files</div>
                  <div class="space-y-1 mb-3">${wazDecoders.map(f => fileItem(f, "decoder")).join("")}</div>` : ""}

                  ${wazInventory.length ? `
                  <div class="text-[10px] uppercase tracking-[0.18em] font-black text-slate-500 mb-1">File inventory</div>
                  <div class="space-y-1">${wazInventory.map(f => fileItem(f.name, f.meta)).join("")}</div>` : ""}

                  ${wazContents.length ? `
                  <details class="mt-3">
                    <summary class="text-[10px] uppercase tracking-[0.2em] font-black text-slate-400 cursor-pointer">Rule file contents (${wazContents.length} files)</summary>
                    ${wazContents.map(fc => `
                    <div class="mt-2">
                      <div class="text-[10px] font-mono text-slate-400 mb-1">${esc(fc.file || fc.path || "")}</div>
                      <pre class="text-[10px] text-slate-300 bg-black/40 rounded-xl p-2 overflow-auto" style="max-height:200px;font-family:ui-monospace,monospace;">${esc((fc.lines||[]).join("\n"))}</pre>
                    </div>`).join("")}
                  </details>` : ""}
                </div>
              </div>
            </details>` : ""}

          </div>` : ""}

          ${lv.error ? `<div class="text-xs text-red-400 mt-1">SSH Error: ${esc(typeof lv.error === "object" ? (lv.error.message||JSON.stringify(lv.error)) : lv.error)}</div>` : ""}
        </div>
      </details>`;
    }).join("")}`;
}

// PROCEDURES
function renderProcedures(proc) {
  if (!proc || proc.collector_status !== "AVAILABLE") {
    document.getElementById("proceduresContent").innerHTML = '<p class="empty-note">Procedures not available.</p>';
    return;
  }
  const policy = proc.snapshot_preservation_policy || {};
  const it = proc.it_scenario_construction || {};
  const ot = proc.ot_node_mounting || {};
  const det = proc.detection_system_configuration || {};
  const tm = proc.tool_management || {};
  const dst = proc.scenario_destruction || {};
  const lc = proc.level_c_redeployment || {};

  const stepsHtml = (steps) => steps?.length
    ? `<ol class="mt-2 space-y-1">${steps.map(s => `<li class="text-xs text-slate-300">${esc(s)}</li>`).join("")}</ol>` : "";
  const scriptInfo = (si) => si?.exists
    ? `<span class="font-mono text-xs text-green-400">✓ ${esc(si.path)}</span>`
    : `<span class="font-mono text-xs text-slate-500">✗ ${esc(si?.path||"—")}</span>`;

  document.getElementById("proceduresContent").innerHTML = `
    <!-- Preservation Policy -->
    <div class="readiness-item mb-4 border-l-4 border-indigo-500">
      <div class="ri-label">Snapshot Preservation Policy</div>
      <div class="text-xs text-indigo-300 mt-1 font-semibold">${esc(policy.rule||"")}</div>
      <div class="text-xs text-slate-400 mt-1">${esc(policy.reason||"")}</div>
    </div>

    <details open class="mb-3">
      <summary>1. IT Scenario Construction (OpenStack)</summary>
      <div class="pl-3 mt-2 space-y-2">
        <div class="text-xs text-slate-300">${esc(it.description||"")}</div>
        <div class="text-xs"><strong class="text-slate-400">Input:</strong> <span class="font-mono text-indigo-300">${esc(it.input_file||"—")}</span></div>
        <div class="text-xs"><strong class="text-slate-400">Credentials:</strong> <code class="text-xs text-yellow-300">${esc(it.openstack_credentials||"")}</code></div>
        <div class="mt-1"><strong class="text-xs text-slate-400">Scripts:</strong>
          <div class="mt-1 space-y-0.5">${Object.entries(it.scripts||{}).map(([k,s]) => `<div>${scriptInfo(s)}</div>`).join("")}</div>
        </div>
        ${stepsHtml(it.steps)}
      </div>
    </details>

    <details class="mb-3">
      <summary>2. OT Node Mounting (PLC / SCADA)</summary>
      <div class="pl-3 mt-2 space-y-3">
        ${["plc", "scada"].map(key => {
          const node = (ot[key] || ot[key.toUpperCase()] || {});
          return `<div>
            <div class="font-bold text-xs text-slate-300 uppercase">${key.toUpperCase()} — ${esc(node.software||"")}</div>
            <div class="text-xs text-slate-400">${esc(node.protocol||"")}</div>
            <div class="mt-1">Cloud-init: ${scriptInfo(node.cloud_init_template)}</div>
            ${stepsHtml(node.steps)}
          </div>`;
        }).join("<hr class='border-slate-700 my-2'/>")}
      </div>
    </details>

    <details class="mb-3">
      <summary>3. Detection Systems (Suricata / Wazuh)</summary>
      <div class="pl-3 mt-2 space-y-3">
        ${["suricata", "wazuh"].map(key => {
          const d = det[key] || {};
          return `<div>
            <div class="font-bold text-xs text-slate-300">${key.toUpperCase()} — ${esc(d.description||"")}</div>
            <div class="mt-1">Playbook: ${scriptInfo(d.ansible_playbook)}</div>
            ${d.manager_ip ? `<div class="text-xs text-slate-400">Manager IP: <code class="text-yellow-300">${esc(d.manager_ip)}</code> · Agent: <code>${esc(d.agent_version||"")}</code></div>` : ""}
            ${Object.keys(d.key_config||{}).length ? `
            <details><summary class="text-xs">Key Configuration</summary>
              <div class="pl-3 mt-1 grid grid-cols-2 gap-1">
                ${Object.entries(d.key_config).map(([k,v]) => `<div class="text-xs"><span class="text-slate-500">${esc(k)}: </span><code class="text-slate-300">${esc(String(v))}</code></div>`).join("")}
              </div>
            </details>` : ""}
            ${stepsHtml(d.steps)}
          </div>`;
        }).join("<hr class='border-slate-700 my-2'/>")}
      </div>
    </details>

    <details class="mb-3">
      <summary>4. Tool Management (${(tm.available_tools||[]).length} tools)</summary>
      <div class="pl-3 mt-2">
        ${stepsHtml(tm.install_steps)}
        <div class="mt-2 flex gap-2 flex-wrap">
          ${(tm.available_tools||[]).map(t => `<span class="badge badge-info">${esc(t.tool)}</span>`).join("")}
        </div>
      </div>
    </details>

    <details class="mb-3">
      <summary>5. Scenario Destruction</summary>
      <div class="pl-3 mt-2 space-y-2">
        <div class="text-xs text-red-400 font-semibold">⚠ ${esc(dst.critical_warning||"")}</div>
        <div>Script: ${scriptInfo(dst.script)}</div>
        <div class="text-xs text-slate-400">Destroys: ${(dst.what_gets_destroyed||[]).join(", ")}</div>
        <div class="text-xs text-green-400">Preserved: ${(dst.what_is_PRESERVED||[]).slice(0,3).join(", ")}…</div>
        ${stepsHtml(dst.steps)}
      </div>
    </details>

    <details class="mb-3">
      <summary>6. Level C — Full Scenario Redeployment
        <span class="badge badge-warn ml-2">${esc(lc.status||"NOT_IMPLEMENTED")}</span>
      </summary>
      <div class="pl-3 mt-2">
        <div class="text-xs text-slate-300 mb-2">${esc(lc.description||"")}</div>
        <div class="text-xs text-slate-400 italic">${esc(lc.note||"")}</div>
        ${stepsHtml(lc.planned_steps)}
      </div>
    </details>`;
}

// AUDIT
function renderAudit(snap) {
  const val = snap.validation || {};
  const forensics = snap.forensics || {};
  const campaigns = snap.campaigns || {};
  const hashes = snap.hashes || {};
  const prov = snap.provenance || {};

  const cases = forensics.cases || [];
  const sealedCases = cases.filter(c => c.sealed).length;
  const custodyCases = cases.filter(c => c.custody_chain_present).length;

  const b_camps = (campaigns.level_b || []);
  const stats = campaigns.level_b_statistics || {};

  const checks = val.checks || [];
  const passed = checks.filter(c => c.status === "PASS").length;
  const failed = checks.filter(c => c.status === "FAIL").length;
  const warned = checks.filter(c => c.status === "WARNING").length;

  document.getElementById("auditContent").innerHTML = `
    <!-- Snapshot Integrity -->
    <details open class="mb-4">
      <summary>Snapshot Integrity</summary>
      <div class="pl-3 mt-2 space-y-2">
        <div class="text-xs"><strong class="text-slate-400">Snapshot ID:</strong> <span class="font-mono text-indigo-300">${esc(snap.snapshot_id||"—")}</span></div>
        <div class="text-xs"><strong class="text-slate-400">SHA-256:</strong> <span class="font-mono text-xs text-indigo-300 break-all">${esc(hashes.snapshot_hash||"—")}</span></div>
        <div class="text-xs"><strong class="text-slate-400">Captured:</strong> ${esc(snap.captured_at_utc||"—")}</div>
        <div class="text-xs"><strong class="text-slate-400">Status:</strong> ${statusBadge(snap.status)} ${snap.sealed ? '<span class="badge badge-sealed">SEALED</span>' : ""}</div>
        <div class="text-xs"><strong class="text-slate-400">Errors during capture:</strong> ${prov.error_count||0} / Warnings: ${prov.warning_count||0}</div>
      </div>
    </details>

    <!-- Reproducibility Summary -->
    <details open class="mb-4">
      <summary>Reproducibility Assessment (Level A / B / C)</summary>
      <div class="pl-3 mt-2 grid grid-cols-2 md:grid-cols-3 gap-3">
        ${[
          ["Overall Ready",      val.overall_reproduction_ready ? "YES" : "NO",    val.overall_reproduction_ready ? "ri-pass" : "ri-fail"],
          ["Snapshot Capture",   val.snapshot_capture_ready ? "READY" : "NOT READY", val.snapshot_capture_ready ? "ri-pass" : "ri-fail"],
          ["Incident Replay",    val.incident_replay_ready ? "READY" : "NOT READY",  val.incident_replay_ready ? "ri-pass" : "ri-warn"],
          ["DFIR Replay",        val.dfir_replay_ready ? "READY" : "NOT READY",      val.dfir_replay_ready ? "ri-pass" : "ri-warn"],
          ["Campaign Replay",    val.campaign_replay_ready ? "READY" : "NOT READY",  val.campaign_replay_ready ? "ri-pass" : "ri-warn"],
          ["Paper Traceability", val.paper_traceability_ready ? "READY" : "NOT READY", val.paper_traceability_ready ? "ri-pass" : "ri-warn"],
          ["Scenario Redeployment", val.scenario_redeployment_ready ? "READY" : "NOT READY", val.scenario_redeployment_ready ? "ri-pass" : "ri-warn"],
        ].map(([l,v,c]) => `<div class="readiness-item"><div class="ri-label">${esc(l)}</div>
          <div class="ri-val ${c}">${esc(v)}</div></div>`).join("")}
      </div>
    </details>

    <!-- Validation Checks Summary -->
    <details class="mb-4">
      <summary>Validation Checks — ${passed} PASS / ${warned} WARN / ${failed} FAIL</summary>
      <div class="grid grid-cols-3 gap-3 my-3">
        ${[["PASS", passed, "ri-pass"], ["WARN", warned, "ri-warn"], ["FAIL", failed, "ri-fail"]]
          .map(([l,v,c]) => `<div class="readiness-item text-center"><div class="ri-label">${l}</div>
            <div class="ri-val ${c} text-3xl">${v}</div></div>`).join("")}
      </div>
      <table class="ss-table">
        <thead><tr><th>Domain</th><th>Requirement</th><th>Status</th><th>Reason</th></tr></thead>
        <tbody>${checks.filter(c => c.status === "FAIL").map(c => `<tr>
          <td class="text-xs font-semibold">${esc(c.domain)}</td>
          <td class="text-xs">${esc(c.requirement)}</td>
          <td><span class="badge badge-fail">FAIL</span></td>
          <td class="text-xs text-slate-400">${esc(c.reason)}</td>
        </tr>`).join("")}
        ${checks.filter(c => c.status === "WARNING").map(c => `<tr>
          <td class="text-xs font-semibold">${esc(c.domain)}</td>
          <td class="text-xs">${esc(c.requirement)}</td>
          <td><span class="badge badge-warn">WARN</span></td>
          <td class="text-xs text-slate-400">${esc(c.reason)}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>

    <!-- Chain of Custody Audit -->
    <details class="mb-4">
      <summary>Chain of Custody — ${cases.length} cases / ${sealedCases} sealed / ${custodyCases} with custody</summary>
      <table class="ss-table mt-2">
        <thead><tr><th>Case ID</th><th>Sealed</th><th>Custody Log</th><th>Analysis</th><th>Bundle</th><th>Campaign</th></tr></thead>
        <tbody>${cases.map(c => `<tr>
          <td class="font-mono text-xs">${esc(c.case_id)}</td>
          <td>${c.sealed ? '<span class="badge badge-sealed">YES</span>' : '<span class="badge badge-fail">NO</span>'}</td>
          <td>${c.custody_chain_present ? '<span class="badge badge-pass">YES</span>' : '<span class="badge badge-warn">NO</span>'}</td>
          <td>${c.analysis_present ? '<span class="badge badge-pass">YES</span>' : '<span class="badge badge-na">—</span>'}</td>
          <td>${c.lightweight_bundle_present ? '<span class="badge badge-pass">YES</span>' : '<span class="badge badge-na">—</span>'}</td>
          <td class="font-mono text-xs text-slate-500">${esc((c.campaign_id||"—").slice(0,20))}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>

    <!-- Level B Scientific Metrics -->
    ${stats.execution_count ? `
    <details open class="mb-4">
      <summary>Level B Scientific Metrics — ${stats.execution_count} executions</summary>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 my-3">
        ${[
          ["Runs", stats.execution_count, ""],
          ["CPR Mean", stats.cpr_mean !== undefined ? (stats.cpr_mean*100).toFixed(2)+"%" : "—", stats.cpr_mean >= 0.7 ? "ri-pass" : "ri-warn"],
          ["CPR Min", stats.cpr_min !== undefined ? (stats.cpr_min*100).toFixed(2)+"%" : "—", "ri-warn"],
          ["WCPR Mean", stats.wcpr_mean !== undefined ? (stats.wcpr_mean*100).toFixed(2)+"%" : "—", ""],
        ].map(([l,v,c]) => `<div class="readiness-item"><div class="ri-label">${esc(l)}</div>
          <div class="ri-val ${c}">${esc(String(v))}</div></div>`).join("")}
      </div>
      <p class="text-xs text-slate-400">CPR = Forensic Continuity Ratio. WCPR = Weighted CPR. Values ≥ 70% indicate good reproducibility.</p>
    </details>` : ""}

    <!-- Key File Integrity -->
    <details class="mb-4">
      <summary>Key File Integrity Hashes</summary>
      <table class="ss-table mt-2">
        <thead><tr><th>File</th><th>SHA-256</th><th>Size</th></tr></thead>
        <tbody>${Object.entries((hashes.key_files||{})).map(([k,h]) => `<tr>
          <td class="font-mono text-xs text-slate-300">${esc(k)}</td>
          <td class="font-mono text-xs ${h.sha256 ? "text-indigo-300" : "text-slate-500"}">${esc(h.sha256 || h.status || "—")}</td>
          <td class="text-xs text-slate-500">${h.size_bytes !== undefined ? (h.size_bytes/1024).toFixed(1)+" KB" : "—"}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>`;
}

// PROVENANCE
function renderProvenance(snap) {
  const prov = snap.provenance || {};
  const hashes = (snap.hashes || {}).key_files || {};

  document.getElementById("provenanceContent").innerHTML = `
    <div class="mb-4">
      <div class="text-xs text-slate-400 mb-2">Snapshot Hash (SHA-256)</div>
      <div class="font-mono text-xs text-indigo-300 break-all">${esc((snap.hashes || {}).snapshot_hash || "—")}</div>
    </div>
    ${prov.warnings?.length
      ? `<details class="mb-3">
          <summary>Warnings (${prov.warnings.length})</summary>
          <ul class="mt-2 space-y-1">${prov.warnings.map(w => `<li class="text-xs text-yellow-400">⚠ ${esc(w)}</li>`).join("")}</ul>
        </details>` : ""}
    ${prov.errors?.length
      ? `<details class="mb-3">
          <summary class="text-red-400">Errors (${prov.errors.length})</summary>
          <ul class="mt-2 space-y-1">${prov.errors.map(e => `<li class="text-xs text-red-400">✕ ${esc(e)}</li>`).join("")}</ul>
        </details>` : ""}
    <details class="mb-3">
      <summary>Sources Consulted</summary>
      <ul class="mt-2 space-y-1">${(prov.sources_consulted || []).map(s =>
        `<li class="font-mono text-xs text-slate-400">${esc(s)}</li>`).join("")}</ul>
    </details>
    <details>
      <summary>Key File Hashes</summary>
      <table class="ss-table mt-2">
        <thead><tr><th>File</th><th>SHA-256</th><th>Size</th></tr></thead>
        <tbody>${Object.entries(hashes).map(([k, h]) => `<tr>
          <td class="font-semibold text-xs">${esc(k)}</td>
          <td class="font-mono text-xs text-indigo-300 break-all">${esc(h.sha256 || h.status || "—")}</td>
          <td class="text-slate-500 text-xs">${h.size_bytes !== undefined ? (h.size_bytes / 1024).toFixed(1) + " KB" : "—"}</td>
        </tr>`).join("")}</tbody>
      </table>
    </details>`;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------
async function sealCurrent() {
  if (!currentSnapshotId) return;
  if (!confirm(`Seal snapshot ${currentSnapshotId}? Sealed snapshots cannot be modified.`)) return;
  try {
    const res = await fetch(API.seal(currentSnapshotId), { method: "POST" });
    const data = await res.json();
    if (data.error) { showError(`Seal failed: ${data.error}`); return; }
    alert(`Snapshot sealed.\nHash: ${data.snapshot_hash}`);
    await loadSnapshot(currentSnapshotId);
  } catch (err) { showError(`Seal error: ${err.message}`); }
}

async function deleteCurrent() {
  if (!currentSnapshotId) return;
  const snap = currentSnapshot || {};
  if (snap.sealed) {
    if (!confirm(`⚠ SEALED snapshot ${currentSnapshotId}\n\nSealed snapshots are the reconstruction blueprint. Are you absolutely sure you want to delete this sealed snapshot? This action is IRREVERSIBLE.`)) return;
    if (!confirm(`FINAL CONFIRMATION: Delete sealed snapshot ${currentSnapshotId}?`)) return;
    try {
      const res = await fetch(`${API.get(currentSnapshotId)}?force=true`, { method: "DELETE" });
      const data = await res.json();
      if (data.error) { showError(`Delete failed: ${data.error}`); return; }
      currentSnapshot = null; currentSnapshotId = null;
      document.getElementById("mainContent").style.display = "none";
      showEmptyState(true);
      await loadSnapshotList();
    } catch (err) { showError(`Delete error: ${err.message}`); }
  } else {
    if (!confirm(`Delete snapshot ${currentSnapshotId}? This action cannot be undone.`)) return;
    try {
      const res = await fetch(API.get(currentSnapshotId), { method: "DELETE" });
      const data = await res.json();
      if (data.error) { showError(`Delete failed: ${data.error}`); return; }
      currentSnapshot = null; currentSnapshotId = null;
      document.getElementById("mainContent").style.display = "none";
      showEmptyState(true);
      await loadSnapshotList();
      await loadLatest();
    } catch (err) { showError(`Delete error: ${err.message}`); }
  }
}

async function verifyNodesCurrent() {
  if (!currentSnapshotId) return;
  const btn = document.getElementById("btnVerify");
  if (btn) { btn.disabled = true; btn.textContent = "Verifying…"; }
  try {
    const res = await fetch(`${API.get(currentSnapshotId)}/verify-nodes`, { method: "POST" });
    const data = await res.json();
    if (data.error) { showError(`Verify failed: ${data.error}`); return; }
    // Poll until verification finishes (poll the snapshot and check live_verified flag)
    let attempts = 0;
    const check = async () => {
      attempts++;
      const r2 = await fetch(API.get(currentSnapshotId));
      const snap = await r2.json();
      if ((snap.node_verification || {}).live_verified) {
        renderSnapshot(snap);
        switchTab("node-verify");
        if (btn) { btn.disabled = false; btn.textContent = "Verify Nodes"; }
        return;
      }
      if (attempts < 30) setTimeout(check, 3000);
      else {
        if (btn) { btn.disabled = false; btn.textContent = "Verify Nodes"; }
        showError("Verification timed out. Nodes may be unreachable via SSH.");
      }
    };
    setTimeout(check, 5000);
  } catch (err) {
    if (btn) { btn.disabled = false; btn.textContent = "Verify Nodes"; }
    showError(`Verify error: ${err.message}`);
  }
}

async function validateCurrent() {
  if (!currentSnapshotId) return;
  try {
    const res = await fetch(API.validate(currentSnapshotId), { method: "POST" });
    const data = await res.json();
    switchTab("readiness");
    renderReadiness(data.validation || {});
  } catch (err) { showError(`Validate error: ${err.message}`); }
}

function exportCurrent() {
  if (!currentSnapshotId) return;
  window.location.href = API.export(currentSnapshotId);
}

// ---------------------------------------------------------------------------
// Progress animation
// ---------------------------------------------------------------------------
const PROG_STEPS = ["scenario","infra","tools","attacks","forensics","campaigns","rel","val","done"];
let progStep = 0;
let progTimer = null;

function animateProgress() {
  progStep = 0;
  PROG_STEPS.forEach(k => {
    const d = document.getElementById("dot-" + k);
    if (d) { d.className = "prog-dot"; }
  });
  clearInterval(progTimer);
  progTimer = setInterval(() => {
    if (progStep > 0) {
      const prev = PROG_STEPS[progStep - 1];
      const d = document.getElementById("dot-" + prev);
      if (d) d.className = "prog-dot done";
    }
    if (progStep < PROG_STEPS.length) {
      const cur = PROG_STEPS[progStep];
      const d = document.getElementById("dot-" + cur);
      if (d) d.className = "prog-dot active";
      progStep++;
    } else {
      clearInterval(progTimer);
    }
  }, 700);
}

function markAllDone() {
  PROG_STEPS.forEach(k => {
    const d = document.getElementById("dot-" + k);
    if (d) d.className = "prog-dot done";
  });
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
function switchTab(id) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  const panel = document.getElementById("tab-" + id);
  if (panel) panel.classList.add("active");
  document.querySelectorAll(".tab-btn").forEach(b => {
    if (b.getAttribute("onclick") === `switchTab('${id}')`) b.classList.add("active");
  });
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------
function setBtn(disabled, label) {
  const btn = document.getElementById("btnCapture");
  if (btn) { btn.disabled = disabled; btn.textContent = label; }
}

function setBadge(text, cls) {
  const el = document.getElementById("captureStatusBadge");
  if (!el) return;
  el.className = "badge " + (cls || "badge-na");
  el.textContent = text || "IDLE";
}

function showProgress(show) {
  const el = document.getElementById("captureProgress");
  if (el) el.style.display = show ? "block" : "none";
  if (!show && progTimer) { clearInterval(progTimer); progTimer = null; }
  if (!show) markAllDone();
}

function showEmptyState(show) {
  document.getElementById("emptyState").style.display = show ? "block" : "none";
  document.getElementById("mainContent").style.display = show ? "none" : "block";
}

function showError(msg) {
  console.error(msg);
  const el = document.getElementById("metaStatus");
  if (el) el.textContent = "Error: " + msg;
}

function statusToBadgeClass(status) {
  const s = String(status || "").toUpperCase();
  if (s === "COMPLETED" || s === "SEALED") return "badge-pass";
  if (s === "COMPLETED_WITH_WARNINGS") return "badge-warn";
  if (s === "FAILED" || s === "INCOMPLETE" || s === "INVALID") return "badge-fail";
  if (s === "COLLECTING") return "badge-info";
  return "badge-na";
}

function statusToCls(status) {
  const s = String(status || "").toUpperCase();
  if (s === "COMPLETED" || s === "SEALED") return "ri-pass";
  if (s === "COMPLETED_WITH_WARNINGS") return "ri-warn";
  if (s === "FAILED" || s === "INCOMPLETE") return "ri-fail";
  return "";
}

function statusBadge(status) {
  const s = String(status || "—").toUpperCase();
  let cls = "badge-na";
  if (["COMPLETED","ACTIVE","INSTALLED","PASS","AVAILABLE","YES"].includes(s)) cls = "badge-pass";
  else if (["WARNING","WARN","PENDING","AMBIGUOUS"].includes(s)) cls = "badge-warn";
  else if (["FAILED","FAIL","ERROR","MISSING","INCOMPLETE","INVALID","NOT_FOUND"].includes(s)) cls = "badge-fail";
  else if (["COLLECTING","IN_PROGRESS","RUNNING"].includes(s)) cls = "badge-info";
  else if (["SEALED"].includes(s)) cls = "badge-sealed";
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function relBadge(status) {
  const s = String(status || "").toUpperCase();
  let cls = "badge-na";
  if (s === "CONFIRMED") cls = "badge-pass";
  else if (s === "AMBIGUOUS") cls = "badge-warn";
  else if (s === "MISSING") cls = "badge-fail";
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function sevBadge(sev) {
  const s = String(sev || "—").toUpperCase();
  let cls = "badge-na";
  if (s === "CRITICAL") cls = "badge-fail";
  else if (s === "HIGH") cls = "badge-warn";
  else if (s === "MEDIUM") cls = "badge-info";
  else if (s === "LOW") cls = "badge-pass";
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function toolBadge(status) {
  const s = String(status || "").toUpperCase();
  let cls = "badge-na";
  if (s === "INSTALLED") cls = "badge-pass";
  else if (s === "PENDING") cls = "badge-warn";
  else if (s === "FAILED") cls = "badge-fail";
  else if (s === "UNRESOLVED") cls = "badge-na";
  return `<span class="badge ${cls}">${esc(s)}</span>`;
}

function esc(str) {
  return String(str ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
