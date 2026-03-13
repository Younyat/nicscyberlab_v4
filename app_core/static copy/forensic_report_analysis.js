const API_BASE = "http://127.0.0.1:5001";

const API = {
  cases: `${API_BASE}/api/forensics/report/cases`,
  summary: (caseDir) => `${API_BASE}/api/forensics/report/summary?case_dir=${encodeURIComponent(caseDir)}`,
  manifest: (caseDir) => `${API_BASE}/api/forensics/report/manifest?case_dir=${encodeURIComponent(caseDir)}`,
  custody: (caseDir, limit = 200) => `${API_BASE}/api/forensics/report/chain-of-custody?case_dir=${encodeURIComponent(caseDir)}&limit=${encodeURIComponent(limit)}`,
  pipeline: (caseDir, limit = 300) => `${API_BASE}/api/forensics/report/pipeline-events?case_dir=${encodeURIComponent(caseDir)}&limit=${encodeURIComponent(limit)}`,
  download: (caseDir, rel) => `${API_BASE}/api/forensics/case/download?case_dir=${encodeURIComponent(caseDir)}&rel=${encodeURIComponent(rel)}`
};

const UI = {
  backendDot: document.getElementById("backend-dot"),
  backendStatus: document.getElementById("backend-status"),
  caseSelector: document.getElementById("case-selector"),
  btnRefreshAll: document.getElementById("btn-refresh-all"),
  topLastSync: document.getElementById("top-last-sync"),

  caseStatusBadge: document.getElementById("case-status-badge"),
  caseIdBadge: document.getElementById("case-id-badge"),
  caseDir: document.getElementById("case-dir"),
  evidenceCount: document.getElementById("evidence-count"),
  manifestStatus: document.getElementById("manifest-status"),

  targetsGrid: document.getElementById("targets-grid"),
  storageKpis: document.getElementById("storage-kpis"),
  integritySummary: document.getElementById("integrity-summary"),

  artifactSearch: document.getElementById("artifact-search"),
  artifactTypeFilter: document.getElementById("artifact-type-filter"),
  artifactsBody: document.getElementById("artifacts-body"),

  manifestSummary: document.getElementById("manifest-summary"),
  custodyList: document.getElementById("custody-list"),
  pipelineList: document.getElementById("pipeline-list"),
  manifestRaw: document.getElementById("manifest-raw"),

  selArtifactName: document.getElementById("sel-artifact-name"),
  selArtifactType: document.getElementById("sel-artifact-type"),
  selArtifactPath: document.getElementById("sel-artifact-path"),
  selAcquisitionMethod: document.getElementById("sel-acquisition-method"),
  selForensicValue: document.getElementById("sel-forensic-value"),
  selSha256: document.getElementById("sel-sha256"),
  selSize: document.getElementById("sel-size"),
  selCollectedAt: document.getElementById("sel-collected-at"),
  selCollectedBy: document.getElementById("sel-collected-by"),

  btnDownloadSelected: document.getElementById("btn-download-selected"),
  btnCopyPath: document.getElementById("btn-copy-path")
};

const State = {
  currentCaseDir: "",
  summary: null,
  manifest: null,
  custody: [],
  pipeline: [],
  artifacts: [],
  filteredArtifacts: [],
  selectedArtifact: null,
  artifactChart: null
};

function nowTime() {
  return new Date().toLocaleTimeString();
}

function setBackendStatus(ok, text) {
  UI.backendDot.className = "w-2 h-2 rounded-full " + (ok ? "bg-emerald-500" : "bg-red-500");
  UI.backendStatus.textContent = text;
}

async function safeFetchJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  return await res.json();
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "--";
  if (n === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 2)} ${units[idx]}`;
}

function formatDateTime(value) {
  if (!value) return "--";
  try {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value;
    return d.toLocaleString();
  } catch {
    return value;
  }
}

function shortHash(v) {
  if (!v) return "--";
  const s = String(v);
  return s.length <= 18 ? s : `${s.slice(0, 10)}...${s.slice(-8)}`;
}

function classifyArtifactFamily(type, relPath = "") {
  const t = String(type || "").toLowerCase();
  const p = String(relPath || "").toLowerCase();

  if (t.includes("memory") || p.startsWith("memory/")) return "memory";
  if (t.includes("disk") || p.startsWith("disk/")) return "disk";
  if (
    t.includes("pcap") ||
    t.includes("network") ||
    p.startsWith("network/")
  ) return "network";
  if (
    t.includes("industrial") ||
    t.includes("ot_export") ||
    p.startsWith("industrial/")
  ) return "industrial";
  if (
    t.includes("manifest") ||
    t.includes("custody") ||
    t.includes("digest") ||
    t.includes("time_sync") ||
    t.includes("ir_") ||
    t.includes("fsr_") ||
    p.startsWith("metadata/") ||
    p === "chain_of_custody.log" ||
    p === "manifest.json"
  ) return "metadata";

  return "other";
}

function typeRowClass(family) {
  if (family === "memory") return "type-memory";
  if (family === "disk") return "type-disk";
  if (family === "network") return "type-network";
  if (family === "industrial") return "type-industrial";
  if (family === "metadata") return "type-metadata";
  return "type-other";
}

function inferTargetFromPath(relPath = "") {
  const p = String(relPath || "").toLowerCase();

  if (p.includes("plc")) return "PLC";
  if (p.includes("scada") || p.includes("fuxa")) return "SCADA";
  if (p.includes("victim")) return "Victim";
  if (p.includes("per_vm")) {
    const parts = relPath.split("/");
    const idx = parts.findIndex(x => x === "per_vm");
    if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
  }

  return "Case";
}

function inferAcquisitionMethod(artifact) {
  const t = String(artifact.type || "").toLowerCase();
  const p = String(artifact.rel_path || "").toLowerCase();

  if (t.includes("memory") || p.startsWith("memory/")) return "LiME over SSH";
  if (t.includes("disk") || p.startsWith("disk/")) return "libvirt raw export";
  if (t.includes("pcap")) return "packet capture";
  if (t.includes("industrial_ot_export")) return "derived OT export from preserved traffic";
  if (t.includes("ir_snapshot")) return "case input snapshot";
  if (t.includes("time_sync")) return "time synchronization export";
  if (t.includes("fsr_eval")) return "post preservation reproducibility evaluation";
  if (t.includes("case_digest")) return "integrity digest generation";
  if (t.includes("custody")) return "append only custody registration";
  return "preservation workflow";
}

function inferForensicValue(artifact) {
  const family = classifyArtifactFamily(artifact.type, artifact.rel_path);

  if (family === "memory") {
    return "Volatile state, processes, memory resident code, network sockets, modules, and transient artifacts not recoverable from disk.";
  }
  if (family === "disk") {
    return "Persistent filesystem state, dropped payloads, execution traces, deleted content, logs, and timeline reconstruction from stable storage.";
  }
  if (family === "network") {
    return "Traffic level reconstruction, session context, protocol exchanges, lateral movement evidence, and preservation of the incident communication window.";
  }
  if (family === "industrial") {
    return "OT protocol specific operational context, extracted commands, industrial communication semantics, and evidence of process level interactions.";
  }
  if (family === "metadata") {
    return "Preservation context, integrity verifiers, case level reproducibility inputs, custody accountability, and event traceability.";
  }
  return "Preserved case material useful for correlation and supporting interpretation.";
}

function renderTargets(targets = []) {
  if (!targets.length) {
    UI.targetsGrid.innerHTML = `
      <div class="rounded-2xl border border-slate-800/70 bg-slate-950/30 p-4 text-xs text-slate-400 mono">
        No explicit targets inferred.
      </div>
    `;
    return;
  }

  UI.targetsGrid.innerHTML = targets.map(t => {
    return `
      <div class="rounded-2xl border border-slate-800/70 bg-slate-950/30 p-4">
        <div class="flex items-center justify-between gap-3">
          <div>
            <div class="kpi">${escapeHtml(t.role || "target")}</div>
            <div class="font-extrabold text-slate-100 mt-1">${escapeHtml(t.name || "--")}</div>
            <div class="mono text-xs text-slate-400 mt-1">${escapeHtml(t.ip || "--")}</div>
          </div>
          <span class="badge">${escapeHtml(t.state || "preserved")}</span>
        </div>
      </div>
    `;
  }).join("");
}

function renderStorage(summary) {
  UI.storageKpis.innerHTML = `
    <div>
      <div class="kpi">Total Preserved Size</div>
      <div class="text-xl font-black text-slate-100 mt-1">${escapeHtml(formatBytes(summary.total_size_bytes || 0))}</div>
    </div>
    <div>
      <div class="kpi">Primary Artifacts</div>
      <div class="text-base font-extrabold text-slate-100 mt-1">${escapeHtml(String(summary.primary_count || 0))}</div>
    </div>
    <div>
      <div class="kpi">Derived and Metadata</div>
      <div class="text-base font-extrabold text-slate-100 mt-1">${escapeHtml(String(summary.derived_count || 0))}</div>
    </div>
  `;
}

function renderIntegrity(summary) {
  UI.integritySummary.innerHTML = `
    <div>
      <div class="kpi">Hashed Artifacts</div>
      <div class="text-xl font-black text-emerald-300 mt-1">${escapeHtml(String(summary.hashed_count || 0))}</div>
    </div>
    <div>
      <div class="kpi">Without Hash</div>
      <div class="text-base font-extrabold text-amber-300 mt-1">${escapeHtml(String(summary.missing_hash_count || 0))}</div>
    </div>
    <div>
      <div class="kpi">Chain Entries</div>
      <div class="text-base font-extrabold text-slate-100 mt-1">${escapeHtml(String(summary.custody_entries || 0))}</div>
    </div>
  `;
}

function initOrUpdateChart(typeCounts) {
  const labels = Object.keys(typeCounts);
  const data = Object.values(typeCounts);
  const canvas = document.getElementById("artifactChart");
  if (!canvas) return;

  if (State.artifactChart) {
    State.artifactChart.destroy();
    State.artifactChart = null;
  }

  State.artifactChart = new Chart(canvas.getContext("2d"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data,
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "rgba(226,232,240,0.8)" }
        }
      }
    }
  });
}

function selectArtifactById(id) {
  const found = State.artifacts.find(a => a.id === id);
  if (!found) return;
  State.selectedArtifact = found;

  UI.selArtifactName.textContent = found.name || "--";
  UI.selArtifactType.textContent = `Type: ${found.type || "--"}`;
  UI.selArtifactPath.textContent = found.absolute_path || found.rel_path || "--";
  UI.selAcquisitionMethod.textContent = found.acquisition_method || "--";
  UI.selForensicValue.textContent = found.forensic_value || "--";
  UI.selSha256.textContent = found.sha256 || "--";
  UI.selSize.textContent = formatBytes(found.size);
  UI.selCollectedAt.textContent = formatDateTime(found.ts || found.acquired_at || "");
  UI.selCollectedBy.textContent = found.collected_by || "preservation workflow";

  document.querySelectorAll(".artifact-row").forEach(row => {
    row.classList.toggle("active", row.dataset.artifactId === id);
  });
}

function applyArtifactFilters() {
  const q = String(UI.artifactSearch.value || "").trim().toLowerCase();
  const tf = String(UI.artifactTypeFilter.value || "all").toLowerCase();

  State.filteredArtifacts = State.artifacts.filter(a => {
    const family = classifyArtifactFamily(a.type, a.rel_path);
    if (tf !== "all" && family !== tf) return false;

    if (!q) return true;

    const hay = [
      a.type,
      a.target,
      a.rel_path,
      a.absolute_path,
      a.sha256,
      a.name
    ].join(" ").toLowerCase();

    return hay.includes(q);
  });

  renderArtifactsTable();
}

function renderArtifactsTable() {
  if (!State.filteredArtifacts.length) {
    UI.artifactsBody.innerHTML = `
      <tr>
        <td class="px-4 py-3 mono text-slate-400" colspan="5">No artifacts match the current filter.</td>
      </tr>
    `;
    return;
  }

  UI.artifactsBody.innerHTML = State.filteredArtifacts.map(a => {
    const family = classifyArtifactFamily(a.type, a.rel_path);
    const rowClass = typeRowClass(family);

    return `
      <tr class="artifact-row ${rowClass}" data-artifact-id="${escapeHtml(a.id)}">
        <td class="px-4 py-3">
          <div class="font-bold text-slate-200">${escapeHtml(a.type || "--")}</div>
          <div class="mono text-[10px] text-slate-400 mt-1">${escapeHtml(family)}</div>
        </td>
        <td class="px-4 py-3">${escapeHtml(a.target || "--")}</td>
        <td class="px-4 py-3 mono text-slate-300 break-all">${escapeHtml(a.rel_path || "--")}</td>
        <td class="px-4 py-3 mono text-slate-300">${escapeHtml(shortHash(a.sha256 || ""))}</td>
        <td class="px-4 py-3">
          <button class="btn px-3 py-2 bg-sky-600 hover:bg-sky-500 text-white text-[10px] download-artifact" data-rel="${escapeHtml(a.rel_path || "")}">
            Download
          </button>
        </td>
      </tr>
    `;
  }).join("");

  UI.artifactsBody.querySelectorAll(".artifact-row").forEach(row => {
    row.addEventListener("click", (ev) => {
      const id = row.dataset.artifactId;
      if (!id) return;
      selectArtifactById(id);
    });
  });

  UI.artifactsBody.querySelectorAll(".download-artifact").forEach(btn => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const rel = btn.getAttribute("data-rel");
      if (!rel || !State.currentCaseDir) return;
      window.open(API.download(State.currentCaseDir, rel), "_blank");
    });
  });

  if (State.selectedArtifact) {
    selectArtifactById(State.selectedArtifact.id);
  } else if (State.filteredArtifacts[0]) {
    selectArtifactById(State.filteredArtifacts[0].id);
  }
}

function renderManifestSummary(summary) {
  UI.manifestSummary.innerHTML = `
    <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-4">
      <div class="kpi">Scenario</div>
      <div class="text-sm font-extrabold text-slate-100 mt-2">${escapeHtml(summary.scenario_name || "--")}</div>
    </div>

    <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-4">
      <div class="kpi">Created At</div>
      <div class="mono text-xs text-slate-200 mt-2">${escapeHtml(formatDateTime(summary.created_at || ""))}</div>
    </div>

    <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-4">
      <div class="kpi">Acquisition Window</div>
      <div class="mono text-xs text-slate-200 mt-2">${escapeHtml(formatDateTime(summary.acquisition_start || ""))}</div>
      <div class="mono text-xs text-slate-400 mt-1">${escapeHtml(formatDateTime(summary.acquisition_end || ""))}</div>
    </div>

    <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-4">
      <div class="kpi">Manifest SHA-256</div>
      <div class="mono text-xs text-slate-200 mt-2 break-all">${escapeHtml(summary.manifest_hash || "--")}</div>
    </div>

    <div class="rounded-2xl border border-slate-800/80 bg-slate-950/35 p-4">
      <div class="kpi">Case Digest SHA-256</div>
      <div class="mono text-xs text-slate-200 mt-2 break-all">${escapeHtml(summary.case_digest_hash || "--")}</div>
    </div>
  `;
}

function renderCustody(entries = []) {
  if (!entries.length) {
    UI.custodyList.innerHTML = `
      <div class="rounded-2xl border border-slate-800/70 bg-slate-950/30 p-4 text-xs text-slate-400 mono">
        No chain of custody entries found.
      </div>
    `;
    return;
  }

  UI.custodyList.innerHTML = entries.map(e => {
    return `
      <div class="rounded-2xl border border-slate-800/70 bg-slate-950/30 p-4">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="font-extrabold text-slate-100">${escapeHtml(e.action || "--")}</div>
            <div class="mono text-[10px] text-slate-400 mt-1">${escapeHtml(formatDateTime(e.ts_utc || ""))}</div>
          </div>
          <span class="badge">${escapeHtml(e.outcome || "ok")}</span>
        </div>
        <div class="mt-3 text-xs text-slate-300">
          <div><span class="text-slate-400 mono">Actor:</span> ${escapeHtml(e.actor || "--")}</div>
          <div class="mt-1 break-all"><span class="text-slate-400 mono">Artifact:</span> ${escapeHtml(e.artifact_rel || "--")}</div>
          <div class="mt-1 break-all"><span class="text-slate-400 mono">Hash:</span> ${escapeHtml(shortHash(e.entry_hash || ""))}</div>
        </div>
      </div>
    `;
  }).join("");
}

function iconForEvent(name) {
  const e = String(name || "").toLowerCase();

  if (e.includes("alert")) return "fa-bell";
  if (e.includes("start")) return "fa-play";
  if (e.includes("preserved")) return "fa-box-archive";
  if (e.includes("failed")) return "fa-triangle-exclamation";
  if (e.includes("digest")) return "fa-fingerprint";
  if (e.includes("time_sync")) return "fa-clock";
  if (e.includes("derived")) return "fa-diagram-project";
  return "fa-circle-info";
}

function renderPipeline(events = []) {
  if (!events.length) {
    UI.pipelineList.innerHTML = `
      <div class="rounded-2xl border border-slate-800/70 bg-slate-950/30 p-4 text-xs text-slate-400 mono">
        No pipeline events found.
      </div>
    `;
    return;
  }

  UI.pipelineList.innerHTML = events.map(e => {
    return `
      <div class="timeline-item">
        <div class="timeline-dot"><i class="fa-solid ${escapeHtml(iconForEvent(e.event || ""))}"></i></div>
        <div class="rounded-2xl border border-slate-800/70 bg-slate-950/30 p-4">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="font-extrabold text-slate-100">${escapeHtml(e.event || "--")}</div>
              <div class="mono text-[10px] text-slate-400 mt-1">${escapeHtml(formatDateTime(e.ts_utc || ""))}</div>
            </div>
            <span class="badge">${escapeHtml(e.run_id || "R1")}</span>
          </div>
          <div class="mt-3 mono text-[10px] text-slate-400 whitespace-pre-wrap break-all">${escapeHtml(JSON.stringify(e.meta || {}, null, 2))}</div>
        </div>
      </div>
    `;
  }).join("");
}

async function loadCases() {
  const data = await safeFetchJson(API.cases);
  const cases = Array.isArray(data.cases) ? data.cases : [];
  const activeCase = data.active_case_dir || "";

  if (!cases.length) {
    UI.caseSelector.innerHTML = `<option value="">No cases found</option>`;
    return;
  }

  UI.caseSelector.innerHTML = cases.map(c => {
    const selected = c.case_dir === activeCase ? "selected" : "";
    return `<option value="${escapeHtml(c.case_dir)}" ${selected}>${escapeHtml(c.case_name)}${c.is_active ? " · active" : ""}</option>`;
  }).join("");

  State.currentCaseDir = UI.caseSelector.value || activeCase || cases[0].case_dir || "";
  if (State.currentCaseDir) {
    UI.caseSelector.value = State.currentCaseDir;
  }
}

async function loadReportForCase(caseDir) {
  if (!caseDir) return;

  const [summaryData, manifestData, custodyData, pipelineData] = await Promise.all([
    safeFetchJson(API.summary(caseDir)),
    safeFetchJson(API.manifest(caseDir)),
    safeFetchJson(API.custody(caseDir)),
    safeFetchJson(API.pipeline(caseDir))
  ]);

  State.summary = summaryData;
  State.manifest = manifestData;
  State.custody = Array.isArray(custodyData.entries) ? custodyData.entries : [];
  State.pipeline = Array.isArray(pipelineData.events) ? pipelineData.events : [];
  State.artifacts = Array.isArray(manifestData.artifacts) ? manifestData.artifacts : [];
  State.filteredArtifacts = [...State.artifacts];

  UI.caseStatusBadge.textContent = `status: ${summaryData.case_status || "unknown"}`;
  UI.caseIdBadge.textContent = `case: ${summaryData.case_id || "--"}`;
  UI.caseDir.textContent = summaryData.case_dir || "--";
  UI.evidenceCount.textContent = String(State.artifacts.length);
  UI.manifestStatus.textContent = summaryData.manifest_status || "loaded";
  UI.topLastSync.textContent = nowTime();

  renderTargets(summaryData.targets || []);
  renderStorage(summaryData.summary || {});
  renderIntegrity(summaryData.summary || {});
  renderManifestSummary(summaryData.manifest_overview || {});
  renderCustody(State.custody);
  renderPipeline(State.pipeline);
  UI.manifestRaw.textContent = JSON.stringify(manifestData.raw_manifest || manifestData, null, 2);

  initOrUpdateChart(summaryData.summary?.type_distribution || {});

  applyArtifactFilters();
}

UI.caseSelector.addEventListener("change", async () => {
  State.currentCaseDir = UI.caseSelector.value || "";
  State.selectedArtifact = null;
  await refreshAll();
});

UI.artifactSearch.addEventListener("input", applyArtifactFilters);
UI.artifactTypeFilter.addEventListener("change", applyArtifactFilters);

UI.btnRefreshAll.addEventListener("click", refreshAll);

UI.btnDownloadSelected.addEventListener("click", () => {
  if (!State.selectedArtifact || !State.currentCaseDir) return;
  window.open(API.download(State.currentCaseDir, State.selectedArtifact.rel_path), "_blank");
});

UI.btnCopyPath.addEventListener("click", async () => {
  if (!State.selectedArtifact) return;
  try {
    await navigator.clipboard.writeText(State.selectedArtifact.absolute_path || State.selectedArtifact.rel_path || "");
  } catch (_) {}
});

async function refreshAll() {
  try {
    setBackendStatus(true, "connected");
    if (!State.currentCaseDir) {
      await loadCases();
    }
    if (State.currentCaseDir) {
      await loadReportForCase(State.currentCaseDir);
    }
  } catch (e) {
    setBackendStatus(false, "offline");
    UI.artifactsBody.innerHTML = `
      <tr>
        <td class="px-4 py-3 mono text-red-300" colspan="5">Failed to load report: ${escapeHtml(e.message)}</td>
      </tr>
    `;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  try {
    await loadCases();
    await refreshAll();
  } catch (e) {
    setBackendStatus(false, "offline");
  }
});