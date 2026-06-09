const API_BASE = "/adv-detection/api";

const API = {
  status: `${API_BASE}/status`,
  config: `${API_BASE}/config`,
  assets: `${API_BASE}/assets`,
  runs: `${API_BASE}/runs`,
  runDetail: (runId) => `${API_BASE}/runs/${encodeURIComponent(runId)}`,
  run: `${API_BASE}/run`,
};

const UI = {
  statusDot: document.getElementById("status-dot"),
  moduleStatus: document.getElementById("module-status"),
  vendorPath: document.getElementById("vendor-path"),
  runsPath: document.getElementById("runs-path"),
  btnRefresh: document.getElementById("btn-refresh"),

  runMode: document.getElementById("run-mode"),
  entrypointSelect: document.getElementById("entrypoint-select"),
  runArguments: document.getElementById("run-arguments"),
  runTimeout: document.getElementById("run-timeout"),
  customCommandBox: document.getElementById("custom-command-box"),
  customCommand: document.getElementById("custom-command"),
  btnRun: document.getElementById("btn-run"),
  btnLoadAssets: document.getElementById("btn-load-assets"),

  resultBox: document.getElementById("result-box"),
  consoleBox: document.getElementById("console-box"),
  repoSummary: document.getElementById("repo-summary"),
  runsTable: document.getElementById("runs-table"),

  detailRunId: document.getElementById("detail-run-id"),
  detailStarted: document.getElementById("detail-started"),
  detailFinished: document.getElementById("detail-finished"),
  detailReturnCode: document.getElementById("detail-return-code"),
  detailFiles: document.getElementById("detail-files"),
  detailStdout: document.getElementById("detail-stdout"),
  detailStderr: document.getElementById("detail-stderr"),
};

const State = {
  assets: null,
  status: null,
  selectedRunId: "",
};

function logLine(text) {
  const now = new Date().toLocaleTimeString();
  UI.consoleBox.value += `[${now}] ${text}\n`;
  UI.consoleBox.scrollTop = UI.consoleBox.scrollHeight;
}

function setResult(value) {
  UI.resultBox.value = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function safeFetchJson(url, options = {}) {
  const res = await fetch(url, options);
  let data = null;

  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok || !data?.ok) {
    throw new Error(data?.error || `HTTP ${res.status} ${res.statusText}`);
  }

  return data;
}

function updateStatusUi(ok, text) {
  UI.statusDot.className = `status-dot ${ok ? "dot-ok" : "dot-bad"}`;
  UI.moduleStatus.textContent = text;
}

function updateModeUi() {
  const mode = UI.runMode.value;
  const isCustom = mode === "custom_command";
  UI.customCommandBox.classList.toggle("hidden", !isCustom);
  UI.entrypointSelect.disabled = isCustom;
}

function populateEntrypoints() {
  const mode = UI.runMode.value;
  const assets = State.assets || { notebooks: [], python_files: [] };

  let items = [];
  if (mode === "notebook") {
    items = assets.notebooks || [];
  } else if (mode === "python_file") {
    items = assets.python_files || [];
  }

  if (!items.length) {
    UI.entrypointSelect.innerHTML = `<option value="">No assets available</option>`;
    return;
  }

  UI.entrypointSelect.innerHTML = items
    .map(item => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`)
    .join("");
}

function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadStatus() {
  const res = await safeFetchJson(API.status);
  const data = res.data;
  State.status = data;

  updateStatusUi(!!data.vendor_repo_exists, data.vendor_repo_exists ? "online" : "vendor missing");
  UI.vendorPath.textContent = data.vendor_repo_dir || "—";
  UI.runsPath.textContent = data.runs_dir || "—";

  const summary = data.vendor_summary || {};
  UI.repoSummary.textContent = JSON.stringify(summary, null, 2);
  setResult(res);
}

async function loadAssets() {
  const res = await safeFetchJson(API.assets);
  State.assets = res.data;
  populateEntrypoints();
  logLine("Vendor assets loaded");
}

async function loadRuns() {
  const res = await safeFetchJson(API.runs);
  const runs = res.data?.runs || [];

  if (!runs.length) {
    UI.runsTable.innerHTML = `<tr><td colspan="5" class="mut">No runs found.</td></tr>`;
    return;
  }

  UI.runsTable.innerHTML = runs.map(run => `
    <tr>
      <td class="mono">${escapeHtml(run.run_id || "")}</td>
      <td>${escapeHtml(run.mode || "")}</td>
      <td class="mono">${escapeHtml(run.entrypoint || "")}</td>
      <td>${escapeHtml(String(run.return_code ?? "—"))}</td>
      <td><button class="view-run-btn" data-run-id="${escapeHtml(run.run_id || "")}">View</button></td>
    </tr>
  `).join("");

  UI.runsTable.querySelectorAll(".view-run-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const runId = btn.getAttribute("data-run-id");
      await loadRunDetail(runId);
    });
  });
}

async function loadRunDetail(runId) {
  const res = await safeFetchJson(API.runDetail(runId));
  const data = res.data || {};
  State.selectedRunId = runId;

  UI.detailRunId.textContent = data.run_id || "—";
  UI.detailStarted.textContent = data.meta?.started_at_utc || "—";
  UI.detailFinished.textContent = data.result?.finished_at_utc || "—";
  UI.detailReturnCode.textContent = String(data.result?.return_code ?? "—");
  UI.detailStdout.value = data.stdout || "";
  UI.detailStderr.value = data.stderr || "";
  UI.detailFiles.textContent = JSON.stringify(data.files || [], null, 2);

  logLine(`Loaded run detail: ${runId}`);
}

async function runVendorEntrypoint() {
  const payload = {
    mode: UI.runMode.value,
    entrypoint: UI.entrypointSelect.value,
    arguments: UI.runArguments.value.trim(),
    timeout: Number(UI.runTimeout.value || 3600),
    custom_command: UI.customCommand.value.trim(),
  };

  const res = await safeFetchJson(API.run, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  setResult(res);
  logLine(`Run finished: ${res.data?.run_id || "unknown"}`);

  await loadRuns();

  if (res.data?.run_id) {
    await loadRunDetail(res.data.run_id);
  }
}

UI.runMode.addEventListener("change", () => {
  updateModeUi();
  populateEntrypoints();
});

UI.btnRefresh.addEventListener("click", async () => {
  try {
    await loadStatus();
    await loadAssets();
    await loadRuns();
    logLine("Refresh complete");
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR: ${e.message}`);
  }
});

UI.btnLoadAssets.addEventListener("click", async () => {
  try {
    await loadAssets();
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR: ${e.message}`);
  }
});

UI.btnRun.addEventListener("click", async () => {
  try {
    await runVendorEntrypoint();
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR: ${e.message}`);
  }
});

document.addEventListener("DOMContentLoaded", async () => {
  try {
    updateModeUi();
    await loadStatus();
    await loadAssets();
    await loadRuns();
    logLine("adv_detection module ready");
  } catch (e) {
    updateStatusUi(false, "offline");
    setResult(e.message);
    logLine(`ERROR on load: ${e.message}`);
  }
});