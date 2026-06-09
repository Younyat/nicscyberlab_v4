const API_BASE = "http://127.0.0.1:5001/api/windows-lab-exchange";

const API = {
  health: `${API_BASE}/health`,
  bootstrap: `${API_BASE}/bootstrap`,
  list: `${API_BASE}/api/list`,
  upload: `${API_BASE}/api/upload`,
  zip: `${API_BASE}/api/zip`,
  send: `${API_BASE}/api/send`,
  sshGetConfig: `${API_BASE}/api/ssh/config`,
  sshSetConfig: `${API_BASE}/api/ssh/config`,
  sshTest: `${API_BASE}/api/ssh/test`,
  sshVerifyRemoteFile: `${API_BASE}/api/ssh/verify-remote-file`,
  sshReadRemoteJson: `${API_BASE}/api/ssh/read-remote-json`,
  sshExec: `${API_BASE}/api/ssh/exec`
};

const UI = {
  backendDot: document.getElementById("backend-dot"),
  backendStatus: document.getElementById("backend-status"),
  sshDot: document.getElementById("ssh-dot"),
  sshStatus: document.getElementById("ssh-status"),

  rootSelector: document.getElementById("root-selector"),
  currentPathBadge: document.getElementById("current-path-badge"),
  currentPath: document.getElementById("current-path"),
  btnOpenPath: document.getElementById("btn-open-path"),
  btnParent: document.getElementById("btn-parent"),
  btnRefreshAll: document.getElementById("btn-refresh-all"),
  browserTable: document.getElementById("browser-table").querySelector("tbody"),
  selectedCount: document.getElementById("selected-count"),

  zipName: document.getElementById("zip-name"),
  btnCreateZip: document.getElementById("btn-create-zip"),

  uploadFile: document.getElementById("upload-file"),
  btnUploadFile: document.getElementById("btn-upload-file"),

  sendPath: document.getElementById("send-path"),
  btnSendFile: document.getElementById("btn-send-file"),

  console: document.getElementById("console"),
  btnClearConsole: document.getElementById("btn-clear-console"),

  selName: document.getElementById("sel-name"),
  selPath: document.getElementById("sel-path"),
  selType: document.getElementById("sel-type"),
  selSize: document.getElementById("sel-size"),
  selModified: document.getElementById("sel-modified"),
  btnUseSelectedForSend: document.getElementById("btn-use-selected-for-send"),
  btnCopySelectedPath: document.getElementById("btn-copy-selected-path"),

  resultBox: document.getElementById("result-box"),

  sshHost: document.getElementById("ssh-host"),
  sshPort: document.getElementById("ssh-port"),
  sshUser: document.getElementById("ssh-user"),
  sshTimeout: document.getElementById("ssh-timeout"),
  sshAuthType: document.getElementById("ssh-auth-type"),
  sshRemoteDir: document.getElementById("ssh-remote-dir"),
  sshPassword: document.getElementById("ssh-password"),
  sshKeyPath: document.getElementById("ssh-key-path"),
  sshKeyPassphrase: document.getElementById("ssh-key-passphrase"),
  passwordAuthBox: document.getElementById("password-auth-box"),
  keyAuthBox: document.getElementById("key-auth-box"),
  btnSaveSshConfig: document.getElementById("btn-save-ssh-config"),
  btnLoadSshConfig: document.getElementById("btn-load-ssh-config"),
  btnTestSsh: document.getElementById("btn-test-ssh"),

  remoteVerifyPath: document.getElementById("remote-verify-path"),
  btnUseLastRemotePath: document.getElementById("btn-use-last-remote-path"),
  btnVerifyRemoteFile: document.getElementById("btn-verify-remote-file"),

  remoteJsonPath: document.getElementById("remote-json-path"),
  jsonSearch: document.getElementById("json-search"),
  btnUseLastJsonPath: document.getElementById("btn-use-last-json-path"),
  btnReadRemoteJson: document.getElementById("btn-read-remote-json"),
  jsonReportPath: document.getElementById("json-report-path"),
  jsonReportSize: document.getElementById("json-report-size"),
  jsonReportModified: document.getElementById("json-report-modified"),
  jsonViewer: document.getElementById("json-viewer"),
  btnCopyJsonRaw: document.getElementById("btn-copy-json-raw"),
  btnExpandJson: document.getElementById("btn-expand-json"),
  btnCollapseJson: document.getElementById("btn-collapse-json"),

  execType: document.getElementById("exec-type"),
  execCwd: document.getElementById("exec-cwd"),
  execCommand: document.getElementById("exec-command"),
  execTimeout: document.getElementById("exec-timeout"),
  execTargetFile: document.getElementById("exec-target-file"),
  execPostCheck: document.getElementById("exec-post-check"),
  btnRunRemote: document.getElementById("btn-run-remote"),

  remoteHostView: document.getElementById("remote-host-view"),
  remoteUserView: document.getElementById("remote-user-view"),
  remoteDirView: document.getElementById("remote-dir-view"),
  lastRemotePathView: document.getElementById("last-remote-path-view"),
  lastConnectionCheckView: document.getElementById("last-connection-check-view")
};

const State = {
  allowedRoots: [],
  currentPath: "",
  parentPath: "",
  entries: [],
  selectedPaths: new Set(),
  selectedEntry: null,
  sshConfig: null,
  lastRemotePath: "",
  loadedJsonReport: null,
  loadedJsonRaw: ""
};

function nowTime() {
  return new Date().toLocaleTimeString();
}

function setBackendStatus(ok, text) {
  UI.backendDot.className = "status-dot " + (ok ? "dot-ok" : "dot-bad");
  UI.backendStatus.textContent = text;
}

function setSshStatus(kind, text) {
  const cls = kind === "ok" ? "dot-ok" : kind === "warn" ? "dot-warn" : "dot-bad";
  UI.sshDot.className = "status-dot " + cls;
  UI.sshStatus.textContent = text;
}

function logLine(text) {
  const prefix = `[${nowTime()}] `;
  UI.console.value += prefix + text + "\n";
  UI.console.scrollTop = UI.console.scrollHeight;
}

function setResult(obj) {
  UI.resultBox.value = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
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

async function safeFetchJson(url, options = {}) {
  const res = await fetch(url, options);

  if (!res.ok) {
    let message = `HTTP ${res.status} ${res.statusText}`;
    try {
      const errData = await res.json();
      if (errData?.error) {
        message = errData.error;
      }
    } catch {
    }
    throw new Error(message);
  }

  return await res.json();
}

function updateSelectedCount() {
  UI.selectedCount.textContent = String(State.selectedPaths.size);
}

function setSelectedEntry(entry) {
  State.selectedEntry = entry || null;
  UI.selName.textContent = entry?.name || "—";
  UI.selPath.textContent = entry?.path || "—";
  UI.selType.textContent = entry ? (entry.is_dir ? "directory" : "file") : "—";
  UI.selSize.textContent = entry && !entry.is_dir ? formatBytes(entry.size) : "—";
  UI.selModified.textContent = entry?.modified_utc || "—";
}

function populateRootSelector(roots) {
  if (!Array.isArray(roots) || !roots.length) {
    UI.rootSelector.innerHTML = `<option value="/tmp">/tmp</option>`;
    return;
  }

  UI.rootSelector.innerHTML = roots
    .map(root => `<option value="${escapeHtml(root)}">${escapeHtml(root)}</option>`)
    .join("");
}

function renderBrowserTable() {
  if (!State.entries.length) {
    UI.browserTable.innerHTML = `<tr><td colspan="6" class="mut">No entries found.</td></tr>`;
    return;
  }

  UI.browserTable.innerHTML = State.entries.map(entry => {
    const checked = State.selectedPaths.has(entry.path) ? "checked" : "";
    const rowClass = State.selectedEntry?.path === entry.path ? "clickrow selected" : "clickrow";
    const typeLabel = entry.is_dir ? "directory" : "file";

    return `
      <tr class="${rowClass}" data-path="${escapeHtml(entry.path)}">
        <td>
          <input type="checkbox" class="path-check" data-path="${escapeHtml(entry.path)}" ${checked}>
        </td>
        <td>${escapeHtml(entry.name)}</td>
        <td><span class="tag">${escapeHtml(typeLabel)}</span></td>
        <td>${entry.is_dir ? "—" : escapeHtml(formatBytes(entry.size))}</td>
        <td class="mono">${escapeHtml(entry.modified_utc || "--")}</td>
        <td>
          ${entry.is_dir
            ? `<button class="open-dir-btn" data-path="${escapeHtml(entry.path)}">Open</button>`
            : `<button class="use-send-btn" data-path="${escapeHtml(entry.path)}">Use</button>`
          }
        </td>
      </tr>
    `;
  }).join("");

  UI.browserTable.querySelectorAll("tr.clickrow").forEach(row => {
    row.addEventListener("click", ev => {
      if (ev.target.closest("button") || ev.target.closest("input")) return;
      const path = row.getAttribute("data-path");
      const entry = State.entries.find(item => item.path === path);
      setSelectedEntry(entry);
      renderBrowserTable();
    });
  });

  UI.browserTable.querySelectorAll(".path-check").forEach(input => {
    input.addEventListener("change", () => {
      const path = input.getAttribute("data-path");

      if (input.checked) {
        State.selectedPaths.add(path);
      } else {
        State.selectedPaths.delete(path);
      }

      updateSelectedCount();
      logLine(`Selection updated: ${path}`);
    });
  });

  UI.browserTable.querySelectorAll(".open-dir-btn").forEach(btn => {
    btn.addEventListener("click", async ev => {
      ev.stopPropagation();
      const path = btn.getAttribute("data-path");
      UI.currentPath.value = path;
      await loadDirectory(path);
    });
  });

  UI.browserTable.querySelectorAll(".use-send-btn").forEach(btn => {
    btn.addEventListener("click", ev => {
      ev.stopPropagation();
      const path = btn.getAttribute("data-path");
      UI.sendPath.value = path;
      logLine(`Send path set to ${path}`);
    });
  });
}

function updateAuthUi() {
  const authType = UI.sshAuthType.value;
  if (authType === "key") {
    UI.passwordAuthBox.classList.add("hidden");
    UI.keyAuthBox.classList.remove("hidden");
  } else {
    UI.passwordAuthBox.classList.remove("hidden");
    UI.keyAuthBox.classList.add("hidden");
  }
}

function updateRemoteSummaryViews(config) {
  UI.remoteHostView.textContent = config?.host || "—";
  UI.remoteUserView.textContent = config?.user || "—";
  UI.remoteDirView.textContent = config?.remote_dir || "—";
  UI.lastRemotePathView.textContent = State.lastRemotePath || "—";
  UI.lastConnectionCheckView.textContent = config?.last_test_at_utc || "—";
}

function applySshConfigToUi(config) {
  if (!config) return;

  UI.sshHost.value = config.host || "";
  UI.sshPort.value = config.port ?? 22;
  UI.sshUser.value = config.user || "";
  UI.sshTimeout.value = config.timeout ?? 15;
  UI.sshAuthType.value = config.auth_type || "password";
  UI.sshRemoteDir.value = config.remote_dir || "";
  UI.sshKeyPath.value = config.key_path || "";
  UI.sshPassword.value = "";
  UI.sshKeyPassphrase.value = "";
  State.lastRemotePath = config.last_remote_path || State.lastRemotePath || "";

  updateAuthUi();
  updateRemoteSummaryViews(config);

  if (config.host && config.user) {
    setSshStatus("warn", "configured");
  } else {
    setSshStatus("bad", "not configured");
  }
}

function collectSshConfigFromUi() {
  const authType = String(UI.sshAuthType.value || "password").trim();

  return {
    host: String(UI.sshHost.value || "").trim(),
    port: Number(UI.sshPort.value || 22),
    user: String(UI.sshUser.value || "").trim(),
    timeout: Number(UI.sshTimeout.value || 15),
    auth_type: authType,
    remote_dir: String(UI.sshRemoteDir.value || "").trim(),
    password: authType === "password" ? String(UI.sshPassword.value || "") : "",
    key_path: authType === "key" ? String(UI.sshKeyPath.value || "").trim() : "",
    key_passphrase: authType === "key" ? String(UI.sshKeyPassphrase.value || "") : ""
  };
}

async function checkBackendHealth() {
  const result = await safeFetchJson(API.health, { method: "GET" });

  if (!result.ok || result.status !== "online") {
    throw new Error("Backend health check failed");
  }

  setBackendStatus(true, "online");
  logLine("Backend health check OK");
}

async function loadBootstrap() {
  const result = await safeFetchJson(API.bootstrap, { method: "GET" });

  if (!result.ok) {
    throw new Error("Bootstrap failed");
  }

  const data = result.data || {};
  const allowedRoots = Array.isArray(data.allowed_roots) ? data.allowed_roots : [];
  const initialPath = String(data.initial_path || "/tmp");

  State.allowedRoots = allowedRoots;
  populateRootSelector(allowedRoots);

  const matchingRoot = allowedRoots.includes(initialPath)
    ? initialPath
    : (allowedRoots[0] || initialPath);

  UI.rootSelector.value = matchingRoot;
  UI.currentPath.value = initialPath;
  UI.currentPathBadge.textContent = initialPath;

  logLine(`Bootstrap loaded. Initial path: ${initialPath}`);
  setResult(result);

  return initialPath;
}

async function loadDirectory(path) {
  try {
    const result = await safeFetchJson(API.list, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path })
    });

    const data = result.data || {};
    State.currentPath = data.current_path || "";
    State.parentPath = data.parent_path || "";
    State.entries = Array.isArray(data.entries) ? data.entries : [];
    State.allowedRoots = Array.isArray(data.allowed_roots) ? data.allowed_roots : State.allowedRoots;

    if (State.allowedRoots.length) {
      populateRootSelector(State.allowedRoots);

      const matchingRoot = State.allowedRoots.find(root =>
        State.currentPath === root || State.currentPath.startsWith(`${root}/`)
      );

      if (matchingRoot) {
        UI.rootSelector.value = matchingRoot;
      }
    }

    UI.currentPath.value = State.currentPath;
    UI.currentPathBadge.textContent = State.currentPath || "—";

    renderBrowserTable();
    setSelectedEntry(null);
    setBackendStatus(true, "online");
    setResult(result);
    logLine(`Directory loaded: ${State.currentPath}`);
  } catch (e) {
    setBackendStatus(false, "offline");
    setResult(e.message);
    logLine(`ERROR loading directory: ${e.message}`);
    throw e;
  }
}

async function createZipFromSelected() {
  try {
    const paths = Array.from(State.selectedPaths);
    if (!paths.length) {
      throw new Error("No files or directories selected");
    }

    const zipName = String(UI.zipName.value || "").trim();

    const result = await safeFetchJson(API.zip, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths, zip_name: zipName })
    });

    setResult(result);

    if (result.data?.path) {
      UI.sendPath.value = result.data.path;
    }

    logLine(`ZIP created: ${result.data?.path || "unknown"}`);
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR creating ZIP: ${e.message}`);
  }
}

async function uploadFileToWorkspace() {
  try {
    const file = UI.uploadFile.files?.[0];
    if (!file) {
      throw new Error("No file selected for upload");
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(API.upload, {
      method: "POST",
      body: formData
    });

    if (!response.ok) {
      let message = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errData = await response.json();
        if (errData?.error) {
          message = errData.error;
        }
      } catch {
      }
      throw new Error(message);
    }

    const result = await response.json();
    if (!result.ok) {
      throw new Error(result.error || "Upload failed");
    }

    setResult(result);

    if (result.data?.path) {
      UI.sendPath.value = result.data.path;
    }

    logLine(`File uploaded: ${result.data?.path || file.name}`);
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR uploading file: ${e.message}`);
  }
}

async function loadSshConfig() {
  try {
    const result = await safeFetchJson(API.sshGetConfig, { method: "GET" });
    const config = result.data || {};
    State.sshConfig = config;
    applySshConfigToUi(config);
    setResult(result);
    logLine("SSH config loaded");
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR loading SSH config: ${e.message}`);
  }
}

async function saveSshConfig() {
  try {
    const payload = collectSshConfigFromUi();

    const result = await safeFetchJson(API.sshSetConfig, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    State.sshConfig = result.data || null;
    applySshConfigToUi(State.sshConfig);
    setResult(result);
    logLine(`SSH config saved for ${payload.host}:${payload.port}`);
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR saving SSH config: ${e.message}`);
  }
}

async function testSshConnection() {
  try {
    const result = await safeFetchJson(API.sshTest, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });

    setResult(result);

    const ok = !!result.data?.connected;
    State.sshConfig = {
      ...(State.sshConfig || {}),
      ...(result.data?.config || {})
    };

    if (ok) {
      setSshStatus("ok", "online");
      logLine(`SSH OK: ${result.data?.banner || "connected"}`);
    } else {
      setSshStatus("bad", "offline");
      logLine(`SSH failed: ${result.data?.error || "unknown error"}`);
    }

    applySshConfigToUi(State.sshConfig);
  } catch (e) {
    setResult(e.message);
    setSshStatus("bad", "offline");
    logLine(`ERROR testing SSH: ${e.message}`);
  }
}

async function sendFileToWindows() {
  try {
    const path = String(UI.sendPath.value || "").trim();
    if (!path) {
      throw new Error("No path provided for transfer");
    }

    const result = await safeFetchJson(API.send, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path })
    });

    setResult(result);

    if (result.data?.remote_path) {
      State.lastRemotePath = result.data.remote_path;
      UI.remoteVerifyPath.value = result.data.remote_path;
      UI.remoteJsonPath.value = result.data.remote_path;
      UI.lastRemotePathView.textContent = result.data.remote_path;
    }

    if (result.data?.verified) {
      setSshStatus("ok", "online");
      logLine(`File sent and verified: ${result.data.remote_path}`);
    } else {
      setSshStatus("warn", "sent not verified");
      logLine(`File sent but verification incomplete: ${result.data?.remote_path || path}`);
    }
  } catch (e) {
    setResult(e.message);
    setSshStatus("bad", "offline");
    logLine(`ERROR sending file: ${e.message}`);
  }
}

async function verifyRemoteFile() {
  try {
    const remotePath = String(UI.remoteVerifyPath.value || "").trim();
    if (!remotePath) {
      throw new Error("Remote path is required");
    }

    const result = await safeFetchJson(API.sshVerifyRemoteFile, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ remote_path: remotePath })
    });

    setResult(result);

    if (result.data?.exists) {
      setSshStatus("ok", "online");
      logLine(`Remote file exists: ${remotePath}`);
    } else {
      setSshStatus("warn", "connected");
      logLine(`Remote file not found: ${remotePath}`);
    }
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR verifying remote file: ${e.message}`);
  }
}

function resetJsonViewerMeta() {
  UI.jsonReportPath.textContent = "—";
  UI.jsonReportSize.textContent = "—";
  UI.jsonReportModified.textContent = "—";
}

function renderJsonEmpty(message) {
  UI.jsonViewer.innerHTML = `<div class="json-empty">${escapeHtml(message)}</div>`;
}

function getJsonSummary(value) {
  if (Array.isArray(value)) {
    return `Array(${value.length})`;
  }

  if (value && typeof value === "object") {
    return `Object(${Object.keys(value).length})`;
  }

  if (value === null) {
    return "null";
  }

  return typeof value;
}

function formatJsonPrimitive(value, searchTerm = "") {
  let cls = "json-string";
  let text = "";

  if (value === null) {
    cls = "json-null";
    text = "null";
  } else if (typeof value === "number") {
    cls = "json-number";
    text = String(value);
  } else if (typeof value === "boolean") {
    cls = "json-bool";
    text = String(value);
  } else {
    cls = "json-string";
    text = `"${String(value)}"`;
  }

  return `<span class="${cls}">${highlightText(escapeHtml(text), searchTerm)}</span>`;
}

function highlightText(text, searchTerm) {
  const q = String(searchTerm || "").trim();
  if (!q) return text;

  const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return text.replace(new RegExp(escaped, "gi"), match => `<span class="report-highlight">${match}</span>`);
}

function buildJsonNode(value, key = null, depth = 0, path = "root", searchTerm = "") {
  const indent = `<span class="json-indent"></span>`.repeat(depth);

  if (value === null || typeof value !== "object") {
    return `
      <div class="json-row" data-json-path="${escapeHtml(path)}">
        ${indent}
        ${key !== null ? `<span class="json-key">"${highlightText(escapeHtml(String(key)), searchTerm)}"</span>: ` : ""}
        ${formatJsonPrimitive(value, searchTerm)}
      </div>
    `;
  }

  const isArray = Array.isArray(value);
  const keys = isArray ? value.map((_, i) => i) : Object.keys(value);
  const openBrace = isArray ? "[" : "{";
  const closeBrace = isArray ? "]" : "}";
  const summary = getJsonSummary(value);

  const childrenHtml = keys.map((childKey, index) => {
    const childValue = value[childKey];
    const childPath = `${path}.${childKey}`;
    const childHtml = buildJsonNode(childValue, childKey, depth + 1, childPath, searchTerm);
    const needsComma = index < keys.length - 1;
    return needsComma
      ? childHtml.replace(/<\/div>\s*$/, `,<\\/div>`).replace("<\\/div>", "</div>")
      : childHtml;
  }).join("");

  return `
    <div class="json-node" data-json-path="${escapeHtml(path)}">
      <div class="json-row">
        ${indent}
        <span class="json-toggle" data-toggle-path="${escapeHtml(path)}">▾</span>
        ${key !== null ? `<span class="json-key">"${highlightText(escapeHtml(String(key)), searchTerm)}"</span>: ` : ""}
        <span class="json-brace">${openBrace}</span>
        <span class="json-summary">${escapeHtml(summary)}</span>
      </div>
      <div class="json-children">
        ${childrenHtml}
        <div class="json-row">
          ${indent}
          <span class="json-indent"></span>
          <span class="json-brace">${closeBrace}</span>
        </div>
      </div>
    </div>
  `;
}

function attachJsonTreeEvents() {
  UI.jsonViewer.querySelectorAll("[data-toggle-path]").forEach(toggle => {
    toggle.addEventListener("click", ev => {
      ev.stopPropagation();
      const path = toggle.getAttribute("data-toggle-path");
      const node = UI.jsonViewer.querySelector(`.json-node[data-json-path="${CSS.escape(path)}"]`);
      if (!node) return;

      const collapsed = node.classList.toggle("collapsed");
      toggle.textContent = collapsed ? "▸" : "▾";
    });
  });
}

function renderJsonReport(data, searchTerm = "") {
  if (data === undefined) {
    renderJsonEmpty("No JSON data available.");
    return;
  }

  const html = buildJsonNode(data, null, 0, "root", searchTerm);
  UI.jsonViewer.innerHTML = html;
  attachJsonTreeEvents();
}

function setJsonReportMeta(meta) {
  UI.jsonReportPath.textContent = meta?.remote_path || "—";
  UI.jsonReportSize.textContent = formatBytes(meta?.size);
  UI.jsonReportModified.textContent = meta?.modified_utc || "—";
}

function collapseAllJsonNodes() {
  UI.jsonViewer.querySelectorAll(".json-node").forEach((node, idx) => {
    if (idx === 0) return;
    node.classList.add("collapsed");
    const toggle = node.querySelector(":scope > .json-row .json-toggle");
    if (toggle) toggle.textContent = "▸";
  });
}

function expandAllJsonNodes() {
  UI.jsonViewer.querySelectorAll(".json-node").forEach(node => {
    node.classList.remove("collapsed");
    const toggle = node.querySelector(":scope > .json-row .json-toggle");
    if (toggle) toggle.textContent = "▾";
  });
}

async function readRemoteJsonReport() {
  try {
    const remotePath = String(UI.remoteJsonPath.value || "").trim();
    if (!remotePath) {
      throw new Error("Remote JSON path is required");
    }

    const result = await safeFetchJson(API.sshReadRemoteJson, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ remote_path: remotePath })
    });

    setResult(result);

    const data = result.data || {};
    State.loadedJsonReport = data.json_data ?? null;
    State.loadedJsonRaw = data.raw_text || "";

    setJsonReportMeta(data);
    renderJsonReport(State.loadedJsonReport, String(UI.jsonSearch.value || "").trim());

    setSshStatus("ok", "online");
    State.lastRemotePath = data.remote_path || State.lastRemotePath || "";
    UI.lastRemotePathView.textContent = State.lastRemotePath || "—";

    logLine(`Remote JSON loaded: ${data.remote_path}`);
  } catch (e) {
    setResult(e.message);
    renderJsonEmpty(`ERROR: ${e.message}`);
    resetJsonViewerMeta();
    logLine(`ERROR reading remote JSON: ${e.message}`);
  }
}

async function copyJsonRawToClipboard() {
  if (!State.loadedJsonRaw) {
    logLine("No JSON report loaded");
    return;
  }

  try {
    await navigator.clipboard.writeText(State.loadedJsonRaw);
    logLine("Raw JSON copied to clipboard");
  } catch {
    logLine("Clipboard copy failed");
  }
}

function rerenderFilteredJson() {
  if (State.loadedJsonReport === null) {
    renderJsonEmpty("No remote JSON report loaded.");
    return;
  }

  const q = String(UI.jsonSearch.value || "").trim();
  renderJsonReport(State.loadedJsonReport, q);
}

async function runRemoteCommand() {
  try {
    const execType = String(UI.execType.value || "command").trim();
    const command = String(UI.execCommand.value || "").trim();
    const cwd = String(UI.execCwd.value || "").trim();
    const timeout = Number(UI.execTimeout.value || 120);
    const postCheck = String(UI.execPostCheck.value || "none").trim();
    const targetFile = String(UI.execTargetFile.value || "").trim();

    if (!command) {
      throw new Error("Remote command is empty");
    }

    const result = await safeFetchJson(API.sshExec, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        exec_type: execType,
        command,
        cwd,
        timeout,
        post_check: postCheck,
        target_file: targetFile
      })
    });

    setResult(result);
    setSshStatus("ok", "online");

    const exitCode = result.data?.exit_code;
    logLine(`Remote execution finished with exit_code=${exitCode}`);

    if (result.data?.stdout) {
      logLine(`STDOUT:\n${result.data.stdout}`);
    }

    if (result.data?.stderr) {
      logLine(`STDERR:\n${result.data.stderr}`);
    }

    if (result.data?.post_check?.remote_path) {
      State.lastRemotePath = result.data.post_check.remote_path;
      UI.remoteVerifyPath.value = result.data.post_check.remote_path;
      UI.remoteJsonPath.value = result.data.post_check.remote_path;
      UI.lastRemotePathView.textContent = result.data.post_check.remote_path;
    }
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR executing remote command: ${e.message}`);
  }
}

async function refreshAll() {
  try {
    await checkBackendHealth();

    if (!State.currentPath) {
      const root = UI.rootSelector.value || UI.currentPath.value || "/tmp";
      await loadDirectory(root);
    } else {
      await loadDirectory(State.currentPath);
    }

    await loadSshConfig();
  } catch (e) {
    setBackendStatus(false, "offline");
    logLine(`ERROR refreshing: ${e.message}`);
  }
}

UI.rootSelector.addEventListener("change", async () => {
  const root = UI.rootSelector.value;
  UI.currentPath.value = root;
  await loadDirectory(root);
});

UI.btnOpenPath.addEventListener("click", async () => {
  const path = String(UI.currentPath.value || "").trim();
  if (!path) return;
  await loadDirectory(path);
});

UI.btnParent.addEventListener("click", async () => {
  if (!State.parentPath) return;
  UI.currentPath.value = State.parentPath;
  await loadDirectory(State.parentPath);
});

UI.btnRefreshAll.addEventListener("click", refreshAll);
UI.btnCreateZip.addEventListener("click", createZipFromSelected);
UI.btnUploadFile.addEventListener("click", uploadFileToWorkspace);
UI.btnSendFile.addEventListener("click", sendFileToWindows);

UI.btnClearConsole.addEventListener("click", () => {
  UI.console.value = "";
});

UI.btnUseSelectedForSend.addEventListener("click", () => {
  if (!State.selectedEntry?.path) return;
  UI.sendPath.value = State.selectedEntry.path;
  logLine(`Selected path copied into send input: ${State.selectedEntry.path}`);
});

UI.btnCopySelectedPath.addEventListener("click", async () => {
  if (!State.selectedEntry?.path) return;

  try {
    await navigator.clipboard.writeText(State.selectedEntry.path);
    logLine(`Path copied to clipboard: ${State.selectedEntry.path}`);
  } catch {
    logLine("Clipboard copy failed");
  }
});

UI.sshAuthType.addEventListener("change", updateAuthUi);
UI.btnSaveSshConfig.addEventListener("click", saveSshConfig);
UI.btnLoadSshConfig.addEventListener("click", loadSshConfig);
UI.btnTestSsh.addEventListener("click", testSshConnection);

UI.btnUseLastRemotePath.addEventListener("click", () => {
  if (!State.lastRemotePath) {
    logLine("No last remote path available");
    return;
  }
  UI.remoteVerifyPath.value = State.lastRemotePath;
  logLine(`Remote verify path set to ${State.lastRemotePath}`);
});

UI.btnVerifyRemoteFile.addEventListener("click", verifyRemoteFile);

UI.btnUseLastJsonPath.addEventListener("click", () => {
  if (!State.lastRemotePath) {
    logLine("No last remote path available");
    return;
  }
  UI.remoteJsonPath.value = State.lastRemotePath;
  logLine(`Remote JSON path set to ${State.lastRemotePath}`);
});

UI.btnReadRemoteJson.addEventListener("click", readRemoteJsonReport);
UI.btnCopyJsonRaw.addEventListener("click", copyJsonRawToClipboard);
UI.btnExpandJson.addEventListener("click", expandAllJsonNodes);
UI.btnCollapseJson.addEventListener("click", collapseAllJsonNodes);
UI.jsonSearch.addEventListener("input", rerenderFilteredJson);

UI.btnRunRemote.addEventListener("click", runRemoteCommand);

document.addEventListener("DOMContentLoaded", async () => {
  try {
    setBackendStatus(false, "checking");
    setSshStatus("warn", "checking");

    updateAuthUi();
    resetJsonViewerMeta();
    renderJsonEmpty("No remote JSON report loaded.");

    await checkBackendHealth();
    const initialPath = await loadBootstrap();
    await loadDirectory(initialPath);
    await loadSshConfig();
  } catch (e) {
    setBackendStatus(false, "offline");
    setSshStatus("bad", "offline");
    setResult(e.message);
    logLine(`ERROR on load: ${e.message}`);
  }
});