const API_BASE = "/windows-lab-exchange";

const API = {
  list: `${API_BASE}/api/list`,
  upload: `${API_BASE}/api/upload`,
  zip: `${API_BASE}/api/zip`,
  send: `${API_BASE}/api/send`
};

const UI = {
  backendDot: document.getElementById("backend-dot"),
  backendStatus: document.getElementById("backend-status"),
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

  resultBox: document.getElementById("result-box")
};

const State = {
  allowedRoots: [],
  currentPath: "",
  parentPath: "",
  entries: [],
  selectedPaths: new Set(),
  selectedEntry: null
};

function nowTime() {
  return new Date().toLocaleTimeString();
}

function setBackendStatus(ok, text) {
  UI.backendDot.className = "status-dot " + (ok ? "dot-ok" : "dot-bad");
  UI.backendStatus.textContent = text;
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
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
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

async function loadDirectory(path) {
  try {
    const result = await safeFetchJson(API.list, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path })
    });

    if (!result.ok) {
      throw new Error(result.error || "Directory listing failed");
    }

    const data = result.data;

    State.currentPath = data.current_path;
    State.parentPath = data.parent_path;
    State.entries = Array.isArray(data.entries) ? data.entries : [];
    State.allowedRoots = Array.isArray(data.allowed_roots) ? data.allowed_roots : [];

    UI.currentPath.value = State.currentPath;
    UI.currentPathBadge.textContent = State.currentPath;

    if (!UI.rootSelector.options.length && State.allowedRoots.length) {
      UI.rootSelector.innerHTML = State.allowedRoots
        .map(root => `<option value="${escapeHtml(root)}">${escapeHtml(root)}</option>`)
        .join("");
    }

    renderBrowserTable();
    setBackendStatus(true, "connected");
    setResult(result);
    logLine(`Directory loaded: ${State.currentPath}`);
  } catch (e) {
    setBackendStatus(false, "offline");
    setResult(e.message);
    logLine(`ERROR loading directory: ${e.message}`);
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
      body: JSON.stringify({
        paths,
        zip_name: zipName
      })
    });

    if (!result.ok) {
      throw new Error(result.error || "ZIP creation failed");
    }

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
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
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

    if (!result.ok) {
      throw new Error(result.error || "Send failed");
    }

    setResult(result);
    logLine(`File sent to Windows Lab: ${result.data?.remote_path || path}`);
  } catch (e) {
    setResult(e.message);
    logLine(`ERROR sending file: ${e.message}`);
  }
}

async function refreshAll() {
  if (!State.currentPath) {
    const root = UI.rootSelector.value || UI.currentPath.value || "/tmp";
    await loadDirectory(root);
    return;
  }

  await loadDirectory(State.currentPath);
}

UI.rootSelector.addEventListener("change", async () => {
  const root = UI.rootSelector.value;
  UI.currentPath.value = root;
  await loadDirectory(root);
});

UI.btnOpenPath.addEventListener("click", async () => {
  const path = String(UI.currentPath.value || "").trim();
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

document.addEventListener("DOMContentLoaded", async () => {
  try {
    setBackendStatus(true, "loading");
    const initialRoot = UI.currentPath.value || UI.rootSelector.value || "/tmp";
    await loadDirectory(initialRoot);
  } catch (e) {
    setBackendStatus(false, "offline");
    logLine(`ERROR on load: ${e.message}`);
  }
});