/* ============================================================
   NICS DFIR UI
   - Lists OpenStack instances
   - Select VM -> auto-fill vm_id + IP into DFIR forms
   - Runs DFIR actions via backend endpoints
============================================================ */

const UI = {
  // instances
  instancesTable: document.getElementById("instances_table"),
  selName: document.getElementById("sel_vm_name"),
  selId: document.getElementById("sel_vm_id"),
  selPriv: document.getElementById("sel_vm_ip_private"),
  selFloat: document.getElementById("sel_vm_ip_floating"),
  btnRefreshInstances: document.getElementById("btn_refresh_instances"),

  // case
  caseDir: document.getElementById("case_dir"),
  btnCreateCase: document.getElementById("btn_create_case"),
  btnRefreshManifest: document.getElementById("btn_refresh_manifest"),

  // disk
  diskUUID: document.getElementById("disk_instance_uuid"),
  diskContainer: document.getElementById("disk_container_name"),
  btnAcquireDisk: document.getElementById("btn_acquire_disk"),
  diskResult: document.getElementById("disk_result"),

  // memory
  memIP: document.getElementById("mem_vm_ip"),
  memUser: document.getElementById("mem_ssh_user"),
  memKey: document.getElementById("mem_ssh_key"),
  memMode: document.getElementById("mem_mode"),
  btnAcquireMemory: document.getElementById("btn_acquire_memory"),
  memResult: document.getElementById("mem_result"),

  // vol
  volDump: document.getElementById("vol_dump_file"),
  volSymbols: document.getElementById("vol_symbols_dir"),
  volCmd: document.getElementById("vol_cmd"),
  btnAnalyzeMemory: document.getElementById("btn_analyze_memory"),
  volResult: document.getElementById("vol_result"),

  // manifest
  artifactsTable: document.getElementById("artifacts_table"),
  manifestRaw: document.getElementById("manifest_raw"),

  // console
  console: document.getElementById("console"),
  btnClearConsole: document.getElementById("btn_clear_console")
};

const STATE = {
  instances: [],
  selected: null,
  case_dir: null,
  manifest: null
};

function now() {
  return new Date().toLocaleTimeString();
}

function cwrite(line) {
  const prev = UI.console.value || "";
  UI.console.value = `${prev}[${now()}] ${line}\n`;
  UI.console.scrollTop = UI.console.scrollHeight;
}

function setSelected(vm) {
  STATE.selected = vm;

  UI.selName.textContent = vm?.name || "—";
  UI.selId.textContent = vm?.id || "—";
  UI.selPriv.textContent = vm?.ip_private || "—";
  UI.selFloat.textContent = vm?.ip_floating || "—";

  // auto-fill DFIR inputs
  UI.diskUUID.value = vm?.id || "";
  UI.memIP.value = (vm?.ip_floating || vm?.ip_private || "");

  cwrite(`Selected VM: ${vm.name} (${vm.id}) | priv=${vm.ip_private || "-"} float=${vm.ip_floating || "-"}`);
}

function setCaseDir(caseDir) {
  STATE.case_dir = caseDir;
  UI.caseDir.textContent = caseDir || "—";
  cwrite(`Case set: ${caseDir || "—"}`);
}

function requireSelected() {
  if (!STATE.selected?.id) throw new Error("No VM selected. Selecciona una instancia primero.");
  return STATE.selected;
}

function requireCase() {
  if (!STATE.case_dir) throw new Error("No Case. Pulsa 'Create Case' primero.");
  return STATE.case_dir;
}

async function httpJSON(url, opts = {}) {
  const res = await fetch(url, opts);
  const text = await res.text();

  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}

  if (!res.ok) {
    const msg = data?.error || data?.message || text || `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }

  const ct = (res.headers.get("content-type") || "");
  if (!ct.includes("application/json")) {
    throw new Error(`Respuesta no JSON del servidor (${ct || "no content-type"}).`);
  }

  return data;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* ============================
   Instances
============================ */

function renderInstances(instances) {
  const tbody = UI.instancesTable.querySelector("tbody");
  if (!instances.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="mut">No instances.</td></tr>`;
    return;
  }

  tbody.innerHTML = instances.map(vm => {
    const isSel = STATE.selected?.id === vm.id;
    const flavorName = (vm.flavor && (vm.flavor.name || vm.flavor)) ? (vm.flavor.name || vm.flavor) : "-";
    return `
      <tr class="clickrow ${isSel ? "selected" : ""}" data-vm-id="${escapeHtml(vm.id)}">
        <td><div style="font-weight:700">${escapeHtml(vm.name)}</div><div class="mut">${escapeHtml(vm.id.slice(0,8))}</div></td>
        <td><span class="tag">${escapeHtml(vm.status || "-")}</span></td>
        <td class="kv">${escapeHtml(vm.ip_private || "-")}</td>
        <td class="kv">${escapeHtml(vm.ip_floating || "-")}</td>
        <td class="mut">${escapeHtml(flavorName)}</td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll("tr[data-vm-id]").forEach(tr => {
    tr.addEventListener("click", () => {
      const id = tr.getAttribute("data-vm-id");
      const vm = STATE.instances.find(x => x.id === id);
      if (vm) {
        setSelected(vm);
        renderInstances(STATE.instances);
      }
    });
  });
}

async function loadInstances() {
  cwrite("Loading OpenStack instances...");
  const data = await httpJSON("/api/openstack/instances/full");
  STATE.instances = data.instances || [];
  renderInstances(STATE.instances);
  cwrite(`Instances loaded: ${STATE.instances.length}`);

  if (!STATE.selected && STATE.instances.length) {
    setSelected(STATE.instances[0]);
    renderInstances(STATE.instances);
  }
}

/* ============================
   Case + Manifest
============================ */

async function createCase() {
  cwrite("Creating case...");
  const data = await httpJSON("/api/forensics/case/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  setCaseDir(data.case_dir);
  cwrite("Case created OK.");
}

function guessLatestDumpFromManifest(manifest) {
  const artifacts = Array.isArray(manifest?.artifacts) ? manifest.artifacts : [];
  const mem = artifacts.filter(a => {
    const t = String(a.type || "").toLowerCase();
    const p = String(a.rel_path || a.path || "").toLowerCase();
    return t.includes("mem") || p.includes(".lime");
  });
  if (!mem.length) return null;
  return mem[mem.length - 1];
}

function renderArtifacts(manifest) {
  const tbody = UI.artifactsTable.querySelector("tbody");
  const artifacts = Array.isArray(manifest?.artifacts) ? manifest.artifacts : [];

  if (!artifacts.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="mut">No artifacts.</td></tr>`;
    return;
  }

  const caseDir = STATE.case_dir;

  tbody.innerHTML = artifacts.map(a => {
    const type = a.type || "-";
    const rel = a.rel_path || a.path || "-";
    const sha = a.sha256 || "-";

    const dl = (caseDir && rel && rel !== "-")
      ? `<a href="/api/forensics/case/download?case_dir=${encodeURIComponent(caseDir)}&rel=${encodeURIComponent(rel)}">Download</a>`
      : `<span class="mut">—</span>`;

    return `
      <tr>
        <td>${escapeHtml(type)}</td>
        <td class="kv">${escapeHtml(rel)}</td>
        <td class="kv">${escapeHtml(sha)}</td>
        <td>${dl}</td>
      </tr>
    `;
  }).join("");

  const lastDump = guessLatestDumpFromManifest(manifest);
  if (lastDump) {
    UI.volDump.value = lastDump.rel_path || lastDump.path || UI.volDump.value;
    cwrite(`Auto-selected dump for Vol3: ${UI.volDump.value}`);
  }
}

async function refreshManifest() {
  const caseDir = requireCase();
  cwrite("Loading manifest...");
  const data = await httpJSON(`/api/forensics/case/manifest?case_dir=${encodeURIComponent(caseDir)}`);
  STATE.manifest = data;
  UI.manifestRaw.value = JSON.stringify(data, null, 2);
  renderArtifacts(data);
  cwrite("Manifest OK.");
}

/* ============================
   DFIR Actions
============================ */

async function acquireDisk() {
  const vm = requireSelected();
  const caseDir = requireCase();

  UI.diskResult.textContent = "Running...";
  cwrite(`Acquire disk: vm_id=${vm.id} container=${UI.diskContainer.value}`);

  const data = await httpJSON("/api/forensics/acquire/disk_kolla", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      case_dir: caseDir,
      vm_id: vm.id,
      container_name: UI.diskContainer.value.trim() || "nova_libvirt"
    })
  });

  UI.diskResult.textContent = data.disk_raw || data.result || "OK";
  cwrite(`Disk acquired OK: ${UI.diskResult.textContent}`);
}

async function acquireMemory() {
  const vm = requireSelected();
  const caseDir = requireCase();

  const vmIp = (UI.memIP.value || "").trim();
  if (!vmIp) throw new Error("mem_vm_ip vacío. Selecciona VM o rellena manualmente.");

  UI.memResult.textContent = "Running...";
  cwrite(`Acquire memory: vm_id=${vm.id} ip=${vmIp} user=${UI.memUser.value} mode=${UI.memMode.value}`);

  const data = await httpJSON("/api/forensics/acquire/memory_lime", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      case_dir: caseDir,
      vm_id: vm.id,
      vm_ip: vmIp,
      ssh_user: (UI.memUser.value || "debian").trim(),
      ssh_key: (UI.memKey.value || "").trim(),
      mode: UI.memMode.value
    })
  });

  UI.memResult.textContent = data.mem_dump || data.result || "OK";
  cwrite(`Memory acquired OK: ${UI.memResult.textContent}`);

  try { await refreshManifest(); } catch {}
}

async function analyzeMemory() {
  const vm = requireSelected();
  const caseDir = requireCase();

  const dumpFile = (UI.volDump.value || "").trim();
  const symbolsDir = (UI.volSymbols.value || "").trim();
  const volCmd = (UI.volCmd.value || "vol").trim();

  if (!dumpFile) throw new Error("vol_dump_file vacío. Refresca manifest o selecciona un dump.");
  if (!symbolsDir) throw new Error("vol_symbols_dir vacío.");

  UI.volResult.textContent = "Running...";
  cwrite(`Vol3: vm_id=${vm.id} dump=${dumpFile} symbols=${symbolsDir}`);

  const data = await httpJSON("/api/forensics/analyze/memory_vol3", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      case_dir: caseDir,
      vm_id: vm.id,
      dump_file: dumpFile,
      symbols_dir: symbolsDir,
      vol_cmd: volCmd
    })
  });

  UI.volResult.textContent = data.out_dir || data.result || "OK";
  cwrite(`Vol3 OK: ${UI.volResult.textContent}`);

  try { await refreshManifest(); } catch {}
}

/* ============================
   Wire events
============================ */

UI.btnRefreshInstances.addEventListener("click", () => {
  loadInstances().catch(e => cwrite(`ERROR instances: ${e.message}`));
});

UI.btnCreateCase.addEventListener("click", () => {
  createCase().catch(e => cwrite(`ERROR create case: ${e.message}`));
});

UI.btnRefreshManifest.addEventListener("click", () => {
  refreshManifest().catch(e => cwrite(`ERROR manifest: ${e.message}`));
});

UI.btnAcquireDisk.addEventListener("click", () => {
  acquireDisk().catch(e => {
    UI.diskResult.textContent = "ERROR";
    cwrite(`ERROR disk: ${e.message}`);
  });
});

UI.btnAcquireMemory.addEventListener("click", () => {
  acquireMemory().catch(e => {
    UI.memResult.textContent = "ERROR";
    cwrite(`ERROR memory: ${e.message}`);
  });
});

UI.btnAnalyzeMemory.addEventListener("click", () => {
  analyzeMemory().catch(e => {
    UI.volResult.textContent = "ERROR";
    cwrite(`ERROR vol3: ${e.message}`);
  });
});

UI.btnClearConsole.addEventListener("click", () => {
  UI.console.value = "";
});

/* ============================
   Boot
============================ */
cwrite("DFIR UI booting...");
loadInstances().catch(e => cwrite(`ERROR boot instances: ${e.message}`));
