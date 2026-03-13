/* ============================================================
   NICS DFIR UI
   - Lists OpenStack instances
   - Select VM -> auto-fill vm_id + IP into DFIR forms
   - Runs DFIR actions via backend endpoints
   - LIVE overlay terminal via SSE for long-running actions
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
  btnClearConsole: document.getElementById("btn_clear_console"),

  // LIVE overlay (must exist in HTML)
  liveOverlay: document.getElementById("dfir-live-overlay"),
  liveTitle: document.getElementById("dfir-live-title"),
  liveInfo: document.getElementById("dfir-live-info"),
  liveStatus: document.getElementById("dfir-live-status"),
  liveTerminal: document.getElementById("dfir-live-terminal"),
  liveClose: document.getElementById("dfir-live-close"),

  caseSelector: document.getElementById("case_selector"),
  btnGenerateSymbols: document.getElementById("btn_generate_symbols"),

  // traffic overlay (optional block in HTML)
  btnOpenTraffic: document.getElementById("btn_open_traffic"),
  btnPreserveScenarioTraffic: document.getElementById("btn_preserve_scenario_traffic"),

  // traffic overlay
  trafficOverlay: document.getElementById("traffic-overlay"),
  trafficTerminal: document.getElementById("traffic-terminal"),
  trafficInfo: document.getElementById("traffic-vm-info"),
  trafficClose: document.getElementById("traffic-close"),
  trafficRefresh: document.getElementById("traffic-refresh"),
  trafficStatus: document.getElementById("traffic-status"),
  diskSelector: document.getElementById("disk_selector"),
  memorySelector: document.getElementById("memory_selector"),
btnAnalyzeDisk: document.getElementById("btn_analyze_disk"),
diskAnalyzeResult: document.getElementById("disk_analyze_result"),
runSelector: document.getElementById("run_selector"),


};


function populateDiskSelectorFromManifest(manifest) {
  if (!UI.diskSelector) return;

  const arts = (manifest && manifest.artifacts) ? manifest.artifacts : [];
  const disks = arts
    .filter(a => a && a.type === "disk_raw" && a.rel_path)
    .map(a => ({ rel: a.rel_path, sha: a.sha256 || "" }));

  // Limpia
  UI.diskSelector.innerHTML = "";

  if (!disks.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "No preserved disks found in manifest.";
    UI.diskSelector.appendChild(opt);
    return;
  }

  // Opciones
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = "Select a disk...";
  UI.diskSelector.appendChild(opt0);

  for (const d of disks) {
    const opt = document.createElement("option");
    opt.value = d.rel;
    opt.textContent = d.sha ? `${d.rel}  (sha: ${d.sha.slice(0, 12)}...)` : d.rel;
    UI.diskSelector.appendChild(opt);
  }

  // Auto-select: primero
 
}




console.log("btn_open_traffic =", UI.btnOpenTraffic);
console.log("traffic overlay =", UI.trafficOverlay);

const STATE = {
  instances: [],
  selected: null,
  case_dir: null,
  manifest: null,

  // [RUN_ID] No invento UI: valor fijo por defecto.
  // Si quieres R2/R3, lo cambias aquí o lo automatizamos luego con tu runner.
  run_id: "R1",

  live: {
    source: null,
    running: false
  },
  traffic: {
    source: null,
    running: false
  },
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

  UI.diskUUID.value = vm?.id || "";
  UI.memIP.value = (vm?.ip_floating || vm?.ip_private || "");

  // auto-default ssh user (solo si está vacío)
  if (UI.memUser && !(UI.memUser.value || "").trim()) {
    const name = String(vm?.name || "").toLowerCase();
    UI.memUser.value = name.includes("ubuntu") ? "ubuntu" : "debian";
  }

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

/* ============================================================
   LIVE OVERLAY (SSE terminal)
============================================================ */

function liveAppend(line) {
  if (!UI.liveTerminal) return;
  UI.liveTerminal.textContent += `${line}\n`;
  UI.liveTerminal.scrollTop = UI.liveTerminal.scrollHeight;
}

function liveSet(show) {
  if (!UI.liveOverlay) return;
  UI.liveOverlay.style.display = show ? "flex" : "none";
}

function freezeUI(disabled) {
  const btns = document.querySelectorAll("button");
  btns.forEach(b => {
    if (b === UI.liveClose) return;
    b.disabled = disabled;
  });
}

function liveClose() {
  try {
    if (STATE.live.source) STATE.live.source.close();
  } catch {}
  STATE.live.source = null;
  STATE.live.running = false;
  freezeUI(false);
  liveSet(false);
  closeTraffic();
}

if (UI.liveClose) {
  UI.liveClose.addEventListener("click", () => {
    liveClose();
    cwrite("Live terminal closed by user.");
  });
}

function startLiveSSE({ title, info, url, onDone }) {
  if (!UI.liveOverlay || !UI.liveTerminal) {
    throw new Error("Overlay terminal no existe en HTML. Añade el bloque dfir-live-overlay.");
  }

  if (STATE.live.source) {
    try { STATE.live.source.close(); } catch {}
    STATE.live.source = null;
  }

  UI.liveTerminal.textContent = "";
  if (UI.liveTitle) UI.liveTitle.textContent = title || "DFIR Live Terminal";
  if (UI.liveInfo) UI.liveInfo.textContent = info || "";
  if (UI.liveStatus) UI.liveStatus.textContent = "Status: running...";

  liveSet(true);
  freezeUI(true);
  STATE.live.running = true;

  cwrite(`LIVE started: ${title} (${url})`);

  const es = new EventSource(url);
  STATE.live.source = es;

  es.onmessage = (e) => {
    if (!e.data) return;
    liveAppend(e.data);
  };

  
es.addEventListener("done", (e) => {
  let payload = {};
  try { payload = JSON.parse(e.data); } catch {}

  liveAppend(`[SISTEMA] DONE result=${payload.result} exit_code=${payload.exit_code}`);

  // Campos comunes (ya los tenías)
  if (payload.mem_dump) liveAppend(`[SISTEMA] mem_dump=${payload.mem_dump}`);
  if (payload.disk_raw) liveAppend(`[SISTEMA] disk_raw=${payload.disk_raw}`);
  if (payload.ssh_user_used) liveAppend(`[SISTEMA] ssh_user_used=${payload.ssh_user_used}`);

  // NUEVO: para TSK (y otros análisis)
  if (payload.out_dir) liveAppend(`[SISTEMA] out_dir=${payload.out_dir}`);
  if (payload.disk) liveAppend(`[SISTEMA] disk=${payload.disk}`);
  if (payload.run_id) liveAppend(`[SISTEMA] run_id=${payload.run_id}`);
  if (payload.script) liveAppend(`[SISTEMA] script=${payload.script}`);

  if (UI.liveStatus) UI.liveStatus.textContent = `Status: finished (${payload.result || "unknown"})`;

  try { es.close(); } catch {}
  STATE.live.source = null;
  STATE.live.running = false;
  freezeUI(false);

  try { if (typeof onDone === "function") onDone(payload); } catch {}
});


  es.onerror = () => {
    liveAppend("[ERROR] SSE connection lost.");
    if (UI.liveStatus) UI.liveStatus.textContent = "Status: error (SSE lost)";
    try { es.close(); } catch {}
    STATE.live.source = null;
    STATE.live.running = false;
    freezeUI(false);
  };
}

/* ============================================================
   TRAFFIC OVERLAY (SSE traffic)
   - Uses /api/openstack/traffic/<vm_id>
   - Passes case_dir to store PCAP under the active case
============================================================ */

function trafficOverlayExists() {
  return UI.trafficOverlay && UI.trafficTerminal && UI.trafficInfo;
}

function trafficSet(show) {
  if (!trafficOverlayExists()) return;
  UI.trafficOverlay.style.display = show ? "flex" : "none";
}

function trafficAppend(htmlOrText, isHtml = false) {
  if (!trafficOverlayExists()) return;

  const line = document.createElement("div");
  line.className = "terminal-entry";
  line.style.padding = "2px 6px";
  line.style.whiteSpace = "pre";
  line.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace";
  line.style.color = "#38d39f";

  if (isHtml) line.innerHTML = htmlOrText;
  else line.innerText = htmlOrText;

  UI.trafficTerminal.appendChild(line);
  UI.trafficTerminal.scrollTop = UI.trafficTerminal.scrollHeight;
}

function closeTraffic() {
  try {
    if (STATE.traffic.source) STATE.traffic.source.close();
  } catch {}
  STATE.traffic.source = null;
  STATE.traffic.running = false;
  trafficSet(false);
}

if (UI.trafficClose) {
  UI.trafficClose.addEventListener("click", () => {
    closeTraffic();
    cwrite("Traffic overlay closed by user.");
  });
}

function applyTrafficFilters() {
  if (STATE.selected?.id && STATE.traffic.running) startTrafficAnalysis(STATE.selected.id);
}

function startTrafficAnalysis(vmId) {
  if (!trafficOverlayExists()) {
    cwrite("Traffic overlay no existe en HTML (ids traffic-overlay/traffic-terminal/traffic-vm-info).");
    return;
  }

  const vm = STATE.instances.find(x => x.id === vmId);
  if (!vm) return;

  let caseDir = null;
  try {
    caseDir = requireCase();
  } catch (e) {
    cwrite(`ERROR traffic: ${e.message}`);
    return;
  }

  // RUN selector (ya existe en tu HTML)
  const runSel = document.getElementById("run_selector");
  const runId = ((runSel && runSel.value) ? runSel.value : (STATE.run_id || "R1")).trim() || "R1";
  STATE.run_id = runId;

  trafficSet(true);
  UI.trafficTerminal.innerHTML = "";
  UI.trafficInfo.textContent =
    `AUDITING NODE: ${vm.name} | MGMT_IP: ${vm.ip_floating || vm.ip_private || "N/A"} | CASE: ${caseDir} | RUN: ${runId}`;

  trafficAppend(`[${now()}] Conectando al sniffer (SSE)...`);

  const protos = Array.from(document.querySelectorAll(".proto-filter:checked"))
    .map(cb => cb.value)
    .join(",") || "modbus,tcp,udp";

  if (STATE.traffic.source) {
    try { STATE.traffic.source.close(); } catch {}
    STATE.traffic.source = null;
  }

  const url =
    `/api/openstack/traffic/${encodeURIComponent(vm.id)}` +
    `?protos=${encodeURIComponent(protos)}` +
    `&case_dir=${encodeURIComponent(caseDir)}` +
    `&run_id=${encodeURIComponent(runId)}`;

  const es = new EventSource(url);
  STATE.traffic.source = es;
  STATE.traffic.running = true;

  if (UI.trafficStatus) UI.trafficStatus.textContent = "Status: running...";

  es.onmessage = (e) => {
    const raw = String(e.data || "");

    if (raw.includes("MODBUS")) {
      trafficAppend(`<span class="text-yellow-400 font-bold">${escapeHtml(raw)}</span>`, true);
    } else if (raw.includes("PROFINET")) {
      trafficAppend(`<span class="text-pink-400 font-bold">${escapeHtml(raw)}</span>`, true);
    } else if (raw.includes("[SISTEMA]")) {
      trafficAppend(`<span class="text-sky-400 font-black underline">${escapeHtml(raw)}</span>`, true);
    } else if (raw.startsWith("[ERROR]") || raw.includes("[ERROR]")) {
      trafficAppend(`<span class="text-red-400 font-bold">${escapeHtml(raw)}</span>`, true);
    } else {
      trafficAppend(raw, false);
    }
  };

  es.onerror = () => {
    trafficAppend("[ERROR] Pérdida de conexión con el sniffer (SSE).");
    if (UI.trafficStatus) UI.trafficStatus.textContent = "Status: error (SSE lost)";
    try { es.close(); } catch {}
    STATE.traffic.source = null;
    STATE.traffic.running = false;
  };
}



function preserveScenarioTrafficLive() {
  const caseDir = requireCase();

  // RUN selector (ya existe en tu HTML)
  const runSel = document.getElementById("run_selector");
  const runId = ((runSel && runSel.value) ? runSel.value : (STATE.run_id || "R1")).trim() || "R1";
  STATE.run_id = runId;

  const url = buildSSEUrl("/api/forensics/traffic/preserve/stream", {
    case_dir: caseDir,
    run_id: runId
  });

  startLiveSSE({
    title: "Preserve Scenario Traffic (PCAP) - Live",
    info: `case=${caseDir} run=${runId}`,
    url,
    onDone: async (payload) => {
      if (payload.result === "ok") {
        cwrite(`Traffic preserved OK (exit=${payload.exit_code}).`);
        try { await refreshManifest(); } catch {}
      } else {
        cwrite(`ERROR preserving traffic: exit_code=${payload.exit_code}`);
      }
    }
  });
}


if (UI.btnPreserveScenarioTraffic) {
  UI.btnPreserveScenarioTraffic.addEventListener("click", () => {
    try {
      preserveScenarioTrafficLive();
    } catch (e) {
      cwrite(`ERROR preserve traffic: ${e.message}`);
    }
  });
}



if (UI.btnOpenTraffic) {
  UI.btnOpenTraffic.addEventListener("click", () => {
    try {
      const vm = requireSelected();
      startTrafficAnalysis(vm.id);
    } catch (e) {
      cwrite(`ERROR traffic: ${e.message}`);
    }
  });
}

if (UI.trafficRefresh) {
  UI.trafficRefresh.addEventListener("click", () => {
    applyTrafficFilters();
  });
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

  // Doble click: abre tráfico sin interferir con selección normal
  tbody.querySelectorAll("tr[data-vm-id]").forEach(tr => {
    tr.addEventListener("dblclick", () => {
      const id = tr.getAttribute("data-vm-id");
      startTrafficAnalysis(id);
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

  // Solo dumps reales: memory/*.lime (o type=memory_lime)
  let mem = artifacts.filter(a => {
    const type = String(a?.type || "");
    const rel  = String(a?.rel_path || a?.path || "");
    return (type === "memory_lime") ||
           (rel.startsWith("memory/") && rel.endsWith(".lime"));
  });

  if (!mem.length) return null;

  // Si hay varios, el más reciente por ts
  mem.sort((a, b) => String(b.ts || "").localeCompare(String(a.ts || "")));

  return mem[0];
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
    populateDiskSelectorFromManifest(data);

   
  try { await loadAndPopulateMemorySelector(caseDir); } catch {}

  cwrite("Manifest OK.");
}

/* ============================
   DFIR Actions
============================ */

function buildSSEUrl(base, params) {
  const qs = new URLSearchParams(params);
  return `${base}?${qs.toString()}`;
}

function acquireDiskLive() {
  const vm = requireSelected();
  const caseDir = requireCase();

  UI.diskResult.textContent = "Running...";
  cwrite(`Acquire disk (LIVE): vm_id=${vm.id} container=${UI.diskContainer.value}`);

  const container = (UI.diskContainer.value || "nova_libvirt").trim() || "nova_libvirt";

  const url = buildSSEUrl("/api/forensics/acquire/disk_kolla/stream", {
    case_dir: caseDir,
    vm_id: vm.id,
    container_name: container
  });

  startLiveSSE({
    title: "Acquire Disk (RAW) - Live",
    info: `vm_id=${vm.id} container=${container}`,
    url,
    onDone: async (payload) => {
      if (payload.result === "ok") {
        UI.diskResult.textContent = payload.disk_raw || "OK";
        cwrite(`Disk acquired OK: ${UI.diskResult.textContent}`);
        try { await refreshManifest(); } catch {}
      } else {
        UI.diskResult.textContent = "ERROR";
        cwrite(`ERROR disk: exit_code=${payload.exit_code}`);
      }
    }
  });
}

function acquireMemoryLive() {
  const vm = requireSelected();
  const caseDir = requireCase();

  const vmIp = (UI.memIP.value || "").trim();
  if (!vmIp) throw new Error("mem_vm_ip vacío. Selecciona VM o rellena manualmente.");

  const sshUser = (UI.memUser.value || "debian").trim() || "debian";
  const sshKey = (UI.memKey.value || "").trim();
  const mode = (UI.memMode.value || "build").trim() || "build";

  if (!sshKey) throw new Error("mem_ssh_key vacío.");

  UI.memResult.textContent = "Running...";
  cwrite(`Acquire memory (LIVE): vm_id=${vm.id} ip=${vmIp} user=${sshUser} mode=${mode}`);

  const url = buildSSEUrl("/api/forensics/acquire/memory_lime/stream", {
    case_dir: caseDir,
    vm_id: vm.id,
    vm_ip: vmIp,
    ssh_user: sshUser,
    ssh_key: sshKey,
    mode
  });

  startLiveSSE({
    title: "Acquire Memory (LiME) - Live",
    info: `vm_id=${vm.id} ip=${vmIp} user=${sshUser} mode=${mode}`,
    url,
    onDone: async (payload) => {
      if (payload.result === "ok") {
        UI.memResult.textContent = payload.mem_dump || "OK";
        cwrite(`Memory acquired OK: ${UI.memResult.textContent}`);
        try { await refreshManifest(); } catch {}
      } else {
        UI.memResult.textContent = "ERROR";
        cwrite(`ERROR memory: exit_code=${payload.exit_code}`);
      }
    }
  });
}

async function analyzeMemory() {
  try {
    // 1. Validar que hay una VM y un Caso seleccionados
    const vm = requireSelected();   // Asume que devuelve {id: "..."}
    const caseDir = requireCase();  // Asume que devuelve el path del caso

    // 2. Obtener valores de la UI (Sincronizado con tus IDs de HTML)
    const selectedDump = (UI.memorySelector && UI.memorySelector.value ? UI.memorySelector.value : "").trim();
const dumpFile = (selectedDump || (document.getElementById('vol_dump_file').value || "")).trim();

    const symbolsDir = (document.getElementById('vol_symbols_dir').value || "").trim();
    const volCmd = (document.getElementById('vol_cmd').value || "vol").trim();

    // 3. Validaciones preventivas
    if (!dumpFile) {
        alert("Error: El campo Dump File está vacío. Refresca el manifest.");
        return;
    }
    if (!symbolsDir) {
        alert("Error: Especifica el directorio de símbolos (/.../symbols/linux)");
        return;
    }

    // 4. Feedback visual en la consola de la UI
    document.getElementById('vol_result').textContent = "Running Volatility 3...";
    cwrite(`Lanzando análisis: vm_id=${vm.id} | dump=${dumpFile}`);

    // 5. Llamada a la API (Puerto 5001 explícito para evitar fallos)
    // Usamos la URL completa para asegurar la conexión
    const response = await fetch("/api/forensics/analyze/memory_vol3", {
      method: "POST",
      headers: { 
          "Content-Type": "application/json" 
      },
      body: JSON.stringify({
        case_dir: caseDir,
        vm_id: vm.id,
        dump_file: dumpFile,
        symbols_dir: symbolsDir,
        vol_cmd: volCmd
      })
    });

    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Error del servidor: ${response.status}`);
    }

    const data = await response.json();

    // 6. Mostrar resultado final
    // Si el script de bash devuelve la ruta al final, la mostramos
    document.getElementById('vol_result').textContent = data.out_dir || data.result || "OK";
    cwrite(`Vol3 Completado: ${document.getElementById('vol_result').textContent}`);

    // 7. Refrescar la lista de archivos (manifest) para ver los .txt generados
    if (typeof refreshManifest === "function") {
        await refreshManifest();
        cwrite("Manifiesto actualizado con nuevos reportes.");
    }

  } catch (err) {
    console.error("Fallo en analyzeMemory:", err);
    document.getElementById('vol_result').textContent = "Error";
    cwrite(`Error en Vol3: ${err.message}`);
    alert("Error en el análisis: " + err.message);
  }
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
  try {
    acquireDiskLive();
  } catch (e) {
    UI.diskResult.textContent = "ERROR";
    cwrite(`ERROR disk: ${e.message}`);
  }
});

UI.btnAcquireMemory.addEventListener("click", () => {
  try {
    acquireMemoryLive();
  } catch (e) {
    UI.memResult.textContent = "ERROR";
    cwrite(`ERROR memory: ${e.message}`);
  }
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

UI.caseSelector.addEventListener("change", () => {
  const v = (UI.caseSelector.value || "").trim();
  if (!v) return;
  setCaseDir(v);
  refreshManifest().catch(e => cwrite(`ERROR manifest: ${e.message}`));
});

UI.btnGenerateSymbols.addEventListener("click", () => {
  try {
    generateSymbolsLive();
  } catch (e) {
    cwrite(`ERROR symbols: ${e.message}`);
  }
});

async function loadCases() {
  const data = await httpJSON("/api/forensics/case/list");
  const cases = data.cases || [];

  UI.caseSelector.innerHTML = `
    <option value="">Select existing case...</option>
    ${cases.map(c => {
      const label = `${c.name}${c.artifacts_count ? ` (${c.artifacts_count} artifacts)` : ""}`;
      return `<option value="${escapeHtml(c.case_dir)}">${escapeHtml(label)}</option>`;
    }).join("")}
  `;

  if (!STATE.case_dir && cases.length) {
    setCaseDir(cases[0].case_dir);
    UI.caseSelector.value = cases[0].case_dir;
    try { await refreshManifest(); } catch {}
  }
}

function generateSymbolsLive() {
  const vm = requireSelected();
  const caseDir = requireCase();

  const vmIp = (UI.memIP.value || "").trim();
  if (!vmIp) throw new Error("mem_vm_ip vacío. Selecciona VM o rellena manualmente.");

  const sshUser = (UI.memUser.value || "ubuntu").trim() || "ubuntu";
  const sshKey = (UI.memKey.value || "").trim();
  if (!sshKey) throw new Error("mem_ssh_key vacío.");

  cwrite(`Generate symbols (LIVE): vm_id=${vm.id} ip=${vmIp} user=${sshUser}`);

  const url = buildSSEUrl("/api/forensics/vol3/symbols/generate/stream", {
    case_dir: caseDir,
    vm_id: vm.id,
    vm_ip: vmIp,
    ssh_user: sshUser,
    ssh_key: sshKey
  });

  startLiveSSE({
    title: "Generate Volatility 3 Symbols - Live",
    info: `vm_id=${vm.id} ip=${vmIp} user=${sshUser}`,
    url,
    onDone: async (payload) => {
      if (payload.result === "ok") {
        const symbolsDir = (payload.last || "").trim();
        if (symbolsDir) {
          UI.volSymbols.value = symbolsDir;
          cwrite(`Symbols generated OK: ${symbolsDir}`);
        } else {
          cwrite("Symbols done OK, pero no recibí directorio (payload.last vacío).");
        }
      } else {
        cwrite(`ERROR symbols: exit_code=${payload.exit_code}`);
      }
    }
  });
}
if (UI.runSelector) {
  UI.runSelector.addEventListener("change", () => {
    STATE.run_id = (UI.runSelector.value || "R1").trim() || "R1";
    if (STATE.selected?.id && STATE.traffic.running) {
      startTrafficAnalysis(STATE.selected.id);
    }
  });
}




if (UI.memorySelector) {
  UI.memorySelector.addEventListener("change", () => {
    const rel = (UI.memorySelector.value || "").trim();
    if (rel) UI.volDump.value = rel;
  });
}


if (UI.btnAnalyzeDisk) {
  UI.btnAnalyzeDisk.addEventListener("click", () => {
    try {
      const caseDir = requireCase();
      const diskRel = (UI.diskSelector && UI.diskSelector.value || "").trim();
      const runId = ((UI.runSelector && UI.runSelector.value) ? UI.runSelector.value : (STATE.run_id || "R1")).trim() || "R1";
      STATE.run_id = runId;

      if (!diskRel) {
        if (UI.diskAnalyzeResult) UI.diskAnalyzeResult.textContent = "ERROR: select a preserved disk (refresh manifest).";
        return;
      }

      const url = buildSSEUrl("/api/forensics/analyze/disk_tsk/stream", {
        case_dir: caseDir,
        disk: diskRel,
        run_id: runId
      });

      startLiveSSE({
        title: "Disk Analysis (TSK) - Live",
        info: `case=${caseDir} disk=${diskRel} run=${runId}`,
        url,
        onDone: async (payload) => {
          const ok = payload.result === "ok";
          if (UI.diskAnalyzeResult) {
            UI.diskAnalyzeResult.textContent = ok
              ? `OK (exit=${payload.exit_code}) out_dir=${payload.out_dir || "—"}`
              : `ERROR (exit=${payload.exit_code})`;
          }
          // refresca manifest para registrar out_dir si lo añades en backend
          try { await refreshManifest(); } catch {}
        }
      });

    } catch (e) {
      if (UI.diskAnalyzeResult) UI.diskAnalyzeResult.textContent = "ERROR";
      cwrite(`ERROR analyze disk: ${e.message}`);
    }
  });
}

async function loadAndPopulateMemorySelector(caseDir) {
  if (!UI.memorySelector) return;

  // Limpia
  UI.memorySelector.innerHTML = "";
  const optLoading = document.createElement("option");
  optLoading.value = "";
  optLoading.textContent = "Loading memory dumps...";
  UI.memorySelector.appendChild(optLoading);

  let dumps = [];
  try {
    const data = await httpJSON(`/api/forensics/case/memory/list?case_dir=${encodeURIComponent(caseDir)}`);
    dumps = data.dumps || [];
  } catch (e) {
    // fallback (si el endpoint falla)
    dumps = [];
  }

  UI.memorySelector.innerHTML = "";

  if (!dumps.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "No .lime memory dumps found in this case.";
    UI.memorySelector.appendChild(opt);
    return;
  }

  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = "Select a memory dump...";
  UI.memorySelector.appendChild(opt0);

  for (const d of dumps) {
    const opt = document.createElement("option");
    opt.value = d.rel_path;
    const shaShort = d.sha256 ? ` (sha: ${String(d.sha256).slice(0, 12)}...)` : "";
    opt.textContent = `${d.rel_path}${shaShort}`;
    UI.memorySelector.appendChild(opt);
  }

  // Auto-select: el más reciente (primer dump)
  UI.memorySelector.value = dumps[0].rel_path;

  // Sincroniza el input que usa analyzeMemory()
  UI.volDump.value = dumps[0].rel_path;
}



/* ============================
   Boot
============================ */
cwrite("DFIR UI booting...");
loadInstances().catch(e => cwrite(`ERROR boot instances: ${e.message}`));
loadCases().catch(e => cwrite(`ERROR boot cases: ${e.message}`));



