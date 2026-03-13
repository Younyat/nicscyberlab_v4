const UI = {
  overlay: document.getElementById("overlay"),
  progress: document.getElementById("progress"),
  statusText: document.getElementById("status-text"),
  statusSub: document.getElementById("status-sub"),
  statusDot: document.getElementById("status-dot"),

  tblInstances: document.getElementById("tbl-instances"),
  tblFlavors: document.getElementById("tbl-flavors"),
  tblNetworks: document.getElementById("tbl-networks"),
  tblSGs: document.getElementById("tbl-sgs"),
  tblKeys: document.getElementById("tbl-keys"),

  detailTitle: document.getElementById("detail-title"),
  detailNetworks: document.getElementById("detail-networks"),
  detailVolumes: document.getElementById("detail-volumes"),
  detailTools: document.getElementById("detail-tools"),
  detailJson: document.getElementById("detail-json"),

  toolsGrid: document.getElementById("tools-grid"),


  cpuBar: document.getElementById("cpu-bar"),
  cpuUsage: document.getElementById("cpu-usage"),
  cpuPercent: document.getElementById("cpu-percent"),
  ramBar: document.getElementById("ram-bar"),
  ramUsage: document.getElementById("ram-usage"),
  ramPercent: document.getElementById("ram-percent"),
  diskBar: document.getElementById("disk-bar"),
  diskUsage: document.getElementById("disk-usage"),
  diskPercent: document.getElementById("disk-percent"),
};

let STATE = {
  instances: [],
  selected: null,
};

function setOverlay(show) {
  UI.overlay.classList.toggle("hidden", !show);
  UI.overlay.classList.toggle("flex", show);
}

function setProgress(p) {
  UI.progress.style.width = `${p}%`;
}

function setStatus(text, sub, type) {
  UI.statusText.textContent = text;
  UI.statusSub.textContent = sub;

  UI.statusDot.className =
    "w-3 h-3 rounded-full " +
    (type === "ok"
      ? "bg-emerald-400"
      : type === "error"
      ? "bg-red-500"
      : "bg-amber-400") +
    " animate-pulse";
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function badge(text, cls) {
  return `<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold ${cls}">${escapeHtml(text)}</span>`;
}

function formatRam(ramMb) {
  if (!ramMb && ramMb !== 0) return "-";
  if (ramMb >= 1024) return `${(ramMb / 1024).toFixed(1)} GB`;
  return `${ramMb} MB`;
}

function renderToolsCompact(tools) {
  const entries = Object.entries(tools || {});
  if (entries.length === 0) return `<span class="text-slate-500">-</span>`;

  // mostrar max 4 en tabla + contador
  const max = 4;
  const shown = entries.slice(0, max).map(([t, st]) => {
    if (st === "pending") return badge(`${t}: pending`, "bg-amber-500/10 text-amber-300 border border-amber-500/20");
    if (st === "error") return badge(`${t}: error`, "bg-red-500/10 text-red-300 border border-red-500/20");
    return badge(`${t}: installed`, "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20");
  });

  const more = entries.length > max ? `<div class="text-xs text-slate-500 mt-1">+${entries.length - max} más</div>` : "";
  return `<div class="space-y-1">${shown.join("")}${more}</div>`;
}

function renderEvidence(evidence) {
  const mem = evidence?.memory ? badge("MEM", "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20") : badge("MEM", "bg-slate-800 text-slate-400 border border-slate-700");
  const disk = evidence?.disk ? badge("DISK", "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20") : badge("DISK", "bg-slate-800 text-slate-400 border border-slate-700");
  const net = evidence?.network ? badge("NET", "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20") : badge("NET", "bg-slate-800 text-slate-400 border border-slate-700");
  return `<div class="flex gap-2 flex-wrap">${mem}${disk}${net}</div>`;
}

function renderFlavorCell(flavor) {
  if (!flavor) return `<span class="text-slate-500">-</span>`;
  return `
    <div class="text-xs">
      <div class="text-slate-200 font-semibold">${escapeHtml(flavor.name || flavor.id)}</div>
      <div class="text-slate-400">${flavor.vcpus} vCPU · ${formatRam(flavor.ram_mb)} · ${flavor.disk_gb} GB</div>
    </div>
  `;
}

function renderVolumesCell(vols) {
  const v = vols || [];
  if (v.length === 0) return `<span class="text-slate-500">-</span>`;
  const total = v.reduce((acc, x) => acc + (Number(x.size_gb) || 0), 0);
  return `
    <div class="text-xs">
      <div class="text-slate-200 font-semibold">${v.length} vol</div>
      <div class="text-slate-400">${total} GB total</div>
    </div>
  `;
}

function renderInstanceRow(vm) {
  const statusCls =
    vm.status === "ACTIVE" ? "text-emerald-300" :
    vm.status === "ERROR"  ? "text-red-300" :
    "text-slate-300";

  return `
    <tr class="hover:bg-slate-950/50 cursor-pointer" data-id="${escapeHtml(vm.id)}">
      <td class="py-3 pr-3">
        <div class="font-semibold text-slate-100">${escapeHtml(vm.name)}</div>
        <div class="text-xs text-slate-500">${escapeHtml(vm.id)}</div>
      </td>
      <td class="py-3 pr-3 ${statusCls} font-semibold">${escapeHtml(vm.status)}</td>
      <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.ip_private || "-")}</td>
      <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.ip_floating || "-")}</td>
      <td class="py-3 pr-3">${renderFlavorCell(vm.flavor)}</td>
      <td class="py-3 pr-3">${renderVolumesCell(vm.volumes)}</td>
      <td class="py-3 pr-3">${renderToolsCompact(vm.tools)}</td>
      <td class="py-3 pr-3">${renderEvidence(vm.evidence)}</td>
    </tr>
  `;
}

function showInstanceDetail(vm) {
  STATE.selected = vm;
  UI.detailTitle.textContent = `${vm.name} · ${vm.status}`;

  // Networks
  const nets = vm.networks || [];
  UI.detailNetworks.innerHTML = nets.length
    ? nets.map(n => `
        <div class="p-3 rounded-lg border border-slate-800 bg-slate-950/40">
          <div class="flex items-center justify-between">
            <div class="font-semibold text-slate-200">${escapeHtml(n.network)}</div>
            <div>${n.type === "floating"
              ? badge("floating", "bg-sky-500/10 text-sky-300 border border-sky-500/20")
              : badge("fixed", "bg-slate-800 text-slate-300 border border-slate-700")
            }</div>
          </div>
          <div class="mt-1 text-slate-300 text-xs">
            IP: <span class="text-slate-100">${escapeHtml(n.ip)}</span>
          </div>
          <div class="text-slate-500 text-xs">MAC: ${escapeHtml(n.mac || "-")}</div>
        </div>
      `).join("")
    : `<div class="text-slate-500">Sin interfaces</div>`;

  // Volumes
  const vols = vm.volumes || [];
  UI.detailVolumes.innerHTML = vols.length
    ? vols.map(v => `
        <div class="p-3 rounded-lg border border-slate-800 bg-slate-950/40">
          <div class="flex items-center justify-between">
            <div class="font-semibold text-slate-200">${escapeHtml(v.name || v.id)}</div>
            <div>${badge(`${v.size_gb ?? "?"} GB`, "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20")}</div>
          </div>
          <div class="mt-1 text-xs text-slate-300">
            Status: <span class="text-slate-100">${escapeHtml(v.status || "-")}</span>
          </div>
          <div class="text-xs text-slate-500">
            Bootable: ${escapeHtml(v.bootable ?? "-")} · Type: ${escapeHtml(v.volume_type ?? "-")}
          </div>
        </div>
      `).join("")
    : `<div class="text-slate-500">Sin volúmenes adjuntos</div>`;

  // Tools
  const tools = vm.tools || {};
  const tEntries = Object.entries(tools);
  UI.detailTools.innerHTML = tEntries.length
    ? tEntries.map(([t, st]) => {
        if (st === "pending") {
          return `<div class="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5">
            <div class="font-semibold text-slate-100">${escapeHtml(t)}</div>
            <div class="text-xs text-amber-300">pending</div>
          </div>`;
        }
        if (st === "error") {
          return `<div class="p-3 rounded-lg border border-red-500/20 bg-red-500/5">
            <div class="font-semibold text-slate-100">${escapeHtml(t)}</div>
            <div class="text-xs text-red-300">error</div>
          </div>`;
        }
        return `<div class="p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
          <div class="font-semibold text-slate-100">${escapeHtml(t)}</div>
          <div class="text-xs text-emerald-300">installed · ${escapeHtml(st)}</div>
        </div>`;
      }).join("")
    : `<div class="text-slate-500">Sin tools registradas</div>`;

  // JSON
  UI.detailJson.textContent = JSON.stringify(vm, null, 2);
}

function bindInstanceRowClicks() {
  UI.tblInstances.querySelectorAll("tr[data-id]").forEach(tr => {
    tr.addEventListener("click", () => {
      const id = tr.getAttribute("data-id");
      const vm = STATE.instances.find(x => x.id === id);
      if (vm) showInstanceDetail(vm);
    });
  });
}

async function loadHostTools() {
  UI.hostLog.textContent = "";
  UI.hostTools.innerHTML = `<div class="text-xs text-slate-400">Cargando…</div>`;

  const res = await fetch("/api/host/forensic/tools");
  const data = await res.json();

  const tools = data.tools || [];
  UI.hostTools.innerHTML = tools.map(t => {
    const isInstalled = t.status === "installed";
    const isError = t.status === "error";

    const badgeCls = isInstalled
      ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
      : isError
      ? "bg-red-500/10 text-red-300 border border-red-500/20"
      : "bg-amber-500/10 text-amber-300 border border-amber-500/20";

    const btn = isInstalled
      ? `<button disabled class="px-3 py-1 text-xs rounded bg-slate-800 border border-slate-700 text-slate-500 cursor-not-allowed">Instalado</button>`
      : `<button data-install="${escapeHtml(t.name)}"
           class="px-3 py-1 text-xs rounded bg-sky-600 hover:bg-sky-500 font-semibold shadow">
           Instalar
         </button>`;

    return `
      <div class="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/40">
        <div>
          <div class="font-semibold text-slate-100">${escapeHtml(t.name)}</div>
          <div class="mt-1">${badge(t.status, badgeCls)}</div>
        </div>
        <div class="flex items-center gap-2">
          ${btn}
        </div>
      </div>
    `;
  }).join("");

  UI.hostTools.querySelectorAll("button[data-install]").forEach(b => {
    b.addEventListener("click", async () => {
      const tool = b.getAttribute("data-install");
      await installHostTool(tool);
    });
  });
}

async function installHostTool(tool) {
  UI.hostLog.textContent += `[${new Date().toLocaleTimeString()}] Instalando ${tool}...\n`;

  const res = await fetch("/api/host/forensic/install", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ tool })
  });

  const data = await res.json();

  UI.hostLog.textContent += `--- STDOUT ---\n${data.stdout || ""}\n`;
  UI.hostLog.textContent += `--- STDERR ---\n${data.stderr || ""}\n`;
  UI.hostLog.textContent += `[${new Date().toLocaleTimeString()}] ExitCode=${data.exit_code}\n\n`;

  await loadHostInventory();
}

async function loadGlobalInventory() {
  // Flavors
  const fRes = await fetch("/api/openstack/flavors");
  const fData = await fRes.json();
  const flavors = fData.flavors || [];
  UI.tblFlavors.innerHTML = flavors.map(f => `
    <tr>
      <td class="py-2 pr-2 text-slate-100 font-semibold">${escapeHtml(f.name)}</td>
      <td class="py-2 pr-2 text-slate-300">${escapeHtml(f.vcpus)}</td>
      <td class="py-2 pr-2 text-slate-300">${escapeHtml(formatRam(f.ram_mb))}</td>
      <td class="py-2 pr-2 text-slate-300">${escapeHtml(f.disk_gb)} GB</td>
    </tr>
  `).join("");

  // Networks
  const nRes = await fetch("/api/openstack/networks");
  const nData = await nRes.json();
  const nets = nData.networks || [];
  UI.tblNetworks.innerHTML = nets.map(n => `
    <tr>
      <td class="py-2 pr-2 text-slate-100 font-semibold">${escapeHtml(n.name)}</td>
      <td class="py-2 pr-2 text-slate-300">${escapeHtml((n.cidrs || []).join(", ") || "-")}</td>
      <td class="py-2 pr-2 text-slate-300">${n.is_router_external ? "yes" : "no"}</td>
    </tr>
  `).join("");

  // Security groups
  const sgRes = await fetch("/api/openstack/security-groups");
  const sgData = await sgRes.json();
  const sgs = sgData.security_groups || [];
  UI.tblSGs.innerHTML = sgs.map(sg => `
    <tr>
      <td class="py-2 pr-2 text-slate-100 font-semibold">${escapeHtml(sg.name)}</td>
      <td class="py-2 pr-2 text-slate-300">${escapeHtml(sg.rules_count)}</td>
      <td class="py-2 pr-2 text-slate-400">${escapeHtml(sg.description || "-")}</td>
    </tr>
  `).join("");

  // Keypairs
  const kRes = await fetch("/api/openstack/keypairs");
  const kData = await kRes.json();
  const keys = kData.keypairs || [];
  UI.tblKeys.innerHTML = keys.map(k => `
    <tr>
      <td class="py-2 pr-2 text-slate-100 font-semibold">${escapeHtml(k.name)}</td>
      <td class="py-2 pr-2 text-slate-400">${escapeHtml(k.fingerprint || "-")}</td>
    </tr>
  `).join("");
}

async function loadInstancesFull() {
  const res = await fetch("/api/openstack/instances/full");
  const data = await res.json();
  const instances = data.instances || [];

  STATE.instances = instances;
  UI.tblInstances.innerHTML = instances.map(renderInstanceRow).join("");

  bindInstanceRowClicks();

  // si no hay seleccionada, selecciona la primera
  if (!STATE.selected && instances.length > 0) {
    showInstanceDetail(instances[0]);
  } else if (STATE.selected) {
    const refreshed = instances.find(x => x.id === STATE.selected.id);
    if (refreshed) showInstanceDetail(refreshed);
  }
}

async function refreshAll() {
  setOverlay(true);
  setProgress(5); // Inicio rápido
  setStatus("Cargando snapshot", "Consultando OpenStack…", "warn");

  try {
    // 1. Recursos de Hardware (Hypervisor)
    setStatus("Analizando recursos", "Leyendo cuotas de hardware…", "warn");
    await loadHypervisorResources(); 
    setProgress(20);

    // 2. Inventario Global (Flavors, Redes, SGs)
    setStatus("Cargando inventario", "Obteniendo objetos globales…", "warn");
    await loadGlobalInventory();
    setProgress(45);

    // 3. Instancias (Cuerpo principal)
    setStatus("Mapeando instancias", "Extrayendo detalle de VMs…", "warn");
    await loadInstancesFull();
    setProgress(75);

    // 4. Herramientas del Host
    setStatus("Verificando herramientas", "Chequeando Forensic Tools…", "warn");
    await loadHostInventory();

    setProgress(100);
    setStatus("Inventario actualizado", "Snapshot forense listo", "ok");
  } catch (e) {
    console.error(e);
    setStatus("Error", "No se pudo cargar el inventario", "error");
  } finally {
    setOverlay(false);
    setTimeout(() => setProgress(0), 600);
  }
}


/**
 * Actualiza los medidores de recursos desde la API
 */
async function loadHypervisorResources() {
  try {
    // Usamos el endpoint del backend que creamos anteriormente
    const stats = await fetchJSON("/api/openstack/hypervisor-stats", "Hypervisor Resources");
    if (!stats) return;

    // vCPU
    updateUIComponent('cpu', stats.vcpus_used, stats.vcpus);
    
    // RAM (Convertimos MB a GB para mejor lectura forense)
    const ramUsed = (stats.memory_mb_used / 1024).toFixed(1);
    const ramTotal = (stats.memory_mb / 1024).toFixed(1);
    updateUIComponent('ram', ramUsed, ramTotal);

    // Disk
    updateUIComponent('disk', stats.local_gb_used, stats.local_gb);

  } catch (err) {
    console.error("Error cargando recursos:", err);
  }
}

/**
 * Helper para manipular el DOM de las barras y textos
 */



function updateUIComponent(id, used, total) {
  const percent = total > 0 ? Math.min((used / total) * 100, 100).toFixed(1) : 0;
  
  // Buscamos los elementos directamente por ID si no están en UI
  const barEl = document.getElementById(`${id}-bar`);
  const textEl = document.getElementById(`${id}-usage`);
  const percentEl = document.getElementById(`${id}-percent`);

  if (barEl) barEl.style.width = `${percent}%`;
  
  // Añadimos unidad según el tipo
  let unit = "";
  if (id === "ram" || id === "disk") unit = " GB";
  
  if (textEl) textEl.textContent = `${used}${unit} / ${total}${unit}`;
  if (percentEl) {
    percentEl.textContent = `${percent}%`;
    
    // Alerta visual forense
    if (percent > 90) {
      percentEl.classList.add('text-red-500');
      barEl?.classList.add('bg-red-600');
    }
  }
}






async function fetchJSON(url, label) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Error HTTP: ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error(`❌ ${label} falló:`, err);
    return null;
  }
}


document.getElementById("btn-refresh").addEventListener("click", refreshAll);



async function loadHostInventory() {
  try {
    const res = await fetch("/api/host/inventory");
    if (!res.ok) throw new Error("HTTP error");

    const data = await res.json();
    const tools = data.tools || [];

    UI.toolsGrid.innerHTML = tools.map(tool => `
      <div class="flex items-center justify-between p-4 rounded-lg border border-slate-800 bg-slate-950/40">

        <div>
          <div class="font-semibold text-slate-100 text-xs uppercase">
            ${escapeHtml(tool.name)}
          </div>
          <div class="text-[10px] font-mono
            ${tool.status === 'installed' ? 'text-emerald-400' : 'text-slate-500'}">
            ${tool.status === 'installed' ? 'INSTALLED' : 'NOT INSTALLED'}
          </div>
        </div>

        <div class="px-3 py-1 rounded-md text-[10px] font-black uppercase border
          ${tool.status === 'installed'
            ? 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
            : 'border-slate-600/30 text-slate-400 bg-slate-700/20'}">
          ${tool.status === 'installed' ? 'READY' : 'UNAVAILABLE'}
        </div>

      </div>
    `).join("");

  } catch (e) {
    UI.toolsGrid.innerHTML = `
      <div class="text-xs text-red-500 font-mono">
        ERROR LOADING HOST INVENTORY
      </div>`;
  }
}



refreshAll();
