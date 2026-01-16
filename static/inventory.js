const API = "";

/* ======================
   HELPERS
====================== */
const term = document.getElementById("terminal-output");

function log(msg, color = "text-slate-200") {
  const line = document.createElement("div");
  line.className = color;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function setStatus(text, sub, type) {
  document.getElementById("status-text").textContent = text;
  document.getElementById("status-subtext").textContent = sub;

  const dot = document.getElementById("status-dot");
  dot.className =
    "w-3 h-3 rounded-full animate-pulse " +
    (type === "ok"
      ? "bg-emerald-400"
      : type === "error"
      ? "bg-red-500"
      : "bg-amber-400");
}

function setProgress(p) {
  document.getElementById("progress-bar-inner").style.width = `${p}%`;
}

function overlay(show) {
  document.getElementById("overlay").classList.toggle("hidden", !show);
}

/* ======================
   SAFE FETCH (CLAVE)
====================== */
async function fetchJSON(url, label) {
  try {
    const res = await fetch(url);

    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      const text = await res.text();
      throw new Error(
        `${label}: respuesta NO JSON (status ${res.status})`
      );
    }

    return await res.json();
  } catch (err) {
    log(`❌ ${label} falló`, "text-red-400");
    console.error(err);
    return null;
  }
}

/* ======================
   TOOLS RENDER
====================== */
function renderToolsInline(tools) {
  // Caso 0: no hay tools
  if (!tools || typeof tools !== "object" || Object.keys(tools).length === 0) {
    return "<span class='text-slate-500'>-</span>";
  }

  return Object.entries(tools)
    .map(([tool, rawStatus]) => {

      // =========================
      // NORMALIZACIÓN (MISMA que en el segundo código)
      // =========================
      let status;

      if (!rawStatus) {
        status = "not_installed";
      } else if (rawStatus === "pending") {
        status = "pending";
      } else if (rawStatus === "error") {
        status = "error";
      } else if (rawStatus === "uninstalling") {
        status = "uninstalling";
      } else {
        // TODO lo demás (incluida FECHA → Zeek)
        status = "installed";
      }

      // =========================
      // RENDER SEGÚN ESTADO
      // =========================
      switch (status) {
        case "installed":
          return `
            <span class="text-emerald-400">
              ${tool} ✔ installed
              ${
                typeof rawStatus === "string"
                  ? `<br><span class="text-xs text-slate-400">${rawStatus}</span>`
                  : ""
              }
            </span>
          `;

        case "pending":
          return `<span class="text-amber-400">${tool} ⏳ pending</span>`;

        case "uninstalling":
          return `<span class="text-amber-400 animate-pulse">${tool} uninstalling…</span>`;

        case "error":
          return `<span class="text-red-500">${tool} ❌ error</span>`;

        default:
          return `<span class="text-slate-400">${tool} -</span>`;
      }
    })
    .join("<br>");
}



/* ======================
   LOADERS
====================== */
async function loadInstances() {
  const data = await fetchJSON(
    "/api/openstack/instances/full",
    "Instancias"
  );
  if (!data) return;

  const tbody = document.getElementById("instances-table");
  tbody.innerHTML = "";

  data.instances.forEach(vm => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${vm.name}</td>
        <td class="p-2">${vm.status}</td>
        <td class="p-2">${vm.ip_private || "-"}</td>
        <td class="p-2">${vm.ip_floating || "-"}</td>
        <td class="p-2">${renderToolsInline(vm.tools)}</td>
      </tr>`;
  });

  log(`✔ ${data.instances.length} instancias cargadas`, "text-emerald-300");
}

async function loadRoles() {
  const data = await fetchJSON("/api/instance_roles", "Roles");
  if (!data) return;

  document.getElementById("roles-box").textContent =
    JSON.stringify(data, null, 2);
}

async function loadFlavors() {
  const data = await fetchJSON("/api/openstack/flavors", "Flavors");
  if (!data) return;

  const tbody = document.getElementById("flavors-table");
  tbody.innerHTML = "";

  data.flavors.forEach(f => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${f.name}</td>
        <td class="p-2">${f.vcpus}</td>
        <td class="p-2">${f.ram_mb}</td>
        <td class="p-2">${f.disk_gb}</td>
      </tr>`;
  });
}

async function loadNetworks() {
  const data = await fetchJSON("/api/openstack/networks", "Redes");
  if (!data) return;

  const tbody = document.getElementById("networks-table");
  tbody.innerHTML = "";

  data.networks.forEach(n => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${n.name}</td>
        <td class="p-2">${(n.cidrs || []).join(", ") || "-"}</td>
      </tr>`;
  });
}

async function loadSecurityGroups() {
  const data = await fetchJSON(
    "/api/openstack/security-groups",
    "Security Groups"
  );
  if (!data) return;

  const tbody = document.getElementById("secgroups-table");
  tbody.innerHTML = "";

  data.security_groups.forEach(sg => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${sg.name}</td>
      </tr>`;
  });
}

async function loadKeypairs() {
  const data = await fetchJSON("/api/openstack/keypairs", "Keypairs");
  if (!data) return;

  const tbody = document.getElementById("keypairs-table");
  tbody.innerHTML = "";

  data.keypairs.forEach(k => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${k.name}</td>
      </tr>`;
  });
}

/* ======================
   LOAD INVENTORY
====================== */
async function loadInventory() {
  overlay(true);
  setProgress(10);
  setStatus("Cargando inventario", "Consultando OpenStack…", "warn");

  try {
    
    await loadHypervisorStats(); 
    setProgress(20);

    await loadInstances();
    setProgress(40);

    await loadRoles();
    setProgress(55);

    await loadFlavors();
    setProgress(65);

    await loadNetworks();
    setProgress(75);

    await loadSecurityGroups();
    setProgress(85);

    await loadKeypairs();
    setProgress(100);

    setStatus("Inventario actualizado", "Snapshot consistente", "ok");
    log("Inventario completo cargado", "text-emerald-300");

  } catch (e) {
    log(`Error general: ${e}`, "text-red-400");
    setStatus("Error", "Inventario inconsistente", "error");
  } finally {
    overlay(false);
  }
}


/* ======================
   RESOURCES LOADER
====================== */
async function loadHypervisorStats() {
    const stats = await fetchJSON("/api/openstack/hypervisor-stats", "Hypervisor Stats");
    if (!stats) return;

    // Mapeo de datos (OpenStack devuelve los valores según el sabor del CLI)
    const cpuUsed = stats.vcpus_used || 0;
    const cpuTotal = stats.vcpus || 1; // Evitar división por cero
    const ramUsed = stats.memory_mb_used || 0;
    const ramTotal = stats.memory_mb || 1;
    const diskUsed = stats.local_gb_used || 0;
    const diskTotal = stats.local_gb || 1;

    // Actualizar barras y texto
    updateMetric("cpu", cpuUsed, cpuTotal);
    updateMetric("ram", (ramUsed / 1024).toFixed(1), (ramTotal / 1024).toFixed(1), true);
    updateMetric("disk", diskUsed, diskTotal);

    log("📊 Estadísticas de hipervisor actualizadas", "text-sky-300");
}

function updateMetric(id, used, total, isGB = false) {
    const percent = Math.min((used / total) * 100, 100).toFixed(1);
    const unit = isGB ? "GB" : "";
    
    document.getElementById(`${id}-usage`).innerText = `${used} / ${total} ${unit}`;
    document.getElementById(`${id}-percent`).innerText = `${percent}%`;
    document.getElementById(`${id}-bar`).style.width = `${percent}%`;
}




/* ======================
   EVENTS
====================== */
document.getElementById("refresh-inventory").onclick = loadInventory;
document.getElementById("clear-terminal").onclick = () => (term.innerHTML = "");

log("Terminal listo. Esperando acción.");



/* ======================
   host tools
====================== */







    let STATE = { instances: [], selected: null, trafficSource: null };

    const UI = {
      tblInstances: document.getElementById("tbl-instances"),
      detailTitle: document.getElementById("detail-title"),
      trafficOverlay: document.getElementById("traffic-overlay"),
      trafficTerminal: document.getElementById("traffic-terminal"),
      trafficInfo: document.getElementById("traffic-vm-info"),
      grid: document.getElementById("tools-grid")
    };

    function escapeHtml(s) { return String(s ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }

    async function loadInstancesFull() {
      try {
        const res = await fetch("/api/openstack/instances/full");
        const data = await res.json();
        STATE.instances = data.instances || [];
        renderTable();
        document.getElementById("last-update").textContent = `LAST SYNC: ${new Date().toLocaleTimeString()}`;
      } catch (err) {
        UI.tblInstances.innerHTML = `<tr><td colspan="6" class="py-10 text-center text-red-500 font-mono uppercase text-xs">Error de conexión con la API</td></tr>`;
      }
    }

    function renderTable() {
      UI.tblInstances.innerHTML = STATE.instances.map(vm => `
        <tr class="hover:bg-slate-800/40 cursor-pointer transition-all group" onclick="startTrafficAnalysis('${vm.id}')">
          <td class="py-4 px-4 font-bold text-slate-100">${escapeHtml(vm.name)}<br><span class="text-[9px] text-slate-500 font-mono">${vm.id.substring(0,8)}</span></td>
          <td class="py-4 px-4"><span class="px-2 py-0.5 rounded text-[9px] font-black uppercase ${vm.status === 'ACTIVE' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}">${vm.status}</span></td>
          <td class="py-4 px-4 font-mono text-xs font-bold text-emerald-400">${escapeHtml(vm.ip_floating || "N/A")}</td>
          <td class="py-4 px-4 text-slate-500 text-[10px] font-mono">${escapeHtml(vm.flavor?.name || "-")}</td>
          <td class="py-4 px-4 text-slate-500 text-[10px] font-mono">${(vm.volumes || []).length} Units</td>
          <td class="py-4 px-4 text-right"><button class="bg-sky-500/10 text-sky-400 px-4 py-1.5 rounded-lg text-[9px] font-black uppercase border border-sky-500/20 group-hover:bg-sky-500 group-hover:text-white transition-all">Audit</button></td>
        </tr>
      `).join("");
    }

    function applyTrafficFilters() {
      if (STATE.selected) startTrafficAnalysis(STATE.selected.id);
    }

    function startTrafficAnalysis(id) {
      const vm = STATE.instances.find(x => x.id === id);
      if (!vm) return;
      STATE.selected = vm;

      UI.trafficOverlay.classList.replace("hidden", "flex");
     // Ahora mostramos la IP principal pero indicamos que es una auditoría de nodo completo
      UI.trafficInfo.textContent = `AUDITING NODE: ${vm.name} | MGMT_IP: ${vm.ip_floating || vm.ip_private || 'N/A'} | MODE: PROMISCUOUS`;
      
      // Limpiamos y ponemos cabecera
      UI.trafficTerminal.innerHTML = `<div class="text-slate-500 italic mb-2">[${new Date().toLocaleTimeString()}] Conectando con el motor Libpcap...</div>`;

      // Obtener filtros seleccionados
      const protos = Array.from(document.querySelectorAll('.proto-filter:checked')).map(cb => cb.value).join(',');
      
      if (STATE.trafficSource) STATE.trafficSource.close();
      
      // Conexión al endpoint
      STATE.trafficSource = new EventSource(`/api/openstack/traffic/${vm.id}?protos=${protos}`);
      
   STATE.trafficSource.onmessage = (e) => {
        // Ignorar mensajes de keep-alive
        if (e.data.trim() === ":") return;

        const line = document.createElement("div");
        line.className = "terminal-entry py-0.5 hover:bg-emerald-500/5 transition-colors px-2 font-mono whitespace-pre";
        
        const rawData = e.data;
        
        // Coloreado dinámico para protocolos industriales
        if (rawData.includes("MODBUS TCP")) {
            line.innerHTML = `<span class="text-yellow-400 font-bold">${rawData}</span>`;
        } else if (rawData.includes("PROFINET")) {
            line.innerHTML = `<span class="text-pink-400 font-bold">${rawData}</span>`;
        } else if (rawData.includes("[SISTEMA]")) {
            line.innerHTML = `<span class="text-sky-400 font-black underline">${rawData}</span>`;
        } else {
            line.innerText = rawData; 
        }
        
        UI.trafficTerminal.appendChild(line);
        
        // Auto-scroll suave
        UI.trafficTerminal.scrollTop = UI.trafficTerminal.scrollHeight;
      };

      STATE.trafficSource.onerror = () => {
        const errDiv = document.createElement("div");
        errDiv.className = "text-red-500 font-bold px-2 py-2";
        errDiv.innerText = "[ERROR] Pérdida de conexión con el sniffer. Reintentando...";
        UI.trafficTerminal.appendChild(errDiv);
      };
    }
    function closeTraffic() {
      if (STATE.trafficSource) STATE.trafficSource.close();
      UI.trafficOverlay.classList.replace("flex", "hidden");
    }

   async function loadHostInventory() {
  try {
    const res = await fetch("/api/host/inventory");
    const data = await res.json();

    UI.grid.innerHTML = data.tools.map(tool => `
      <div class="bg-slate-900/40 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
        
        <div class="flex items-center gap-4">
          <div class="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center 
                      ${tool.status === 'installed' ? 'text-emerald-500' : 'text-slate-500'} 
                      font-bold italic">
            #
          </div>
          <div>
            <h3 class="font-bold text-slate-100 text-xs uppercase">${tool.name}</h3>
            <p class="text-[9px] font-mono 
               ${tool.status === 'installed' ? 'text-emerald-500' : 'text-slate-500'}">
              ${tool.status === 'installed' ? 'INSTALLED' : 'NOT INSTALLED'}
            </p>
          </div>
        </div>

        <!-- Estado informativo, NO interactivo -->
        <div class="px-4 py-2 rounded-lg text-[9px] font-black uppercase border 
             ${tool.status === 'installed'
                ? 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
                : 'border-slate-600/30 text-slate-400 bg-slate-700/20'}">
          ${tool.status === 'installed' ? 'READY' : 'UNAVAILABLE'}
        </div>

      </div>
    `).join("");

  } catch (e) {
    UI.grid.innerHTML = `<div class="text-red-500 text-xs font-mono">ERROR LOADING INVENTORY</div>`;
  }
}


    document.addEventListener('DOMContentLoaded', () => {
      loadHostInventory();
      loadInstancesFull();
    });
  