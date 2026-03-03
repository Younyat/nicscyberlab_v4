// 1. Elementos UI
const UI = {
    overlay: document.getElementById("overlay"),
    terminal: document.getElementById("ics-log-terminal"),
    grid: document.getElementById("tools-grid"),
    status: document.getElementById("overlay-status"),
    title: document.getElementById("overlay-title"),
    dot: document.getElementById("status-dot"),
    tblInstances: document.getElementById("tbl-instances"),
    detailTitle: document.getElementById("detail-title")
};

let STATE = {
    instances: [],
    selected: null,
};

let trafficSource = null;

// --- LÓGICA DE OVERLAY Y TERMINAL (SISTEMA) ---

function setOverlay(show, mode = 'install') {
    UI.overlay.classList.toggle("hidden", !show);
    UI.overlay.classList.toggle("flex", show);
    
    if (show) {
        UI.terminal.textContent = ""; 
        if (mode === 'version') {
            UI.title.textContent = "Consulta de Versión";
            UI.dot.className = "w-4 h-4 rounded-full bg-sky-500 animate-pulse";
            UI.status.textContent = "Status: Ejecutando comando de auditoría...";
        } else if (mode === 'uninstall') {
            UI.title.textContent = "Eliminando Herramienta";
            UI.dot.className = "w-4 h-4 rounded-full bg-red-500 animate-pulse";
            UI.status.textContent = "Status: Ejecutando purga del sistema...";
        } else {
            UI.title.textContent = "Desplegando Herramienta";
            UI.dot.className = "w-4 h-4 rounded-full bg-emerald-500 animate-pulse";
            UI.status.textContent = "Status: Procesando instalación vía SSE...";
        }
    }
}

// --- GESTIÓN DE INVENTARIO DE HERRAMIENTAS ---

async function loadHostInventory() {
    try {
        const res = await fetch("/api/host/inventory");
        const data = await res.json();
        
        UI.grid.innerHTML = "";
        const lastUpdateEl = document.getElementById("last-update");
        if (lastUpdateEl) lastUpdateEl.textContent = `LAST SYNC: ${new Date().toLocaleTimeString()}`;

        data.tools.forEach(tool => {
            const isInstalled = tool.status === "installed";
            const card = document.createElement("div");
            card.className = `group bg-slate-900/40 border border-slate-800 rounded-xl p-6 flex items-center justify-between transition-all duration-300 ${isInstalled ? 'hover:border-sky-500/50 hover:bg-slate-900/80 cursor-pointer' : ''}`;
            
            if (isInstalled) {
                card.onclick = () => fetchVersion(tool.id);
            }

            card.innerHTML = `
                <div class="flex items-center gap-6">
                    <div class="flex-shrink-0">
                        <div class="w-14 h-14 rounded-xl ${isInstalled ? 'bg-emerald-500/10 text-emerald-500 group-hover:bg-sky-500/10 group-hover:text-sky-400' : 'bg-slate-800 text-slate-600'} flex items-center justify-center border ${isInstalled ? 'border-emerald-500/20 group-hover:border-sky-500/20' : 'border-slate-700'} transition-all duration-500">
                            <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                ${isInstalled 
                                    ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>' 
                                    : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>'
                                }
                            </svg>
                        </div>
                    </div>
                    <div>
                        <h3 class="font-bold text-slate-100 font-mono text-lg group-hover:text-sky-400 transition-colors uppercase tracking-tight">${tool.name}</h3>
                        <div id="version-${tool.id}" class="text-[10px] font-mono mt-1 ${isInstalled ? 'text-emerald-500/60' : 'text-slate-500'}">
                            ${isInstalled ? '✓ READY - PULSE PARA AUDITAR SALIDA' : '✗ PENDIENTE DE INSTALACIÓN'}
                        </div>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    ${isInstalled 
                        ? `<button onclick="event.stopPropagation(); runUninstallation('${tool.id}')" class="px-4 py-2 bg-red-900/20 hover:bg-red-600 border border-red-500/50 text-red-500 hover:text-white text-[10px] font-black rounded-lg uppercase transition-all shadow-lg active:scale-95">Desinstalar</button>`
                        : `<button onclick="event.stopPropagation(); runInstallation('${tool.id}')" class="px-6 py-2.5 bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-black rounded-lg uppercase transition-all shadow-lg shadow-sky-900/20 active:scale-95">Instalar</button>`
                    }
                </div>`;
            UI.grid.appendChild(card);
        });
    } catch (e) {
        UI.grid.innerHTML = `<div class="p-4 bg-red-500/10 border border-red-500/20 text-red-500 text-xs rounded-lg font-mono">CRITICAL_ERROR: Failed to connect to backend inventory.</div>`;
    }
}

// --- GESTIÓN DE INSTANCIAS (TABLA Y TRÁFICO) ---

function escapeHtml(s) {
    return String(s ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function renderInstanceRow(vm) {
    const statusCls = vm.status === "ACTIVE" ? "text-emerald-300" : vm.status === "ERROR" ? "text-red-300" : "text-slate-300";
    return `
        <tr class="hover:bg-slate-950/50 cursor-pointer" data-id="${escapeHtml(vm.id)}">
            <td class="py-3 pr-3 font-semibold text-slate-100">${escapeHtml(vm.name)}</td>
            <td class="py-3 pr-3 ${statusCls} font-semibold">${escapeHtml(vm.status)}</td>
            <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.ip_private || "-")}</td>
            <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.ip_floating || "-")}</td>
            <td class="py-3 pr-3 text-slate-400 text-xs">${escapeHtml(vm.flavor?.name || "-")}</td>
            <td class="py-3 pr-3 text-slate-400 text-xs">${(vm.volumes || []).length} vol</td>
            <td class="py-3 pr-3">${Object.keys(vm.tools || {}).length} tools</td>
            <td class="py-3 pr-3 text-sky-500 font-bold text-[10px] uppercase">Capturar Tráfico</td>
        </tr>`;
}

function showInstanceDetail(vm) {
    STATE.selected = vm;
    if (UI.detailTitle) {
        UI.detailTitle.textContent = `Seleccionada: ${vm.name} (${vm.id})`;
    }
}

// ESTA FUNCIÓN AHORA ACTIVA AMBAS COSAS: DETALLE Y TRÁFICO
function bindInstanceRowClicks() {
    UI.tblInstances.querySelectorAll("tr[data-id]").forEach(tr => {
        tr.addEventListener("click", () => {
            const id = tr.getAttribute("data-id");
            const vm = STATE.instances.find(x => x.id === id);
            if (vm) {
                showInstanceDetail(vm);   // Actualiza el texto de la UI
                openTrafficCapture(vm);   // Abre la ventana de captura de tráfico
            }
        });
    });
}

// --- CAPTURA DE TRÁFICO (SSE) ---

function openTrafficCapture(vm) {
    const overlay = document.getElementById('traffic-overlay');
    const terminal = document.getElementById('traffic-terminal');
    const title = document.getElementById('traffic-vm-name');

    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
    title.textContent = `TARGET: ${vm.name} (${vm.ip_private})`;
    terminal.textContent = `[INFO] Iniciando captura de paquetes en ${vm.name}...\n`;

    if (trafficSource) trafficSource.close();

    trafficSource = new EventSource(`/api/openstack/traffic/${vm.id}`);
    
    trafficSource.onmessage = (e) => {
        const line = document.createElement('div');
        line.className = "border-b border-white/5 py-0.5 hover:bg-white/5";
        line.textContent = e.data;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    };

    trafficSource.onerror = () => {
        const err = document.createElement('div');
        err.className = "text-red-500 font-bold";
        err.textContent = "[ERROR] Interrupción en el flujo de datos forenses.";
        terminal.appendChild(err);
        trafficSource.close();
    };
}

function closeTraffic() {
    if (trafficSource) trafficSource.close();
    const trafficOverlay = document.getElementById('traffic-overlay');
    trafficOverlay.classList.add('hidden');
    trafficOverlay.classList.remove('flex');
}

// --- CARGA INICIAL ---

async function loadInstancesFull() {
    try {
        const res = await fetch("/api/openstack/instances/full");
        if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
        const data = await res.json();
        STATE.instances = data.instances || [];
        UI.tblInstances.innerHTML = STATE.instances.map(renderInstanceRow).join("");
        bindInstanceRowClicks();
    } catch (err) {
        UI.tblInstances.innerHTML = `<tr><td colspan="8" class="py-4 text-center text-red-400 font-mono">ERROR_CARGA_API</td></tr>`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadHostInventory();
    loadInstancesFull();
});