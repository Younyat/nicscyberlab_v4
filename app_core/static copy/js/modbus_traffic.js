  
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
              <div class="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center text-sky-500 font-bold italic">#</div>
              <div>
                <h3 class="font-bold text-slate-100 text-xs uppercase">${tool.name}</h3>
                <p class="text-[9px] font-mono ${tool.status === 'installed' ? 'text-emerald-500' : 'text-slate-500'}">${tool.status.toUpperCase()}</p>
              </div>
            </div>
            <button class="px-4 py-2 rounded-lg text-[9px] font-black uppercase transition-all ${tool.status === 'installed' ? 'bg-red-900/20 text-red-500 border border-red-500/30' : 'bg-sky-600 text-white'}">${tool.status === 'installed' ? 'Purge' : 'Deploy'}</button>
          </div>
        `).join("");
      } catch (e) {}
    }

    document.addEventListener('DOMContentLoaded', () => {
      loadHostInventory();
      loadInstancesFull();
    });
 