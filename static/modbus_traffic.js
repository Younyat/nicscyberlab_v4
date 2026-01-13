    const UI = {
        overlay: document.getElementById("overlay"),
        terminal: document.getElementById("ics-log-terminal"),
        grid: document.getElementById("tools-grid"),
        status: document.getElementById("overlay-status"),
        title: document.getElementById("overlay-title"),
        dot: document.getElementById("status-dot")
    };

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

    async function loadHostInventory() {
        try {
            const res = await fetch("/api/host/inventory");
            const data = await res.json();
            
            UI.grid.innerHTML = "";
            document.getElementById("last-update").textContent = `LAST SYNC: ${new Date().toLocaleTimeString()}`;

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
                    </div>
                `;
                UI.grid.appendChild(card);
            });
        } catch (e) {
            UI.grid.innerHTML = `<div class="p-4 bg-red-500/10 border border-red-500/20 text-red-500 text-xs rounded-lg font-mono">CRITICAL_ERROR: Failed to connect to backend inventory.</div>`;
        }
    }

    async function fetchVersion(toolId) {
        setOverlay(true, 'version');
        UI.terminal.textContent = `[NICS-SHELL] Iniciando auditoría de binario...\n`;
        UI.terminal.textContent += `----------------------------------------------------------------\n\n`;
        
        try {
            const res = await fetch(`/api/host/version/${toolId}`);
            const data = await res.json();
            UI.terminal.textContent += data.output;
            UI.terminal.textContent += `\n\n----------------------------------------------------------------`;
            UI.terminal.textContent += `\n[FIN] Auditoría finalizada.`;
            UI.terminal.scrollTop = UI.terminal.scrollHeight;
        } catch (e) {
            UI.terminal.textContent += `\n[ERROR] Fallo en la comunicación con el host remoto.`;
        }
    }

    function runInstallation(toolId) {
        setOverlay(true, 'install');
        UI.terminal.textContent = `[NICS-SHELL] Preparando entorno para instalar: ${toolId.toUpperCase()}\n\n`;

        const eventSource = new EventSource(`/api/host/install/${toolId}`);
        
        eventSource.onmessage = (e) => {
            if (e.data.includes("[FIN]")) {
                eventSource.close();
                UI.terminal.textContent += `\n[OK] Instalación completada. Refrescando...`;
                setTimeout(() => { setOverlay(false); loadHostInventory(); }, 2000);
                return;
            }
            UI.terminal.textContent += e.data + "\n";
            UI.terminal.scrollTop = UI.terminal.scrollHeight;
        };

        eventSource.onerror = () => {
            UI.terminal.textContent += `\n[ERROR] Error en el flujo de instalación.\n`;
            eventSource.close();
        };
    }

    function runUninstallation(toolId) {
        if (!confirm(`¿Confirmar desinstalación completa de ${toolId}?`)) return;

        setOverlay(true, 'uninstall');
        UI.terminal.textContent = `[NICS-SHELL] Iniciando desinstalación de: ${toolId.toUpperCase()}\n\n`;

        const eventSource = new EventSource(`/api/host/uninstall/${toolId}`);
        
        eventSource.onmessage = (e) => {
            if (e.data.includes("[FIN]")) {
                eventSource.close();
                UI.terminal.textContent += `\n[OK] Herramienta eliminada correctamente.`;
                setTimeout(() => { setOverlay(false); loadHostInventory(); }, 2000);
                return;
            }
            UI.terminal.textContent += e.data + "\n";
            UI.terminal.scrollTop = UI.terminal.scrollHeight;
        };

        eventSource.onerror = () => {
            UI.terminal.textContent += `\n[ERROR] Error en el flujo de desinstalación.\n`;
            eventSource.close();
        };
    }

    document.addEventListener('DOMContentLoaded', loadHostInventory);