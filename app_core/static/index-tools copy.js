console.log("JS CARGADO CORRECTAMENTE ");

/* ============================================================
    VARIABLES GLOBALES
   ============================================================ */
let cy = null;
let selectedInstance = null;

/* ============================================================
    SE EJECUTA AL CARGAR LA PÁGINA
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
    console.log(" Cargando escenario inicial…");
    loadExistingScenario();
});

/* ============================================================
   Inicializar Cytoscape de forma segura (evita errores)
   ============================================================ */
function ensureCy() {
    const container = document.getElementById("cy");

    if (!container) {
        console.error(" Contenedor #cy no encontrado.");
        return false;
    }

    if (typeof cytoscape === "undefined") {
        console.error(" Cytoscape NO está cargado.");
        return false;
    }

    // Si ya existe un cy previo → destruirlo correctamente
    if (cy && typeof cy.destroy === "function") {
        cy.destroy();
    }

    cy = cytoscape({
        container: container,
        elements: [],
        style: [
            {
                selector: "node",
                style: {
                    "background-color": "#4A90E2",
                    "label": "data(label)",
                    "color": "white",
                    "text-outline-color": "#1E3A8A",
                    "text-outline-width": 2
                }
            },
            { selector: 'node[type="attack"]', style: { "background-color": "#e53935" } },
            { selector: 'node[type="victim"]', style: { "background-color": "#1976d2" } },
            { selector: 'node[type="monitor"]', style: { "background-color": "#43a047" } },

            { selector: "edge", style: { "width": 3, "line-color": "#888" } }
        ]
    });

    console.log(" Cytoscape inicializado correctamente.");
    return true;
}

/* ============================================================
   1. Consultar instancias en OpenStack
   ============================================================ */
async function loadExistingScenario() {
    console.log(" Iniciando carga del escenario...");

    try {
        const res = await fetch("/api/openstack/instances");
        const data = await res.json();

        if (!data.instances || data.instances.length === 0) {
            showNoScenario();
            return;
        }

        const scenario = {
            nodes: data.instances.map((vm, i) => ({
                id: vm.id, // Este es el UUID de OpenStack
                name: vm.name,
                type: detectType(vm.name),
                ip: vm.ip || "N/A",
                ip_private: vm.ip_private,
                ip_floating: vm.ip_floating,
                status: vm.status,
                // CARGAMOS LAS TOOLS QUE EL BACKEND YA CONOCE
                tools: vm.installed_tools || {}, 
                position: { x: 200 + i * 200, y: 150 }
            })),
            edges: []
        };

        loadScenarioGraph(scenario);
        loadScenarioTools(scenario);

    } catch (error) {
        console.error(" Error llamando al backend:", error);
        showNoScenario();
    }
}

/* ============================================================
   Detectar tipo de instancia según nombre
   ============================================================ */
function detectType(name) {
    name = name.toLowerCase();
    if (name.includes("monitor")) return "monitor";
    if (name.includes("attack")) return "attack";
    if (name.includes("victim")) return "victim";
    return "generic";
}

/* ============================================================
   2. Si NO hay instancias
   ============================================================ */
function showNoScenario() {
    document.getElementById("instance-list").innerHTML = `
        <div class="p-4 bg-red-700 rounded-lg text-center">
             No hay instancias en OpenStack.<br>
             Verifica que OpenStack esté funcionando.
        </div>
    `;

    if (cy && typeof cy.destroy === "function") {
        cy.destroy();
        cy = null;
    }
}

/* ============================================================
   3. Pintar grafo
   ============================================================ */
/* ============================================================
    3. PINTAR GRAFO (Versión Completa y Sincronizada)
   ============================================================ */
/* ============================================================
    3. PINTAR GRAFO (Optimizado para Uninstaller)
   ============================================================ */
function loadScenarioGraph(scenario) {
    console.log(" Renderizando grafo con estados de herramientas...");

    if (!ensureCy()) return;

    // 1. Configurar estilos dinámicos según el estado de las herramientas
    cy.style()
        .selector('node[?has_installed]')
        .style({
            'border-width': 4,
            'border-color': '#10B981', // Verde: Al menos una instalada
            'border-opacity': 1,
            'border-style': 'solid'
        })
        .selector('node[?has_pending]')
        .style({
            'border-width': 4,
            'border-color': '#F59E0B', // Naranja: Hay instalaciones en curso
            'border-style': 'dashed'
        })
        .selector('node[?has_error]')
        .style({
            'border-width': 5,
            'border-color': '#EF4444', // Rojo: Falló la desinstalación/instalación
            'border-style': 'double'
        })
        .update();

    let elements = [];

    // 2. Procesar Nodos
    scenario.nodes.forEach(n => {
        // Obtenemos los estados actuales de las herramientas
        const toolStatuses = Object.values(n.tools || {});
        
        // Lógica de estados visuales
        const isInstalled = toolStatuses.some(s => s !== 'pending' && s !== 'error' && s !== 'uninstalling');
        const isPending = toolStatuses.includes("pending");
        const hasError = toolStatuses.includes("error");

        elements.push({
            data: {
                id: n.id,
                label: n.name,
                type: n.type,
                ip: n.ip,
                ip_private: n.ip_private,
                ip_floating: n.ip_floating,
                status: n.status,
                tools: n.tools || {},
                // Flags para los selectores de estilo de Cytoscape
                has_installed: isInstalled,
                has_pending: isPending && !isInstalled,
                has_error: hasError
            },
            position: n.position || { x: 100, y: 100 }
        });
    });

    // 3. Procesar Aristas (si existen)
    if (scenario.edges) {
        scenario.edges.forEach(e => {
            elements.push({
                data: { id: e.id, source: e.source, target: e.target }
            });
        });
    }

    // 4. Limpiar y refrescar el visor
    cy.elements().remove();
    cy.add(elements);

    // 5. Layout y ajuste
    cy.layout({ name: 'preset' }).run();
    cy.fit();

    // 6. Listener de selección (Tap)
    cy.off("tap", "node"); // Evitar duplicar eventos
    cy.on("tap", "node", evt => {
        const nodeData = evt.target.data();
        selectInstanceFromScenario(nodeData);
    });
}
/* ============================================================
   4. Panel izquierdo
   ============================================================ */
function loadScenarioTools(scenario) {
    const list = document.getElementById("instance-list");
    list.innerHTML = "";

    scenario.nodes.forEach(node => {
        const card = document.createElement("div");
        card.className = "p-3 bg-gray-700 hover:bg-gray-600 rounded-lg cursor-pointer";
        card.innerHTML = `
            <p class="font-bold">${node.name}</p>
            <p class="text-xs text-gray-300">${node.ip}</p>
        `;

        card.onclick = () => selectInstanceFromScenario(node);

        list.appendChild(card);
    });
}

/* ============================================================
   5. Seleccionar instancia
   ============================================================ */
async function selectInstanceFromScenario(node) {
    selectedInstance = node;
    const instanceName = node.name || node.label || node.id;

    // 1. Mostrar el panel y actualizar nombre
    document.getElementById("selected-instance-info").classList.remove("hidden");
    document.getElementById("instance-name").innerText = instanceName;

    // 2. RECUPERADO: Mostrar las IPs en el panel derecho
    document.getElementById("instance-ip").innerText = 
        `Privada: ${node.ip_private || "N/A"} | Flotante: ${node.ip_floating || "N/A"}`;

    // 3. Cargar herramientas desde el backend usando el nombre con espacios
    try {
        // Usamos encodeURIComponent para que "attack 2" viaje bien en la URL
        const res = await fetch(`/api/get_tools_for_instance?instance=${encodeURIComponent(instanceName)}`);
        const data = await res.json();
        
        // Guardar las tools en el nodo (ahora es un objeto) y dibujar
        selectedInstance.tools = data.tools || {};
        renderToolsList(selectedInstance.tools);
        
    } catch (err) {
        console.error("Error obteniendo tools:", err);
        renderToolsList({}); // Limpiar lista si hay error
    }
}

/* ============================================================
   6. Render Tools con botones JSON / UNINSTALL
   ============================================================ */
function renderToolsList(tools) {
    const toolsBox = document.getElementById("installed-tools");
    toolsBox.innerHTML = ""; 

    if (!tools || Object.keys(tools).length === 0) {
        toolsBox.innerHTML = `<p class="text-gray-400 text-sm italic">No hay herramientas configuradas.</p>`;
        return;
    }

    Object.entries(tools).forEach(([toolName, status]) => {
        // Si el status no es 'pending' ni 'error', asumimos que es la fecha de instalación
        const isInstalled = status !== 'pending' && status !== 'error';
        
        const row = document.createElement("div");
        row.className = `flex justify-between p-2 rounded-lg items-center mb-1 border-l-4 transition-all ${
            isInstalled ? 'bg-gray-900 border-green-500' : 'bg-gray-800 border-yellow-500'
        }`;

        row.innerHTML = `
            <div class="flex items-center space-x-3">
                <i class="fas ${isInstalled ? 'fa-check-circle text-green-500' : 'fa-hourglass-half text-yellow-500'}"></i>
                <div class="flex flex-col">
                    <span class="font-bold text-white text-sm">${toolName.toUpperCase()}</span>
                    <span class="text-[9px] uppercase font-bold ${isInstalled ? 'text-green-400' : 'text-yellow-500'}">
                        ${isInstalled ? `INSTALADO (${status})` : status}
                    </span>
                </div>
            </div>
            <div class="flex space-x-2">
                ${isInstalled ? `
                    <button onclick="uninstallTool('${toolName}')" 
                            class="text-orange-500 hover:bg-orange-500/10 p-1 text-[10px] font-bold border border-orange-500/30 rounded px-2">
                        UNINSTALL
                    </button>
                ` : `
                    <button onclick="removeToolFromScenario('${toolName}')" class="text-red-500 hover:text-red-400 p-1">
                        <i class="fas fa-trash-alt"></i>
                    </button>
                `}
            </div>
        `;
        toolsBox.appendChild(row);
    });
}

/* ============================================================
    FUNCIONES DE APOYO
   ============================================================ */
async function refreshSelectedInstance() {
    // Esta función vuelve a pedir las instancias para actualizar los estados de las tools
    try {
        const res = await fetch("/api/openstack/instances");
        const data = await res.json();
        const updated = data.instances.find(i => i.id === selectedInstance.id);
        if (updated) {
            selectedInstance.tools = updated.installed_tools || {};
            renderToolsList(selectedInstance.tools);
        }
    } catch (e) {
        console.error("Error al refrescar instancia:", e);
    }
}
/* ============================================================
   7. Añadir herramienta + enviar JSON al backend
   ============================================================ */
async function addTool() {
    const select = document.getElementById("available-tools");
    const tool = select.value;
    
    if (!selectedInstance || !tool) {
        alert("Selecciona una instancia y una herramienta primero");
        return;
    }

    // Asegurar que tools sea un objeto
    if (!selectedInstance.tools || Array.isArray(selectedInstance.tools)) {
        selectedInstance.tools = {};
    }

    // 1. VALIDACIÓN: Bloquear duplicados
    if (selectedInstance.tools.hasOwnProperty(tool)) {
        alert(`La herramienta ${tool.toUpperCase()} ya está en la lista de esta instancia.`);
        return;
    }

    // 2. Añadir localmente con estado inicial
    selectedInstance.tools[tool] = "pending";

    // 3. PAYLOAD: Respetando estrictamente tu formato JSON original
    const payload = {
        id: selectedInstance.id,
        name: selectedInstance.name,
        type: selectedInstance.type,
        ip: selectedInstance.ip,
        ip_private: selectedInstance.ip_private,
        ip_floating: selectedInstance.ip_floating,
        status: selectedInstance.status,
        tools: selectedInstance.tools,
        position: selectedInstance.position // Mantenemos la posición original
    };

    try {
        const res = await fetch("/api/add_tool_to_instance", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            console.log(`Herramienta ${tool} registrada exitosamente.`);
            // Actualizar solo la lista visual
            renderToolsList(selectedInstance.tools);
        } else {
            console.error("Error en el servidor al añadir la herramienta.");
        }
    } catch (err) {
        console.error("Error de red al añadir herramienta:", err);
    }
}
/* ============================================================
   8. Leer archivos JSON con configuraciones de tools
   ============================================================ */
async function loadToolsConfig() {
    const terminal = document.getElementById("tools-terminal");
    terminal.innerHTML += " Leyendo archivos de configuración...\n";

    try {
        const res = await fetch("/api/read_tools_configs");
        const data = await res.json();

        terminal.innerHTML += " Archivos detectados:\n";

        data.files.forEach(file => {
            terminal.innerHTML += ` ${file.instance}: ${JSON.stringify(file.tools)}\n`;
        });

        terminal.innerHTML += " Lectura completada.\n";

    } catch (err) {
        terminal.innerHTML += ` Error leyendo archivos: ${err}\n`;
    }
}

/* ============================================================
    Ejecutar instalación de tools
   ============================================================ */
async function installTools() {
    if (!selectedInstance) {
        alert("Selecciona una instancia primero");
        return;
    }

    const terminal = document.getElementById("tools-terminal");
    terminal.innerHTML += "\n Iniciando instalación...\n";
    freezeUI();

    try {
        // Enviamos el ID y la lista de herramientas que están en 'pending'
        const payload = {
            instance: selectedInstance.name,
            instance_id: selectedInstance.id,
            tools: Object.keys(selectedInstance.tools)
        };

        const res = await fetch("/api/install_tools", { 
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error(`Error HTTP: ${res.status}`);

        const reader = res.body.getReader();
        const decoder = new TextDecoder("utf-8");

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            const text = decoder.decode(value, { stream: true });
            text.split("\n").forEach(line => {
                if (line.startsWith("data:")) {
                    const msg = line.replace("data: ", "");
                    terminal.innerHTML += msg + "\n";
                    terminal.scrollTop = terminal.scrollHeight;
                }
            });
        }

        terminal.innerHTML += " Finalizado correctamente.\n";

        // IMPORTANTE: Refrescar la instancia para obtener las nuevas fechas de instalación
        await refreshSelectedInstance();

    } catch (err) {
        terminal.innerHTML += ` Error: ${err.message}\n`;
    } finally {
        unfreezeUI();
    }
}
/* ============================================================
    Eliminar tool SOLO de JSON
   ============================================================ */
async function removeToolFromScenario(tool) {
    if (!selectedInstance || !selectedInstance.tools) return;

    // ELIMINACIÓN PARA OBJETO
    if (selectedInstance.tools[tool]) {
        delete selectedInstance.tools[tool];
    }

    // Actualizamos la UI localmente
    renderToolsList(selectedInstance.tools);

    // Payload actualizado con el objeto
    const payload = {
        instance: selectedInstance.name || selectedInstance.label,
        tools: selectedInstance.tools
    };

    await fetch("/api/add_tool_to_instance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    // Recargamos para asegurar sincronía
    await selectInstanceFromScenario(selectedInstance);
}

/* ============================================================
    Desinstalación REAL via Backend (MEJORADA)
   ============================================================ */
async function uninstallTool(tool) {
    if (!selectedInstance) return;

    if (!confirm(`¿Estás seguro de desinstalar completamente ${tool.toUpperCase()}? Esta acción purgará los datos en el servidor.`)) {
        return;
    }

    const terminal = document.getElementById("tools-terminal");
    terminal.innerHTML += `\n[${new Date().toLocaleTimeString()}] Iniciando purga forense de ${tool}...\n`;
    terminal.scrollTop = terminal.scrollHeight; // Auto-scroll
    
    freezeUI_uninstall(`Desinstalando ${tool.toUpperCase()}...`);

    try {
        const payload = {
            instance: selectedInstance.name,
            instance_id: selectedInstance.id,
            ip_private: selectedInstance.ip_private,
            ip_floating: selectedInstance.ip_floating,
            tool: tool
        };

        const res = await fetch("/api/uninstall_tool_from_instance", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (data.status === "success") {
            terminal.innerHTML += ` SUCCESS: ${data.msg}\n`;
            
            // 1. Sincronizar objeto local
            selectedInstance.tools = data.tools || {}; 
            
            // 2. Actualizar el DATA del nodo en Cytoscape directamente
            // Esto asegura que el estilo (borde verde/rojo) cambie inmediatamente
            const node = cy.getElementById(selectedInstance.id);
            if (node) {
                const toolStatuses = Object.values(data.tools);
                const isInstalled = toolStatuses.some(s => s !== 'pending' && s !== 'error');
                
                node.data('tools', data.tools);
                node.data('has_installed', isInstalled);
            }

            // 3. Refrescar lista de UI y el Grafo completo
            renderToolsList(selectedInstance.tools);
            loadScenarioGraph({ nodes: cy.nodes().map(n => n.data()), edges: [] }); 

        } else {
            terminal.innerHTML += ` ERROR: ${data.msg}\n`;
            if(data.log_file) terminal.innerHTML += ` Ver detalles en: ${data.log_file}\n`;
        }

    } catch (err) {
        terminal.innerHTML += ` FATAL ERROR: ${err}\n`;
    } finally {
        terminal.scrollTop = terminal.scrollHeight; // Auto-scroll al finalizar
        unfreezeUI(); 
    }
}


function freezeUI_uninstall(mensaje) {
    const overlay = document.createElement("div");
    overlay.id = "ui-freeze";
    overlay.className = "fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50";
    overlay.innerHTML = `
        <div class="text-center">
            <div class="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-orange-400 mx-auto"></div>
            <p class="mt-4 text-lg font-bold text-white">${mensaje}</p>
        </div>
    `;
    document.body.appendChild(overlay);
}
/* ============================================================
    BLOQUEAR / DESBLOQUEAR FRONTEND
   ============================================================ */
function freezeUI() {
    const overlay = document.createElement("div");
    overlay.id = "ui-freeze";
    overlay.className = `
        fixed inset-0 bg-black bg-opacity-60
        flex items-center justify-center
        z-50
    `;
    overlay.innerHTML = `
        <div class="text-center">
            <div class="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-blue-400 mx-auto"></div>
            <p class="mt-4 text-lg font-bold text-white">Instalando herramientas...</p>
        </div>
    `;
    document.body.appendChild(overlay);
}

function unfreezeUI() {
    const overlay = document.getElementById("ui-freeze");
    if (overlay) overlay.remove();
}

/* ============================================================
   Sincronizar backend
   ============================================================ */
async function updateToolsBackend(instance) {
    const payload = {
        instance: instance.name || instance.label || instance.id,
        tools: instance.tools
    };

    await fetch("/api/add_tool_to_instance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
}




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