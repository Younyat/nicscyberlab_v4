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
    3. PINTAR GRAFO (Respetando tu formato JSON original)
   ============================================================ */
function loadScenarioGraph(scenario) {
    console.log(" Renderizando grafo con formato original...");

    if (!ensureCy()) return;

    // 1. Configurar estilos para que el borde indique el estado
    cy.style()
        .selector('node[?has_installed]')
        .style({
            'border-width': 4,
            'border-color': '#10B981', // Verde: "installed"
            'border-opacity': 1
        })
        .selector('node[?has_pending]')
        .style({
            'border-width': 4,
            'border-color': '#F59E0B', // Naranja: "pending"
            'border-style': 'dashed'
        })
        .update();

    let elements = [];

    // 2. Procesar Nodos según tu esquema: { id, name, tools: { tool: status } }
    scenario.nodes.forEach(n => {
        const toolValues = Object.values(n.tools || {});
        
        // Verificamos estados dentro del objeto tools
        const isInstalled = toolValues.includes("installed");
        const isPending = toolValues.includes("pending");

        elements.push({
            data: {
                id: n.id,           // Tu "id" original
                label: n.name,      // Tu "name" original
                type: n.type,
                ip: n.ip,
                ip_private: n.ip_private,
                ip_floating: n.ip_floating,
                status: n.status,
                tools: n.tools || {}, // El objeto { "caldera": "installed" }
                // Marcadores para el estilo visual
                has_installed: isInstalled,
                has_pending: isPending && !isInstalled
            },
            position: n.position || { x: 100, y: 100 }
        });
    });

    // 3. Procesar Aristas
    if (scenario.edges) {
        scenario.edges.forEach(e => {
            elements.push({
                data: { id: e.id, source: e.source, target: e.target }
            });
        });
    }

    // 4. Actualizar Cy
    cy.elements().remove();
    cy.add(elements);

    // 5. Ajustar vista
    cy.layout({ name: 'preset' }).run();
    cy.fit();

    // 6. Evento de click
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
    Desinstalación REAL via Backend
   ============================================================ */
async function uninstallTool(tool) {
    if (!selectedInstance) return;

    const terminal = document.getElementById("tools-terminal");
    terminal.innerHTML += `\n Desinstalando ${tool} en ${selectedInstance.name}...\n`;

    try {
        const payload = {
            instance: selectedInstance.name,
            instance_id: selectedInstance.id, // Enviamos el UUID
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
            terminal.innerHTML += ` OK: ${tool} desinstalado.\n`;
            // Quitamos la tool localmente y refrescamos
            delete selectedInstance.tools[tool];
            renderToolsList(selectedInstance.tools);
        } else {
            terminal.innerHTML += ` Error: ${data.msg || 'No se pudo desinstalar'}\n`;
        }

    } catch (err) {
        terminal.innerHTML += ` Error en petición: ${err}\n`;
    }
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
