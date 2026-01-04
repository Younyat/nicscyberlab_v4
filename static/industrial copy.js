let cy;
let nodeCounter = 0;
let connectionMode = false;
let selectedNodes = [];
let industrialMode = null;
const INDUSTRIAL_TOOLS = {
    industrial_plc: [
        {
            id: "openplc",
            name: "OpenPLC",
            description: "PLC runtime IEC 61131-3",
            icon: "fa-microchip"
        }
    ],
    industrial_scada: [
        {
            id: "fuxa",
            name: "FUXA",
            description: "SCADA / HMI web-based",
            icon: "fa-desktop"
        }
    ]
};


/* =========================
   INIT CYTOSCAPE
========================= */
document.addEventListener("DOMContentLoaded", () => {
    cy = cytoscape({
        container: document.getElementById("cy"),
        elements: [],
        style: [
            {
                selector: "node",
                style: {
                    label: "data(name)",
                    color: "#ffffff",
                    "background-color": "#374151",
                    "border-width": 3,
                    "border-color": "#9ca3af",
                    "font-size": "12px"
                }
            },
            { selector: 'node[type="monitor"]', style: { "background-color": "#16a34a" } },
            { selector: 'node[type="victim"]',  style: { "background-color": "#2563eb" } },
            { selector: 'node[type="attack"]',  style: { "background-color": "#dc2626" } },

            { selector: 'node[type^="industrial_"]', style: {
                shape: "round-rectangle",
                "background-color": "#9333ea",
                "border-color": "#c084fc"
            }},

            {
                selector: "edge",
                style: {
                    width: 2,
                    "line-color": "#9ca3af",
                    "target-arrow-shape": "triangle",
                    "target-arrow-color": "#9ca3af",
                    "curve-style": "bezier"
                }
            }
        ],
        layout: { name: "preset" }
    });

   cy.on("select", "node", evt => {

    const node = evt.target;

    /* === MODO INDUSTRIAL (CREAR COMPONENTE) === */
    if (industrialMode) {
        addIndustrialComponent(industrialMode);
        industrialMode = null;
        cy.$(":selected").unselect();
        return;
    }

    /* === PANEL INDUSTRIAL (PLC / SCADA) === */
    if (node.data("industrial")) {
        renderIndustrialPanel(node);
        return;
    }

    /* === MODO CONEXIÓN === */
    if (!connectionMode) return;

    selectedNodes.push(node);
    if (selectedNodes.length === 2) {
        connectNodes(selectedNodes[0], selectedNodes[1]);
        selectedNodes = [];
        connectionMode = false;
        toast("Modo conexión desactivado");
    }
});


    updateStats();
});



function renderIndustrialPanel(node) {
    const panel = document.getElementById("industrial-panel");
    const type = node.data("type");

    /* ============================
       PLC → OpenPLC
    ============================ */
    if (type === "industrial_plc") {
        panel.innerHTML = `
            <h2 class="text-lg font-bold text-gray-200 mb-4 text-center">
                PLC – Configuración
            </h2>

            <div class="bg-gray-800 p-4 rounded-lg flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <i class="fas fa-microchip text-orange-400 text-xl"></i>
                    <div>
                        <p class="text-white font-semibold">OpenPLC</p>
                        <p class="text-xs text-gray-400">
                            Runtime PLC IEC 61131-3
                        </p>
                    </div>
                </div>

                <button
                    onclick="deployIndustrial('plc')"
                    class="px-4 py-2 bg-green-700 hover:bg-green-600 rounded text-white font-bold">
                    Instalar
                </button>
            </div>
        `;
        return;
    }

    /* ============================
       SCADA → FUXA
    ============================ */
    if (type === "industrial_scada") {
        panel.innerHTML = `
            <h2 class="text-lg font-bold text-gray-200 mb-4 text-center">
                SCADA – Configuración
            </h2>

            <div class="bg-gray-800 p-4 rounded-lg flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <i class="fas fa-desktop text-purple-400 text-xl"></i>
                    <div>
                        <p class="text-white font-semibold">FUXA</p>
                        <p class="text-xs text-gray-400">
                            SCADA / HMI Web
                        </p>
                    </div>
                </div>

                <button
                    onclick="deployIndustrial('scada')"
                    class="px-4 py-2 bg-green-700 hover:bg-green-600 rounded text-white font-bold">
                    Instalar
                </button>
            </div>
        `;
        return;
    }

    /* ============================
       DEFAULT
    ============================ */
    panel.innerHTML = `
        <p class="text-gray-400 text-center">
            Selecciona un componente industrial
        </p>
    `;
}

function freezeUI(freeze) {
    const panel = document.getElementById("controls-panel");
    panel.style.pointerEvents = freeze ? "none" : "auto";
    panel.style.opacity = freeze ? "0.4" : "1";
}

async function addIndustrialTool(nodeId, toolName) {
    const node = cy.getElementById(nodeId);

    const payload = {
        instance: node.data("name"),
        node_type: node.data("type"),
        tool: toolName
    };

    try {
        const res = await fetch(
            "http://127.0.0.1:5001/api/add_industrial_tool",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            }
        );

        if (!res.ok) throw new Error("Error backend");

        toast(`Tool ${toolName} añadida`);
        logAction(
            "ACTION",
            `Tool ${toolName} registrada para ${node.data("name")}`
        );

    } catch (err) {
        toast("Error añadiendo tool");
        logAction("ERROR", err.message);
    }
}


/* =========================
   LOAD BASE SCENARIO
========================= */
async function loadScenario() {
    try {
        const res = await fetch("http://127.0.0.1:5001/api/get_active_scenario");

        if (res.status === 404) {
            toast("No hay escenario creado todavía");
            logAction("INFO", "No existe escenario previo");
            return;
        }

        const scenario = await res.json();

        cy.elements().remove();

        const elements = [];

        scenario.nodes.forEach(n => {
            elements.push({
                group: "nodes",
                data: {
                    id: n.id,
                    name: n.name,
                    type: n.type,
                    industrial: n.industrial || false,
                    installed: n.installed ?? true,
                    installable: n.installable ?? false,
                    linked_to: n.linked_to || null
                },
                position: n.position
            });
        });

        scenario.edges.forEach(e => {
            elements.push({
                group: "edges",
                data: e
            });
        });

        cy.add(elements);
        centerScenarioLeft();
        updateStats();

        toast("Escenario cargado");
        logAction("SUCCESS", "Escenario cargado correctamente");

    } catch (err) {
        console.error(err);
        toast("Error cargando escenario");
        logAction("ERROR", "Error cargando escenario");
    }
}


function centerScenarioLeft() {
    cy.fit(cy.elements(), 50);
    cy.pan({
        x: cy.pan().x - 150,
        y: cy.pan().y
    });
}



/* =========================
   INDUSTRIAL MODE
========================= */
function setIndustrialMode(type) {
    industrialMode = type;
    toast("Modo industrial activado");
    logAction("ACTION", `Modo industrial activado: ${type}`);
}


function addIndustrialComponent(type) {

    if (isIndustrialAlreadyInstalled(type)) {
        toast("Este componente ya existe");
        logAction("WARNING", `Intento de crear componente duplicado: ${type}`);
        return;
    }

    const selected = cy.$("node:selected");
    if (selected.length !== 1) {
        toast("Selecciona un nodo base");
        logAction("WARNING", "Intento de añadir componente sin nodo base");
        return;
    }

    const base = selected[0];
    const id = `${type}_${Date.now()}`;

    cy.add([
        {
            group: "nodes",
            data: {
                id,
                name: type.toUpperCase(),
                type: `industrial_${type}`,
                industrial: true,
                installed: false,
                installable: true,
                linked_to: base.id()
            },
            position: {
                x: base.position("x") + 120,
                y: base.position("y") + 120
            }
        },
        {
            group: "edges",
            data: {
                id: `edge_${base.id()}_${id}`,
                source: base.id(),
                target: id
            }
        }
    ]);

    updateStats();
    toast("Componente industrial añadido");
    logAction(
        "ACTION",
        `Componente ${type} añadido y enlazado a ${base.data("name")}`
    );
}



async function deleteIndustrialScenario() {
    try {
        const res = await fetch("http://127.0.0.1:5001/api/get_active_scenario");
        if (!res.ok) {
            toast("No hay escenario para eliminar");
            logAction("INFO", "Intento de eliminar escenario inexistente");
            return;
        }

        const scenario = await res.json();
        const dep = scenario.deployment;

        if (
            dep?.plc_instance?.state === "created" ||
            dep?.scada_instance?.state === "created"
        ) {
            toast("No se puede eliminar: PLC o SCADA creados");
            logAction(
                "WARNING",
                "Eliminación bloqueada por estado created en PLC o SCADA"
            );
            return;
        }

        const delRes = await fetch(
            "http://127.0.0.1:5001/api/delete_industrial_scenario",
            { method: "DELETE" }
        );

        if (!delRes.ok) {
            throw new Error("Error backend eliminando escenario");
        }

        cy.elements().remove();
        updateStats();

        toast("Escenario industrial eliminado");
        logAction("ACTION", "Escenario industrial eliminado");

    } catch (err) {
        console.error(err);
        toast("Error eliminando escenario");
        logAction("ERROR", "Error eliminando escenario industrial");
    }
}

function logAction(level, message) {
    const terminal = document.getElementById("feedback-terminal");
    if (!terminal) return;

    // Crear el contenedor de la línea
    const line = document.createElement("div");
    line.className = "mb-1 flex gap-2 font-mono text-[11px]";

    // Obtener la hora actual
    const now = new Date();
    const timeStr = now.toLocaleTimeString('es-ES', { hour12: false });

    // Definir colores según el nivel (usando clases de Tailwind)
    let colorClass = "text-green-400"; // Por defecto
    if (level === "ERROR") colorClass = "text-red-500 font-bold";
    if (level === "WARNING") colorClass = "text-yellow-500";
    if (level === "SUCCESS") colorClass = "text-cyan-400 font-bold";
    if (level === "ACTION") colorClass = "text-purple-400";

    // Construir el HTML de la línea
    line.innerHTML = `
        <span class="text-gray-500">[${timeStr}]</span>
        <span class="${colorClass}">[${level}]</span>
        <span class="text-gray-200">${message}</span>
    `;

    terminal.appendChild(line);

    // Mantener el scroll siempre abajo
    terminal.scrollTop = terminal.scrollHeight;

    // Opcional: Limitar a 50 mensajes para mantener el rendimiento
    if (terminal.childNodes.length > 50) {
        terminal.removeChild(terminal.firstChild);
    }
}

function clearFeedbackTerminal() {
    const terminal = document.getElementById("feedback-terminal");
    terminal.innerHTML = "<div>[INFO] Terminal limpiado</div>";
}


function isIndustrialAlreadyInstalled(type) {
    return cy.nodes().some(n =>
        n.data("type") === `industrial_${type}`
    );
}

function markIndustrialInstalled(type) {
    cy.nodes().forEach(n => {
        if (!n.data("industrial")) {
            n.data("installed", true);
            n.data("installable", false);
        }
    });
}


/* =========================
   CONNECTION MODE
========================= */


function toggleConnectionMode() {
    connectionMode = !connectionMode;
    selectedNodes = [];
    toast(connectionMode ? "Modo conexión activo" : "Modo conexión desactivado");
    logAction(
        "ACTION",
        connectionMode ? "Modo conexión activado" : "Modo conexión desactivado"
    );
}


function connectNodes(a, b) {
    const id = `edge_${a.id()}_${b.id()}`;
    if (cy.getElementById(id).length > 0) return;

    cy.add({
        group: "edges",
        data: { id, source: a.id(), target: b.id() }
    });

    updateStats();
}

/* =========================
   DELETE / CLEAR
========================= */
function deleteSelected() {
    const selected = cy.$(":selected");

    if (selected.length === 0) {
        toast("No hay selección");
        logAction("WARNING", "Intento de eliminar sin selección");
        return;
    }

    const forbidden = selected.filter(el =>
        el.isNode() &&
        ["monitor", "victim", "attack"].includes(el.data("type"))
    );

    if (forbidden.length > 0) {
        toast("No se pueden eliminar nodos base");
        logAction("WARNING", "Intento de eliminar nodo base");
        return;
    }

    selected.remove();
    updateStats();

    toast("Elemento eliminado");
    logAction("ACTION", "Elemento eliminado del escenario");
}


function clearScenario() {
    const industrialNodes = cy.nodes('[industrial]');
    const industrialEdges = cy.edges().filter(e =>
        industrialNodes.contains(e.source()) ||
        industrialNodes.contains(e.target())
    );

    industrialEdges.remove();
    industrialNodes.remove();

    updateStats();
    toast("Componentes industriales eliminados");
    logAction("ACTION", "Todos los componentes industriales eliminados");
}

/* =========================
   SAVE INDUSTRIAL SCENARIO
========================= */
async function saveIndustrialScenario() {
    try {
        const payload = {
            scenario: {
                scenario_name: "industrial_file",
                base_scenario: "scenario/scenario_file.json",

                nodes: cy.nodes().map(n => {
                    const type = n.data("type");

                    const isIndustrial = type.startsWith("industrial_");
                    const isPLC = type === "industrial_plc";
                    const isSCADA = type === "industrial_scada";

                    return {
                        id: n.id(),
                        name: n.data("name"),
                        type: type,

                        /* ===== ESTADO INDUSTRIAL ===== */
                        industrial: isIndustrial,

                        /* 
                           Reglas:
                           - PLC / SCADA → no instalados hasta despliegue
                           - resto → ya instalados, prohibido reinstalar
                        */
                        installed: isPLC || isSCADA
                            ? (n.data("installed") ?? false)
                            : true,

                        installable: isPLC || isSCADA,

                        linked_to: n.data("linked_to") || null,

                        /* ===== POSICIÓN ===== */
                        position: n.position()
                    };
                }),

                edges: cy.edges().map(e => ({
                    id: e.id(),
                    source: e.source().id(),
                    target: e.target().id()
                })),

                /* ===== ESTADO DE DESPLIEGUE INDUSTRIAL ===== */
                deployment: {
                    plc_instance: {
                        exists: cy.nodes('[type="industrial_plc"]').length === 1,
                        name: "plc-1",
                        ip: null,
                        openplc_installed: false
                    },
                    scada_instance: {
                        exists: cy.nodes('[type="industrial_scada"]').length === 1,
                        name: "scada-1",
                        ip: null,
                        fuxa_installed: false
                    }
                }
            }
        };

        const res = await fetch(
            "http://127.0.0.1:5001/api/save_industrial_scenario",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            }
        );

        if (!res.ok) {
            throw new Error("Error guardando escenario industrial");
        }

        toast(" Escenario industrial guardado correctamente");

    } catch (err) {
        console.error(err);
        toast(" Error al guardar el escenario industrial");
    }
}

function freezeUI_install(mensaje) {
    const overlay = document.createElement("div");
    overlay.id = "ui-freeze";

    overlay.className = `
        fixed inset-0 bg-black bg-opacity-60
        flex items-center justify-center
        z-50
    `;

    overlay.innerHTML = `
        <div class="text-center">
            <div class="animate-spin rounded-full h-16 w-16
                        border-t-4 border-b-4 border-green-400 mx-auto">
            </div>
            <p class="mt-4 text-lg font-bold text-white">
                ${mensaje}
            </p>
            <p class="mt-2 text-sm text-gray-300">
                No cierres ni recargues la página
            </p>
        </div>
    `;

    document.body.appendChild(overlay);
}


function unfreezeUI_install() {
    const overlay = document.getElementById("ui-freeze");
    if (overlay) overlay.remove();
}

async function deployIndustrial(component) {

    const label = component === "plc"
        ? "Instalando PLC (OpenPLC)..."
        : "Instalando SCADA (FUXA)...";

    freezeUI_install(label);

    logAction("ACTION", `Iniciando instalación ${component.toUpperCase()}`);

    try {
        const res = await fetch(
            "http://127.0.0.1:5001/api/industrial/deploy",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ component })
            }
        );

        if (!res.ok) {
            const err = await res.text();
            throw new Error(err);
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            const text = decoder.decode(value);
            text.split("\n").forEach(line => {
                if (line.trim() !== "") {
                    logAction("INFO", line);
                }
            });
        }

        logAction("SUCCESS", "Instalación finalizada");

    } catch (err) {
        logAction("ERROR", err.message);
    } finally {
        unfreezeUI_install();
    }
}





/* =========================
   UI HELPERS
========================= */
function updateStats() {
    document.getElementById("nodeCount").textContent = cy.nodes().length;
    document.getElementById("edgeCount").textContent = cy.edges().length;
}

function toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 3000);
}



