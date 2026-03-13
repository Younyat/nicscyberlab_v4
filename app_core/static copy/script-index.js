let cy;
let nodeCounter = 0;
let currentMode = 'select';
let selectedNodes = [];
let connectionMode = false;

// Inicializar Cytoscape
function initCytoscape() {
    const cyContainer = document.getElementById('cy');

    // Comprueba si el contenedor existe antes de inicializar Cytoscape
    if (!cyContainer || typeof cytoscape === 'undefined') {
        // Esto evita errores si este JS se ejecuta en una página que no tiene el lienzo #cy
        console.warn("Contenedor '#cy' no encontrado o librería Cytoscape no cargada. Omitiendo inicialización del gráfico.");
        return;
    }

    cy = cytoscape({
        container: cyContainer,
        elements: [],
        style: [
            // Estilos generales para nodos
            {
                selector: 'node',
                style: {
                    'width': 60,
                    'height': 60,
                    'label': 'data(name)',
                    'text-valign': 'bottom',
                    'text-margin-y': 5,
                    'color': '#f0f0f0',
                    'text-outline-width': 2,
                    'text-outline-color': 'var(--bg-dark)',
                    'border-width': 4,
                    'border-opacity': 0.8,
                    'cursor': 'grab',
                    'font-size': '12px',
                    'font-weight': 'bold',
                    'font-family': 'var(--font-mono)'
                }
            },
            // Estilos específicos por tipo de nodo
            { selector: 'node[type="monitor"]', style: { 'background-color': '#388e3c', 'border-color': '#66bb6a', 'shape': 'round-rectangle' } },
            { selector: 'node[type="attack"]', style: { 'background-color': '#e53935', 'border-color': '#ef9a9a', 'shape': 'triangle' } },
            { selector: 'node[type="victim"]', style: { 'background-color': '#1976d2', 'border-color': '#64b5f6', 'shape': 'ellipse' } },
            // Selección
            { selector: 'node:selected', style: { 'border-width': 5, 'border-color': 'var(--primary-color)', 'overlay-color': 'rgba(0, 230, 118, 0.15)', 'overlay-padding': 8, 'overlay-opacity': 0.8 } },
            // Estilos de aristas
            { selector: 'edge', style: { 'width': 2, 'line-color': 'var(--border-color-light)', 'target-arrow-color': 'var(--border-color-light)', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'arrow-scale': 1.2 } },
            // Estilo de arista seleccionada
            { selector: 'edge:selected', style: { 'line-color': 'var(--secondary-color)', 'target-arrow-color': 'var(--secondary-color)', 'width': 3 } },
            // Estilo de arista en modo conexión
            { selector: 'edge.connecting', style: { 'line-color': 'var(--accent-warning)', 'target-arrow-color': 'var(--accent-warning)', 'line-style': 'dashed', 'width': 3 } }
        ],
        layout: { name: 'preset' },
        wheelSensitivity: 0.2,
        minZoom: 0.5,
        maxZoom: 3
    });

    // Añadir event listeners solo si Cytoscape se inicializó correctamente
    cy.on('tap', function(evt) {
        if (evt.target === cy && currentMode !== 'select') {
            addNode(evt.position.x, evt.position.y);
        }
    });

    cy.on('select', 'node', function(evt) {
        const node = evt.target;
        // Solo llamar a loadNodeProperties si los elementos existen en el DOM
        if (document.getElementById('nodeName')) {
            loadNodeProperties(node);
        }

        if (connectionMode) {
            selectedNodes.push(node);
            if (selectedNodes.length === 2) {
                connectNodes(selectedNodes[0], selectedNodes[1]);
                selectedNodes = [];
                toggleConnectionMode(); 
            }
        }
    });

    cy.on('unselect', 'node', function() {
        if (cy.$('node:selected').length === 0 && document.getElementById('nodeName')) { 
              clearNodeProperties();
        }
    });

    // Solo actualizar las estadísticas si existen los elementos
    if (document.getElementById('nodeCount')) {
        updateStats();
    }
}

// ... (TODAS LAS DEMÁS FUNCIONES DE CYTOSCAPE - SIN CAMBIOS) ...
function getScenarioData() {
    const nodes = cy.nodes().map(node => ({
        id: node.data('id'),
        name: node.data('name'),
        type: node.data('type'),
        position: node.position(),
        properties: {
            os: node.data('os'),
            ip: node.data('ip'),
            mitre: node.data('mitre'),
            snort: node.data('snort'),
            snortMode: node.data('snortMode'),
            suricata: node.data('suricata'),
            suricataMode: node.data('suricataMode')
        }
    }));
    const edges = cy.edges().map(edge => ({
        id: edge.data('id'),
        source: edge.data('source'),
        target: edge.data('target')
    }));
    return {
        scenario_name: "file",
        nodes: nodes,
        edges: edges
    };
}

async function createScenario() {
    updateNodeProperties(false);
    const scenarioData = getScenarioData();
    const endpoint = 'http://127.0.0.1:5000/api/create_scenario';

    showToast('Enviando escenario al servidor Python...');

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scenarioData)
        });

        if (response.ok) {
            const result = await response.json();
            showToast(` Escenario creado: ${result.message}`);
            console.log("Respuesta del Back-end:", result);
        } else {
            const errorText = await response.text();
            showToast(` Error al crear escenario: ${response.status} - ${errorText.substring(0, 50)}...`);
        }
    } catch (error) {
        console.error('Error de red o CORS:', error);
        showToast(' Error de conexión con el back-end. ¿Está ejecutándose el servidor Python?');
    }
}

function addNodeMode(type) {
    currentMode = type;
    showToast(`Modo activo: Añadir nodo ${type}. Haz clic en el lienzo para añadir.`);
}

function addNode(x, y) {
    nodeCounter++;
    const nodeId = `node${nodeCounter}`;
    const nodeType = currentMode;
    const icons = { monitor: '', attack: '', victim: '' };
    const nodeData = {
        id: nodeId,
        name: `${icons[nodeType]} ${nodeType.charAt(0).toUpperCase() + nodeType.slice(1)} ${nodeCounter}`,
        type: nodeType,
        os: 'windows',
        ip: `192.168.1.${100 + nodeCounter}`,
        mitre: nodeType === 'attack' ? 'T1078' : null,
        snort: false, snortMode: 'ids',
        suricata: false, suricataMode: 'ids'
    };
    cy.add({ group: 'nodes', data: nodeData, position: { x: x, y: y } });
    currentMode = 'select'; 
    updateStats();
    showToast(`Nodo ${nodeType} añadido correctamente`);
}

function toggleConnectionMode() {
    connectionMode = !connectionMode;
    selectedNodes = [];
    const btn = document.querySelector('.btn-connect');
    if (btn) {
        if (connectionMode) {
            btn.textContent = 'Cancelar';
            btn.style.background = 'linear-gradient(135deg, #c62828 0%, #e53935 100%)';
            showToast('Modo conexión activo. Selecciona dos nodos para conectar.');
        } else {
            btn.textContent = 'Conectar';
            btn.style.background = 'linear-gradient(135deg, #d84315 0%, #ff5722 100%)';
            showToast('Modo conexión desactivado');
        }
    }
}

function connectNodes(node1, node2) {
    const edgeId = `edge_${node1.id()}_${node2.id()}`;
    if (cy.getElementById(edgeId).length > 0) {
        showToast('Los nodos ya están conectados');
        return;
    }
    cy.add({ group: 'edges', data: { id: edgeId, source: node1.id(), target: node2.id() } });
    updateStats();
    showToast('Nodos conectados correctamente');
}

function deleteSelected() {
    const selected = cy.$(':selected');
    if (selected.length === 0) {
        showToast('Selecciona un elemento para eliminar');
        return;
    }
    selected.remove();
    updateStats();
    clearNodeProperties();
    showToast('Elementos eliminados correctamente');
}

function clearAll() {
    if (confirm('¿Estás seguro de que quieres eliminar todos los elementos?')) {
        cy.elements().remove();
        nodeCounter = 0;
        updateStats();
        clearNodeProperties();
        showToast('Escenario limpiado correctamente');
    }
}

function loadNodeProperties(node) {
    const nodeType = node.data('type');
    document.getElementById('nodeName').value = node.data('name') || '';
    document.getElementById('nodeOS').value = node.data('os') || 'windows';
    document.getElementById('nodeIP').value = node.data('ip') || '';
    
    const mitreGroup = document.getElementById('mitreGroup');
    const securityGroup = document.getElementById('securityGroup'); 

    mitreGroup.style.display = 'none';
    securityGroup.style.display = 'none';

    if (nodeType === 'attack') {
        mitreGroup.style.display = 'block';
        document.getElementById('mitreTechnique').value = node.data('mitre') || 'T1078';
    } else if (nodeType === 'victim') { 
        securityGroup.style.display = 'block';
        document.getElementById('snortCheckbox').checked = node.data('snort') || false;
        document.getElementById('snortMode').value = node.data('snortMode') || 'ids';
        document.getElementById('suricataCheckbox').checked = node.data('suricata') || false;
        document.getElementById('suricataMode').value = node.data('suricataMode') || 'ids';
    }
}

function clearNodeProperties() {
    document.getElementById('nodeName').value = '';
    document.getElementById('nodeOS').value = 'windows';
    document.getElementById('nodeIP').value = '';
    
    const mitreGroup = document.getElementById('mitreGroup');
    const securityGroup = document.getElementById('securityGroup'); 

    if (mitreGroup) mitreGroup.style.display = 'none';
    if (securityGroup) securityGroup.style.display = 'none';

    const snortCheckbox = document.getElementById('snortCheckbox');
    if (snortCheckbox) snortCheckbox.checked = false;
    const snortMode = document.getElementById('snortMode');
    if (snortMode) snortMode.value = 'ids';
    const suricataCheckbox = document.getElementById('suricataCheckbox');
    if (suricataCheckbox) suricataCheckbox.checked = false;
    const suricataMode = document.getElementById('suricataMode');
    if (suricataMode) suricataMode.value = 'ids';
}

function updateNodeProperties(showSuccessToast = true) {
    const selected = cy.$('node:selected');
    if (selected.length === 0) {
        if (showSuccessToast) showToast('Selecciona un nodo para actualizar sus propiedades');
        return;
    }

    const node = selected[0];
    const newName = document.getElementById('nodeName').value;
    const newOS = document.getElementById('nodeOS').value;
    const newIP = document.getElementById('nodeIP').value;
    
    if (newName) node.data('name', newName);
    node.data('os', newOS);
    node.data('ip', newIP);
    
    if (node.data('type') === 'attack') {
        const newMitre = document.getElementById('mitreTechnique').value;
        node.data('mitre', newMitre);
    } else if (node.data('type') === 'victim') { 
        node.data('snort', document.getElementById('snortCheckbox').checked);
        node.data('snortMode', document.getElementById('snortMode').value);
        node.data('suricata', document.getElementById('suricataCheckbox').checked);
        node.data('suricataMode', document.getElementById('suricataMode').value);
    }
    
    if (showSuccessToast) showToast('Propiedades actualizadas correctamente');
}

function updateStats() {
    const nodeCount = document.getElementById('nodeCount');
    const edgeCount = document.getElementById('edgeCount');
    if (nodeCount) nodeCount.textContent = cy.nodes().length;
    if (edgeCount) edgeCount.textContent = cy.edges().length;
}

function showToast(message) {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    } else {
        console.log("TOAST:", message); // Mensaje de fallback si no hay toast
    }
}


// ====================================================================
// BLOQUE PRINCIPAL DE INICIALIZACIÓN (MENÚ Y CYTOSCAPE CONDICIONAL)
// ====================================================================

document.addEventListener('DOMContentLoaded', function() {
    
    // Inicializa Cytoscape si los elementos necesarios están en el DOM actual
    initCytoscape(); 

    // --- Lógica del Menú Lateral y Iframe ---
    
    const mainIframe = document.getElementById('mainIframe');
    const sidebarLinks = document.querySelectorAll('.sidebar-link');

    if (mainIframe && sidebarLinks.length > 0) {
        
        sidebarLinks.forEach(link => {
            link.addEventListener('click', function(event) {
                event.preventDefault(); 
                
                const newUrl = this.getAttribute('data-url');
                
                if (newUrl) {
                    mainIframe.src = newUrl;
                    
                    // Gestionar las clases 'activo'
                    sidebarLinks.forEach(l => {
                        l.classList.remove('bg-indigo-600');
                        l.classList.add('hover:bg-indigo-700'); 
                    });
                    
                    this.classList.add('bg-indigo-600');
                    this.classList.remove('hover:bg-indigo-700');
                }
            });
        });
        
        // Configuración inicial del enlace activo al cargar la página
        const initialSrc = mainIframe.src;
        sidebarLinks.forEach(link => {
            // Usa .includes() para manejar posibles barras ('/') o parámetros en la URL
            if (initialSrc.includes(link.getAttribute('data-url'))) { 
                link.classList.add('bg-indigo-600');
                link.classList.remove('hover:bg-indigo-700');
            } else {
                link.classList.remove('bg-indigo-600');
            }
        });
    }
});

// ... (después de tu función createScenario)

async function loadScenario() {
    // Endpoint de ejemplo en tu back-end para obtener un escenario por su nombre/ID
    const scenarioName = "file"; // Puedes hacerlo dinámico si quieres
    const endpoint = `http://127.0.0.1:5000/api/get_scenario/${scenarioName}`;

    showToast('Cargando escenario desde el servidor...');

    try {
        const response = await fetch(endpoint, { method: 'GET' });

        if (!response.ok) {
            const errorText = await response.text();
            showToast(` Error al cargar: ${response.status} - ${errorText}`);
            return;
        }

        const scenarioData = await response.json();

        // 1. Limpiar completamente el lienzo antes de cargar
        cy.elements().remove();
        nodeCounter = 0; // Opcional: resetear contador si es necesario

        // 2. Preparar los elementos (nodos y aristas) para añadirlos
        // Se asume que el JSON del backend tiene la misma estructura que el que se envía
        const elementsToAdd = [];
        
        scenarioData.nodes.forEach(node => {
            elementsToAdd.push({
                group: 'nodes',
                data: {
                    id: node.id,
                    name: node.name,
                    type: node.type,
                    // Aseguramos que las propiedades existan
                    os: node.properties?.os,
                    ip: node.properties?.ip,
                    mitre: node.properties?.mitre,
                    snort: node.properties?.snort,
                    snortMode: node.properties?.snortMode,
                    suricata: node.properties?.suricata,
                    suricataMode: node.properties?.suricataMode
                },
                position: node.position
            });
            // Actualizamos el contador para que los nuevos nodos no se solapen
            const numericId = parseInt(node.id.replace('node', ''));
            if (numericId > nodeCounter) {
                nodeCounter = numericId;
            }
        });

        scenarioData.edges.forEach(edge => {
            elementsToAdd.push({
                group: 'edges',
                data: {
                    id: edge.id,
                    source: edge.source,
                    target: edge.target
                }
            });
        });

        // 3. Añadir todos los elementos al lienzo de una sola vez
        cy.add(elementsToAdd);

        // 4. Actualizar las estadísticas y notificar al usuario
        updateStats();
        showToast(' Escenario cargado correctamente.');

    } catch (error) {
        console.error('Error de red o CORS al cargar escenario:', error);
        showToast(' Error de conexión. No se pudo cargar el escenario.');
    }
}

