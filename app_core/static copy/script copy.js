// =======================
// VARIABLES GLOBALES
// =======================
let cy;
let nodeCounter = 0;
let currentMode = 'select';
let selectedNodes = [];
let connectionMode = false;

// =======================
// MODAL DE CONFIRMACIÓN
// =======================
function showConfirmationModal(title, message, onConfirmCallback) {
  const modal = document.getElementById('customModal');
  const modalTitle = document.getElementById('modalTitle');
  const modalMessage = document.getElementById('modalMessage');

  if (!modal) {
    console.error('Modal no encontrado');
    if (onConfirmCallback) onConfirmCallback();
    return;
  }

  modalTitle.textContent = title;
  modalMessage.textContent = message;
  modal.classList.remove('hidden');

  const closeModal = () => {
    modal.classList.add('hidden');
    newModalConfirm.removeEventListener('click', handleConfirm);
    newModalCancel.removeEventListener('click', handleCancel);
  };

  const handleConfirm = () => {
    onConfirmCallback();
    closeModal();
  };
  const handleCancel = () => closeModal();

  // limpiar listeners previos
  const modalConfirm = document.getElementById('modalConfirm');
  const modalCancel = document.getElementById('modalCancel');
  modalConfirm.replaceWith(modalConfirm.cloneNode(true));
  modalCancel.replaceWith(modalCancel.cloneNode(true));

  const newModalConfirm = document.getElementById('modalConfirm');
  const newModalCancel = document.getElementById('modalCancel');

  newModalConfirm.addEventListener('click', handleConfirm);
  newModalCancel.addEventListener('click', handleCancel);
}

function showClearConfirmation() {
  showConfirmationModal(
    'Confirmar Limpieza de Lienzo',
    '¿Estás absolutamente seguro de que quieres eliminar todos los nodos y conexiones?',
    clearAll
  );
}
function destruirScenarioConfirmation() {
  showConfirmationModal(
    '¿Destruir el escenario actual?',
    ' Esta acción eliminará todos los recursos desplegados. No podrás revertirla.',
    destruirScenario
  );
}


function newScenarioConfirmation() {
  showConfirmationModal(
    'Crear un nuevo escenario?',
    '¿Estás absolutamente seguro de que quieres crear el escenario?',
    createScenario
  );
}
// =======================
// INICIALIZAR CYTOSCAPE
// =======================
function initCytoscape() {
  const cyContainer = document.getElementById('cy');
  if (!cyContainer || typeof cytoscape === 'undefined') {
    console.warn('Cytoscape no disponible');
    return;
  }

  cy = cytoscape({
    container: cyContainer,
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          width: 60,
          height: 60,
          label: 'data(name)',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          color: '#f0f0f0',
          'text-outline-width': 2,
          'text-outline-color': 'var(--bg-dark)',
          'border-width': 4,
          'border-opacity': 0.8,
          cursor: 'grab',
          'font-size': '12px',
          'font-weight': 'bold'
        }
      },
      { selector: 'node[type="monitor"]', style: { 'background-color': '#388e3c', 'border-color': '#66bb6a', 'shape': 'round-rectangle' } },
      { selector: 'node[type="attack"]', style: { 'background-color': '#e53935', 'border-color': '#ef9a9a', 'shape': 'triangle' } },
      { selector: 'node[type="victim"]', style: { 'background-color': '#1976d2', 'border-color': '#64b5f6', 'shape': 'ellipse' } },
      { selector: 'node:selected', style: { 'border-width': 5, 'border-color': 'var(--secondary-color)' } },
      { selector: 'edge', style: { width: 2, 'line-color': '#999', 'target-arrow-color': '#999', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } },
      { selector: 'edge:selected', style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316', width: 3 } }
    ],
    layout: { name: 'preset' },
    wheelSensitivity: 0.2
  });


  cy.on('dblclick', 'node', evt => {
    const node = evt.target;
    requestConsole(node.data('name')); // nombre del nodo
  });






  cy.on('tap', evt => {
    if (evt.target === cy && currentMode !== 'select' && currentMode !== 'connect') {
      addNode(evt.position.x, evt.position.y);
    } else if (evt.target === cy && currentMode === 'select' && connectionMode) {
      toggleConnectionMode();
    }
  });

  cy.on('select', 'node', evt => {
    loadNodeProperties(evt.target);
    document.getElementById('update-node-btn').disabled = false;
    document.getElementById('update-node-btn').classList.remove('cursor-not-allowed','bg-yellow-600/50');
    document.getElementById('update-node-btn').classList.add('bg-yellow-600');
    if (connectionMode) {
      selectedNodes.push(evt.target);
      if (selectedNodes.length === 2) {
        connectNodes(selectedNodes[0], selectedNodes[1]);
        selectedNodes = [];
        toggleConnectionMode();
      }
    }
  });

  cy.on('unselect', 'node', () => {
    if (cy.$('node:selected').length === 0) {
      clearNodeProperties();
      document.getElementById('update-node-btn').disabled = true;
      document.getElementById('update-node-btn').classList.add('cursor-not-allowed','bg-yellow-600/50');
      document.getElementById('update-node-btn').classList.remove('bg-yellow-600');
    }
  });

  updateStats();


  
  
}

// =======================
// CRUD DE NODOS Y EDGES
// =======================
function addNodeMode(type) {
  currentMode = type;
  if (connectionMode) toggleConnectionMode();
  showToast(`Modo activo: añadir ${type}`);
}

function addNode(x, y) {
  nodeCounter++;
  const nodeId = `node${nodeCounter}`;
  const nodeType = currentMode;
  const nodeData = {
    id: nodeId,
    name: `${nodeType} ${nodeCounter}`,
    type: nodeType,
    os: "linux",
    ip: `192.168.1.${100 + nodeCounter}`,
     network: "net_private_01",
            subnet: "subnet_net_private_01",
    flavor: "S_2CPU_4GB",
    image: 'ubuntu-22.04',
    security_group: "sg_basic",
    keypair: "my_key",
  };
  cy.add({ group: 'nodes', data: nodeData, position: { x, y } });
  currentMode = 'select';
  updateStats();
  showToast('Nodo añadido');
}

function toggleConnectionMode() {
  connectionMode = !connectionMode;
  selectedNodes = [];
  currentMode = connectionMode ? 'connect' : 'select';
  const btn = document.querySelector('.btn-connect');
  if (btn) {
    if (connectionMode) {
      btn.innerHTML = '<i class="fas fa-times mr-1"></i> Cancelar';
      btn.style.background = '#dc2626';
      showToast('Modo conexión activo');
    } else {
      btn.innerHTML = '<i class="fas fa-link text-lg"></i> <span class="mt-1">Conectar</span>';
      btn.style.background = '#ea580c';
      showToast('Modo conexión desactivado');
    }
  }
}

function connectNodes(node1, node2) {
  const currentEdgeId = `edge_${node1.id()}_${node2.id()}`;
  if (cy.getElementById(currentEdgeId).length > 0) {
    showToast('La conexión ya existe');
    return;
  }
  cy.add({ group: 'edges', data: { id: currentEdgeId, source: node1.id(), target: node2.id() } });
  updateStats();
  showToast('Nodos conectados');
}

function deleteSelected() {
  const selected = cy.$(':selected');
  if (selected.length === 0) {
    showToast('Selecciona algo para eliminar');
    return;
  }
  selected.remove();
  updateStats();
  clearNodeProperties();
  showToast('Eliminado');
}

function clearAll() {
  cy.elements().remove();
  nodeCounter = 0;
  updateStats();
  clearNodeProperties();
  showToast('Escenario limpiado');
}

// =======================
// PROPIEDADES DE NODOS
// =======================
function loadNodeProperties(node) {
  document.getElementById('nodeNetwork').value = node.data('network') || 'net_private_01';
  document.getElementById('nodeSubNetwork').value = node.data('subnet') || 'subnet_net_private_01';
  document.getElementById('nodeFlavor').value = node.data('flavor') || 'S_2CPU_4GB';
  document.getElementById('nodeImage').value = node.data('image') || 'ubuntu-22.04';
  document.getElementById('nodeSecurityGroup').value = node.data('security_group') || 'sg_basic';
  document.getElementById('nodeSSHKey').value = node.data('keypair') || 'my_key';
}

function clearNodeProperties() {
  document.getElementById('nodeNetwork').value = 'net_private_01';
  document.getElementById('nodeSubNetwork').value = 'subnet_net_private_01';
  document.getElementById('nodeFlavor').value = 'S_2CPU_4GB';
  document.getElementById('nodeImage').value = 'ubuntu-22.04';
  document.getElementById('nodeSecurityGroup').value = 'sg_basic';
  document.getElementById('nodeSSHKey').value = 'my_key';
}

function updateNodeProperties(showToastMsg = true) {
  const selected = cy.$('node:selected');
  if (selected.length === 0) {
    if (showToastMsg) showToast('Selecciona un nodo');
    return;
  }
  const node = selected[0];
  node.data('network', document.getElementById('nodeNetwork').value);
  node.data('subnet', document.getElementById('nodeSubNetwork').value);
  node.data('flavor', document.getElementById('nodeFlavor').value);
  node.data('image', document.getElementById('nodeImage').value);
  node.data('security_group', document.getElementById('nodeSecurityGroup').value);
  node.data('keypair', document.getElementById('nodeSSHKey').value);
  if (showToastMsg) showToast('Nodo actualizado');
}

// =======================
// ESTADÍSTICAS Y TOAST
// =======================
function updateStats() {
  document.getElementById('nodeCount').textContent = cy.nodes().length;
  document.getElementById('edgeCount').textContent = cy.edges().length;
}

async function requestConsole(nodeName) {
    try {
        const res = await fetch('http://127.0.0.1:5001/api/console_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ instance_name: nodeName })
        });
        const data = await res.json();

        if (data.output) {
            const url = data.output.trim();
            if (/^http?:\/\//i.test(url)) {
                // Abrir nueva ventana con tamaño fijo
                window.open(
                    url,
                    '_blank',
                    'toolbar=no,location=no,status=no,menubar=no,scrollbars=yes,resizable=yes,width=1024,height=768'
                );
            } else {
                showToast('La URL devuelta no es válida: ' + url);
                console.warn('URL inválida:', url);
            }
        } else {
            showToast(data.message || data.error || 'No se recibió URL');
            console.warn('Respuesta backend:', data);
        }
    } catch (e) {
        console.error(e);
        showToast('Error al solicitar la consola');
    }
}





function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3000);
}

// =======================
// INTEGRACIÓN BACKEND
// =======================
function getScenarioData() {
  const nodes = cy.nodes().map(node => ({
    id: node.data('id'),
    name: node.data('name'),
    type: node.data('type'),
    position: node.position(),
    properties: {
      os: node.data('image'),
      ip: node.data('ip'),
      network: node.data('network'),
      subnet: node.data('subnet'),
      flavor: node.data('flavor'),
      image: node.data('image'),
      security_group: node.data('security_group'),
      keypair: node.data('keypair')
    }
  }));
  const edges = cy.edges().map(edge => ({
    id: edge.data('id'),
    source: edge.data('source'),
    target: edge.data('target')
  }));
  return { scenario_name: 'file', nodes, edges };
}
// =======================
// OVERLAY DE ESPERA
// =======================
function showOverlay(show) {
  const overlay = document.getElementById('overlay');
  if (!overlay) {
    console.warn(' Overlay no encontrado en el DOM.');
    return;
  }
  overlay.classList.toggle('hidden', !show);
}

// =======================
// CREACIÓN DE ESCENARIO (CON BLOQUEO DE BOTONES Y MONITOREO)
// =======================
// =======================
// CREACIÓN DE ESCENARIO (CON OVERLAY Y MONITOREO)
// =======================
async function createScenario() {
  updateNodeProperties(false);
  const data = getScenarioData();

  //  Bloquear botones y mostrar overlay
  const buttons = document.querySelectorAll("button");
  buttons.forEach(btn => {
    btn.disabled = true;
    btn.classList.add("opacity-50", "cursor-not-allowed");
  });
  showOverlay(true);

  showToast(' Escenario en proceso... esto puede tardar varios minutos.');
  appendToTerminal('$  Iniciando creación de escenario...', 'text-yellow-400');

  try {
    const res = await fetch('http://127.0.0.1:5001/api/create_scenario', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      showToast(' Error al enviar el escenario.');
      appendToTerminal('$  Error al enviar el escenario al backend.', 'text-red-400');
      desbloquearBotones();
      showOverlay(false);
      return;
    }

    const info = await res.json();
    appendToTerminal(`$ ${info.message}`, 'text-yellow-300');
    showToast(' Despliegue iniciado. Monitoreando progreso...');

    if (info.status === 'running') {
      monitorDeploymentProgress();
    } else {
      appendToTerminal(' Estado inesperado del backend.', 'text-orange-400');
      desbloquearBotones();
      showOverlay(false);
    }

  } catch (e) {
    showToast(' Error de conexión con el backend.');
    appendToTerminal(`$  Error de conexión: ${e}`, 'text-red-400');
    desbloquearBotones();
    showOverlay(false);
  }
}

// =======================
// MONITOREO DE ESTADO DEL BACKEND
// =======================
async function monitorDeploymentProgress() {
  appendToTerminal(' Monitoreando progreso del despliegue...', 'text-gray-400');

  const checkStatus = async () => {
    try {
      const res = await fetch('http://127.0.0.1:5001/api/deployment_status');
      if (!res.ok) {
        appendToTerminal(' No se pudo leer el estado del despliegue.', 'text-red-400');
        desbloquearBotones();
        return;
      }

      const statusData = await res.json();

      if (statusData.status === 'running') {
        appendToTerminal(' Despliegue aún en curso...', 'text-yellow-300');
        setTimeout(checkStatus, 10000); // vuelve a revisar cada 10s
      } else if (statusData.status === 'success') {
        appendToTerminal(' Despliegue completado con éxito.', 'text-green-400');
        showToast(' Escenario creado correctamente.');
        desbloquearBotones();
      } else if (statusData.status === 'error') {
        appendToTerminal(' Error durante el despliegue.', 'text-red-400');
        if (statusData.stderr)
          appendToTerminal(statusData.stderr, 'text-red-300');
        showToast(' Fallo en el despliegue.');
        desbloquearBotones();
      }
    } catch (err) {
      appendToTerminal(` Error al consultar estado: ${err}`, 'text-red-400');
      desbloquearBotones();
    }
  };

  // Inicia la primera comprobación con un pequeño retardo
  setTimeout(checkStatus, 8000);
}

// =======================
// DESBLOQUEAR BOTONES
// =======================
function desbloquearBotones() {
  const buttons = document.querySelectorAll("button");
  buttons.forEach(btn => {
    btn.disabled = false;
    btn.classList.remove("opacity-50", "cursor-not-allowed");
  });
  showOverlay(false); //  Cierra overlay al desbloquear
}







// Función para agregar mensajes al terminal
function appendToTerminal(message, className = 'text-white') {
    const terminalOutput = document.getElementById('terminal-output');
    const p = document.createElement('p');
    p.className = className;
    p.textContent = message;
    terminalOutput.appendChild(p);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

// =======================
//  DESTRUIR ESCENARIO (NUEVA VERSION)
// =======================
async function destruirScenario___() {
  const buttons = document.querySelectorAll("button");
  
  // Bloquear UI
  buttons.forEach(btn => {
    btn.disabled = true;
    btn.classList.add("opacity-50", "cursor-not-allowed");
  });
  showOverlay(true);

  appendToTerminal('$  Iniciando destrucción del escenario...', 'text-yellow-400');

  try {
    const response = await fetch("http://localhost:5001/api/destroy_scenario", {
      method: "POST"
    });

    let data = {};
    try { data = await response.json(); } catch {}

    if (response.ok && data.status === "success") {
      appendToTerminal(" Destrucción iniciada en segundo plano.", "text-green-400");
      appendToTerminal(data.message || "", "text-gray-300");
    } else {
      appendToTerminal('$  Error al iniciar la destrucción.', 'text-orange-400');
      if (data.message) appendToTerminal(data.message, 'text-red-300');
    }

  } catch (err) {
    appendToTerminal(`$  Error al conectar con el backend: ${err}`, 'text-red-400');

  } finally {
    // Desbloquear UI
    buttons.forEach(btn => {
      btn.disabled = false;
      btn.classList.remove("opacity-50", "cursor-not-allowed");
    });

    showOverlay(false);
  }
}

async function destruirScenario() {
    appendToTerminal('$  Iniciando destrucción...', 'text-yellow-400');
    showOverlay(true);

    const buttons = document.querySelectorAll("button");
    buttons.forEach(b => {
        b.disabled = true;
        b.classList.add("opacity-50", "cursor-not-allowed");
    });

    try {
        const res = await fetch("http://localhost:5001/api/destroy_scenario", {
            method: "POST"
        });

        const info = await res.json();
        appendToTerminal(info.message, "text-gray-300");

        if (info.status === "running") {
            monitorDestroyProgress();
        }

    } catch (err) {
        appendToTerminal(` Error de conexión: ${err}`, "text-red-400");
    }
}


async function monitorDestroyProgress() {
    const check = async () => {
        const res = await fetch("http://localhost:5001/api/destroy_status");
        const status = await res.json();

        if (status.status === "running") {
            appendToTerminal(' Destrucción en curso...', 'text-yellow-400');
            setTimeout(check, 5000);
        } else {
            appendToTerminal(' Escenario destruido.', 'text-green-400');
            showToast(" Escenario eliminado");
            showOverlay(false);

            document.querySelectorAll("button").forEach(b => {
                b.disabled = false;
                b.classList.remove("opacity-50", "cursor-not-allowed");
            });
        }
    };

    setTimeout(check, 3000);
}


async function loadScenario() {
  showToast('Cargando escenario...');
  appendToTerminal('$ Cargando escenario "file"...', 'text-green-400');

  try {
    const res = await fetch('http://localhost:5001/api/get_scenario/file');
    if (!res.ok) {
      showToast('Escenario No creado');
      return;
    }
    const scenarioData = await res.json();
    cy.elements().remove();
    nodeCounter = 0;
    const elementsToAdd = [];
    scenarioData.nodes.forEach(node => {
      elementsToAdd.push({
        group: 'nodes',
        data: {
          id: node.id,
          name: node.name,
          type: node.type,
          os: node.properties?.image,
          ip: node.properties?.ip,
          network: node.properties?.network,
          subnet: node.properties?.subnet,
          flavor: node.properties?.flavor,
          image: node.properties?.image,
          security_group: node.properties?.security_group,
          keypair: node.properties?.keypair
        },
        position: node.position
      });
      const num = parseInt(node.id.replace('node',''));
      if (!isNaN(num) && num > nodeCounter) nodeCounter = num;
    });
    scenarioData.edges.forEach(edge => {
      elementsToAdd.push({ group: 'edges', data: { id: edge.id, source: edge.source, target: edge.target } });
    });
    cy.add(elementsToAdd);
    updateStats();
    showToast('Escenario cargado');
     appendToTerminal(`Escenario cargado.`, 'text-white');
  } catch (e) {
    showToast('Error de conexión');
    appendToTerminal(`Error de conexión.`, 'text-white');
  }
}
// =======================
// INICIO
// =======================
document.addEventListener('DOMContentLoaded', initCytoscape);
