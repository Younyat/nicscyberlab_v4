// =======================
// GLOBAL VARIABLES
// =======================
let cy;
let nodeCounter = 0;
let currentMode = 'select';
let selectedNodes = [];
let connectionMode = false;

// =======================
// CONFIRMATION MODAL
// =======================
function showConfirmationModal(title, message, onConfirmCallback) {
  const modal = document.getElementById('customModal');
  const modalTitle = document.getElementById('modalTitle');
  const modalMessage = document.getElementById('modalMessage');

  if (!modal) {
    console.error('Modal not found');
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

  // clean up previous listeners
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
    'Confirm Canvas Clear',
    'Are you absolutely sure you want to remove all nodes and connections?',
    clearAll
  );
}
function destruirScenarioConfirmation() {
  showConfirmationModal(
    'Destroy the current scenario?',
    'This action will remove all deployed resources. It cannot be undone.',
    destruirScenario
  );
}


function newScenarioConfirmation() {
  showConfirmationModal(
    'Create a new scenario?',
    'Are you absolutely sure you want to create the scenario?',
    createScenario
  );
}
// =======================
// INITIALIZE CYTOSCAPE
// =======================
function initCytoscape() {
  const cyContainer = document.getElementById('cy');
  if (!cyContainer || typeof cytoscape === 'undefined') {
    console.warn('Cytoscape not available');
    return;
  }

  cy = cytoscape({
    container: cyContainer,
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          width: 64,
          height: 64,
          label: 'data(name)',
          'text-valign': 'bottom',
          'text-margin-y': 7,
          color: '#e2e8f0',
          'text-outline-width': 2,
          'text-outline-color': '#0c1020',
          'border-width': 4,
          'border-opacity': 0.9,
          cursor: 'grab',
          'font-size': '12px',
          'font-weight': 'bold',
          'font-family': 'Inter, sans-serif'
        }
      },
      { selector: 'node[type="monitor"]', style: { 'background-color': '#16a34a', 'border-color': '#4ade80', 'shape': 'round-rectangle' } },
      { selector: 'node[type="attack"]', style: { 'background-color': '#dc2626', 'border-color': '#f87171', 'shape': 'triangle' } },
      { selector: 'node[type="victim"]', style: { 'background-color': '#2563eb', 'border-color': '#60a5fa', 'shape': 'ellipse' } },
      { selector: 'node:selected', style: { 'border-width': 5, 'border-color': '#6366f1' } },
      { selector: 'edge', style: { width: 2.5, 'line-color': '#475569', 'target-arrow-color': '#475569', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } },
      { selector: 'edge:selected', style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316', width: 3.5 } }
    ],
    layout: { name: 'preset' },
    wheelSensitivity: 0.2
  });


  cy.on('dblclick', 'node', evt => {
    const node = evt.target;
    requestConsole(node.data('name')); // node name
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
// NODE AND EDGE CRUD
// =======================
function addNodeMode(type) {
  currentMode = type;
  if (connectionMode) toggleConnectionMode();
  showToast(`Active mode: add ${type}`);
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
  showToast('Node added');
}

function toggleConnectionMode() {
  connectionMode = !connectionMode;
  selectedNodes = [];
  currentMode = connectionMode ? 'connect' : 'select';
  const btn = document.querySelector('.btn-connect');
  if (btn) {
    if (connectionMode) {
      btn.innerHTML = '<i class="fas fa-times"></i><span>Cancel</span>';
      btn.style.background = '#dc2626';
      showToast('Connection mode active');
    } else {
      btn.innerHTML = '<i class="fas fa-link"></i><span>Connect</span>';
      btn.style.background = '#ea580c';
      showToast('Connection mode disabled');
    }
  }
}

function connectNodes(node1, node2) {
  const currentEdgeId = `edge_${node1.id()}_${node2.id()}`;
  if (cy.getElementById(currentEdgeId).length > 0) {
    showToast('The connection already exists');
    return;
  }
  cy.add({ group: 'edges', data: { id: currentEdgeId, source: node1.id(), target: node2.id() } });
  updateStats();
  showToast('Nodes connected');
}

function deleteSelected() {
  const selected = cy.$(':selected');
  if (selected.length === 0) {
    showToast('Select something to delete');
    return;
  }
  selected.remove();
  updateStats();
  clearNodeProperties();
  showToast('Deleted');
}

function clearAll() {
  cy.elements().remove();
  nodeCounter = 0;
  updateStats();
  clearNodeProperties();
  showToast('Scenario cleared');
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
    if (showToastMsg) showToast('Select a node');
    return;
  }
  const node = selected[0];
  node.data('network', document.getElementById('nodeNetwork').value);
  node.data('subnet', document.getElementById('nodeSubNetwork').value);
  node.data('flavor', document.getElementById('nodeFlavor').value);
  node.data('image', document.getElementById('nodeImage').value);
  node.data('security_group', document.getElementById('nodeSecurityGroup').value);
  node.data('keypair', document.getElementById('nodeSSHKey').value);
  if (showToastMsg) showToast('Node updated');
}

// =======================
// STATISTICS AND TOAST
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
                // Open a new window with a fixed size
                window.open(
                    url,
                    '_blank',
                    'toolbar=no,location=no,status=no,menubar=no,scrollbars=yes,resizable=yes,width=1024,height=768'
                );
            } else {
                showToast('The returned URL is not valid: ' + url);
                console.warn('Invalid URL:', url);
            }
        } else {
            showToast(data.message || data.error || 'No URL received');
            console.warn('Backend response:', data);
        }
    } catch (e) {
        console.error(e);
        showToast('Error requesting the console');
    }
}





function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3000);
}

// =======================
// BACKEND INTEGRATION
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
    console.warn(' Overlay not found in the DOM.');
    return;
  }
  overlay.classList.toggle('hidden', !show);
}

// =======================
// SCENARIO CREATION (WITH BUTTON LOCKING AND MONITOREO)
// =======================
// =======================
// SCENARIO CREATION (WITH OVERLAY AND MONITORING)
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

  showToast(' Scenario in progress... this can take several minutes.');
  appendToTerminal('$  Starting scenario creation...', 'text-yellow-400');

  try {
    const res = await fetch('http://127.0.0.1:5001/api/create_scenario', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      showToast(' Error sending the scenario.');
      appendToTerminal('$  Error sending the scenario to the backend.', 'text-red-400');
      desbloquearBotones();
      showOverlay(false);
      return;
    }

    const info = await res.json();
    appendToTerminal(`$ ${info.message}`, 'text-yellow-300');
    showToast(' Deployment started. Monitoring progress...');

    if (info.status === 'running') {
      monitorDeploymentProgress();
    } else {
      appendToTerminal(' Unexpected backend status.', 'text-orange-400');
      desbloquearBotones();
      showOverlay(false);
    }

  } catch (e) {
    showToast(' Error connecting to the backend.');
    appendToTerminal(`$  Connection error: ${e}`, 'text-red-400');
    desbloquearBotones();
    showOverlay(false);
  }
}

// =======================
// BACKEND STATUS MONITORING
// =======================
async function monitorDeploymentProgress() {
  appendToTerminal(' Monitoring deployment progress...', 'text-gray-400');

  const checkStatus = async () => {
    try {
      const res = await fetch('http://127.0.0.1:5001/api/deployment_status');
      if (!res.ok) {
        appendToTerminal(' Could not read the deployment status.', 'text-red-400');
        desbloquearBotones();
        return;
      }

      const statusData = await res.json();

      if (statusData.status === 'running') {
        appendToTerminal(' Deployment still in progress...', 'text-yellow-300');
        setTimeout(checkStatus, 10000); // check again every 10s
      } else if (statusData.status === 'success') {
        appendToTerminal(' Deployment completed successfully.', 'text-green-400');
        showToast(' Scenario created successfully.');
        desbloquearBotones();
      } else if (statusData.status === 'error') {
        appendToTerminal(' Error during deployment.', 'text-red-400');
        if (statusData.stderr)
          appendToTerminal(statusData.stderr, 'text-red-300');
        showToast(' Deployment failed.');
        desbloquearBotones();
      }
    } catch (err) {
      appendToTerminal(` Error checking status: ${err}`, 'text-red-400');
      desbloquearBotones();
    }
  };

  // Starts the first check after a short delay
  setTimeout(checkStatus, 8000);
}

// =======================
// UNLOCK BUTTONS
// =======================
function desbloquearBotones() {
  const buttons = document.querySelectorAll("button");
  buttons.forEach(btn => {
    btn.disabled = false;
    btn.classList.remove("opacity-50", "cursor-not-allowed");
  });
  showOverlay(false); // Closes the overlay when unlocking
}







// Function to add messages to the terminal
function appendToTerminal(message, className = 'text-white') {
    const terminalOutput = document.getElementById('terminal-output');
    const p = document.createElement('p');
    p.className = className;
    p.textContent = message;
    terminalOutput.appendChild(p);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

// =======================
//  DESTROY SCENARIO (NEW VERSION)
// =======================
async function destruirScenario___() {
  const buttons = document.querySelectorAll("button");

  // Lock UI
  buttons.forEach(btn => {
    btn.disabled = true;
    btn.classList.add("opacity-50", "cursor-not-allowed");
  });
  showOverlay(true);

  appendToTerminal('$  Starting scenario destruction...', 'text-yellow-400');

  try {
    const response = await fetch("http://localhost:5001/api/destroy_scenario", {
      method: "POST"
    });

    let data = {};
    try { data = await response.json(); } catch {}

    if (response.ok && data.status === "success") {
      appendToTerminal(" Destruction started in the background.", "text-green-400");
      appendToTerminal(data.message || "", "text-gray-300");
    } else {
      appendToTerminal('$  Error starting the destruction.', 'text-orange-400');
      if (data.message) appendToTerminal(data.message, 'text-red-300');
    }

  } catch (err) {
    appendToTerminal(`$  Error connecting to the backend: ${err}`, 'text-red-400');

  } finally {
    // Unlock UI
    buttons.forEach(btn => {
      btn.disabled = false;
      btn.classList.remove("opacity-50", "cursor-not-allowed");
    });

    showOverlay(false);
  }
}

async function destruirScenario() {
    appendToTerminal('$  Starting destruction...', 'text-yellow-400');
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
        appendToTerminal(` Connection error: ${err}`, "text-red-400");
    }
}


async function monitorDestroyProgress() {
    const check = async () => {
        const res = await fetch("http://localhost:5001/api/destroy_status");
        const status = await res.json();

        if (status.status === "running") {
            appendToTerminal(' Destruction in progress...', 'text-yellow-400');
            setTimeout(check, 5000);
        } else {
            appendToTerminal(' Scenario destroyed.', 'text-green-400');
            showToast(" Scenario removed");
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
  showToast('Loading scenario....');
  appendToTerminal('$ Loading "file" scenario.', 'text-green-400');

  try {
    const res = await fetch('http://localhost:5001/api/get_scenario/file');
    if (!res.ok) {
      showToast('Scenario Not Created');
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
    showToast('Loaded scenario');
     appendToTerminal(`Loaded scenario`, 'text-white');
  } catch (e) {
    showToast('Connection error');
    appendToTerminal(`Connection error.`, 'text-white');
  }
}
// =======================
// INICIO
// =======================
document.addEventListener('DOMContentLoaded', initCytoscape);
