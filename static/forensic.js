let selectedNode = null;

/* ===============================
   DEFINICIÓN DE CAPACIDADES
================================ */
const FORENSIC_CAPABILITIES = {
  memory: ["volatility3", "lime"],
  disk: ["autopsy", "tsk"],
  network: ["tcpdump", "tshark", "termshark"]
};

/* ===============================
   LOG
================================ */
function flog(msg) {
  const log = document.getElementById("forensic-log");
  const line = document.createElement("div");
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

/* ===============================
   CARGA DE INSTANCIAS
================================ */
async function loadNodes() {
  const res = await fetch("/api/openstack/instances");
  const data = await res.json();

  const box = document.getElementById("node-list");
  box.innerHTML = "";

  data.instances.forEach(vm => {
    const btn = document.createElement("button");
    btn.className =
      "w-full text-left px-3 py-2 rounded bg-slate-800 hover:bg-slate-700";

    btn.textContent = `${vm.name} (${vm.status})`;

    btn.onclick = () => selectNode(vm);
    box.appendChild(btn);
  });

  flog("Instancias cargadas");
}

/* ===============================
   SELECCIÓN DE NODO
================================ */
async function selectNode(vm) {
  selectedNode = vm;
  flog(`Nodo seleccionado: ${vm.name}`);

  const res = await fetch(
    `/api/get_tools_for_instance?instance=${encodeURIComponent(vm.name)}`
  );
  const data = await res.json();

  renderCapabilities(data.tools || {});
  renderActions(data.tools || {});
}

/* ===============================
   CAPACIDADES FORENSES
================================ */
function renderCapabilities(tools) {
  const box = document.getElementById("capabilities");
  box.innerHTML = "";

  Object.entries(FORENSIC_CAPABILITIES).forEach(([cap, reqTools]) => {
    const available = reqTools.some(t => tools[t]);

    box.innerHTML += `
      <div class="flex justify-between">
        <span>${cap.toUpperCase()}</span>
        <span class="${available ? "text-emerald-400" : "text-red-400"}">
          ${available ? "READY" : "NOT READY"}
        </span>
      </div>
    `;
  });
}

/* ===============================
   ACCIONES GUIADAS
================================ */
function renderActions(tools) {
  const box = document.getElementById("actions");
  box.innerHTML = "";

  if (!selectedNode) return;

  addAction(
    "Preparar análisis de memoria",
    "volatility3",
    tools,
    ["volatility3", "lime"]
  );

  addAction(
    "Preparar análisis de disco",
    "autopsy",
    tools,
    ["autopsy", "tsk"]
  );

  addAction(
    "Preparar captura de red",
    "tcpdump",
    tools,
    ["tcpdump", "tshark"]
  );
}

/* ===============================
   BOTÓN DE ACCIÓN
================================ */
function addAction(label, mainTool, tools, required) {
  const box = document.getElementById("actions");

  const ready = required.every(t => tools[t]);

  const btn = document.createElement("button");
  btn.className = `
    w-full py-2 rounded font-semibold
    ${ready
      ? "bg-emerald-600 hover:bg-emerald-500"
      : "bg-slate-700 cursor-not-allowed"}
  `;
  btn.textContent = label;

  btn.onclick = async () => {
    if (!ready) {
      flog(`Herramientas faltantes: ${required.join(", ")}`);
      return;
    }

    flog(`${label} iniciado en ${selectedNode.name}`);
    // Aquí irían dumps, capturas, etc.
  };

  box.appendChild(btn);
}

/* ===============================
   INIT
================================ */
loadNodes();
