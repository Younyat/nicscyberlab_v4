/* ======================
   CONFIG
====================== */
const API = "";

/* ======================
   UI HELPERS
====================== */
const term = document.getElementById("terminal-output");

function log(msg, color = "text-slate-200") {
  const line = document.createElement("div");
  line.className = color;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function setStatus(text, sub, type) {
  document.getElementById("status-text").textContent = text;
  document.getElementById("status-subtext").textContent = sub;

  const dot = document.getElementById("status-dot");
  dot.className = "w-3 h-3 rounded-full animate-pulse " + (
    type === "ok" ? "bg-emerald-400" :
    type === "error" ? "bg-red-500" :
    "bg-amber-400"
  );
}

function setProgress(p) {
  document.getElementById("progress-bar-inner").style.width = `${p}%`;
}

function overlay(show) {
  document.getElementById("overlay").classList.toggle("hidden", !show);
}



async function getToolsForInstance(instanceName) {
  try {
    const res = await fetch(
      `/api/get_tools_for_instance?instance=${encodeURIComponent(instanceName)}`
    );
    const data = await res.json();
    return data.tools || {};
  } catch (e) {
    console.error("Error obteniendo tools:", e);
    return {};
  }
}


function renderToolsInline(tools) {
  if (!tools || Object.keys(tools).length === 0) {
    return "<span class='text-slate-500'>-</span>";
  }

  return Object.entries(tools)
    .map(([tool, status]) => {
      let cls = "text-slate-400";
      let label = status;

      if (status === "pending") {
        cls = "text-amber-400";
      } else if (status === "error") {
        cls = "text-red-500";
      } else {
        // INSTALADO (fecha)
        cls = "text-emerald-400";
        label = "installed";
      }

      return `<span class="${cls}">${tool} (${label})</span>`;
    })
    .join("<br>");
}

async function loadFlavors() {
  log("Consultando flavors…", "text-sky-300");
  const res = await fetch("/api/openstack/flavors");
  const data = await res.json();

  data.flavors.forEach(f =>
    log(`FLAVOR  ${f.name} | vCPU=${f.vcpus} RAM=${f.ram}MB DISK=${f.disk}GB`, "text-slate-300")
  );
}

async function loadNetworks() {
  log("Consultando redes…", "text-sky-300");
  const res = await fetch("/api/openstack/networks");
  const data = await res.json();

  data.networks.forEach(n =>
    log(`NETWORK ${n.name} (${n.cidr || "sin CIDR"})`, "text-slate-300")
  );
}

async function loadSecurityGroups() {
  log("Consultando grupos de seguridad…", "text-sky-300");
  const res = await fetch("/api/openstack/security-groups");
  const data = await res.json();

  data.security_groups.forEach(sg =>
    log(`SEC-GROUP ${sg.name}`, "text-slate-300")
  );
}

async function loadKeypairs() {
  log("Consultando keypairs…", "text-sky-300");
  const res = await fetch("/api/openstack/keypairs");
  const data = await res.json();

  data.keypairs.forEach(k =>
    log(`KEYPAIR ${k.name}`, "text-slate-300")
  );
}



/* ======================
   LOAD INVENTORY
====================== */
async function loadInventory() {
  overlay(true);
  setProgress(20);
  setStatus("Cargando inventario", "Consultando OpenStack…", "warn");

  try {
    log("Consultando instancias…", "text-sky-300");
    const instRes = await fetch(`${API}/api/openstack/instances`);
    const instData = await instRes.json();

    const tbody = document.getElementById("instances-table");
    tbody.innerHTML = "";

    for (const vm of instData.instances) {
      // 🔹 AQUÍ ESTÁ LA CLAVE: reutilizamos tu backend de tools
      const tools = await getToolsForInstance(vm.name);

      tbody.innerHTML += `
        <tr>
          <td class="p-2">${vm.name}</td>
          <td class="p-2">${vm.status}</td>
          <td class="p-2">${vm.ip_private || "-"}</td>
          <td class="p-2">${vm.ip_floating || "-"}</td>
          <td class="p-2">${renderToolsInline(tools)}</td>
        </tr>`;
    }

    setProgress(60);

    log("Consultando roles detectados…", "text-sky-300");
    const roleRes = await fetch(`${API}/api/instance_roles`);
    const roles = await roleRes.json();

    document.getElementById("roles-box").textContent =
      JSON.stringify(roles, null, 2);


    setProgress(70);

    await loadFlavors();
    setProgress(75);

    await loadNetworks();
    setProgress(80);

    await loadSecurityGroups();
    setProgress(90);

    await loadKeypairs();



    setProgress(100);
    setStatus("Inventario actualizado", "Estado real del laboratorio", "ok");
    log("Inventario cargado correctamente", "text-emerald-300");

  } catch (e) {
    log(`Error: ${e}`, "text-red-400");
    setStatus("Error", "No se pudo cargar el inventario", "error");
    setProgress(30);
  } finally {
    overlay(false);
  }
}

/* ======================
   EVENTS
====================== */
document.getElementById("refresh-inventory").onclick = loadInventory;
document.getElementById("clear-terminal").onclick = () => term.innerHTML = "";

log("Terminal listo. Esperando acción.");
