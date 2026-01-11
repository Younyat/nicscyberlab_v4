const API = "";

/* ======================
   HELPERS
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
  dot.className =
    "w-3 h-3 rounded-full animate-pulse " +
    (type === "ok"
      ? "bg-emerald-400"
      : type === "error"
      ? "bg-red-500"
      : "bg-amber-400");
}

function setProgress(p) {
  document.getElementById("progress-bar-inner").style.width = `${p}%`;
}

function overlay(show) {
  document.getElementById("overlay").classList.toggle("hidden", !show);
}

/* ======================
   SAFE FETCH (CLAVE)
====================== */
async function fetchJSON(url, label) {
  try {
    const res = await fetch(url);

    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      const text = await res.text();
      throw new Error(
        `${label}: respuesta NO JSON (status ${res.status})`
      );
    }

    return await res.json();
  } catch (err) {
    log(`❌ ${label} falló`, "text-red-400");
    console.error(err);
    return null;
  }
}

/* ======================
   TOOLS RENDER
====================== */
function renderToolsInline(tools) {
  // Caso 0: no hay tools
  if (!tools || typeof tools !== "object" || Object.keys(tools).length === 0) {
    return "<span class='text-slate-500'>-</span>";
  }

  return Object.entries(tools)
    .map(([tool, rawStatus]) => {

      // =========================
      // NORMALIZACIÓN (MISMA que en el segundo código)
      // =========================
      let status;

      if (!rawStatus) {
        status = "not_installed";
      } else if (rawStatus === "pending") {
        status = "pending";
      } else if (rawStatus === "error") {
        status = "error";
      } else if (rawStatus === "uninstalling") {
        status = "uninstalling";
      } else {
        // TODO lo demás (incluida FECHA → Zeek)
        status = "installed";
      }

      // =========================
      // RENDER SEGÚN ESTADO
      // =========================
      switch (status) {
        case "installed":
          return `
            <span class="text-emerald-400">
              ${tool} ✔ installed
              ${
                typeof rawStatus === "string"
                  ? `<br><span class="text-xs text-slate-400">${rawStatus}</span>`
                  : ""
              }
            </span>
          `;

        case "pending":
          return `<span class="text-amber-400">${tool} ⏳ pending</span>`;

        case "uninstalling":
          return `<span class="text-amber-400 animate-pulse">${tool} uninstalling…</span>`;

        case "error":
          return `<span class="text-red-500">${tool} ❌ error</span>`;

        default:
          return `<span class="text-slate-400">${tool} -</span>`;
      }
    })
    .join("<br>");
}



/* ======================
   LOADERS
====================== */
async function loadInstances() {
  const data = await fetchJSON(
    "/api/openstack/instances/full",
    "Instancias"
  );
  if (!data) return;

  const tbody = document.getElementById("instances-table");
  tbody.innerHTML = "";

  data.instances.forEach(vm => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${vm.name}</td>
        <td class="p-2">${vm.status}</td>
        <td class="p-2">${vm.ip_private || "-"}</td>
        <td class="p-2">${vm.ip_floating || "-"}</td>
        <td class="p-2">${renderToolsInline(vm.tools)}</td>
      </tr>`;
  });

  log(`✔ ${data.instances.length} instancias cargadas`, "text-emerald-300");
}

async function loadRoles() {
  const data = await fetchJSON("/api/instance_roles", "Roles");
  if (!data) return;

  document.getElementById("roles-box").textContent =
    JSON.stringify(data, null, 2);
}

async function loadFlavors() {
  const data = await fetchJSON("/api/openstack/flavors", "Flavors");
  if (!data) return;

  const tbody = document.getElementById("flavors-table");
  tbody.innerHTML = "";

  data.flavors.forEach(f => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${f.name}</td>
        <td class="p-2">${f.vcpus}</td>
        <td class="p-2">${f.ram_mb}</td>
        <td class="p-2">${f.disk_gb}</td>
      </tr>`;
  });
}

async function loadNetworks() {
  const data = await fetchJSON("/api/openstack/networks", "Redes");
  if (!data) return;

  const tbody = document.getElementById("networks-table");
  tbody.innerHTML = "";

  data.networks.forEach(n => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${n.name}</td>
        <td class="p-2">${(n.cidrs || []).join(", ") || "-"}</td>
      </tr>`;
  });
}

async function loadSecurityGroups() {
  const data = await fetchJSON(
    "/api/openstack/security-groups",
    "Security Groups"
  );
  if (!data) return;

  const tbody = document.getElementById("secgroups-table");
  tbody.innerHTML = "";

  data.security_groups.forEach(sg => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${sg.name}</td>
      </tr>`;
  });
}

async function loadKeypairs() {
  const data = await fetchJSON("/api/openstack/keypairs", "Keypairs");
  if (!data) return;

  const tbody = document.getElementById("keypairs-table");
  tbody.innerHTML = "";

  data.keypairs.forEach(k => {
    tbody.innerHTML += `
      <tr>
        <td class="p-2">${k.name}</td>
      </tr>`;
  });
}

/* ======================
   LOAD INVENTORY
====================== */
async function loadInventory() {
  overlay(true);
  setProgress(10);
  setStatus("Cargando inventario", "Consultando OpenStack…", "warn");

  try {
    
    await loadHypervisorStats(); 
    setProgress(20);

    await loadInstances();
    setProgress(40);

    await loadRoles();
    setProgress(55);

    await loadFlavors();
    setProgress(65);

    await loadNetworks();
    setProgress(75);

    await loadSecurityGroups();
    setProgress(85);

    await loadKeypairs();
    setProgress(100);

    setStatus("Inventario actualizado", "Snapshot consistente", "ok");
    log("Inventario completo cargado", "text-emerald-300");

  } catch (e) {
    log(`Error general: ${e}`, "text-red-400");
    setStatus("Error", "Inventario inconsistente", "error");
  } finally {
    overlay(false);
  }
}


/* ======================
   RESOURCES LOADER
====================== */
async function loadHypervisorStats() {
    const stats = await fetchJSON("/api/openstack/hypervisor-stats", "Hypervisor Stats");
    if (!stats) return;

    // Mapeo de datos (OpenStack devuelve los valores según el sabor del CLI)
    const cpuUsed = stats.vcpus_used || 0;
    const cpuTotal = stats.vcpus || 1; // Evitar división por cero
    const ramUsed = stats.memory_mb_used || 0;
    const ramTotal = stats.memory_mb || 1;
    const diskUsed = stats.local_gb_used || 0;
    const diskTotal = stats.local_gb || 1;

    // Actualizar barras y texto
    updateMetric("cpu", cpuUsed, cpuTotal);
    updateMetric("ram", (ramUsed / 1024).toFixed(1), (ramTotal / 1024).toFixed(1), true);
    updateMetric("disk", diskUsed, diskTotal);

    log("📊 Estadísticas de hipervisor actualizadas", "text-sky-300");
}

function updateMetric(id, used, total, isGB = false) {
    const percent = Math.min((used / total) * 100, 100).toFixed(1);
    const unit = isGB ? "GB" : "";
    
    document.getElementById(`${id}-usage`).innerText = `${used} / ${total} ${unit}`;
    document.getElementById(`${id}-percent`).innerText = `${percent}%`;
    document.getElementById(`${id}-bar`).style.width = `${percent}%`;
}




/* ======================
   EVENTS
====================== */
document.getElementById("refresh-inventory").onclick = loadInventory;
document.getElementById("clear-terminal").onclick = () => (term.innerHTML = "");

log("Terminal listo. Esperando acción.");
