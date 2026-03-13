/* ============================================================
 * NICS CyberLab – Forensic Inventory + Live OT Correlation
 * Fuente única: OpenStack (/api/openstack/instances/full)
 * ============================================================
 */

const UI = {
  overlay: document.getElementById("overlay"),
  progress: document.getElementById("progress"),
  statusText: document.getElementById("status-text"),
  statusSub: document.getElementById("status-sub"),
  statusDot: document.getElementById("status-dot"),

  tblInstances: document.getElementById("tbl-instances"),
  tblFlavors: document.getElementById("tbl-flavors"),
  tblNetworks: document.getElementById("tbl-networks"),
  tblSGs: document.getElementById("tbl-sgs"),
  tblKeys: document.getElementById("tbl-keys"),

  detailTitle: document.getElementById("detail-title"),
  detailNetworks: document.getElementById("detail-networks"),
  detailVolumes: document.getElementById("detail-volumes"),
  detailTools: document.getElementById("detail-tools"),
  detailJson: document.getElementById("detail-json"),

  hostTools: document.getElementById("host-tools"),
  hostLog: document.getElementById("host-log"),

  cpuBar: document.getElementById("cpu-bar"),
  cpuUsage: document.getElementById("cpu-usage"),
  cpuPercent: document.getElementById("cpu-percent"),
  ramBar: document.getElementById("ram-bar"),
  ramUsage: document.getElementById("ram-usage"),
  ramPercent: document.getElementById("ram-percent"),
  diskBar: document.getElementById("disk-bar"),
  diskUsage: document.getElementById("disk-usage"),
  diskPercent: document.getElementById("disk-percent"),

  inventoryNodes: document.getElementById("node-list"),
  packetFlow: document.getElementById("packet-flow")
};

let STATE = {
  instances: [],
  selected: null,
};

/* ============================================================
 * HELPERS
 * ============================================================
 */
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function badge(text, cls) {
  return `<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold ${cls}">${escapeHtml(text)}</span>`;
}

/* ============================================================
 * INVENTORY CONTEXT (REAL, DESDE OPENSTACK)
 * ============================================================
 */
function renderInventoryContext() {
  if (!UI.inventoryNodes) return;

  UI.inventoryNodes.innerHTML = "";

  STATE.instances.forEach(vm => {
    const ips = new Set();

    if (vm.ip_private) ips.add(vm.ip_private);
    if (vm.ip_floating) ips.add(vm.ip_floating);
    (vm.networks || []).forEach(n => n.ip && ips.add(n.ip));

    ips.forEach(ip => {
      UI.inventoryNodes.innerHTML += `
        <div class="p-3 rounded-xl bg-white/5 border border-white/5">
          <div class="text-[10px] font-bold text-slate-300 uppercase">
            ${escapeHtml(vm.name)}
          </div>
          <div class="flex justify-between items-center mt-1">
            <span class="text-[9px] font-mono text-slate-500">${escapeHtml(ip)}</span>
            ${badge("VM", "bg-sky-500/10 text-sky-400 border border-sky-500/20")}
          </div>
        </div>
      `;
    });
  });
}

/* ============================================================
 * INSTANCES TABLE
 * ============================================================
 */
function renderInstanceRow(vm) {
  const statusCls =
    vm.status === "ACTIVE" ? "text-emerald-300" :
    vm.status === "ERROR"  ? "text-red-300" :
    "text-slate-300";

  return `
    <tr class="hover:bg-slate-950/50 cursor-pointer" data-id="${escapeHtml(vm.id)}">
      <td class="py-3 pr-3">
        <div class="font-semibold text-slate-100">${escapeHtml(vm.name)}</div>
        <div class="text-xs text-slate-500">${escapeHtml(vm.id)}</div>
      </td>
      <td class="py-3 pr-3 ${statusCls} font-semibold">${escapeHtml(vm.status)}</td>
      <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.ip_private || "-")}</td>
      <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.ip_floating || "-")}</td>
      <td class="py-3 pr-3 text-slate-200">${escapeHtml(vm.flavor?.name || "-")}</td>
      <td class="py-3 pr-3 text-slate-200">${(vm.volumes || []).length}</td>
      <td class="py-3 pr-3">${JSON.stringify(vm.tools || {}) !== "{}" ? "OK" : "-"}</td>
      <td class="py-3 pr-3">${JSON.stringify(vm.evidence || {}) !== "{}" ? "YES" : "-"}</td>
    </tr>
  `;
}

function bindInstanceRowClicks() {
  UI.tblInstances.querySelectorAll("tr[data-id]").forEach(tr => {
    tr.addEventListener("click", () => {
      const id = tr.getAttribute("data-id");
      const vm = STATE.instances.find(x => x.id === id);
      if (vm) showInstanceDetail(vm);
    });
  });
}

function showInstanceDetail(vm) {
  STATE.selected = vm;
  UI.detailTitle.textContent = `${vm.name} · ${vm.status}`;
  UI.detailJson.textContent = JSON.stringify(vm, null, 2);
}

/* ============================================================
 * LOAD INSTANCES (OPENSTACK REAL)
 * ============================================================
 */
async function loadInstancesFull() {
  const res = await fetch("/api/openstack/instances/full");
  const data = await res.json();

  STATE.instances = data.instances || [];
  UI.tblInstances.innerHTML = STATE.instances.map(renderInstanceRow).join("");

  bindInstanceRowClicks();
  renderInventoryContext();

  if (!STATE.selected && STATE.instances.length) {
    showInstanceDetail(STATE.instances[0]);
  }
}

/* ============================================================
 * LIVE MODBUS TRAFFIC (WEBSOCKET REAL)
 * ============================================================
 */
function resolveVMByIP(ip) {
  return STATE.instances.find(vm =>
    vm.ip_private === ip ||
    vm.ip_floating === ip ||
    (vm.networks || []).some(n => n.ip === ip)
  );
}

function addPacket(srcIp, dstIp, func, hexPayload) {
  const src = resolveVMByIP(srcIp);
  const dst = resolveVMByIP(dstIp);

  const time = new Date().toLocaleTimeString("en-GB", { hour12: false });

  const card = document.createElement("div");
  card.className = "packet-card bg-slate-900/40 border border-slate-800 rounded-lg overflow-hidden cursor-pointer";
  card.onclick = () => card.classList.toggle("active");

  card.innerHTML = `
    <div class="grid grid-cols-12 p-4 items-center text-[11px]">
      <div class="col-span-2 font-mono text-slate-500">${time}</div>
      <div class="col-span-4">
        <div class="font-bold text-slate-200">${src ? src.name : "UNKNOWN"}</div>
        <div class="text-[9px] font-mono text-slate-500">${srcIp}</div>
      </div>
      <div class="col-span-4">
        <div class="font-bold text-slate-200">${dst ? dst.name : "UNKNOWN"}</div>
        <div class="text-[9px] font-mono text-slate-500">${dstIp}</div>
      </div>
      <div class="col-span-2 text-right">
        ${badge(func, "bg-sky-500/10 text-sky-400 border border-sky-500/20")}
      </div>
    </div>
    <div class="details p-4 bg-black/40 border-t border-slate-800">
      <div class="text-[10px] font-mono text-sky-200 break-all">${hexPayload}</div>
    </div>
  `;

  UI.packetFlow.prepend(card);
  if (UI.packetFlow.children.length > 50) {
    UI.packetFlow.lastChild.remove();
  }
}

function initLiveTraffic() {
  const ws = new WebSocket("ws://localhost:8765");

  ws.onmessage = (evt) => {
    const pkt = JSON.parse(evt.data);
    addPacket(pkt.src, pkt.dst, pkt.fc, pkt.hex);
  };
}

/* ============================================================
 * INIT
 * ============================================================
 */
document.getElementById("btn-refresh")?.addEventListener("click", loadInstancesFull);

loadInstancesFull();
initLiveTraffic();
