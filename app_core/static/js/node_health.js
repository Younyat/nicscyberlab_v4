const NH = {
  graphHost: document.getElementById("nh-graph"),
  statusPill: document.getElementById("nh-status-pill"),
  lastUpdate: document.getElementById("nh-last-update"),
  identity: document.getElementById("nh-node-identity"),
  cpuCard: document.getElementById("nh-cpu-card"),
  memoryCard: document.getElementById("nh-memory-card"),
  diskCard: document.getElementById("nh-disk-card"),
  services: document.getElementById("nh-services"),
  storageTable: document.getElementById("nh-storage-table"),
  topCpu: document.getElementById("nh-top-cpu"),
  topMem: document.getElementById("nh-top-mem"),
  console: document.getElementById("nh-console"),
  btnRefreshNodes: document.getElementById("nh-refresh-nodes"),
  btnRefreshSelected: document.getElementById("nh-refresh-selected"),
  btnCleanupSelected: document.getElementById("nh-cleanup-selected"),
  btnClearConsole: document.getElementById("nh-clear-console"),
};

const STATE = {
  nodes: [],
  nodeMap: new Map(),
  selectedId: null,
  cy: null,
  cleanupSource: null,
};

function now() {
  return new Date().toLocaleTimeString();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function consoleWrite(line) {
  NH.console.textContent += `[${now()}] ${line}\n`;
  NH.console.scrollTop = NH.console.scrollHeight;
}

function setStatus(label, tone = "idle") {
  const klass = tone === "ok"
    ? "border-emerald-500/40 text-emerald-300"
    : tone === "warn"
    ? "border-amber-500/40 text-amber-300"
    : tone === "error"
    ? "border-red-500/40 text-red-300"
    : "border-slate-700 text-slate-300";
  NH.statusPill.className = `rounded-full border px-3 py-1 text-xs font-black uppercase tracking-[0.2em] ${klass}`;
  NH.statusPill.textContent = label;
}

function severityBadge(sev) {
  const cls = sev === "critical"
    ? "text-red-300 border-red-500/40 bg-red-500/10"
    : sev === "warning"
    ? "text-amber-300 border-amber-500/40 bg-amber-500/10"
    : sev === "ok"
    ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
    : "text-slate-300 border-slate-700 bg-slate-800/50";
  return `<span class="inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.2em] ${cls}">${esc(sev || "unknown")}</span>`;
}

function bytesHuman(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "not_available";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

async function fetchJson(url, label) {
  const res = await fetch(url);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!res.ok) {
    throw new Error(data?.error || text || `${label} failed (${res.status})`);
  }
  return data;
}

function graphColorForRole(role) {
  switch ((role || "").toLowerCase()) {
    case "attacker": return "#ef4444";
    case "victim": return "#38bdf8";
    case "monitor": return "#22c55e";
    case "plc": return "#f59e0b";
    case "scada": return "#a855f7";
    default: return "#64748b";
  }
}

function buildGraph(graph) {
  if (STATE.cy) {
    STATE.cy.destroy();
  }

  STATE.cy = cytoscape({
    container: NH.graphHost,
    elements: [...(graph.nodes || []), ...(graph.edges || [])],
    style: [
      {
        selector: 'node[kind="instance"]',
        style: {
          "background-color": ele => graphColorForRole(ele.data("role")),
          "label": "data(label)",
          "color": "#e2e8f0",
          "text-outline-width": 2,
          "text-outline-color": "#0f172a",
          "font-size": 11,
          "font-weight": 700,
          "width": 56,
          "height": 56,
        }
      },
      {
        selector: 'node[kind="network"]',
        style: {
          "shape": "round-rectangle",
          "background-color": "#1e293b",
          "border-width": 1,
          "border-color": "#475569",
          "label": "data(label)",
          "color": "#cbd5e1",
          "font-size": 10,
          "padding": "12px",
          "text-outline-width": 0,
        }
      },
      {
        selector: "edge",
        style: {
          "width": 2,
          "line-color": "#334155",
          "target-arrow-shape": "none",
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": 8,
          "color": "#64748b",
          "text-background-color": "#020617",
          "text-background-opacity": 0.85,
          "text-background-padding": 2,
        }
      },
      {
        selector: ".selected-node",
        style: {
          "border-width": 4,
          "border-color": "#f8fafc",
          "shadow-blur": 18,
          "shadow-color": "#38bdf8",
          "shadow-opacity": 0.45,
        }
      }
    ],
    layout: {
      name: "cose",
      animate: false,
      nodeRepulsion: 120000,
      idealEdgeLength: 140,
      gravity: 0.4,
    }
  });

  STATE.cy.on("tap", "node", evt => {
    const node = evt.target;
    STATE.cy.nodes().removeClass("selected-node");
    node.addClass("selected-node");
    const kind = node.data("kind");
    if (kind !== "instance") {
      NH.identity.innerHTML = `<div class="text-slate-400">Network segment selected: <span class="font-bold text-slate-200">${esc(node.data("label"))}</span></div>`;
      return;
    }
    selectNode(node.id());
  });
}

function renderIdentity(node, probe) {
  NH.identity.innerHTML = `
    <div><strong>Name:</strong> ${esc(node.name)}</div>
    <div><strong>Role:</strong> ${esc(node.role)}</div>
    <div><strong>Status:</strong> ${esc(node.status)}</div>
    <div><strong>OS:</strong> ${esc(node.os)}</div>
    <div><strong>SSH user:</strong> ${esc(node.ssh_user)}</div>
    <div><strong>SSH target:</strong> ${esc(node.ssh_target_ip || "not_available")}</div>
    <div><strong>Private IP:</strong> ${esc(node.ip_private || "not_available")}</div>
    <div><strong>Floating IP:</strong> ${esc(node.ip_floating || "not_available")}</div>
    <div><strong>Hostname:</strong> ${esc(probe.identity.hostname)}</div>
    <div><strong>Kernel:</strong> ${esc(probe.identity.kernel)}</div>
    <div><strong>Uptime:</strong> ${esc(probe.identity.uptime)}</div>
  `;
}

function renderProbe(node, probe) {
  renderIdentity(node, probe);
  NH.lastUpdate.textContent = probe.identity.date_utc || "not_available";

  NH.cpuCard.innerHTML = `
    <div class="flex items-center justify-between">${severityBadge(probe.cpu.severity)} <span>${esc(probe.cpu.usage_pct ?? "not_available")}%</span></div>
    <div class="mt-2">Cores: <span class="font-bold">${esc(probe.cpu.cores ?? "not_available")}</span></div>
    <div class="mt-1">Loadavg: <span class="font-bold">${esc(probe.identity.loadavg)}</span></div>
  `;

  NH.memoryCard.innerHTML = `
    <div class="flex items-center justify-between">${severityBadge(probe.memory.severity)} <span>${esc(probe.memory.usage_pct ?? "not_available")}%</span></div>
    <div class="mt-2">Used: <span class="font-bold">${esc(probe.memory.used_mb ?? "not_available")} MB</span></div>
    <div class="mt-1">Available: <span class="font-bold">${esc(probe.memory.available_mb ?? "not_available")} MB</span></div>
    <div class="mt-1">Swap: <span class="font-bold">${esc(probe.memory.swap_used_mb ?? "not_available")} / ${esc(probe.memory.swap_total_mb ?? "not_available")} MB</span></div>
  `;

  NH.diskCard.innerHTML = `
    <div class="flex items-center justify-between">${severityBadge(probe.disk.severity)} <span>${esc(probe.disk.root_use_pct ?? "not_available")}%</span></div>
    <div class="mt-2">Used: <span class="font-bold">${bytesHuman(probe.disk.root_used_bytes)}</span></div>
    <div class="mt-1">Free: <span class="font-bold">${bytesHuman(probe.disk.root_avail_bytes)}</span></div>
    <div class="mt-1">Inodes: <span class="font-bold">${esc(probe.disk.root_inodes_use_pct ?? "not_available")}%</span></div>
  `;

  const services = Object.entries(probe.services || {});
  NH.services.innerHTML = services.map(([name, state]) => {
    const sev = state === "active" ? "ok" : state === "inactive" ? "warning" : "unknown";
    return `<div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2"><div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">${esc(name)}</div><div class="mt-1">${severityBadge(sev)} <span class="ml-2">${esc(state)}</span></div></div>`;
  }).join("") || '<div class="text-slate-500">No service data.</div>';

  NH.storageTable.innerHTML = `
    <div class="grid grid-cols-2 gap-3">
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/var/log: <span class="font-bold">${bytesHuman(probe.disk.var_log_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/var/log/suricata: <span class="font-bold">${bytesHuman(probe.disk.suricata_log_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/tmp: <span class="font-bold">${bytesHuman(probe.disk.tmp_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">/var/tmp: <span class="font-bold">${bytesHuman(probe.disk.var_tmp_size_bytes)}</span></div>
      <div class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">APT cache: <span class="font-bold">${bytesHuman(probe.disk.apt_cache_size_bytes)}</span></div>
    </div>
    <div class="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Filesystem Snapshot</div>
      <pre class="mt-2 whitespace-pre-wrap text-xs text-slate-300">${esc((probe.tables.filesystems || []).join("\n"))}</pre>
    </div>
    <div class="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div class="text-[10px] uppercase tracking-[0.2em] text-slate-500 font-black">Largest /var Paths</div>
      <pre class="mt-2 whitespace-pre-wrap text-xs text-slate-300">${esc((probe.tables.largest_var || []).join("\n"))}</pre>
    </div>
  `;

  NH.topCpu.textContent = (probe.tables.top_cpu || []).join("\n");
  NH.topMem.textContent = (probe.tables.top_mem || []).join("\n");
}

async function loadNodes(autoSelect = true) {
  setStatus("Loading", "warn");
  consoleWrite("Loading OpenStack node inventory...");
  const data = await fetchJson("/api/node-health/nodes", "nodes");
  STATE.nodes = data.nodes || [];
  STATE.nodeMap = new Map(STATE.nodes.map(node => [node.id, node]));
  buildGraph(data.graph || { nodes: [], edges: [] });
  setStatus(`Nodes ${STATE.nodes.length}`, "ok");
  if (autoSelect && STATE.nodes.length) {
    const preferred = STATE.nodes.find(node => node.role !== "monitor") || STATE.nodes[0];
    selectNode(preferred.id);
  }
}

async function selectNode(nodeId) {
  STATE.selectedId = nodeId;
  const node = STATE.nodeMap.get(nodeId);
  if (!node) return;
  setStatus(`Probing ${node.name}`, "warn");
  consoleWrite(`Probing node ${node.name} (${node.ssh_user}@${node.ssh_target_ip || node.ip_private || node.ip_floating || "?"})`);
  try {
    const data = await fetchJson(`/api/node-health/nodes/${encodeURIComponent(nodeId)}/probe`, "probe");
    renderProbe(node, data.probe);
    setStatus(`Ready ${node.name}`, "ok");
    consoleWrite(`Probe completed for ${node.name}`);
  } catch (error) {
    setStatus("Probe Error", "error");
    consoleWrite(`Probe failed: ${error.message}`);
    NH.identity.innerHTML = `<div class="text-red-300">${esc(error.message)}</div>`;
  }
}

function startCleanup() {
  const node = STATE.nodeMap.get(STATE.selectedId);
  if (!node) {
    consoleWrite("No node selected for cleanup.");
    return;
  }
  if (STATE.cleanupSource) {
    STATE.cleanupSource.close();
    STATE.cleanupSource = null;
  }
  setStatus(`Cleanup ${node.name}`, "warn");
  consoleWrite(`Starting safe disk cleanup on ${node.name}...`);
  const url = `/api/node-health/nodes/${encodeURIComponent(node.id)}/cleanup/stream`;
  const source = new EventSource(url);
  STATE.cleanupSource = source;
  source.onmessage = evt => {
    consoleWrite(evt.data);
  };
  source.addEventListener("done", async () => {
    consoleWrite("Cleanup stream finished.");
    source.close();
    STATE.cleanupSource = null;
    await selectNode(node.id);
  });
  source.onerror = () => {
    consoleWrite("Cleanup stream closed.");
    source.close();
    STATE.cleanupSource = null;
  };
}

NH.btnRefreshNodes.addEventListener("click", () => loadNodes(false));
NH.btnRefreshSelected.addEventListener("click", () => STATE.selectedId ? selectNode(STATE.selectedId) : consoleWrite("Select a node first."));
NH.btnCleanupSelected.addEventListener("click", startCleanup);
NH.btnClearConsole.addEventListener("click", () => { NH.console.textContent = ""; });

document.addEventListener("DOMContentLoaded", () => {
  loadNodes(true).catch(error => {
    setStatus("Load Error", "error");
    consoleWrite(`Failed to load node health module: ${error.message}`);
  });
});

