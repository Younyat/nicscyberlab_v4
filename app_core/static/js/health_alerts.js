const HA = {
  summary: document.getElementById("ha-summary"),
  list: document.getElementById("ha-list"),
  detail: document.getElementById("ha-detail"),
  meta: document.getElementById("ha-meta"),
  detailState: document.getElementById("ha-detail-state"),
  btnRefresh: document.getElementById("ha-refresh"),
  btnMarkRead: document.getElementById("ha-mark-read"),
  btnOpenNodeHealth: document.getElementById("ha-open-node-health"),
};

const HA_STATE = {
  alerts: [],
  selectedAlertId: null,
};

const HA_READ_KEY = "nics-health-alerts-read";
const HA_FOCUS_KEY = "nics-health-alert-focus";

function haEsc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function haSeverityBadge(sev) {
  const value = String(sev || "unknown").toLowerCase();
  const cls = value === "critical"
    ? "text-red-300 border-red-500/40 bg-red-500/10"
    : value === "warning"
    ? "text-amber-300 border-amber-500/40 bg-amber-500/10"
    : value === "ok"
    ? "text-emerald-300 border-emerald-500/40 bg-emerald-500/10"
    : "text-slate-300 border-slate-700 bg-slate-800/50";
  return `<span class="inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.2em] ${cls}">${haEsc(value)}</span>`;
}

function haLoadReadSet() {
  try {
    const parsed = JSON.parse(localStorage.getItem(HA_READ_KEY) || "[]");
    return new Set(Array.isArray(parsed) ? parsed : []);
  } catch {
    return new Set();
  }
}

function haSaveReadSet(set) {
  try {
    localStorage.setItem(HA_READ_KEY, JSON.stringify([...set]));
  } catch {}
}

function haMarkRead(ids) {
  const read = haLoadReadSet();
  (ids || []).forEach(id => {
    if (id) read.add(id);
  });
  haSaveReadSet(read);
}

async function haFetchJson(url) {
  const res = await fetch(url, { cache: "no-store" });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!res.ok) throw new Error(data?.error || text || `${url} -> ${res.status}`);
  return data;
}

function haRenderSummary(payload) {
  const alerts = payload?.alerts || [];
  const read = haLoadReadSet();
  const unread = alerts.filter(alert => !read.has(alert.alert_id));
  const critical = alerts.filter(alert => String(alert.severity || "").toLowerCase() === "critical").length;
  const warning = alerts.filter(alert => String(alert.severity || "").toLowerCase() === "warning").length;
  HA.meta.textContent = `Generated ${payload?.generated_at || "--"} | total=${alerts.length} | unread=${unread.length}`;
  HA.summary.innerHTML = `
    <div class="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-4">
      <div class="text-xs uppercase tracking-[0.25em] text-red-200 font-black">Critical</div>
      <div class="mt-2 text-2xl font-black text-white">${critical}</div>
    </div>
    <div class="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-4">
      <div class="text-xs uppercase tracking-[0.25em] text-amber-200 font-black">Warning</div>
      <div class="mt-2 text-2xl font-black text-white">${warning}</div>
    </div>
    <div class="rounded-xl border border-slate-800 bg-slate-950/70 px-4 py-4">
      <div class="text-xs uppercase tracking-[0.25em] text-slate-500 font-black">Unread</div>
      <div class="mt-2 text-2xl font-black text-white">${unread.length}</div>
    </div>
  `;
}

function haRenderList(payload) {
  const alerts = payload?.alerts || [];
  const read = haLoadReadSet();
  if (!alerts.length) {
    HA.list.innerHTML = `<div class="rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-4 text-sm text-emerald-200">No health alerts are currently active.</div>`;
    return;
  }
  HA.list.innerHTML = alerts.map(alert => {
    const unread = !read.has(alert.alert_id);
    const selected = alert.alert_id === HA_STATE.selectedAlertId;
    return `
      <button type="button" data-alert-id="${haEsc(alert.alert_id)}" class="ha-alert-item flex w-full items-start justify-between gap-3 rounded-xl border px-4 py-4 text-left ${selected ? "border-sky-500/60 bg-sky-500/10" : unread ? "border-red-500/30 bg-red-500/5" : "border-slate-800 bg-slate-950/70"}">
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            ${haSeverityBadge(alert.severity)}
            ${unread ? `<span class="inline-flex items-center rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-black uppercase tracking-[0.2em] text-red-200">new</span>` : ""}
            <span class="text-xs uppercase tracking-[0.2em] text-slate-500">${haEsc(alert.scope || "health")}</span>
          </div>
          <div class="mt-2 text-base font-black text-white">${haEsc(alert.title || "Health alert")}</div>
          <div class="mt-2 text-sm text-slate-300">${haEsc(alert.detail || "No detail available.")}</div>
          <div class="mt-2 text-xs text-slate-500">${haEsc(alert.target || "platform")} · ${haEsc(alert.generated_at || "--")}</div>
        </div>
      </button>
    `;
  }).join("");
  HA.list.querySelectorAll(".ha-alert-item").forEach(btn => {
    btn.addEventListener("click", () => haSelectAlert(btn.dataset.alertId));
  });
}

function haOpenRelatedView() {
  if (window.parent && typeof window.parent.openView === "function") {
    window.parent.openView("node_health");
    return;
  }
  window.location.href = "/node_health.html";
}

async function haSelectAlert(alertId) {
  if (!alertId) return;
  try {
    const payload = await haFetchJson(`/api/node-health/alerts/${encodeURIComponent(alertId)}`);
    const alert = payload?.alert || null;
    HA_STATE.selectedAlertId = alertId;
    localStorage.setItem(HA_FOCUS_KEY, alertId);
    haMarkRead([alertId]);
    HA.detailState.textContent = alert?.alert_id || "alert";
    HA.detail.innerHTML = alert ? `
      <div class="flex flex-wrap items-center gap-2">
        ${haSeverityBadge(alert.severity)}
        <span class="text-xs uppercase tracking-[0.2em] text-slate-500">${haEsc(alert.scope || "health")}</span>
        ${alert.target ? `<span class="text-xs text-slate-500">${haEsc(alert.target)}</span>` : ""}
      </div>
      <div class="mt-3 text-xl font-black text-white">${haEsc(alert.title || "Health alert")}</div>
      <div class="mt-3 text-sm text-slate-300">${haEsc(alert.detail || "No detail available.")}</div>
      <div class="mt-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-300">
        <div><strong>Recommendation:</strong> ${haEsc(alert.recommendation || "No recommendation available.")}</div>
        <div class="mt-2"><strong>Generated at:</strong> ${haEsc(alert.generated_at || "--")}</div>
        <div class="mt-2"><strong>Source backend:</strong> ${haEsc(payload?.source_backend || "node_health")}</div>
      </div>
      <div class="mt-4 flex flex-wrap gap-3">
        <button type="button" id="ha-open-related" class="rounded-xl border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-sm font-black text-sky-200 hover:bg-sky-500/20">${haEsc(payload?.alert?.related_action_label || "Open related service")}</button>
      </div>
    ` : `No health alert selected yet.`;
    const btn = document.getElementById("ha-open-related");
    if (btn) btn.addEventListener("click", haOpenRelatedView);
    await haLoadAlerts(false);
  } catch (error) {
    HA.detail.innerHTML = `<div class="text-red-300">${haEsc(error.message)}</div>`;
  }
}

async function haLoadAlerts(refresh = false) {
  const payload = await haFetchJson(`/api/node-health/alerts${refresh ? "?refresh=1" : ""}`);
  HA_STATE.alerts = payload?.alerts || [];
  haRenderSummary(payload);
  haRenderList(payload);
  const focus = localStorage.getItem(HA_FOCUS_KEY);
  if (focus && !HA_STATE.selectedAlertId && HA_STATE.alerts.some(alert => alert.alert_id === focus)) {
    HA_STATE.selectedAlertId = focus;
  }
  if (HA_STATE.selectedAlertId && HA_STATE.alerts.some(alert => alert.alert_id === HA_STATE.selectedAlertId)) {
    const current = HA_STATE.selectedAlertId;
    HA_STATE.selectedAlertId = null;
    await haSelectAlert(current);
  }
}

HA.btnRefresh.addEventListener("click", () => haLoadAlerts(true).catch(error => {
  HA.detail.innerHTML = `<div class="text-red-300">${haEsc(error.message)}</div>`;
}));
HA.btnMarkRead.addEventListener("click", () => {
  haMarkRead(HA_STATE.alerts.map(alert => alert.alert_id));
  haLoadAlerts(false).catch(() => {});
});
HA.btnOpenNodeHealth.addEventListener("click", haOpenRelatedView);

document.addEventListener("DOMContentLoaded", () => {
  haLoadAlerts(false).catch(error => {
    HA.detail.innerHTML = `<div class="text-red-300">${haEsc(error.message)}</div>`;
  });
});
