/* FORGE-VI Scientific Dashboard — JS */

const API = "/api/forge-vi/dashboard";
let DATA = null;
let SELECTED_RUN = 0;

// ── utils ────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
function esc(v) {
  return String(v ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function fmt(v, decimals = 2) {
  if (v === null || v === undefined) return "—";
  return Number(v).toFixed(decimals);
}
function pct(v) { return v !== null && v !== undefined ? (v * 100).toFixed(1) + "%" : "—"; }

const STATUS_COLOR = {
  recovered:     "#22c55e",
  satisfied:     "#22c55e",
  preserved:     "#22c55e",
  ambiguous:     "#eab308",
  partial:       "#eab308",
  degraded:      "#f97316",
  missing:       "#ef4444",
  failed:        "#ef4444",
  unknown:       "#64748b",
  not_applicable:"#64748b",
};
const STATUS_LABEL = {
  recovered:"rec", ambiguous:"amb", degraded:"deg", missing:"mis",
  satisfied:"✓", failed:"✗", partial:"~", not_applicable:"n/a", unknown:"?",
};

function stColor(s) { return STATUS_COLOR[s] || "#64748b"; }
function stLabel(s) { return STATUS_LABEL[s] || esc(s); }

function stPill(s, text) {
  const c = stColor(s);
  const lbl = text || stLabel(s);
  return `<span class="tag-pill" style="color:${c};border-color:${c}40;background:${c}12;">${lbl}</span>`;
}

function row(label, value, sub) {
  return `<div class="flex items-start justify-between gap-4 py-2 border-t border-slate-800/50">
    <span style="color:var(--muted);font-size:15px;">${esc(label)}</span>
    <span style="font-size:15px;font-weight:700;text-align:right;">${value}${sub ? `<br><span style="font-size:13px;color:var(--muted);">${sub}</span>` : ""}</span>
  </div>`;
}

// ── fetch ────────────────────────────────────────────────────────────────────
// 2026-07-20: added campaignId param + selector (see renderHeader below). Previously this
// endpoint had no notion of "which campaign" at all -- it aggregated every case this
// install has ever preserved under one hardcoded, unrelated campaign label, which read as
// "the last repetition's comparison" when it was actually a lifetime-of-the-lab mashup.
// Default (no campaignId) now asks the backend for its own best default (the most recently
// active campaign); "all" explicitly asks for the full historical mashup.
async function load(campaignId) {
  const url = campaignId ? `${API}?campaign_id=${encodeURIComponent(campaignId)}` : API;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  DATA = await res.json();
  render();
}

// ── HEADER BADGES ────────────────────────────────────────────────────────────
function renderHeader() {
  const c = DATA.campaign;
  const a = DATA.aggregate;
  const badges = [
    ["Campaign", c.id],
    ["Scenario", c.scenario_id],
    ["N executions", c.n_executions],
    ["Cases sealed", a.cases_sealed],
  ];
  $("campaign-badges").innerHTML = badges.map(([l, v]) =>
    `<span class="tag-pill" style="color:var(--info);border-color:#38bdf840;background:#38bdf810;font-size:14px;">${esc(l)}: <strong>${esc(String(v))}</strong></span>`
  ).join("");

  const selectorEl = $("campaign-selector");
  if (selectorEl) {
    const options = (DATA.available_campaigns || []).map(item => {
      const selected = item.campaign_id === DATA.selected_campaign_id ? " selected" : "";
      return `<option value="${esc(item.campaign_id)}"${selected}>${esc(item.campaign_id)} (${item.n_executions} exec, ${esc(item.scenario_id)})</option>`;
    }).join("");
    selectorEl.innerHTML = `${options}<option value="all">All campaigns (full history)</option>`;
    selectorEl.value = DATA.campaign.id && (DATA.available_campaigns || []).some(c2 => c2.campaign_id === DATA.campaign.id)
      ? DATA.campaign.id
      : "all";
  }
}

// ── KPI STRIP ────────────────────────────────────────────────────────────────
function kpiCard(val, label, sub, color) {
  return `<div class="glass2 rounded-[22px] p-5 kpi">
    <div class="kpi-val" style="color:${color || "var(--info)"};">${esc(String(val))}</div>
    <div class="kpi-lbl">${esc(label)}</div>
    ${sub ? `<div class="kpi-sub">${esc(sub)}</div>` : ""}
  </div>`;
}

function renderKpis() {
  const a = DATA.aggregate;
  const r0 = DATA.runs[0] || {};
  const cprPct = a.mean_cpr !== null ? (a.mean_cpr * 100).toFixed(1) + "%" : "—";
  const cprColor = a.mean_cpr >= 0.875 ? "#22c55e" : a.mean_cpr >= 0.625 ? "#eab308" : "#ef4444";

  $("kpi-strip").innerHTML = [
    kpiCard(a.n,             "Executions",             "evaluated runs",        "#38bdf8"),
    kpiCard(a.cases_sealed,  "Cases sealed",           "intervention_status=completed", "#22c55e"),
    kpiCard(pct(a.mean_integrity_ratio), "SHA-256 coverage", "primary artifacts",  "#a78bfa"),
    kpiCard(cprPct,          "CPR",                    `${a.n} runs`,             cprColor),
    kpiCard(r0.expected_edges ?? 8, "Expected edges",  "causal relations",       "#94a3b8"),
    kpiCard(a.edge_aggregate ? Object.values(a.edge_aggregate).filter(e=>e.recovered===a.n).length : "—",
            "Stable rec.",   "edges: 100% recovered",   "#22c55e"),
    kpiCard(a.cpr_stable ? "Stable" : "Variable", "CPR stability", "across runs", a.cpr_stable ? "#22c55e" : "#eab308"),
  ].join("");
}

// ── PIPELINE ─────────────────────────────────────────────────────────────────
function renderPipeline() {
  const a = DATA.aggregate;
  const lc = a.layer_coverage || {};

  const ACTIVE  = "#38bdf8";   // single unified color for all fully-active steps
  const PARTIAL = "#f97316";   // orange for degraded/partial coverage
  const NONE    = "rgba(148,163,184,0.35)";

  function stepColor(covered, total) {
    if (total === 0 || covered === 0) return NONE;
    if (covered < total)              return PARTIAL;
    return ACTIVE;
  }
  function alwaysActive()    { return ACTIVE; }

  const steps = [
    { icon:"⚙️", label:"Deploy &\nValidate",      color: alwaysActive() },
    { icon:"⚡", label:"Incident\nExecution",      color: alwaysActive() },
    { icon:"🔍", label:"Detection\n& Trigger",     color: stepColor(lc.alert?.covered    ?? 0, lc.alert?.total    ?? 1) },
    { icon:"🧠", label:"Memory\nAcquisition",      color: stepColor(lc.memory?.covered   ?? 0, lc.memory?.total   ?? 1) },
    { icon:"🌐", label:"PCAP\nImport",             color: stepColor(lc.network?.covered  ?? 0, lc.network?.total  ?? 1) },
    { icon:"🏭", label:"OT\nExport",              color: stepColor(lc.ot?.covered        ?? 0, lc.ot?.total       ?? 1) },
    { icon:"💾", label:"Disk\nPreservation",       color: stepColor(lc.disk?.covered     ?? 0, lc.disk?.total     ?? 1) },
    { icon:"🔒", label:"Case\nSealing",            color: a.cases_sealed > 0 ? (a.cases_sealed < a.n ? PARTIAL : ACTIVE) : NONE },
    { icon:"🔬", label:"Multilayer\nAnalysis",     color: stepColor(lc.analysis?.covered ?? 0, lc.analysis?.total ?? 1) },
    { icon:"🕸️", label:"Causal\nReconstruction",  color: a.mean_cpr !== null ? ACTIVE : NONE },
    { icon:"📊", label:"Cross-run\nComparison",    color: a.n > 1 ? ACTIVE : NONE },
  ];

  $("pipeline-diagram").innerHTML = steps.map((s, i) => {
    const active = s.color !== NONE;
    const bg = active ? s.color + "1a" : "transparent";
    const arrow = i < steps.length - 1 ? `<div class="pipe-arrow"></div>` : "";
    return `<div class="pipe-step">
      <div class="pipe-icon" style="border-color:${s.color};background:${bg};">${s.icon}</div>
      <div class="pipe-label" style="color:${active ? s.color : "var(--muted)"};">${s.label.replace(/\n/g,"<br>")}</div>
    </div>${arrow}`;
  }).join("");
}

// ── CPR DONUT ────────────────────────────────────────────────────────────────
// Palette: warm editorial tones
const P = {
  rec:  "#1d7a47",   // deep forest
  amb:  "#c47a0a",   // warm bronze
  deg:  "#b5450e",   // burnt sienna
  mis:  "#9b1b1b",   // deep garnet
  tgt:  "#3d6e8a",   // steel teal (target/ideal)
  muted:"#8fa3bf",
};

function renderCprDonut() {
  const a = DATA.aggregate;
  const r0 = DATA.runs[0] || {};
  const total = r0.expected_edges || 8;
  const edgeMeta = DATA.edge_meta || [];

  const rec = DATA.runs.reduce((s,r) => s + (r.recovered_edges || 0), 0) / DATA.runs.length;
  const amb = DATA.runs.reduce((s,r) => s + (r.ambiguous_edges || 0), 0) / DATA.runs.length;
  const deg = DATA.runs.reduce((s,r) => s + (r.degraded_edges || 0), 0) / DATA.runs.length;
  const mis = DATA.runs.reduce((s,r) => s + (r.missing_edges || 0), 0) / DATA.runs.length;

  const segments = [
    { val:rec, color:P.rec, label:"Recovered" },
    { val:amb, color:P.amb, label:"Ambiguous" },
    { val:deg, color:P.deg, label:"Degraded" },
    { val:mis, color:P.mis, label:"Missing" },
  ].filter(s => s.val > 0);

  // ── Donut SVG ──
  const cx=90, cy=90, R=72, Ri=50;
  let angle = -Math.PI / 2;
  const paths = segments.map(seg => {
    const slice = (seg.val / total) * 2 * Math.PI;
    const x1=cx+R*Math.cos(angle), y1=cy+R*Math.sin(angle);
    angle += slice;
    const x2=cx+R*Math.cos(angle), y2=cy+R*Math.sin(angle);
    const xi1=cx+Ri*Math.cos(angle-slice), yi1=cy+Ri*Math.sin(angle-slice);
    const xi2=cx+Ri*Math.cos(angle), yi2=cy+Ri*Math.sin(angle);
    const large = slice > Math.PI ? 1 : 0;
    return `<path d="M${x1},${y1} A${R},${R},0,${large},1,${x2},${y2} L${xi2},${yi2} A${Ri},${Ri},0,${large},0,${xi1},${yi1} Z" fill="${seg.color}" opacity=".92" stroke="rgba(0,0,0,.18)" stroke-width="1"/>`;
  }).join("");

  const cprPct = a.mean_cpr !== null ? (a.mean_cpr * 100).toFixed(1) : "—";
  const cprColor = a.mean_cpr >= 0.875 ? P.rec : a.mean_cpr >= 0.625 ? P.amb : P.mis;

  const svg = `<svg width="180" height="180" viewBox="0 0 180 180">
    ${paths}
    <text x="90" y="86" text-anchor="middle" fill="${cprColor}" font-size="26" font-weight="900" font-family="Inter,sans-serif">${cprPct}%</text>
    <text x="90" y="104" text-anchor="middle" fill="${P.muted}" font-size="12" font-family="Inter,sans-serif" letter-spacing="3">CPR</text>
  </svg>`;

  const legend = segments.map(s =>
    `<div class="flex items-center gap-2"><span style="width:12px;height:12px;border-radius:3px;background:${s.color};display:inline-block;flex-shrink:0;"></span><span style="font-size:13px;">${s.label}: <strong>${s.val.toFixed(1)}</strong></span></div>`
  ).join("");

  $("cpr-donut-wrap").innerHTML = svg + `<div class="flex flex-col gap-2 mt-3 w-full px-2">${legend}</div>`;

  // Per-edge dominant status across all runs
  const edgeDominant = edgeMeta.map(e => {
    const statuses = DATA.runs.map(r => {
      const st = (r.edge_states || {})[e.label];
      return typeof st === "object" ? (st?.support || "unknown") : (st || "unknown");
    });
    return ["recovered","ambiguous","degraded","missing"].find(s => statuses.filter(x=>x===s).length === statuses.length) || statuses[0] || "unknown";
  });
  const statusColor = s => ({ recovered:P.rec, ambiguous:P.amb, degraded:P.deg, missing:P.mis }[s] || "#475569");

  // ── Figure 1: Edge CPR Contribution — binary weights ──
  // CPR = recovered / total; each recovered edge contributes 1/total to CPR, others contribute 0.
  const recCount   = edgeDominant.filter(s => s === "recovered").length;
  const edgeWeight = 1 / total;

  const edgeStripItems = edgeMeta.map((e, i) => {
    const dom = edgeDominant[i];
    const c   = statusColor(dom);
    const isRec = dom === "recovered";
    const cprContrib = isRec ? (edgeWeight * 100).toFixed(1) : "0.0";  // binary CPR contribution
    return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
      <div style="width:100%;height:38px;background:${c}${isRec?"28":"12"};border:${isRec?"2":"1.5"}px solid ${c}${isRec?"88":"44"};border-radius:8px;display:flex;align-items:center;justify-content:center;">
        <span style="font-size:13px;font-weight:900;color:${c};">${esc(e.label)}</span>
      </div>
      <span style="font-size:12px;font-weight:800;color:${c};">${cprContrib}%</span>
    </div>`;
  }).join("");

  const fig1 = `<div>
    <div style="font-size:12px;letter-spacing:.2em;text-transform:uppercase;color:${P.amb};font-weight:900;margin-bottom:6px;">Actual CPR contribution per edge</div>
    <div style="font-size:13px;color:${P.muted};margin-bottom:10px;">
      CPR = recovered / total = <strong style="color:var(--ink);">${recCount} / ${total} = ${(recCount/total*100).toFixed(1)}%</strong> &nbsp;·&nbsp;
      each recovered edge contributes <strong style="color:${P.rec};">${(edgeWeight*100).toFixed(1)}%</strong> &nbsp;·&nbsp;
      non-recovered edges contribute <strong style="color:${P.amb};">0%</strong> to CPR
    </div>
    <div style="display:flex;gap:6px;">${edgeStripItems}</div>
  </div>`;

  // ── Figure 2: Edge Reproducibility Across Runs ──
  // For each edge, count how many runs produced each status.
  // Perfect σ=0 means 100% consistency — scientifically meaningful for reproducibility claims.
  const edgeConsistency = edgeMeta.map(e => {
    const counts = {};
    DATA.runs.forEach(r => {
      const st = (r.edge_states || {})[e.label];
      const s = (typeof st === "object" ? st?.support : st) || "unknown";
      counts[s] = (counts[s] || 0) + 1;
    });
    const dominant = Object.entries(counts).sort((a,b) => b[1]-a[1])[0];
    const consistency = dominant ? (dominant[1] / DATA.runs.length * 100).toFixed(0) : "0";
    return { label: e.label, desc: e.desc, counts, dominant: dominant?.[0] || "unknown", consistency };
  });

  const ORDER = ["recovered","ambiguous","degraded","missing","unknown"];
  const statusLabel = { recovered:"rec", ambiguous:"amb", degraded:"deg", missing:"mis", unknown:"?" };

  const reproRows = edgeConsistency.map(e => {
    const c = statusColor(e.dominant);
    const bars = ORDER.map(st => {
      const n = e.counts[st] || 0;
      if (!n) return "";
      const w = (n / DATA.runs.length * 100).toFixed(0);
      const bc = statusColor(st);
      return `<div title="${st}: ${n}/${DATA.runs.length}" style="height:14px;width:${w}%;min-width:4px;background:${bc};border-radius:3px;flex-shrink:0;" ></div>`;
    }).join("");
    const statBadge = `<span style="font-size:11px;font-weight:900;color:${c};background:${c}18;border:1px solid ${c}44;border-radius:5px;padding:1px 7px;">${statusLabel[e.dominant]}</span>`;
    return `<tr>
      <td style="padding:7px 10px;font-size:13px;font-weight:900;color:${c};">${esc(e.label)}</td>
      <td style="padding:7px 10px;font-size:12px;color:rgba(148,163,184,.75);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(e.desc)}</td>
      <td style="padding:7px 10px;">${statBadge}</td>
      <td style="padding:7px 14px;">
        <div style="display:flex;gap:2px;width:120px;height:14px;background:rgba(30,41,59,.6);border-radius:4px;overflow:hidden;">${bars}</div>
      </td>
      <td style="padding:7px 10px;font-size:13px;font-weight:900;color:${parseInt(e.consistency)===100?P.rec:P.amb};">${e.consistency}%</td>
    </tr>`;
  }).join("");

  const fig2 = `<div>
    <div style="font-size:12px;letter-spacing:.2em;text-transform:uppercase;color:${P.tgt};font-weight:900;margin-bottom:8px;">Edge State Reproducibility — ${DATA.runs.length} runs</div>
    <div style="font-size:13px;color:${P.muted};margin-bottom:12px;">
      For each causal edge, state distribution across all experimental runs.
      Consistency = fraction of runs in which the edge held its dominant state.
    </div>
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr style="border-bottom:1px solid rgba(148,163,184,.15);">
          <th style="padding:4px 10px;font-size:11px;color:${P.muted};text-align:left;letter-spacing:.1em;text-transform:uppercase;">Edge</th>
          <th style="padding:4px 10px;font-size:11px;color:${P.muted};text-align:left;letter-spacing:.1em;text-transform:uppercase;">Description</th>
          <th style="padding:4px 10px;font-size:11px;color:${P.muted};text-align:left;letter-spacing:.1em;text-transform:uppercase;">Dominant state</th>
          <th style="padding:4px 10px;font-size:11px;color:${P.muted};text-align:left;letter-spacing:.1em;text-transform:uppercase;">Run distribution</th>
          <th style="padding:4px 10px;font-size:11px;color:${P.muted};text-align:left;letter-spacing:.1em;text-transform:uppercase;">Consistency</th>
        </tr>
      </thead>
      <tbody>${reproRows}</tbody>
    </table>
  </div>`;

  $("cpr-stats").innerHTML = fig1 + fig2;
}

// ── CAUSAL HEATMAP ───────────────────────────────────────────────────────────
function renderCausalHeatmap() {
  const edgeMeta = DATA.edge_meta || [];
  const runs = DATA.runs;

  const colHeaders = edgeMeta.map(e =>
    `<th style="padding:0 6px 12px;min-width:80px;text-align:center;font-size:15px;font-weight:900;" title="${esc(e.desc)}">${esc(e.label)}</th>`
  ).join("");

  const bodyRows = runs.map(r => {
    const cells = edgeMeta.map(e => {
      const st = (r.edge_states || {})[e.label];
      const sup = typeof st === "object" ? (st?.support || "unknown") : (st || "unknown");
      const c = stColor(sup);
      const lbl = stLabel(sup);
      return `<td style="padding:4px 6px;text-align:center;">
        <div class="hm-cell has-tooltip" style="background:${c}28;color:${c};border:1.5px solid ${c}44;">${lbl}
          <div class="tooltip">${esc(e.desc)}: ${esc(sup)}</div>
        </div>
      </td>`;
    }).join("");
    const cprColor = r.cpr>=0.875?'#22c55e':r.cpr>=0.625?'#eab308':'#ef4444';
    return `<tr>
      <td style="padding:4px 16px 4px 0;white-space:nowrap;font-size:14px;font-weight:700;color:var(--ink);">${esc(r.exec_id)}</td>
      ${cells}
      <td style="padding:4px 4px 4px 16px;font-size:15px;font-weight:900;color:${cprColor};">${pct(r.cpr)}</td>
    </tr>`;
  }).join("");

  $("causal-heatmap").innerHTML = `<table style="border-collapse:separate;border-spacing:0;width:100%;">
    <thead><tr>
      <th style="padding-bottom:12px;padding-right:16px;font-size:14px;text-align:left;">Run</th>
      ${colHeaders}
      <th style="padding-bottom:12px;padding-left:16px;min-width:70px;font-size:15px;">CPR</th>
    </tr></thead>
    <tbody>${bodyRows}</tbody>
  </table>`;
}

// ── EDGE TABLE ───────────────────────────────────────────────────────────────
function renderEdgeTable() {
  const edgeMeta = DATA.edge_meta || [];
  const agg = DATA.aggregate.edge_aggregate || {};
  const runs = DATA.runs;

  const rows = edgeMeta.map(e => {
    const ea = agg[e.label] || {};
    const dominant = ["recovered","ambiguous","degraded","missing"].find(s => (ea[s]||0) === (DATA.aggregate.n)) || "mixed";
    const sup = dominant !== "mixed" ? dominant : "ambiguous";
    const stable = ea.stable;

    // First run sample for temporal + required_evidence
    const sample = (runs[0]?.edge_states || {})[e.label] || {};
    const temporal = typeof sample === "object" ? (sample.temporal || "—") : "—";
    const reqEv = Array.isArray(e.required_evidence) ? e.required_evidence.join(", ") : "—";

    return `<tr class="edge-row" data-edge="${esc(e.label)}" onclick="openEdgeModal('${esc(e.label)}')">
      <td><span class="mono" style="font-weight:900;color:var(--info);">${esc(e.label)}</span></td>
      <td style="max-width:260px;">${esc(e.desc)}</td>
      <td style="font-size:14px;color:var(--muted);">${esc(reqEv)}</td>
      <td>${stPill(sup)}</td>
      <td>${stPill(temporal === "not_required" ? "not_applicable" : temporal, temporal)}</td>
      <td>${stable ? '<span style="color:#22c55e;font-weight:900;">✓ Stable</span>' : '<span style="color:#eab308;">~ Mixed</span>'}</td>
    </tr>`;
  }).join("");

  $("edge-table").innerHTML = rows;
}

// ── EDGE MODAL ───────────────────────────────────────────────────────────────
function openEdgeModal(label) {
  const edgeMeta = (DATA.edge_meta || []).find(e => e.label === label) || {};
  const runs = DATA.runs;
  const agg = DATA.aggregate.edge_aggregate || {};
  const ea = agg[label] || {};

  $("edge-modal-title").textContent = `${label} — ${edgeMeta.desc || ""}`;

  const runRows = runs.map(r => {
    const st = (r.edge_states || {})[label] || {};
    const sup = st.support || "unknown";
    const tmp = st.temporal || "—";
    const lims = (st.limitations || []).join("; ") || "none";
    const refs = (st.evidence_refs || []).join(", ") || "—";
    return `<div class="glass2 rounded-[14px] p-4">
      <div class="flex items-center justify-between gap-3">
        <span class="mono text-xs font-bold" style="color:var(--info);">${esc(r.exec_id)}</span>
        <div class="flex gap-2">${stPill(sup)} ${stPill(tmp === "not_required" ? "not_applicable" : tmp, tmp)}</div>
      </div>
      <div class="mt-2 text-xs" style="color:var(--muted);">Evidence: ${esc(refs)}</div>
      ${lims !== "none" ? `<div class="mt-1 text-xs" style="color:#ef4444;">⚠ ${esc(lims)}</div>` : ""}
    </div>`;
  }).join("");

  $("edge-modal-body").innerHTML = `
    <div class="glass2 rounded-[14px] p-4 mb-3">
      <div class="text-xs font-black uppercase tracking-[.18em] text-slate-400 mb-2">Required Evidence</div>
      <div class="text-sm">${esc((edgeMeta.required_evidence || []).join(", ") || "—")}</div>
      <div class="mt-3 flex flex-wrap gap-2 text-xs">
        ${["recovered","ambiguous","degraded","missing"].map(s =>
          `<span style="color:${stColor(s)};">${s}: <strong>${ea[s]||0}/${DATA.aggregate.n}</strong></span>`
        ).join("")}
      </div>
    </div>
    <div class="space-y-2">${runRows}</div>`;

  const m = $("edge-modal");
  m.style.display = "flex";
}

// ── EVIDENCE MATRIX ──────────────────────────────────────────────────────────
function renderEvidenceMatrix() {
  const layers = DATA.layer_keys || [];
  const runs = DATA.runs;
  const a = DATA.aggregate;

  const colHeaders = layers.map(l =>
    `<th style="padding:0 8px 12px;text-align:center;min-width:80px;font-size:13px;text-transform:uppercase;letter-spacing:.08em;">${esc(l)}</th>`
  ).join("");

  const bodyRows = runs.map(r => {
    const cells = layers.map(l => {
      const ok = (r.evidence_layers || {})[l];
      const c = ok ? "#22c55e" : "#ef4444";
      const lbl = ok ? "✓" : "✗";
      return `<td style="text-align:center;padding:6px 8px;">
        <span style="color:${c};font-weight:900;font-size:18px;" title="${ok?'preserved':'missing'}">${lbl}</span>
      </td>`;
    }).join("");

    return `<tr>
      <td style="padding:6px 16px 6px 0;white-space:nowrap;font-size:14px;font-weight:700;color:var(--ink);">${esc(r.exec_id)}</td>
      ${cells}
    </tr>`;
  }).join("");

  // Coverage summary row
  const summaryRow = layers.map(l => {
    const lc = (a.layer_coverage || {})[l] || {};
    const ratio = lc.total > 0 ? lc.covered / lc.total : 0;
    const c = ratio === 1 ? "#22c55e" : ratio > 0 ? "#eab308" : "#ef4444";
    return `<td style="text-align:center;padding:6px 8px;">
      <span style="color:${c};font-size:13px;font-weight:900;">${lc.covered||0}/${lc.total||0}</span>
    </td>`;
  }).join("");

  $("evidence-matrix").innerHTML = `<table style="border-collapse:separate;border-spacing:0;width:100%;">
    <thead><tr>
      <th style="padding-bottom:12px;padding-right:16px;font-size:14px;text-align:left;">Run</th>
      ${colHeaders}
    </tr></thead>
    <tbody>
      ${bodyRows}
      <tr style="border-top:2px solid rgba(148,163,184,0.2);">
        <td style="padding:6px 16px 6px 0;font-size:15px;font-weight:900;color:var(--muted);">COVERAGE</td>
        ${summaryRow}
      </tr>
    </tbody>
  </table>`;
}

// ── OPERATIONAL METRICS ──────────────────────────────────────────────────────
function barRow(label, mean, std, min, max, maxVal, color, note) {
  // For metrics where mean can be negative (pre-alert acquisition), clamp bar to 0 but show real value
  const displayMean = Math.max(0, mean);
  const w = maxVal > 0 ? Math.min(100, (displayMean / maxVal) * 100) : 0;
  const noteHtml = note ? ` <span style="color:var(--muted);font-size:10px;">${esc(note)}</span>` : "";
  return `<div class="mb-3">
    <div class="flex items-center justify-between text-xs mb-1">
      <span style="color:var(--muted);">${esc(label)}</span>
      <span style="font-weight:900;color:${color};">${fmt(mean,1)}s <span style="color:var(--muted);font-weight:400;">±${fmt(std,1)} [${fmt(min,0)}–${fmt(max,0)}]</span>${noteHtml}</span>
    </div>
    <div class="bar-track">
      <div class="bar-fill" style="width:${w.toFixed(1)}%;background:${color};"></div>
    </div>
  </div>`;
}

function renderM2() {
  const ls = DATA.aggregate.latency_stats || {};
  const defs = [
    ["Attack duration",          "attack_duration_s",           "#f97316", null],
    ["Attack → Alert",           "attack_to_alert_s",           "#eab308", null],
    ["Alert → Memory start",     "alert_to_memory_start_s",     "#7c3aed", ls.alert_to_memory_start_s?.min < 0 ? "pre-alert in 1 run" : null],
    ["Alert → Memory sealed",    "alert_to_memory_sealed_s",    "#a78bfa", null],
    ["Alert → Case sealed",      "alert_to_case_sealed_s",      "#38bdf8", null],
    ["Acquisition duration",     "acquisition_duration_s",      "#22c55e", null],
  ];
  const maxVal = Math.max(...defs.map(([,k]) => ls[k]?.max || 0));
  $("m2-panel").innerHTML = defs.map(([lbl, k, c, note]) => {
    const s = ls[k];
    if (!s) return `<div class="text-xs text-slate-500 mb-2">${esc(lbl)}: no data</div>`;
    return barRow(lbl, s.mean, s.std, s.min, s.max, maxVal, c, note);
  }).join("");
}

function renderM3() {
  const vs = DATA.aggregate.volume_stats || {};
  const runs = DATA.runs;
  const maxMemGib  = Math.max(...runs.map(r => r.volumes?.memory_gib || 0), 1);
  const maxDiskGib = Math.max(...runs.map(r => r.volumes?.disk_gib   || 0), 1);
  const maxPcapGib = Math.max(...runs.map(r => r.volumes?.pcap_gib   || 0), 1);

  const aggMem  = vs.memory_gib;
  const aggDisk = vs.disk_gib;
  const aggPcap = vs.pcap_gib;

  const aggRow = (label, s, color) => s
    ? `<div class="text-xs mb-1" style="color:${color};">${esc(label)}: ${fmt(s.mean,2)} ± ${fmt(s.std,2)} GiB&nbsp;&nbsp;<span style="opacity:.6;">[${fmt(s.min,2)}–${fmt(s.max,2)}]</span></div>`
    : "";

  const runBars = runs.map(r => {
    const mem  = r.volumes?.memory_gib || 0;
    const disk = r.volumes?.disk_gib   || 0;
    const pcap = r.volumes?.pcap_gib   || 0;
    const nDisk = r.volumes?.n_disk_images || 0;
    const nMem  = r.volumes?.n_memory_dumps || 0;
    return `<div class="mb-2">
      <div class="text-xs text-slate-500 mb-1">${esc(r.exec_id)}</div>
      <div class="flex gap-3 items-center">
        <div class="flex-1">
          <div class="bar-track mb-1"><div class="bar-fill" style="width:${(mem/maxMemGib*100).toFixed(1)}%;background:#7c3aed;"></div></div>
          ${disk > 0 ? `<div class="bar-track mb-1"><div class="bar-fill" style="width:${(disk/maxDiskGib*100).toFixed(1)}%;background:#0ea5e9;"></div></div>` : ""}
          <div class="bar-track mb-1"><div class="bar-fill" style="width:${(pcap/maxPcapGib*100).toFixed(1)}%;background:#2563eb;"></div></div>
        </div>
        <div class="text-xs mono" style="white-space:nowrap;min-width:180px;">
          <span style="color:#7c3aed;">mem ${fmt(mem,2)} GiB</span> (${nMem}×)<br>
          ${disk > 0 ? `<span style="color:#0ea5e9;">disk ${fmt(disk,1)} GiB</span> (${nDisk}×)<br>` : ""}
          <span style="color:#2563eb;">pcap ${fmt(pcap,2)} GiB</span>
        </div>
      </div>
    </div>`;
  }).join("");

  $("m3-panel").innerHTML = `
    <div class="flex gap-4 text-xs mb-3">
      <span style="color:#7c3aed;">■ Memory</span>
      <span style="color:#0ea5e9;">■ Disk</span>
      <span style="color:#2563eb;">■ Network/PCAP</span>
    </div>
    <div class="mb-3 p-2 rounded" style="background:rgba(255,255,255,.04);">
      ${aggRow("Memory (mean ± σ)", aggMem, "#7c3aed")}
      ${aggRow("Disk (mean ± σ)", aggDisk, "#0ea5e9")}
      ${aggRow("PCAP (mean ± σ)", aggPcap, "#2563eb")}
    </div>
    ${runBars}`;
}

function renderM1() {
  const runs = DATA.runs;
  const checks = [
    ["Topology match",  "validation_gate_passed"],
    ["Manifest",        "manifest_ok"],
    ["Custody chain",   "custody_ok"],
  ];
  const items = runs.map(r => {
    const gate = r.validation_gate_passed;
    const mani = (r.sha256_covered || 0) > 0;
    const cust = (r.custody_entries || 0) > 0;
    const vals = [gate, mani, cust];
    const ok = vals.filter(Boolean).length;
    const total = vals.length;
    const c = ok === total ? "#22c55e" : ok > 0 ? "#eab308" : "#ef4444";
    return `<div class="flex items-center justify-between py-2 border-t border-slate-800/40">
      <span class="text-xs">${esc(r.exec_id)}</span>
      <div class="flex gap-2 text-xs">
        ${vals.map((v,i) => `<span class="has-tooltip" style="color:${v?'#22c55e':'#ef4444'};cursor:default;">${v?'✓':'✗'}
          <div class="tooltip">${esc(["Topology","Manifest","Custody"][i])}: ${v?'pass':'fail'}</div>
        </span>`).join("")}
        <span style="color:${c};font-weight:900;">${ok}/${total}</span>
      </div>
    </div>`;
  }).join("");
  $("m1-panel").innerHTML = items;
}

function renderM4() {
  const runs = DATA.runs;
  const items = runs.map(r => {
    const diskFailed = !(r.evidence_layers?.disk);
    const failures = diskFailed ? 1 : 0;
    const c = failures === 0 ? "#22c55e" : "#ef4444";
    return `<div class="flex items-center justify-between py-2 border-t border-slate-800/40">
      <span class="text-xs">${esc(r.exec_id)}</span>
      <div class="flex gap-3 items-center">
        ${diskFailed ? '<span style="font-size:14px;color:#ef4444;">disk ✗</span>' : '<span style="font-size:14px;color:#22c55e;">no failures</span>'}
        <span style="color:${c};font-weight:900;font-size:15px;">${failures}</span>
      </div>
    </div>`;
  }).join("");
  $("m4-panel").innerHTML = items;
}

// ── C1-C5 / E1-E4 ────────────────────────────────────────────────────────────
function renderCriteriaMatrix(containerId, meta, aggKey, runsKey) {
  const runs = DATA.runs;
  const agg = DATA.aggregate[aggKey] || {};

  const colHeaders = meta.map(m =>
    `<th style="text-align:center;padding:0 10px 12px;min-width:60px;font-size:15px;" title="${esc(m.description)}">${esc(m.id)}</th>`
  ).join("");

  const bodyRows = runs.map(r => {
    const cells = meta.map(m => {
      const st = (r[runsKey] || {})[m.id] || "unknown";
      const c = stColor(st);
      const lbl = stLabel(st);
      return `<td style="text-align:center;padding:6px 8px;">
        <span class="has-tooltip" style="color:${c};font-weight:900;font-size:16px;cursor:default;">${lbl}
          <div class="tooltip">${esc(m.name)}: ${esc(st)}</div>
        </span>
      </td>`;
    }).join("");
    return `<tr><td style="padding:6px 12px 6px 0;font-size:14px;font-weight:700;color:var(--ink);">${esc(r.exec_id)}</td>${cells}</tr>`;
  }).join("");

  const summaryRow = meta.map(m => {
    const a = agg[m.id] || {};
    const s = a.total > 0 ? a.satisfied / a.total : 0;
    const c = s === 1 ? "#22c55e" : s > 0 ? "#eab308" : "#ef4444";
    return `<td style="text-align:center;padding:6px 8px;font-size:14px;font-weight:900;color:${c};">
      ${a.satisfied||0}/${a.total||0}
    </td>`;
  }).join("");

  const legend = meta.map(m =>
    `<div class="py-2 border-t border-slate-800/40" style="font-size:14px;"><strong style="color:var(--info);">${esc(m.id)}</strong>: ${esc(m.name)} <span style="color:var(--muted);">— ${esc(m.description)}</span></div>`
  ).join("");

  $(containerId).innerHTML = `
    <table style="border-collapse:separate;border-spacing:0;width:100%;" class="mb-4">
      <thead><tr><th style="padding-bottom:12px;padding-right:8px;">Run</th>${colHeaders}</tr></thead>
      <tbody>
        ${bodyRows}
        <tr style="border-top:2px solid rgba(148,163,184,0.2);">
          <td style="font-size:14px;font-weight:900;color:var(--muted);">TOTAL</td>
          ${summaryRow}
        </tr>
      </tbody>
    </table>
    <div class="mt-2">${legend}</div>`;
}

// ── INTEGRITY PANEL ──────────────────────────────────────────────────────────
function renderIntegrity() {
  const a = DATA.aggregate;
  const runs = DATA.runs;

  // Aggregate stats
  const totalArtifacts = runs.reduce((s,r) => s + (r.total_artifacts||0), 0);
  const sha256Covered  = runs.reduce((s,r) => s + (r.sha256_covered||0), 0);
  const custodyEntries = runs.reduce((s,r) => s + (r.custody_entries||0), 0);
  const intRatio = totalArtifacts > 0 ? sha256Covered / totalArtifacts : 0;

  const col1 = `<div class="glass2 rounded-[18px] p-5">
    <div class="text-xs uppercase tracking-[.2em] text-slate-400 font-black mb-3">Aggregate Integrity</div>
    ${row("SHA-256 coverage", pct(intRatio), `${sha256Covered} / ${totalArtifacts} artifacts`)}
    ${row("Custody entries", String(custodyEntries), `${Math.round(custodyEntries/runs.length)} per run avg`)}
    ${row("Manifest presence", `${runs.filter(r=>r.evidence_layers?.manifest).length}/${runs.length}`, "runs with manifest.json")}
    ${row("Integrity status", stPill(intRatio >= 0.95 ? "satisfied" : intRatio >= 0.8 ? "partial" : "failed",
         intRatio >= 0.95 ? "Verified" : intRatio >= 0.8 ? "Partial" : "Failed"))}
  </div>`;

  const col2 = `<div class="glass2 rounded-[18px] p-5">
    <div class="text-xs uppercase tracking-[.2em] text-slate-400 font-black mb-3">Per-Run SHA-256 Coverage</div>
    ${runs.map(r => {
      const ratio = r.total_artifacts > 0 ? r.sha256_covered / r.total_artifacts : 0;
      const c = ratio >= 0.95 ? "#22c55e" : ratio >= 0.8 ? "#eab308" : "#ef4444";
      return `<div class="mb-2">
        <div class="flex justify-between text-xs mb-1">
          <span style="color:var(--muted);">${esc(r.exec_id)}</span>
          <span style="color:${c};font-weight:900;">${pct(ratio)}</span>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:${(ratio*100).toFixed(1)}%;background:${c};"></div></div>
      </div>`;
    }).join("")}
  </div>`;

  const col3 = `<div class="glass2 rounded-[18px] p-5">
    <div class="text-xs uppercase tracking-[.2em] text-slate-400 font-black mb-3">Custody Chain Entries</div>
    ${runs.map(r => {
      const n = r.custody_entries || 0;
      const maxN = Math.max(...runs.map(x => x.custody_entries || 0), 1);
      const c = "#38bdf8";
      return `<div class="mb-2">
        <div class="flex justify-between text-xs mb-1">
          <span style="color:var(--muted);">${esc(r.exec_id)}</span>
          <span style="color:${c};font-weight:900;">${n} entries</span>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:${(n/maxN*100).toFixed(1)}%;background:${c};"></div></div>
      </div>`;
    }).join("")}
  </div>`;

  $("integrity-panel").innerHTML = col1 + col2 + col3;
}

// ── FOC MODEL ────────────────────────────────────────────────────────────────
function renderFocSelector() {
  const runs = DATA.runs;
  $("foc-run-selector").innerHTML = runs.map((r, i) =>
    `<button onclick="selectFocRun(${i})" id="foc-btn-${i}"
      class="rounded-2xl px-3 py-2 text-xs font-extrabold tracking-[.14em] uppercase cursor-pointer"
      style="background:${i===SELECTED_RUN?'rgba(56,189,248,.15)':'rgba(15,23,42,.7)'};border:1px solid ${i===SELECTED_RUN?'#38bdf8':'rgba(148,163,184,.18)'};color:${i===SELECTED_RUN?'#38bdf8':'var(--muted)'};">
      ${esc(r.exec_id)}
    </button>`
  ).join("");
}

function selectFocRun(i) {
  SELECTED_RUN = i;
  renderFocSelector();
  renderFocPanel();
}

function renderFocPanel() {
  const r = DATA.runs[SELECTED_RUN];
  if (!r) return;

  const fmtTs = ts => ts ? ts.replace("T"," ").replace(/\.\d+/, "").replace("+00:00","Z") : "—";

  const col1 = `<div class="glass2 rounded-[18px] p-5">
    <div class="text-xs uppercase tracking-[.2em] text-slate-400 font-black mb-3">Incident Window</div>
    ${row("Attack started",     fmtTs(r.attack_started_at))}
    ${row("Alert observed",     fmtTs(r.alert_observed_at))}
    ${row("Case sealed",        fmtTs(r.case_sealed_at))}
    ${row("Attack duration",    r.latencies?.attack_duration_s != null ? fmt(r.latencies.attack_duration_s,1) + "s" : "—")}
    ${row("Alert to case sealed", r.latencies?.alert_to_case_sealed_s != null ? fmt(r.latencies.alert_to_case_sealed_s,0) + "s" : "—")}
  </div>`;

  const col2 = `<div class="glass2 rounded-[18px] p-5">
    <div class="text-xs uppercase tracking-[.2em] text-slate-400 font-black mb-3">Acquisition Profile</div>
    ${row("Profile ID",         r.acquisition_profile || "—")}
    ${row("Intervention status", stPill(r.intervention_status || "unknown", r.intervention_status || "—"))}
    ${row("Memory",             stPill(r.evidence_layers?.memory ? "preserved" : "missing"))}
    ${row("Network / PCAP",     stPill(r.evidence_layers?.network ? "preserved" : "missing"))}
    ${row("OT export",          stPill(r.evidence_layers?.ot ? "preserved" : "missing"))}
    ${row("Disk snapshot",      stPill(r.evidence_layers?.disk ? "preserved" : "missing"))}
  </div>`;

  const col3 = `<div class="glass2 rounded-[18px] p-5">
    <div class="text-xs uppercase tracking-[.2em] text-slate-400 font-black mb-3">Reconstruction State</div>
    ${row("CPR",                `<span style="color:${r.cpr>=0.875?'#22c55e':r.cpr>=0.625?'#eab308':'#ef4444'};font-weight:900;">${pct(r.cpr)}</span>`)}
    ${row("Recoverability",     stPill(r.recoverability_label || "unknown", r.recoverability_label || "—"))}
    ${row("Temporal confidence",stPill(r.temporal_confidence_state === "limited" ? "partial" : r.temporal_confidence_state || "unknown", r.temporal_confidence_state || "—"))}
    ${row("Analysis coverage",  r.analysis_coverage_ratio != null ? pct(r.analysis_coverage_ratio) : "—")}
    ${row("Reconstruction conf.",r.reconstruction_confidence != null ? fmt(r.reconstruction_confidence,4) : "—")}
  </div>`;

  $("foc-panel").innerHTML = col1 + col2 + col3;
}

// ── RENDER ALL ────────────────────────────────────────────────────────────────
function render() {
  renderHeader();
  renderKpis();
  renderPipeline();
  renderCprDonut();
  renderCausalHeatmap();
  renderEdgeTable();
  renderEvidenceMatrix();
  renderM1();
  renderM2();
  renderM3();
  renderM4();
  renderCriteriaMatrix("c-matrix", DATA.invariant_meta || [], "c_aggregate", "c_checks");
  renderCriteriaMatrix("e-matrix", DATA.evidence_criteria_meta || [], "e_aggregate", "e_checks");
  renderIntegrity();
  renderFocSelector();
  renderFocPanel();

  $("loading-overlay").style.display = "none";
  $("app").style.display = "block";
}

// ── PUBLICATION MODE ──────────────────────────────────────────────────────────
let pubMode = false;
function togglePubMode() {
  pubMode = !pubMode;
  document.body.classList.toggle("pub-mode", pubMode);
  $("btn-pub-mode").textContent = pubMode ? "Exit Publication Mode" : "Publication Mode";
  $("btn-pub-mode").style.background = pubMode
    ? "linear-gradient(135deg,#22c55e,#16a34a)"
    : "linear-gradient(135deg,#7c3aed,#4f46e5)";
}

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  $("btn-pub-mode")?.addEventListener("click", togglePubMode);
  $("btn-refresh")?.addEventListener("click", () => { $("loading-overlay").style.display="flex"; $("app").style.display="none"; load($("campaign-selector")?.value).catch(e => { alert("Error loading data: " + e.message); }); });
  $("campaign-selector")?.addEventListener("change", (e) => { load(e.target.value).catch(err => alert("Error loading data: " + err.message)); });
  $("edge-modal-close")?.addEventListener("click", () => { $("edge-modal").style.display = "none"; });
  $("edge-modal")?.addEventListener("click", e => { if (e.target === $("edge-modal")) $("edge-modal").style.display = "none"; });
  load().catch(err => {
    $("loading-overlay").innerHTML = `<div style="text-align:center;color:#ef4444;"><div style="font-size:1.3rem;font-weight:900;">Error loading dashboard</div><div style="font-size:13px;margin-top:8px;">${esc(String(err))}</div><button onclick="location.reload()" style="margin-top:20px;padding:10px 24px;background:#1e293b;border:1px solid #334155;border-radius:14px;color:#fff;cursor:pointer;font-weight:900;">Retry</button></div>`;
  });
});
