/* Repetition process-tree library — 2026-07-23.
   Pure, self-contained tree-building/rendering helpers reused by the
   EXISTING repBell -> #repDetailOverlay flow already in index.html (no
   separate page, no new icon — this file only supplies functions that
   repDetailOpen()/repDetailRenderHtml() call into). Reuses the same
   /api/campaign-repetitions/* endpoints that overlay already fetches from.
   Every exported name is prefixed repTree* to avoid colliding with
   index.html's own (very large) inline script. */

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

function repTreeEsc(v) {
  return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function repTreeUnk(v, fallback = "unknown") {
  return (v === null || v === undefined || v === "") ? fallback : v;
}

function repTreeFmtAbs(iso) {
  if (!iso) return "unknown";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "unknown";
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  } catch (e) {
    return "unknown";
  }
}

function repTreeFmtElapsed(seconds) {
  if (seconds === null || seconds === undefined || isNaN(seconds)) return null;
  seconds = Math.max(0, Math.round(seconds));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function repTreeStatusColor(status) {
  const s = String(status || "").toLowerCase();
  if (["completed", "recovered", "installed", "ok", "completed_with_degradation"].includes(s)) return "#22c55e";
  if (["running", "waiting", "started"].includes(s)) return "#38bdf8";
  if (["partial", "ambiguous", "wait"].includes(s)) return "#eab308";
  if (["failed", "stopped", "cancelled", "completed_with_failures", "failed_or_skipped", "error"].includes(s)) return "#ef4444";
  if (["pending", "unknown"].includes(s)) return "#64748b";
  return "#64748b";
}

async function repTreeGetJson(url) {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Generic tree node shape: { label, status, started_at, finished_at,
// elapsed_seconds, target, detail, error_detail, children: [] }
// ---------------------------------------------------------------------------

function repTreeNode(label, status, opts = {}) {
  return {
    label,
    status: status || "unknown",
    started_at: opts.started_at ?? null,
    finished_at: opts.finished_at ?? null,
    elapsed_seconds: opts.elapsed_seconds ?? null,
    target: opts.target ?? null,
    detail: opts.detail ?? null,
    error_detail: opts.error_detail ?? null,
    children: opts.children ?? [],
  };
}

function repTreeStageToNode(stage, extraChildren = []) {
  return repTreeNode(stage.label || stage.stage_key || "stage", stage.status, {
    started_at: stage.started_at,
    finished_at: stage.finished_at,
    elapsed_seconds: stage.elapsed_seconds,
    detail: stage.detail,
    error_detail: stage.error_detail,
    children: extraChildren,
  });
}

// ---------------------------------------------------------------------------
// Level A tree
// ---------------------------------------------------------------------------

function repTreeBuildLevelATree(detail) {
  const root = repTreeNode(
    `Level A — ${repTreeUnk(detail.execution_label)}`,
    detail.repetition_status,
    {
      started_at: detail.started_at,
      finished_at: detail.finished_at,
      elapsed_seconds: detail.total_elapsed_seconds,
      children: [],
    }
  );

  for (const stage of detail.stages || []) {
    root.children.push(repTreeStageToNode(stage));
  }

  const dr = detail.dry_run_repetitions || {};
  const dryRunNode = repTreeNode(
    `Dry-run repetitions (${repTreeUnk(dr.completed, "0")}/${repTreeUnk(dr.requested, "?")} completed)`,
    dr.completed >= dr.requested && dr.requested ? "completed" : "running",
    { children: [] }
  );
  for (const run of detail.per_dry_run_reconstruction || []) {
    dryRunNode.children.push(repTreeNode(
      `${repTreeUnk(run.execution_id)} — CPR ${run.cpr != null ? (run.cpr * 100).toFixed(1) + "%" : "unknown"}`,
      run.status,
      {
        started_at: run.started_at,
        finished_at: run.finished_at,
        elapsed_seconds: run.elapsed_seconds,
        detail: run.weighted_cpr != null ? `Weighted CPR: ${(run.weighted_cpr * 100).toFixed(1)}%` : null,
      }
    ));
  }
  if (dryRunNode.children.length) root.children.push(dryRunNode);

  if (detail.conclusions) {
    const c = detail.conclusions;
    root.children.push(repTreeNode("Conclusions", "completed", {
      detail: `CPR mean ${repTreeUnk(c.cpr_mean)}, WCPR mean ${repTreeUnk(c.weighted_cpr_mean)}, Δ CPR ${repTreeUnk(c.delta_cpr)}, Δ WCPR ${repTreeUnk(c.delta_weighted_cpr)}`,
    }));
  }

  if (detail.parent_level_b && detail.parent_level_b.job_id) {
    root.children.push(repTreeNode(
      `↑ Parent Level B repetition ${repTreeUnk(detail.parent_level_b.repetition_number)} (${repTreeUnk(detail.parent_level_b.campaign_id)})`,
      "completed",
      { detail: "This Level A run was launched from that Level B repetition." }
    ));
  }

  return root;
}

// ---------------------------------------------------------------------------
// Level B tree
// ---------------------------------------------------------------------------

async function repTreeBuildLevelBTree(detail) {
  const root = repTreeNode(
    `Level B repetition ${repTreeUnk(detail.repetition_number)} — ${repTreeUnk(detail.execution_label)}`,
    detail.repetition_status,
    {
      started_at: detail.stages?.[0]?.started_at,
      elapsed_seconds: detail.total_elapsed_seconds,
      children: [],
    }
  );

  const attack = detail.attack;
  const detection = detail.detection;
  const acquisition = detail.acquisition;

  for (const stage of detail.stages || []) {
    let extra = [];
    if (stage.stage_key === "lb.rep.attack" && attack) {
      extra.push(repTreeNode(
        `Attack: ${repTreeUnk(attack.attack_name)} (${repTreeUnk(attack.attack_profile_id)})`,
        attack.completed_at ? "completed" : "unknown",
        {
          started_at: attack.started_at, finished_at: attack.completed_at,
          target: repTreeUnk(attack.target_node),
          detail: `protocol=${repTreeUnk(attack.protocol)} fc=${repTreeUnk(attack.function_code)} register=${repTreeUnk(attack.register)} value=${repTreeUnk(attack.value)}`,
        }
      ));
    }
    if (stage.stage_key === "lb.rep.alert" && detection) {
      extra.push(repTreeNode(
        `Detection outcome: ${repTreeUnk(detection.outcome)}`,
        detection.trigger_alert_detected ? "completed" : "failed",
        {
          started_at: detection.trigger_alert_timestamp,
          target: detection.trigger_alert_rule ? `rule ${detection.trigger_alert_rule}` : null,
          detail: `severity=${repTreeUnk(detection.trigger_alert_severity)} attempts=${repTreeUnk(detection.trigger_attempts_total)}`,
        }
      ));
      for (const attempt of detection.trigger_attempt_trace || []) {
        extra.push(repTreeNode(
          `Trigger attempt ${repTreeUnk(attempt.attempt_number, "?")}`,
          attempt.trigger_alert_detected ? "completed" : "failed",
          {
            started_at: attempt.attack_started_at,
            finished_at: attempt.attack_completed_at,
            detail: attempt.eligibility_reason || null,
          }
        ));
      }
    }
    if (stage.stage_key === "lb.rep.acquisition" && acquisition) {
      if (detail.stage_timeline && detail.stage_timeline.length) {
        for (const st of detail.stage_timeline) {
          const sizeDetail = st.size_bytes ? `${(st.size_bytes / (1024 ** 3)).toFixed(2)} GiB` : null;
          extra.push(repTreeNode(
            repTreeUnk(st.label),
            st.status,
            {
              started_at: st.started_at, finished_at: st.finished_at, elapsed_seconds: st.elapsed_seconds,
              target: st.target ? `${st.target}${st.target_ip ? " (" + st.target_ip + ")" : ""}` : null,
              detail: [sizeDetail, st.progress_detail].filter(Boolean).join(" — ") || null,
              error_detail: st.error_detail || null,
            }
          ));
        }
      } else {
        extra.push(repTreeNode("Memory acquisition", acquisition.memory_status, {
          detail: acquisition.memory_size_bytes ? `${(acquisition.memory_size_bytes / (1024 ** 3)).toFixed(2)} GiB` : null,
        }));
        extra.push(repTreeNode("Disk acquisition", acquisition.disk_status, {
          detail: acquisition.disk_size_bytes ? `${(acquisition.disk_size_bytes / (1024 ** 3)).toFixed(2)} GiB` : null,
        }));
        extra.push(repTreeNode("Network/OT acquisition", acquisition.network_status, {
          detail: acquisition.network_size_gib ? `${acquisition.network_size_gib} GiB, ${repTreeUnk(acquisition.pcap_segments_imported)} segments` : null,
        }));
      }
    }
    if (stage.stage_key === "lb.rep.analysis" && detail.analysis_layers) {
      for (const layer of detail.analysis_layers) {
        extra.push(repTreeNode(`Analysis layer: ${repTreeUnk(layer.layer)}`, layer.status, { detail: layer.detail || null, error_detail: layer.error || null }));
      }
    }
    root.children.push(repTreeStageToNode(stage, extra));
  }

  if (detail.nested_level_a && detail.nested_level_a.job_id) {
    const laDetail = await repTreeGetJson(`/api/campaign-repetitions/level-a/${encodeURIComponent(detail.nested_level_a.job_id)}`);
    if (laDetail) {
      root.children.push(repTreeBuildLevelATree(laDetail));
    } else {
      root.children.push(repTreeNode(
        `Level A (nested) — ${repTreeUnk(detail.nested_level_a.execution_label)}`,
        detail.nested_level_a.status || "unknown",
        { started_at: detail.nested_level_a.started_at, finished_at: detail.nested_level_a.finished_at, detail: "Detail could not be resolved for this job." }
      ));
    }
  }

  return root;
}

// ---------------------------------------------------------------------------
// Level C tree
// ---------------------------------------------------------------------------

async function repTreeBuildLevelCTree(detail) {
  const root = repTreeNode(
    `Level C repetition ${repTreeUnk(detail.repetition_number)}/${repTreeUnk(detail.total_repetitions)} — ${repTreeUnk(detail.execution_label)}`,
    detail.repetition_status,
    {
      started_at: detail.stages?.[0]?.started_at,
      elapsed_seconds: detail.total_elapsed_seconds,
      children: [],
    }
  );

  const toolsByInstance = {};
  for (const t of detail.tool_installs || []) {
    toolsByInstance[t.instance] = toolsByInstance[t.instance] || [];
    toolsByInstance[t.instance].push(t);
  }

  for (const stage of detail.stages || []) {
    let extra = [];
    if (stage.stage_key === "lc.installing_tools" && detail.tool_installs?.length) {
      for (const [instance, tools] of Object.entries(toolsByInstance)) {
        const instNode = repTreeNode(instance, "completed", { children: [] });
        for (const t of tools) {
          instNode.children.push(repTreeNode(t.tool, t.status === "installed" ? "installed" : "failed_or_skipped", { started_at: t.ts }));
        }
        extra.push(instNode);
      }
    }
    if (stage.stage_key === "lc.verifying_monitoring" && detail.monitoring_verification?.length) {
      const seen = new Map();
      for (const m of detail.monitoring_verification) seen.set(m.detail, m);
      for (const m of seen.values()) {
        extra.push(repTreeNode(m.detail.trim(), m.level === "WARN" ? "waiting" : "completed", { started_at: m.ts }));
      }
    }
    if (stage.stage_key === "lc.waiting_level_b" && detail.level_b_job_id) {
      const repNum = detail.level_b_live?.repetition_number || 1;
      const lbDetail = await repTreeGetJson(`/api/campaign-repetitions/level-b/${encodeURIComponent(detail.level_b_job_id)}/${repNum}`);
      if (lbDetail) {
        extra.push(await repTreeBuildLevelBTree(lbDetail));
      } else {
        extra.push(repTreeNode(`Level B job ${detail.level_b_job_id}`, "unknown", { detail: "Detail could not be resolved for this job." }));
      }
    }
    root.children.push(repTreeStageToNode(stage, extra));
  }

  if (detail.snapshot_infrastructure) {
    const infra = detail.snapshot_infrastructure;
    const infraNode = repTreeNode(`Snapshot infrastructure (captured ${repTreeFmtAbs(infra.captured_at)})`, "completed", { children: [] });
    for (const inst of infra.instances || []) {
      const ip = inst.ip_floating || inst.ip_private;
      const instNode = repTreeNode(
        `${repTreeUnk(inst.name)} (${repTreeUnk(ip)})`,
        inst.status || "unknown",
        { started_at: inst.created_at, detail: `flavor=${repTreeUnk(inst.flavor_id)}`, children: [] }
      );
      for (const t of inst.tools || []) {
        instNode.children.push(repTreeNode(repTreeUnk(t.tool_name), t.status, { started_at: t.installed_at }));
      }
      infraNode.children.push(instNode);
    }
    if (infraNode.children.length) root.children.push(infraNode);
  }

  if (detail.floating_ip_cleanups?.length) {
    const fipNode = repTreeNode("Floating IP cleanups during this repetition", "completed", { children: [] });
    for (const c of detail.floating_ip_cleanups) {
      fipNode.children.push(repTreeNode(
        `Released ${repTreeUnk(c.released_count)} IP(s) (${repTreeUnk(c.triggered_by)})`,
        c.status,
        { started_at: c.started_at, finished_at: c.finished_at, detail: `quota available: ${repTreeUnk(c.before_available_pct)}% → ${repTreeUnk(c.after_available_pct)}%` }
      ));
    }
    root.children.push(fipNode);
  }

  if (detail.time_sync_checks?.length) {
    const tsNode = repTreeNode("Time sync checks during this repetition", "completed", { children: [] });
    for (const c of detail.time_sync_checks) {
      tsNode.children.push(repTreeNode(
        repTreeUnk(c.node_name || c.instance_id),
        repTreeUnk(c.temporal_sync_status, "unknown"),
        { finished_at: c.finished_at, detail: `max clock offset: ${repTreeUnk(c.max_clock_offset_ms)} ms, correction applied: ${repTreeUnk(c.correction_applied)}` }
      ));
    }
    root.children.push(tsNode);
  }

  return root;
}

async function repTreeBuildTree(level, detail) {
  if (level === "C") return repTreeBuildLevelCTree(detail);
  if (level === "B") return repTreeBuildLevelBTree(detail);
  return repTreeBuildLevelATree(detail);
}

// ---------------------------------------------------------------------------
// Tree rendering (terminal-style connectors)
// ---------------------------------------------------------------------------

function repTreeNodeLineHtml(n) {
  const color = repTreeStatusColor(n.status);
  const elapsed = repTreeFmtElapsed(n.elapsed_seconds);
  const timeParts = [];
  if (n.started_at) timeParts.push(repTreeFmtAbs(n.started_at));
  if (n.finished_at) timeParts.push("→ " + repTreeFmtAbs(n.finished_at));
  else if (n.started_at) timeParts.push("→ …");
  if (elapsed) timeParts.push(`(${elapsed})`);
  let html = `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;background:${color};"></span>`;
  html += `<span style="font-weight:800;color:rgba(241,245,249,0.94);">${repTreeEsc(n.label)}</span> `;
  html += `<span style="font-size:10px;font-weight:900;text-transform:uppercase;color:${color};border:1px solid ${color}55;background:${color}18;border-radius:999px;padding:1px 7px;">${repTreeEsc(n.status || "unknown")}</span>`;
  if (timeParts.length) html += ` <span style="color:rgba(148,163,184,0.7);font-size:10.5px;">${repTreeEsc(timeParts.join(" "))}</span>`;
  return html;
}

// Builds the tree-connector prefix purely from recursion depth, carrying an
// explicit array of "is this ancestor the last sibling at its level" -- the
// standard approach for rendering an arbitrary-depth tree with box-drawing
// connectors (├──/└──/│) without string-hacking a prefix in place.
function repTreeRenderLines(rootNodes) {
  const out = [];
  function walk(n, ancestorsLast) {
    let prefix = "";
    for (let i = 0; i < ancestorsLast.length - 1; i++) {
      prefix += ancestorsLast[i] ? "&nbsp;&nbsp;&nbsp;&nbsp;" : "│&nbsp;&nbsp;&nbsp;";
    }
    if (ancestorsLast.length > 0) {
      prefix += ancestorsLast[ancestorsLast.length - 1] ? "└── " : "├── ";
    }
    out.push(`<div style="white-space:pre;font-size:11.5px;line-height:1.85;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;">${prefix}${repTreeNodeLineHtml(n)}</div>`);
    const subPrefix = (() => {
      let p = "";
      for (let i = 0; i < ancestorsLast.length; i++) {
        p += ancestorsLast[i] ? "&nbsp;&nbsp;&nbsp;&nbsp;" : "│&nbsp;&nbsp;&nbsp;";
      }
      return p + "&nbsp;&nbsp;&nbsp;&nbsp;";
    })();
    if (n.target) out.push(`<div style="white-space:pre;font-size:11px;line-height:1.7;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:#a78bfa;">${subPrefix}target: ${repTreeEsc(n.target)}</div>`);
    if (n.detail) out.push(`<div style="white-space:pre;font-size:11px;line-height:1.7;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:rgba(148,163,184,0.75);font-style:italic;">${subPrefix}${repTreeEsc(n.detail)}</div>`);
    if (n.error_detail) out.push(`<div style="white-space:pre;font-size:11px;line-height:1.7;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:#f87171;">${subPrefix}⚠ ${repTreeEsc(n.error_detail)}</div>`);
    const children = n.children || [];
    children.forEach((child, i) => walk(child, [...ancestorsLast, i === children.length - 1]));
  }
  rootNodes.forEach((r, i) => walk(r, [i === rootNodes.length - 1]));
  return out.join("");
}
