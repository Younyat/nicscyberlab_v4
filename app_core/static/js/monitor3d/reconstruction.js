// Post-campaign reconstruction ("replay") mode -- a self-contained 3D scene
// composer that builds a completed campaign's real history progressively,
// piece by piece ("like a mason building a house"), instead of swapping the
// whole scene per beat. Purely reads an already-assembled timeline from the
// backend (GET /api/monitor3d/reconstruction/<job_id>, itself built entirely
// from files that already exist on disk, see monitor3d/service.py) -- never
// issues anything but GET requests, so it cannot create or modify any
// artifact, by construction.
//
// State isolation: this module owns its OWN set of Three.js objects
// (persistentObjects/repScopedObjects/reconObjects below), separate from
// app.js's live-mode entityGroups/ghostShells/connectors/relationObjects.
// It never calls app.js's rebuildScene()/setState() during playback -- only
// on enter()/exitReconstruction() to save and restore the live view exactly.
// This means a bug here can never corrupt live mode's own state.

import {
  createEntityBox, createConnector, createRelationLine, createFloatingLabel,
  disposeEntity, updateRing, updateBadge, recolorEntity,
  BOX_COLOR_ATTACKER, statusColor,
} from "./entities.js";
import { applyRowLayout } from "./layout.js";
import { monitorBridge } from "./app.js";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtSeconds(s) {
  if (s == null) return "—";
  const v = Math.max(0, Math.round(s));
  const m = Math.floor(v / 60), sec = v % 60;
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}
function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}
function fmtBytes(bytes) {
  if (bytes == null) return null;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(bytes), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

const MIN_BEAT_MS = 2000;
const MAX_BEAT_MS = 6000;
const BASE_MS_PER_REAL_HOUR = 2500;
// The attacker->PLC red thread is the single most important visual beat of
// the whole replay -- explicitly called out as too fast to read at the
// normal compression rate. Kept as a dedicated multiplier (not a change to
// the shared floor/ceiling) so only the attack beat itself gets slower.
const ATTACK_SLOWDOWN_FACTOR = 5;

// User-controlled playback speed (the reconstruction-bar slider) -- a plain
// divisor on top of the already-compressed duration. Takes effect from the
// NEXT beat scheduled onward (matching the existing Pause behaviour of
// letting whatever's already running finish, rather than yanking a running
// timer/animation mid-flight).
const MIN_SPEED = 0.25;
const MAX_SPEED = 4;
let speedMultiplier = 1;

export function setSpeed(multiplier) {
  const v = Number(multiplier);
  speedMultiplier = Number.isFinite(v) ? clamp(v, MIN_SPEED, MAX_SPEED) : 1;
}
export function getSpeed() {
  return speedMultiplier;
}

// "Thousands of times faster than real time", with floors/ceilings so a
// beat is never too fast to read or so slow it stalls playback -- a 3-hour
// real stage (e.g. a long memory analysis) still only takes 6s on screen.
// `kind` is optional; only "attack" gets the extra slowdown. The user-facing
// speed slider (speedMultiplier) is applied last, on top of everything else.
export function compressedDurationMs(realSeconds, kind) {
  const base = realSeconds == null || realSeconds <= 0
    ? MIN_BEAT_MS
    : clamp((realSeconds / 3600) * BASE_MS_PER_REAL_HOUR, MIN_BEAT_MS, MAX_BEAT_MS);
  const withKind = kind === "attack" ? base * ATTACK_SLOWDOWN_FACTOR : base;
  return withKind / speedMultiplier;
}

// ---------------------------------------------------------------------
// Module state -- entirely reconstruction's own, never shared with app.js.
// ---------------------------------------------------------------------
let beats = [];
let totalRepetitions = 0;
let currentIndex = 0;
let isActive = false;
let isPlaying = false;
let foundationBuilt = false;
let timerId = null;
let pendingTimers = []; // every staggered setTimeout handle, cancellable on Reset/Exit
let persistentObjects = []; // campaign box + repetition-row boxes/connectors -- survive the whole run
let repScopedObjects = []; // current repetition's case/hosts/artifacts/relations -- torn down each handoff
let reconObjects = []; // superset of both, for full teardown
let savedState = null;
let onTick = null;

let campaignBox = null;
let repBoxes = new Map(); // repetition_number -> box
let caseBox = null;
let hostBoxes = new Map(); // instance_id -> box
let hostToolBoxes = new Map(); // instance_id -> [tool box, ...]
let lastHostBeatIds = new Set(); // beat_id of the LAST deployment/tool_install beat per host, for the "leaving this machine" camera cue
let caseFocusedForRep = null; // repetition_number already given its one-time "enter the case" camera focus

// Cumulative, campaign-wide counters -- "progress since the first machine of
// repetition 1" for the left-side panel. Every field is a running count of
// beats that have genuinely fired, never a fabricated estimate; reset only
// on loadTimeline()/reset()/exitReconstruction().
function freshProgressStats() {
  return {
    hostsDeployed: 0,
    toolsInstalled: 0,
    attacksExecuted: 0,
    detectionsTriggered: 0,
    detectionsMissed: 0,
    artifactsPreserved: 0,
    artifactBytesTotal: 0,
    analysisPhasesCompleted: 0,
    casesCreated: 0,
    casesSealed: 0,
    cprValues: [], // one per repetition that reached a reconstruction beat
    repetitionsCompleted: 0,
  };
}
let progressStats = freshProgressStats();

// Called once per beat from applyBeat(), independent of the visual
// handlers -- so the counters stay accurate even if a handler bails early
// (e.g. a missing box reference) and reflect exactly what the backend's
// real timeline recorded.
function bumpProgress(beat) {
  switch (beat.kind) {
    case "deployment":
      progressStats.hostsDeployed += 1;
      break;
    case "tool_install":
      progressStats.toolsInstalled += 1;
      break;
    case "attack":
      progressStats.attacksExecuted += 1;
      break;
    case "detection":
      if (beat.payload?.detection?.outcome === "detected") progressStats.detectionsTriggered += 1;
      else progressStats.detectionsMissed += 1;
      break;
    case "case_created":
      progressStats.casesCreated += 1;
      break;
    case "preservation_step": {
      progressStats.artifactsPreserved += 1;
      const size = beat.payload?.stage_timeline_entry?.size_bytes;
      if (typeof size === "number") progressStats.artifactBytesTotal += size;
      break;
    }
    case "analysis_phase":
      progressStats.analysisPhasesCompleted += 1;
      break;
    case "reconstruction": {
      const cpr = beat.payload?.causal_status?.metrics_preview?.causal_path_recoverability;
      if (typeof cpr === "number") progressStats.cprValues.push(cpr);
      break;
    }
    case "seal":
      if (beat.payload?.integrity?.case_sealed) progressStats.casesSealed += 1;
      break;
    case "repetition_summary":
      progressStats.repetitionsCompleted += 1;
      break;
  }
}

// Read by app.js to render the left-side "Reconstruction progress" panel.
export function getProgressSummary() {
  const avgCpr = progressStats.cprValues.length
    ? progressStats.cprValues.reduce((a, b) => a + b, 0) / progressStats.cprValues.length
    : null;
  return {
    ...progressStats,
    avgCpr,
    currentRepetition: beats[currentIndex]?.repetition_number ?? null,
    totalRepetitions,
    beatIndex: currentIndex,
    totalBeats: beats.length,
  };
}

export function onBeatChange(cb) {
  onTick = cb;
}
export function isReconstructionActive() {
  return isActive;
}
export function getAllRenderedGroups() {
  return reconObjects.filter((o) => o.isGroup);
}

// ---------------------------------------------------------------------
// Timeline fetch
// ---------------------------------------------------------------------
export async function loadTimeline(jobId) {
  const res = await fetch(`/api/monitor3d/reconstruction/${encodeURIComponent(jobId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`reconstruction HTTP ${res.status}`);
  const data = await res.json();

  const flat = [];
  for (const rep of data.repetitions || []) {
    for (const beat of rep.beats || []) flat.push({ ...beat, _rep: rep });
  }
  if (data.finale_beat) flat.push({ ...data.finale_beat, _rep: null });

  beats = flat;
  totalRepetitions = data.total_repetitions || 0;
  currentIndex = 0;
  foundationBuilt = false;
  progressStats = freshProgressStats();
  return { jobId, totalBeats: beats.length, campaignId: data.campaign_id, totalRepetitions };
}

// ---------------------------------------------------------------------
// Tracking / teardown helpers
// ---------------------------------------------------------------------
function track(obj, { persistent = false } = {}) {
  reconObjects.push(obj);
  (persistent ? persistentObjects : repScopedObjects).push(obj);
  monitorBridge.addObject(obj);
  return obj;
}

function disposeNow(obj) {
  monitorBridge.removeObject(obj);
  disposeEntity(obj);
}

// Reverse-materialize (shrink/fade) then dispose -- the repetition-handoff
// "unbuild this room before starting the next one" effect.
function fadeAndDispose(obj, duration = 350) {
  const card = obj.isGroup ? obj.userData?.card : null;
  const domEl = obj.isCSS2DObject ? obj.element : null;
  const startScale = obj.isGroup ? obj.scale.x : null;
  const startOpacity = obj.material ? obj.material.opacity : null;
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / duration);
    const k = 1 - t;
    if (obj.isGroup) {
      obj.scale.setScalar(Math.max(0.05, startScale * k));
      if (card) card.style.opacity = String(k);
    }
    if (startOpacity != null) obj.material.opacity = startOpacity * k;
    if (domEl) domEl.style.opacity = String(k);
    if (t < 1) requestAnimationFrame(step);
    else disposeNow(obj);
  }
  step();
}

// ---------------------------------------------------------------------
// Animation primitives -- same hand-rolled rAF + cubic-ease style already
// used by scene.js's focusOn/focusOnGroups, kept consistent on purpose.
// ---------------------------------------------------------------------
function materialize(group, { duration = 700 } = {}) {
  const card = group.userData?.card;
  group.scale.setScalar(0.05);
  if (card) card.style.opacity = "0";
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / duration);
    const ease = 1 - Math.pow(1 - t, 3);
    group.scale.setScalar(0.05 + 0.95 * ease);
    if (card) card.style.opacity = String(ease);
    if (t < 1) requestAnimationFrame(step);
  }
  step();
}

function materializeLine(line, { duration = 700 } = {}) {
  const targetOpacity = line.material.opacity;
  line.material.opacity = 0;
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / duration);
    line.material.opacity = targetOpacity * (1 - Math.pow(1 - t, 3));
    if (t < 1) requestAnimationFrame(step);
  }
  step();
}

function stagger(items, gap, fn) {
  items.forEach((item, i) => {
    const handle = setTimeout(() => fn(item, i), i * gap);
    pendingTimers.push(handle);
  });
}

// Only beats with a real recorded duration (attack/preservation_step/
// analysis_phase) get this numeric readout -- everything else would be a
// fabricated number, which this codebase never does (see service.py's own
// "never invent a value that doesn't exist" rule).
function runProgressBar(container, durationMs, realSeconds) {
  const fill = container?.querySelector(".bar-fill");
  const timer = container?.querySelector(".beat-timer");
  if (!fill && !timer) return;
  const t0 = performance.now();
  function step() {
    const t = Math.min(1, (performance.now() - t0) / durationMs);
    if (fill) fill.style.width = `${Math.round(t * 100)}%`;
    if (timer && realSeconds != null) {
      timer.textContent = `${fmtSeconds(realSeconds * t)} / ${fmtSeconds(realSeconds)} (${Math.round(t * 100)}%)`;
    }
    if (t < 1) requestAnimationFrame(step);
  }
  step();
}

// ---------------------------------------------------------------------
// Foundation -- campaign box + repetition row. Built once per Play (from
// empty), persists across the whole run, only cleared by Reset/Exit.
// ---------------------------------------------------------------------
function buildFoundation() {
  if (foundationBuilt) return;
  foundationBuilt = true;
  const firstSnapshot = beats[0]?._rep?.snapshot;
  if (!firstSnapshot) return;

  campaignBox = createEntityBox({
    id: `campaign:${firstSnapshot.job_id}`, kind: "campaign", title: firstSnapshot.job_id,
    subtitle: `${totalRepetitions} repetition(s)`,
    status: "pending", statusLabel: "constructing", statLines: [],
    ringPct: 0, width: 14, height: 7, depth: 10,
  });
  campaignBox.position.set(0, 26, 0);
  track(campaignBox, { persistent: true });

  const repEntries = firstSnapshot.repetitions || [];
  const repBoxList = repEntries.map((r) => {
    const box = createEntityBox({
      id: `rep:${r.repetition_number}`, kind: "repetition", title: `Rep ${r.repetition_number}`,
      status: "pending", statusLabel: "pending", statLines: [],
      width: 4.5, height: 3.5, depth: 3.5,
    });
    box.scale.setScalar(0.05);
    box.userData.card.style.opacity = "0";
    track(box, { persistent: true });
    repBoxes.set(r.repetition_number, box);
    return box;
  });
  applyRowLayout(repBoxList, { y: 18, spacing: 6, maxPerRow: 10 });

  materialize(campaignBox);
  monitorBridge.focusOnGroups([campaignBox, ...repBoxList]);
  stagger(repBoxList, 120, (box) => {
    materialize(box);
    const conn = createConnector(campaignBox, box);
    track(conn, { persistent: true });
    materializeLine(conn);
  });
}

// ---------------------------------------------------------------------
// Per-repetition skeleton -- pre-computes and finalizes every row position
// for this repetition's hosts and preservation/analysis artifacts BEFORE
// any of them is revealed, since the full beat list (and therefore every
// row's final size) is already known before Play. This guarantees
// connectors are always drawn against a box's true, final position, never
// a stale one that a later re-layout would silently invalidate.
// ---------------------------------------------------------------------
const builtRepetitions = new Set();

function beatsForRep(repNum) {
  return beats.filter((b) => b.repetition_number === repNum);
}

function prepareRepetitionSkeleton(repNum) {
  if (builtRepetitions.has(repNum)) return;
  builtRepetitions.add(repNum);
  const repBeats = beatsForRep(repNum);
  const snapshot = repBeats[0]?._rep?.snapshot;
  if (!snapshot) return;

  const roleByName = new Map((snapshot.hosts || []).map((h) => [h.name, h.role]));
  const hostsSeen = new Map();
  const hostBeatsById = new Map();
  for (const b of repBeats) {
    if (b.kind !== "deployment" && b.kind !== "tool_install") continue;
    const inst = b.payload?.instance;
    if (!inst) continue;
    if (b.kind === "deployment" && !hostsSeen.has(inst.instance_id)) hostsSeen.set(inst.instance_id, inst);
    if (!hostBeatsById.has(inst.instance_id)) hostBeatsById.set(inst.instance_id, []);
    hostBeatsById.get(inst.instance_id).push(b);
  }
  // The last deployment/tool_install beat seen for each host is the cue to
  // pull the camera back out to the campaign-wide view ("sale de la máquina
  // y centraliza la vista") before moving on to whatever comes next.
  for (const list of hostBeatsById.values()) {
    lastHostBeatIds.add(list[list.length - 1].beat_id);
  }
  const hostBoxList = [...hostsSeen.values()].map((inst) => {
    const box = createEntityBox({
      id: `host:${inst.instance_id}`, kind: "host", title: inst.name,
      subtitle: inst.ip_floating || inst.ip_private,
      status: "pending", statusLabel: "constructing", statLines: [],
      width: 10, height: 5.5, depth: 7,
      raw: { ...inst, role: roleByName.get(inst.name) },
      boxColor: roleByName.get(inst.name) === "attacker" ? BOX_COLOR_ATTACKER : undefined,
    });
    box.scale.setScalar(0.05);
    box.userData.card.style.opacity = "0";
    track(box);
    hostBoxes.set(inst.instance_id, box);
    return box;
  });
  applyRowLayout(hostBoxList, { y: -6, spacing: 13, maxPerRow: 5 });

  const artifactBeats = repBeats.filter((b) => b.kind === "preservation_step" || b.kind === "analysis_phase");
  const artifactBoxList = artifactBeats.map((b) => {
    // Real per-artifact detail (memory/disk size, first hash characters) --
    // stage_timing_service now surfaces sha256/size_bytes on exactly the
    // entries that have them (memory/disk acquisition); every other stage
    // (network import, each analysis phase) simply omits the line rather
    // than showing a fabricated size/hash.
    const entry = b.payload?.stage_timeline_entry;
    const detailBits = [];
    const size = fmtBytes(entry?.size_bytes);
    if (size) detailBits.push(size);
    if (entry?.sha256) detailBits.push(`sha256 ${entry.sha256.slice(0, 12)}…`);
    const detailHtml = detailBits.length ? `<div class="ent-stat">${esc(detailBits.join(" · "))}</div>` : "";
    const box = createEntityBox({
      id: b.beat_id, kind: "evidence", title: b.title,
      status: "pending", statusLabel: "constructing", statLines: [],
      width: 6, height: 3.2, depth: 4,
      extraHtml: `${detailHtml}<div class="bar-track"><div class="bar-fill" style="width:0%"></div></div><div class="beat-timer"></div>`,
    });
    box.scale.setScalar(0.05);
    box.userData.card.style.opacity = "0";
    track(box);
    b._box = box;
    return box;
  });
  applyRowLayout(artifactBoxList, { y: -14, spacing: 8, maxPerRow: 6, zOffset: 6 });
}

// ---------------------------------------------------------------------
// Per-repetition "replay progress" ring for the case box (see plan finding:
// evidence_pipeline arrives already-frozen/complete from a historical
// repetition, so it can't be used as an incremental ring -- this counts
// real beats of THIS repetition that have actually played instead, which
// genuinely does move as the repetition's story advances).
// ---------------------------------------------------------------------
function updateCaseReplayRing(beat) {
  if (!caseBox) return;
  const repBeats = beatsForRep(beat.repetition_number);
  const idx = repBeats.indexOf(beat);
  const pct = repBeats.length ? Math.round(((idx + 1) / repBeats.length) * 100) : 0;
  updateRing(caseBox.userData.card, pct, "#22d3ee");
}

// ---------------------------------------------------------------------
// Beat handlers
// ---------------------------------------------------------------------
function handleDeployment(beat) {
  prepareRepetitionSkeleton(beat.repetition_number);
  const inst = beat.payload?.instance;
  if (!inst) return;
  const box = hostBoxes.get(inst.instance_id);
  if (!box || box.userData._revealed) return;
  box.userData._revealed = true;
  materialize(box);
  const parent = caseBox || repBoxes.get(beat.repetition_number) || campaignBox;
  if (parent) {
    const conn = createConnector(parent, box);
    track(conn);
    materializeLine(conn);
  }
  // Camera enters exactly this machine's box while it's being built --
  // "entra en la caja de la máquina" -- instead of staying on the wide shot.
  monitorBridge.focusOnGroups([box]);
}

// One small box per tool, materializing next to the host it's installed on
// -- same visual pattern app.js's renderDrilledHost() already uses for its
// (live-mode) tool boxes, at a smaller scale since reconstruction's hosts
// sit at overview scale, not the large "drilled" scale. Camera stays framed
// on the host + all its tool boxes revealed so far while this plays out.
function handleToolInstall(beat) {
  const inst = beat.payload?.instance;
  const tool = beat.payload?.tool;
  const hostBox = inst ? hostBoxes.get(inst.instance_id) : null;
  if (!inst || !tool || !hostBox) return;

  let toolList = hostToolBoxes.get(inst.instance_id);
  if (!toolList) {
    toolList = [];
    hostToolBoxes.set(inst.instance_id, toolList);
  }
  const box = createEntityBox({
    id: beat.beat_id, kind: "tool", title: tool.tool_name, subtitle: inst.name,
    status: "pending", statusLabel: "installing", statLines: [],
    width: 3, height: 1.8, depth: 2.2,
    extraHtml: `<div class="bar-track"><div class="bar-fill" style="width:0%"></div></div><div class="beat-timer"></div>`,
  });
  toolList.push(box);
  track(box);
  // Same-center, smaller-scale placement as renderDrilledHost's tool row --
  // reads as "inside" the host's own volume. Tool boxes have no connectors
  // (mirroring the live-mode pattern), so re-laying out the growing row on
  // every new arrival is safe here.
  applyRowLayout(toolList, { y: -4, spacing: 3.6, maxPerRow: 3, zOffset: 1 });
  for (const b of toolList) {
    b.position.x += hostBox.position.x;
    b.position.y += hostBox.position.y;
    b.position.z += hostBox.position.z;
  }
  materialize(box);
  runProgressBar(box.userData.card, compressedDurationMs(beat.real_duration_seconds, beat.kind), beat.real_duration_seconds);
  monitorBridge.focusOnGroups([hostBox, ...toolList]);
}

// The last deployment/tool_install beat for a given machine is the cue to
// pull back out to a campaign-wide view before the story moves on --
// "sale de la máquina y centraliza la vista global" -- with a slightly
// longer, more deliberate camera move than the tight per-box focuses.
function maybeReturnToGlobalView(beat) {
  if (!lastHostBeatIds.has(beat.beat_id)) return;
  const groups = [campaignBox, ...repBoxes.values(), caseBox, ...hostBoxes.values()].filter(Boolean);
  monitorBridge.focusOnGroups(groups, { duration: 1100 });
}

function handleAttack(beat) {
  const attack = beat.payload?.attack;
  if (!attack) return;
  const attackerBox = [...hostBoxes.values()].find((b) => b.userData.raw?.role === "attacker");
  const targetBox = [...hostBoxes.values()].find((b) => b.userData.raw?.name === attack.target_node);
  if (!attackerBox || !targetBox || attackerBox === targetBox) return;
  const line = createRelationLine(attackerBox, targetBox, 0xef4444, { bow: 8, radius: 0.22 });
  track(line);
  materializeLine(line);
  const midpoint = attackerBox.position.clone().lerp(targetBox.position, 0.5);
  midpoint.y += 10.5;
  const html = `${esc(attack.attack_name || "Attack")}${attack.protocol ? ` (${esc(attack.protocol)})` : ""}` +
    `<div class="bar-track"><div class="bar-fill" style="width:0%"></div></div><div class="beat-timer"></div>`;
  const label = createFloatingLabel(midpoint, html, "security");
  track(label);
  monitorBridge.focusOnGroups([attackerBox, targetBox]);
  runProgressBar(label.element, compressedDurationMs(beat.real_duration_seconds, beat.kind), beat.real_duration_seconds);
}

function handleDetection(beat) {
  const detection = beat.payload?.detection;
  const attackBeat = beatsForRep(beat.repetition_number).find((b) => b.kind === "attack");
  const targetName = attackBeat?.payload?.attack?.target_node;
  const targetBox = targetName ? [...hostBoxes.values()].find((b) => b.userData.raw?.name === targetName) : null;
  if (!targetBox) return;
  const detected = detection?.outcome === "detected";
  updateBadge(targetBox.userData.card, detected ? "under_attack" : "warning", detection?.outcome || "unknown");
}

function handleCaseCreated(beat) {
  const repNum = beat.repetition_number;
  const caseData = beat.payload?.case;
  caseBox = createEntityBox({
    id: `case:${caseData?.case_id || "rep" + repNum}`, kind: "case",
    title: caseData?.case_id || "Case (not available)",
    subtitle: caseData?.case_real_name,
    status: "pending", statusLabel: "constructing", statLines: [],
    ringPct: 0, width: 12, height: 6, depth: 8, raw: caseData,
  });
  caseBox.position.set(0, 10, 0);
  track(caseBox);
  materialize(caseBox);
  const parent = repBoxes.get(repNum) || campaignBox;
  if (parent) {
    const conn = createConnector(parent, caseBox);
    track(conn);
    materializeLine(conn);
  }
  // Evidence source link -- same real relationship live mode already draws
  // (Case -> the specific host it was acquired from, "evidence" in the live
  // sensor-coverage panel), missing from reconstruction until now.
  const attackBeat = beatsForRep(repNum).find((b) => b.kind === "attack");
  const targetName = attackBeat?.payload?.attack?.target_node;
  const targetBox = targetName ? [...hostBoxes.values()].find((b) => b.userData.raw?.name === targetName) : null;
  if (targetBox) {
    const link = createRelationLine(caseBox, targetBox, 0x6366f1, { bow: 3, radius: 0.16 });
    track(link);
    materializeLine(link);
    const midpoint = caseBox.position.clone().lerp(targetBox.position, 0.5);
    midpoint.y += 5;
    track(createFloatingLabel(midpoint, `Acquired from ${esc(targetName)}`, "evidence"));
  }
  monitorBridge.focusOnGroups([parent, caseBox, targetBox].filter(Boolean));
}

// One-time "enter the case" camera move for a repetition -- frames the case
// box together with every artifact/analysis box it will show, ONCE, so the
// camera doesn't jump for every single artifact that materializes inside
// that already-fixed framing afterward.
function maybeFocusCaseArea(beat) {
  if (caseFocusedForRep === beat.repetition_number || !caseBox) return;
  caseFocusedForRep = beat.repetition_number;
  const artifactBoxes = beatsForRep(beat.repetition_number)
    .filter((b) => (b.kind === "preservation_step" || b.kind === "analysis_phase") && b._box)
    .map((b) => b._box);
  monitorBridge.focusOnGroups([caseBox, ...artifactBoxes], { duration: 1000 });
}

function handleArtifact(beat) {
  prepareRepetitionSkeleton(beat.repetition_number);
  maybeFocusCaseArea(beat);
  const box = beat._box;
  if (!box || box.userData._revealed) return;
  box.userData._revealed = true;
  materialize(box);
  if (caseBox) {
    const conn = createConnector(caseBox, box);
    track(conn);
    materializeLine(conn);
  }
  updateBadge(box.userData.card, "running", "constructing");
  runProgressBar(box.userData.card, compressedDurationMs(beat.real_duration_seconds, beat.kind), beat.real_duration_seconds);
  updateCaseReplayRing(beat);
}

function handleReconstruction(beat) {
  if (!caseBox) return;
  const metrics = beat.payload?.causal_status?.metrics_preview;
  const cpr = metrics?.causal_path_recoverability;
  updateBadge(caseBox.userData.card, "info", cpr != null ? `CPR ${cpr}` : "reconstruction n/a");
  updateCaseReplayRing(beat);
}

function handleSeal(beat) {
  if (!caseBox) return;
  const sealed = !!beat.available;
  recolorEntity(caseBox, statusColor(sealed ? "completed" : "pending"));
  updateBadge(caseBox.userData.card, sealed ? "completed" : "pending", sealed ? "sealed" : "unsealed");
  updateCaseReplayRing(beat);
}

function handleRepetitionSummary(beat) {
  const repNum = beat.repetition_number;
  const rBox = repBoxes.get(repNum);
  if (rBox) {
    recolorEntity(rBox, statusColor("completed"));
    updateBadge(rBox.userData.card, "completed", "completed");
  }
  if (campaignBox) {
    updateRing(campaignBox.userData.card, Math.round((repNum / (totalRepetitions || repNum)) * 100), "#22d3ee");
  }
  teardownRepetitionScoped();
}

function handleCampaignFinale(beat) {
  if (!campaignBox) return;
  updateRing(campaignBox.userData.card, 100, "#34d399");
  updateBadge(campaignBox.userData.card, "completed", "completed");

  const report = beat.payload?.comparison_report;
  let label = null;
  if (report) {
    const pos = campaignBox.position.clone();
    pos.y += 10;
    label = createFloatingLabel(pos, esc(report.verdict || "Campaign finished"), "security");
    track(label, { persistent: true });
  }
  // Closing shot: pull all the way back to the entire real hierarchy still
  // standing (campaign + every repetition box) in one frame -- a longer,
  // more deliberate move and extra padding than the per-stage focuses, plus
  // the same fixed oblique `dir` focusOnGroups already frames from, so it
  // reads unmistakably as a 3D scene rather than a flat top-down grid.
  const everything = [campaignBox, ...repBoxes.values(), label].filter(Boolean);
  monitorBridge.focusOnGroups(everything, { paddingFactor: 1.6, duration: 1800 });
}

const HANDLERS = {
  deployment: handleDeployment,
  tool_install: handleToolInstall,
  attack: handleAttack,
  detection: handleDetection,
  case_created: handleCaseCreated,
  preservation_step: handleArtifact,
  analysis_phase: handleArtifact,
  reconstruction: handleReconstruction,
  seal: handleSeal,
  repetition_summary: handleRepetitionSummary,
  campaign_finale: handleCampaignFinale,
};

function teardownRepetitionScoped() {
  const objs = [...repScopedObjects];
  repScopedObjects = [];
  reconObjects = reconObjects.filter((o) => !objs.includes(o));
  for (const obj of objs) fadeAndDispose(obj);
  caseBox = null;
  hostBoxes = new Map();
  hostToolBoxes = new Map();
  caseFocusedForRep = null;
}

let activeRepNum = null;

// The repetition row's own box otherwise only ever changes once, at
// repetition_summary (pending -> completed) -- this flips it to
// "in-progress" the moment its repetition's first beat fires, so the row
// actually shows the pending/in-progress/completed sequence the construction
// model describes, instead of jumping straight from pending to completed.
function markRepetitionInProgress(repNum) {
  if (repNum == null || repNum === activeRepNum) return;
  activeRepNum = repNum;
  const box = repBoxes.get(repNum);
  if (!box) return;
  recolorEntity(box, statusColor("running"));
  updateBadge(box.userData.card, "running", "in progress");
}

function applyBeat(index) {
  const beat = beats[index];
  if (!beat) return;
  markRepetitionInProgress(beat.repetition_number);
  bumpProgress(beat);
  HANDLERS[beat.kind]?.(beat);
  maybeReturnToGlobalView(beat);
  onTick?.(beat, index, beats.length);
}

// ---------------------------------------------------------------------
// Transport: play / pause / reset / enter / exit
// ---------------------------------------------------------------------
function scheduleNext() {
  clearTimeout(timerId);
  if (!isPlaying) return;
  const beat = beats[currentIndex];
  const delay = compressedDurationMs(beat?.real_duration_seconds, beat?.kind);
  timerId = setTimeout(() => {
    if (currentIndex >= beats.length - 1) {
      isPlaying = false;
      return;
    }
    currentIndex += 1;
    applyBeat(currentIndex);
    scheduleNext();
  }, delay);
}

export function enter() {
  if (isActive) return;
  isActive = true;
  savedState = monitorBridge.getState();
  monitorBridge.stopLivePolling();
  monitorBridge.clearLiveScene();
  monitorBridge.setConnStatus("reconstruction mode · live polling paused", { reconstructing: true });
}

export function play() {
  if (!beats.length) return;
  enter();
  if (isPlaying) return;
  isPlaying = true;
  if (!foundationBuilt) {
    buildFoundation();
    const handle = setTimeout(() => {
      applyBeat(0);
      scheduleNext();
    }, 900);
    pendingTimers.push(handle);
    return;
  }
  scheduleNext();
}

export function pause() {
  isPlaying = false;
  clearTimeout(timerId);
}

// Rewinds to the first beat but stays inside reconstruction mode (live
// polling stays paused) -- matches the explicit "Reset != exit" contract,
// and now does a REAL full teardown (every object, campaign/rep-row
// included) instead of just re-applying beat 0 on top of an already-built
// scene, per the user's explicit correction that the previous Reset "no
// elimina nada".
export function reset() {
  isPlaying = false;
  clearTimeout(timerId);
  timerId = null;
  pendingTimers.forEach(clearTimeout);
  pendingTimers = [];
  const objs = [...reconObjects];
  reconObjects = [];
  persistentObjects = [];
  repScopedObjects = [];
  for (const obj of objs) disposeNow(obj);
  campaignBox = null;
  repBoxes = new Map();
  caseBox = null;
  hostBoxes = new Map();
  hostToolBoxes = new Map();
  lastHostBeatIds = new Set();
  caseFocusedForRep = null;
  builtRepetitions.clear();
  activeRepNum = null;
  currentIndex = 0;
  foundationBuilt = false;
  progressStats = freshProgressStats();
}

export function exitReconstruction() {
  reset();
  if (!isActive) return;
  isActive = false;
  if (savedState) {
    monitorBridge.setState(savedState);
    monitorBridge.rebuildScene();
    monitorBridge.focusOnGroups(monitorBridge.allVisibleGroups());
  }
  monitorBridge.startLivePolling();
  savedState = null;
}
