// Monitor3D — polling client. Polling, not SSE/WebSocket: gunicorn runs
// plain sync workers shared with the whole platform's real traffic. An SSE
// connection left open for a monitoring dashboard would tie up a worker for
// its entire session; a poll request occupies one for single-digit ms.

const POLL_INTERVAL_MS = 2500;
const VITALS_POLL_INTERVAL_MS = 15000;

let lastHash = null;
let pollTimer = null;
let vitalsTimer = null;

export async function fetchSnapshot() {
  const qs = lastHash ? `?since_hash=${encodeURIComponent(lastHash)}` : "";
  const res = await fetch(`/api/monitor3d/snapshot${qs}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`snapshot HTTP ${res.status}`);
  const data = await res.json();
  if (data.hash) lastHash = data.hash;
  return data;
}

export async function fetchHostVitals(instanceId, { refresh = false } = {}) {
  const qs = refresh ? "?refresh=1" : "";
  const res = await fetch(`/api/monitor3d/hosts/${encodeURIComponent(instanceId)}/vitals${qs}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`vitals HTTP ${res.status}`);
  return res.json();
}

export async function fetchRepetitionDetail(repNum) {
  const res = await fetch(`/api/monitor3d/repetitions/${encodeURIComponent(repNum)}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`repetition detail HTTP ${res.status}`);
  return res.json();
}

export async function fetchSensorCoverage() {
  const res = await fetch("/api/monitor3d/sensor-coverage", { cache: "no-store" });
  if (!res.ok) throw new Error(`sensor-coverage HTTP ${res.status}`);
  return res.json();
}

export function startPolling(onSnapshot, onError, onSyncChange) {
  stopPolling();
  const tick = async () => {
    if (document.hidden) return;
    onSyncChange?.(true);
    try {
      onSnapshot(await fetchSnapshot());
    } catch (err) {
      onError?.(err);
    } finally {
      onSyncChange?.(false);
    }
  };
  tick();
  pollTimer = setInterval(tick, POLL_INTERVAL_MS);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) tick();
  });
}

export function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

export function startVitalsPolling(getWatchedInstanceId, onVitals, onError) {
  stopVitalsPolling();
  const tick = async () => {
    if (document.hidden) return;
    const instanceId = getWatchedInstanceId();
    if (!instanceId) return;
    try {
      onVitals(instanceId, await fetchHostVitals(instanceId, { refresh: true }));
    } catch (err) {
      onError?.(err);
    }
  };
  tick();
  vitalsTimer = setInterval(tick, VITALS_POLL_INTERVAL_MS);
}

export function stopVitalsPolling() {
  if (vitalsTimer) {
    clearInterval(vitalsTimer);
    vitalsTimer = null;
  }
}
