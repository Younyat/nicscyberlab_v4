(() => {
  "use strict";

  // -----------------------------
  // Helpers
  // -----------------------------
  const $ = (id) => document.getElementById(id);

  function logLine(msg) {
    const el = $("console");
    const ts = new Date().toISOString();
    el.value += `[${ts}] ${msg}\n`;
    el.scrollTop = el.scrollHeight;
  }

  function setBusy(button, busy) {
    button.disabled = busy;
    button.dataset._old = button.textContent;
    button.textContent = busy ? "Working..." : button.dataset._old;
  }

  async function apiFetch(url, { method = "GET", body = null, headers = {} } = {}) {
    const opts = { method, headers: { ...headers } };

    if (body !== null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }

    const res = await fetch(url, opts);
    const text = await res.text();

    // Intentar JSON si procede
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) {}

    if (!res.ok) {
      const errMsg = (data && (data.error || data.message)) ? (data.error || data.message) : text;
      throw new Error(`${res.status} ${res.statusText} — ${errMsg}`);
    }

    return data !== null ? data : text;
  }

  function requireCaseDir() {
    const caseDir = $("case_dir").textContent.trim();
    if (!caseDir || caseDir === "—") throw new Error("No case_dir. Pulsa 'Create Case' primero.");
    return caseDir;
  }

  function renderArtifacts(manifest) {
    const tbody = $("artifacts_table").querySelector("tbody");
    tbody.innerHTML = "";

    // Esperamos un manifest tipo:
    // { artifacts: [ {type, rel_path, sha256}, ... ] }
    const artifacts = (manifest && Array.isArray(manifest.artifacts)) ? manifest.artifacts : [];

    if (artifacts.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4" class="mut">No artifacts in manifest.</td>`;
      tbody.appendChild(tr);
      return;
    }

    for (const a of artifacts) {
      const type = a.type || "—";
      const rel = a.rel_path || a.path || "—";
      const sha = a.sha256 || "—";

      const tr = document.createElement("tr");

      const downloadUrl = buildDownloadUrl(rel);
      tr.innerHTML = `
        <td>${escapeHtml(type)}</td>
        <td class="kv">${escapeHtml(rel)}</td>
        <td class="kv">${escapeHtml(sha)}</td>
        <td>${rel !== "—" ? `<a href="${downloadUrl}">Download</a>` : "—"}</td>
      `;
      tbody.appendChild(tr);
    }
  }

  function buildDownloadUrl(relPath) {
    const caseDir = $("case_dir").textContent.trim();
    const qs = new URLSearchParams({ case_dir: caseDir, rel: relPath });
    return `/api/forensics/case/download?${qs.toString()}`;
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // -----------------------------
  // Actions
  // -----------------------------
  async function createCase() {
    const btn = $("btn_create_case");
    setBusy(btn, true);
    try {
      logLine("Creating case...");
      const r = await apiFetch("/api/forensics/case/create", { method: "POST", body: {} });
      $("case_dir").textContent = r.case_dir || "—";
      logLine(`Case created: ${r.case_dir}`);
      await refreshManifest();
    } finally {
      setBusy(btn, false);
    }
  }

  async function acquireDisk() {
    const btn = $("btn_acquire_disk");
    setBusy(btn, true);
    try {
      const caseDir = requireCaseDir();
      const instanceUuid = $("disk_instance_uuid").value.trim();
      const containerName = $("disk_container_name").value.trim() || "nova_libvirt";

      if (!instanceUuid) throw new Error("Instance UUID vacío.");

      logLine(`Acquire disk: instance_uuid=${instanceUuid} container=${containerName}`);
      const r = await apiFetch("/api/forensics/acquire/disk_kolla", {
        method: "POST",
        body: { case_dir: caseDir, instance_uuid: instanceUuid, container_name: containerName }
      });

      $("disk_result").textContent = JSON.stringify(r, null, 2);
      logLine(`Disk acquired OK: ${r.disk_raw || "(disk_raw missing)"}`);
      await refreshManifest();
    } finally {
      setBusy(btn, false);
    }
  }

  async function acquireMemory() {
    const btn = $("btn_acquire_memory");
    setBusy(btn, true);
    try {
      const caseDir = requireCaseDir();
      const vmIp = $("mem_vm_ip").value.trim();
      const sshUser = $("mem_ssh_user").value.trim();
      const sshKey = $("mem_ssh_key").value.trim();
      const mode = $("mem_mode").value;

      if (!vmIp) throw new Error("VM IP vacío.");
      if (!sshUser) throw new Error("SSH user vacío.");
      if (!sshKey) throw new Error("SSH key path vacío.");

      logLine(`Acquire memory: ip=${vmIp} user=${sshUser} mode=${mode}`);
      const r = await apiFetch("/api/forensics/acquire/memory_lime", {
        method: "POST",
        body: { case_dir: caseDir, vm_ip: vmIp, ssh_user: sshUser, ssh_key: sshKey, mode }
      });

      $("mem_result").textContent = JSON.stringify(r, null, 2);
      if (r.mem_dump) $("vol_dump_file").value = r.mem_dump;
      logLine(`Memory acquired OK: ${r.mem_dump || "(mem_dump missing)"}`);
      await refreshManifest();
    } finally {
      setBusy(btn, false);
    }
  }

  async function analyzeMemory() {
    const btn = $("btn_analyze_memory");
    setBusy(btn, true);
    try {
      const caseDir = requireCaseDir();
      const dumpFile = $("vol_dump_file").value.trim();
      const symbolsDir = $("vol_symbols_dir").value.trim();
      const volCmd = $("vol_cmd").value.trim() || "vol";

      if (!dumpFile) throw new Error("dump_file vacío (primero adquiere memoria o pega ruta).");
      if (!symbolsDir) throw new Error("symbols_dir vacío.");

      logLine(`Volatility: dump=${dumpFile}`);
      const r = await apiFetch("/api/forensics/analyze/memory_vol3", {
        method: "POST",
        body: { case_dir: caseDir, dump_file: dumpFile, symbols_dir: symbolsDir, vol_cmd: volCmd }
      });

      $("vol_result").textContent = JSON.stringify(r, null, 2);
      logLine(`Volatility OK: out_dir=${r.out_dir || "(missing)"}`);
      await refreshManifest();
    } finally {
      setBusy(btn, false);
    }
  }

  async function refreshManifest() {
    try {
      const caseDir = requireCaseDir();
      logLine("Refreshing manifest...");
      const qs = new URLSearchParams({ case_dir: caseDir });
      const manifest = await apiFetch(`/api/forensics/case/manifest?${qs.toString()}`);
      $("manifest_raw").value = JSON.stringify(manifest, null, 2);
      renderArtifacts(manifest);
      logLine("Manifest loaded.");
    } catch (e) {
      // Si no hay case todavía, no es error fatal
      $("manifest_raw").value = "—";
      const tbody = $("artifacts_table").querySelector("tbody");
      tbody.innerHTML = `<tr><td colspan="4" class="mut">No manifest loaded.</td></tr>`;
      logLine(`Manifest not loaded: ${e.message}`);
    }
  }

  function clearConsole() {
    $("console").value = "";
  }

  // -----------------------------
  // Wire events
  // -----------------------------
  function main() {
    $("btn_create_case").addEventListener("click", () => createCase().catch(e => logLine(`ERROR: ${e.message}`)));
    $("btn_refresh_manifest").addEventListener("click", () => refreshManifest().catch(e => logLine(`ERROR: ${e.message}`)));

    $("btn_acquire_disk").addEventListener("click", () => acquireDisk().catch(e => logLine(`ERROR: ${e.message}`)));
    $("btn_acquire_memory").addEventListener("click", () => acquireMemory().catch(e => logLine(`ERROR: ${e.message}`)));
    $("btn_analyze_memory").addEventListener("click", () => analyzeMemory().catch(e => logLine(`ERROR: ${e.message}`)));

    $("btn_clear_console").addEventListener("click", clearConsole);

    logLine("Forensics UI ready.");
  }

  window.addEventListener("DOMContentLoaded", main);
})();
