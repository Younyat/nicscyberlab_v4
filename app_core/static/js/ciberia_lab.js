const API_BASE = "/api/ciberia";

const PCAP_DATASET_UI = {
  name: document.getElementById("pcap-dataset-name"),
  datasetId: document.getElementById("pcap-dataset-id"),
  label: document.getElementById("pcap-dataset-label"),
  autoLabel: document.getElementById("pcap-auto-label"),
  labelColumn: document.getElementById("pcap-label-column"),
  testSize: document.getElementById("pcap-test-size"),
  flowTimeout: document.getElementById("pcap-flow-timeout"),
  activityTimeout: document.getElementById("pcap-activity-timeout"),
  file: document.getElementById("pcap-dataset-file"),
  output: document.getElementById("pcap-dataset-output"),
  importBtn: document.getElementById("btn-import-pcap-dataset"),
};

const CUSTOM_DATASET_UI = {
  name: document.getElementById("custom-dataset-name"),
  datasetId: document.getElementById("custom-dataset-id"),
  labelColumn: document.getElementById("custom-label-column"),
  splitFile: document.getElementById("custom-split-file"),
  output: document.getElementById("custom-dataset-output"),
  importBtn: document.getElementById("btn-import-custom-dataset"),
};

const CUSTOM_DATASET_SELECTOR_UI = {
  select: document.getElementById("custom-dataset-select"),
  loadProfilesBtn: document.getElementById("btn-load-custom-profiles"),
  loadStatusBtn: document.getElementById("btn-load-custom-status"),
  info: document.getElementById("custom-dataset-info"),
};

document.addEventListener("DOMContentLoaded", () => {
  const feedbackEl = document.getElementById("global-feedback");

  let cachedProfiles = null;
  let activeDatasetSource = "built_in";

  function setFeedback(message, kind = "idle") {
    if (!feedbackEl) return;
    feedbackEl.textContent = message;
    feedbackEl.className = `feedback ${kind}`;
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderSummary(containerId, summary) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!summary || Object.keys(summary).length === 0) {
      el.innerHTML = "";
      return;
    }

    const rows = Object.entries(summary)
      .map(([k, v]) => `<div><strong>${escapeHtml(k)}</strong>: ${escapeHtml(String(v))}</div>`)
      .join("");

    el.innerHTML = `<div class="summary">${rows}</div>`;
  }

  function renderTable(containerId, rows, limit = 50) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!rows || rows.length === 0) {
      el.innerHTML = "";
      return;
    }

    const data = rows.slice(0, limit);
    const cols = Object.keys(data[0] || {});

    if (!cols.length) {
      el.innerHTML = "";
      return;
    }

    const head = cols.map(c => `<th>${escapeHtml(c)}</th>`).join("");
    const body = data.map(row => {
      const cells = cols.map(c => {
        const val = row[c];
        const text = typeof val === "object" ? JSON.stringify(val) : String(val ?? "");
        return `<td>${escapeHtml(text)}</td>`;
      }).join("");
      return `<tr>${cells}</tr>`;
    }).join("");

    el.innerHTML = `
      <div class="small">Showing ${data.length} rows</div>
      <div class="table-wrap">
        <table>
          <thead><tr>${head}</tr></thead>
          <tbody>${body}</tbody>
        </table>
      </div>
    `;
  }

  function renderBulletBox(containerId, title, items = [], extraText = "") {
    const el = document.getElementById(containerId);
    if (!el) return;

    if ((!items || items.length === 0) && !extraText) {
      el.innerHTML = "";
      return;
    }

    const bullets = items.length
      ? `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
      : "";

    const paragraph = extraText ? `<p>${escapeHtml(extraText)}</p>` : "";
    const heading = title ? `<h3>${escapeHtml(title)}</h3>` : "";

    el.innerHTML = `
      <div class="info-box">
        ${heading}
        ${bullets}
        ${paragraph}
      </div>
    `;
  }

  function splitProfilesBySource(profiles) {
    const builtIn = [];
    const custom = [];

    (profiles || []).forEach(profile => {
      if (profile.source === "custom") {
        custom.push(profile);
      } else {
        builtIn.push(profile);
      }
    });

    return { builtIn, custom };
  }

  function getSelectedBuiltInDatasetKey() {
    return document.getElementById("dataset-select")?.value || "2017";
  }

  function getSelectedCustomDatasetKey() {
    return CUSTOM_DATASET_SELECTOR_UI.select?.value || "";
  }

  function getEffectiveDatasetKey() {
    if (activeDatasetSource === "custom") {
      const customValue = getSelectedCustomDatasetKey();
      if (customValue) {
        return customValue;
      }
    }
    return getSelectedBuiltInDatasetKey();
  }

  function getEffectiveProfile() {
    const profiles = Array.isArray(cachedProfiles?.profiles) ? cachedProfiles.profiles : [];
    const effectiveKey = getEffectiveDatasetKey();
    return profiles.find(p => p.profile === effectiveKey) || null;
  }

  function refillBuiltInDatasetSelect(profiles, selectedValue = null) {
    const select = document.getElementById("dataset-select");
    if (!select || !Array.isArray(profiles)) return;

    const currentValue = selectedValue || select.value || "2017";
    select.innerHTML = "";

    profiles.forEach(profile => {
      const option = document.createElement("option");
      option.value = profile.profile;
      option.textContent = profile.title || profile.profile;
      select.appendChild(option);
    });

    const exists = profiles.some(profile => profile.profile === currentValue);
    if (exists) {
      select.value = currentValue;
    } else if (profiles.length > 0) {
      select.value = profiles[0].profile;
    }
  }

  function refillCustomDatasetSelect(profiles, selectedValue = null) {
    const select = CUSTOM_DATASET_SELECTOR_UI.select;
    if (!select) return;

    const currentValue = selectedValue || select.value || "";
    select.innerHTML = `<option value="">No custom dataset selected</option>`;

    profiles.forEach(profile => {
      const option = document.createElement("option");
      option.value = profile.profile;
      option.textContent = profile.title || profile.profile;
      select.appendChild(option);
    });

    const exists = profiles.some(profile => profile.profile === currentValue);
    if (exists) {
      select.value = currentValue;
    } else {
      select.value = "";
    }
  }

  function renderSelectedProfileCard() {
    const profile = getEffectiveProfile();
    const el = document.getElementById("profile-info");
    if (!el) return;

    if (!profile) {
      el.innerHTML = `<div class="profile-empty">No profile information available.</div>`;
      return;
    }

    const source = profile.source || "unknown";
    const importedAt = profile.imported_at_utc || "";
    const rowsTrain = profile.rows_train ?? "";
    const rowsTest = profile.rows_test ?? "";
    const features = Array.isArray(profile.features) ? profile.features.length : "";

    el.innerHTML = `
      <div class="info-box">
        <h3>${escapeHtml(profile.title || profile.profile || "Dataset")}</h3>
        <ul>
          <li><strong>Effective dataset:</strong> ${escapeHtml(profile.profile || "")}</li>
          <li><strong>Notebook:</strong> ${escapeHtml(profile.notebook || "")}</li>
          <li><strong>Goal:</strong> ${escapeHtml(profile.goal || "")}</li>
          <li><strong>Split artifact:</strong> <code>${escapeHtml(profile.split_file || "")}</code></li>
          <li><strong>Base model artifact:</strong> <code>${escapeHtml(profile.base_model_file || "")}</code></li>
          <li><strong>Mode:</strong> ${escapeHtml(profile.mode || "")}</li>
          <li><strong>Source:</strong> ${escapeHtml(source)}</li>
          ${importedAt ? `<li><strong>Imported at:</strong> ${escapeHtml(importedAt)}</li>` : ""}
          ${rowsTrain !== "" ? `<li><strong>Train rows:</strong> ${escapeHtml(String(rowsTrain))}</li>` : ""}
          ${rowsTest !== "" ? `<li><strong>Test rows:</strong> ${escapeHtml(String(rowsTest))}</li>` : ""}
          ${features !== "" ? `<li><strong>Feature count:</strong> ${escapeHtml(String(features))}</li>` : ""}
        </ul>
      </div>
    `;
  }

  function renderCustomDatasetCard(profile) {
    const el = CUSTOM_DATASET_SELECTOR_UI.info;
    if (!el) return;

    if (!profile) {
      el.innerHTML = `<div class="profile-empty">No custom dataset selected.</div>`;
      return;
    }

    const importedAt = profile.imported_at_utc || "";
    const rowsTrain = profile.rows_train ?? "";
    const rowsTest = profile.rows_test ?? "";
    const features = Array.isArray(profile.features) ? profile.features.length : "";

    el.innerHTML = `
      <div class="info-box">
        <h3>${escapeHtml(profile.title || profile.profile || "Custom dataset")}</h3>
        <ul>
          <li><strong>Profile:</strong> ${escapeHtml(profile.profile || "")}</li>
          <li><strong>Goal:</strong> ${escapeHtml(profile.goal || "")}</li>
          <li><strong>Split artifact:</strong> <code>${escapeHtml(profile.split_file || "")}</code></li>
          <li><strong>Mode:</strong> ${escapeHtml(profile.mode || "")}</li>
          <li><strong>Source:</strong> ${escapeHtml(profile.source || "custom")}</li>
          ${importedAt ? `<li><strong>Imported at:</strong> ${escapeHtml(importedAt)}</li>` : ""}
          ${rowsTrain !== "" ? `<li><strong>Train rows:</strong> ${escapeHtml(String(rowsTrain))}</li>` : ""}
          ${rowsTest !== "" ? `<li><strong>Test rows:</strong> ${escapeHtml(String(rowsTest))}</li>` : ""}
          ${features !== "" ? `<li><strong>Feature count:</strong> ${escapeHtml(String(features))}</li>` : ""}
        </ul>
      </div>
    `;
  }

  function refreshSelectorsAndCards(profilesResponse, selectedBuiltIn = null, selectedCustom = null) {
    cachedProfiles = profilesResponse;

    const profiles = Array.isArray(profilesResponse?.profiles) ? profilesResponse.profiles : [];
    const { builtIn, custom } = splitProfilesBySource(profiles);

    refillBuiltInDatasetSelect(builtIn, selectedBuiltIn);
    refillCustomDatasetSelect(custom, selectedCustom);

    const selectedCustomProfile = custom.find(p => p.profile === getSelectedCustomDatasetKey()) || null;
    renderCustomDatasetCard(selectedCustomProfile);
    renderSelectedProfileCard();
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll("button").forEach(btn => {
      btn.disabled = disabled;
    });
  }

  async function jsonRequest(url, options = {}, startMessage = "Executing request...") {
    setFeedback(startMessage, "running");
    setButtonsDisabled(true);

    try {
      const res = await fetch(url, options);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Request failed");
      }

      setFeedback("Operation completed successfully.", "success");
      return data;
    } catch (e) {
      setFeedback(`Operation failed: ${e.message}`, "error");
      throw e;
    } finally {
      setButtonsDisabled(false);
    }
  }

  async function formRequest(url, fileInput, startMessage = "Uploading file...") {
    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
      throw new Error("Select a file first");
    }

    const form = new FormData();
    form.append("file", fileInput.files[0]);

    setFeedback(`${startMessage} ${fileInput.files[0].name}`, "running");
    setButtonsDisabled(true);

    try {
      const res = await fetch(url, {
        method: "POST",
        body: form
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Request failed");
      }

      setFeedback("Operation completed successfully.", "success");
      return data;
    } catch (e) {
      setFeedback(`Operation failed: ${e.message}`, "error");
      throw e;
    } finally {
      setButtonsDisabled(false);
    }
  }

  async function formRequestWithExtraFields(url, fileInput, extraFields = {}, startMessage = "Uploading file...") {
    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
      throw new Error("Select a file first");
    }

    const form = new FormData();

    Object.entries(extraFields).forEach(([key, value]) => {
      form.append(key, value ?? "");
    });

    form.append("file", fileInput.files[0]);

    setFeedback(`${startMessage} ${fileInput.files[0].name}`, "running");
    setButtonsDisabled(true);

    try {
      const res = await fetch(url, {
        method: "POST",
        body: form
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Request failed");
      }

      setFeedback("Operation completed successfully.", "success");
      return data;
    } catch (e) {
      setFeedback(`Operation failed: ${e.message}`, "error");
      throw e;
    } finally {
      setButtonsDisabled(false);
    }
  }

  function buildEvaluationExplanation(data) {
    const summary = data.summary_explanation || {};
    const items = [];

    if (summary.accuracy !== undefined) {
      items.push(`Overall accuracy: ${Number(summary.accuracy).toFixed(6)}`);
    }
    if (summary.macro_f1 !== undefined) {
      items.push(`Macro F1: ${Number(summary.macro_f1).toFixed(6)}`);
    }
    if (summary.rows !== undefined && summary.rows !== null) {
      items.push(`Evaluated rows: ${summary.rows}`);
    }

    const strongest = (summary.strongest_classes || []).map(
      x => `${x.label} with F1 ${Number(x.f1_score).toFixed(6)}`
    );
    if (strongest.length) {
      items.push(`Strongest classes: ${strongest.join(", ")}`);
    }

    const weakest = (summary.weakest_classes || []).map(
      x => `${x.label} with F1 ${Number(x.f1_score).toFixed(6)}`
    );
    if (weakest.length) {
      items.push(`Lowest relative class scores: ${weakest.join(", ")}`);
    }

    renderBulletBox(
      "explanation-box",
      "Result interpretation",
      items,
      summary.interpretation || ""
    );
  }

  function buildPredictionExplanation(containerId, data) {
    const summary = data.summary_explanation || {};
    const items = [];

    if (summary.input_rows !== undefined) {
      items.push(`Input rows: ${summary.input_rows}`);
    }
    if (summary.dominant_class !== null && summary.dominant_class !== undefined) {
      items.push(`Dominant predicted class: ${summary.dominant_class} (${summary.dominant_count} rows)`);
    }
    if (summary.class_diversity !== undefined) {
      items.push(`Predicted class diversity: ${summary.class_diversity}`);
    }
    if (summary.average_confidence !== null && summary.average_confidence !== undefined) {
      items.push(`Average confidence: ${Number(summary.average_confidence).toFixed(6)}`);
    }

    renderBulletBox(
      containerId,
      "Inference interpretation",
      items,
      summary.interpretation || ""
    );
  }

  async function loadProfiles() {
    const data = await jsonRequest(`${API_BASE}/profiles`, {}, "Loading framework profiles...");
    refreshSelectorsAndCards(
      data,
      getSelectedBuiltInDatasetKey(),
      getSelectedCustomDatasetKey()
    );

    setText("status-output", {
      ...data,
      effective_dataset: getEffectiveDatasetKey(),
      active_source: activeDatasetSource
    });

    return data;
  }

  async function loadStatus() {
    const data = await jsonRequest(`${API_BASE}/status`, {}, "Loading active artifact status...");

    if (Array.isArray(data.profiles)) {
      refreshSelectorsAndCards(
        { profiles: data.profiles },
        getSelectedBuiltInDatasetKey(),
        getSelectedCustomDatasetKey()
      );
    }

    setText("status-output", {
      ...data,
      effective_dataset: getEffectiveDatasetKey(),
      active_source: activeDatasetSource
    });

    return data;
  }

  async function loadCustomProfiles() {
    const data = await jsonRequest(`${API_BASE}/profiles`, {}, "Loading custom dataset profiles...");

    const profiles = Array.isArray(data.profiles) ? data.profiles : [];
    const { builtIn, custom } = splitProfilesBySource(profiles);

    cachedProfiles = data;

    refillBuiltInDatasetSelect(builtIn, getSelectedBuiltInDatasetKey());
    refillCustomDatasetSelect(custom, getSelectedCustomDatasetKey());

    const selectedCustomProfile = custom.find(p => p.profile === getSelectedCustomDatasetKey()) || null;
    renderCustomDatasetCard(selectedCustomProfile);
    renderSelectedProfileCard();

    setText("status-output", {
      ok: true,
      custom_dataset_count: custom.length,
      custom_datasets: custom,
      effective_dataset: getEffectiveDatasetKey(),
      active_source: activeDatasetSource,
      message: "Custom dataset profiles loaded successfully."
    });

    return data;
  }

  async function loadCustomStatus() {
    const data = await jsonRequest(`${API_BASE}/datasets/custom/status`, {}, "Loading custom dataset status...");

    const customProfiles = Array.isArray(data.custom_datasets) ? data.custom_datasets : [];
    refillCustomDatasetSelect(customProfiles, getSelectedCustomDatasetKey());

    const selectedCustomProfile = customProfiles.find(p => p.profile === getSelectedCustomDatasetKey()) || null;
    renderCustomDatasetCard(selectedCustomProfile);

    if (cachedProfiles && Array.isArray(cachedProfiles.profiles)) {
      const builtIn = cachedProfiles.profiles.filter(p => p.source !== "custom");
      cachedProfiles = {
        ...cachedProfiles,
        profiles: [...builtIn, ...customProfiles]
      };
    } else {
      cachedProfiles = {
        profiles: [...customProfiles]
      };
    }

    renderSelectedProfileCard();

    setText("status-output", {
      ...data,
      effective_dataset: getEffectiveDatasetKey(),
      active_source: activeDatasetSource
    });

    return data;
  }

  async function importCustomDataset() {
    const datasetName = (CUSTOM_DATASET_UI.name?.value || "").trim();
    const datasetId = (CUSTOM_DATASET_UI.datasetId?.value || "").trim();
    const labelColumn = (CUSTOM_DATASET_UI.labelColumn?.value || "").trim() || "Attack Type";

    if (!datasetName) {
      setText("custom-dataset-output", { ok: false, error: "Dataset display name is required" });
      setFeedback("Operation failed: Dataset display name is required", "error");
      return;
    }

    try {
      const data = await formRequestWithExtraFields(
        `${API_BASE}/datasets/import-split`,
        CUSTOM_DATASET_UI.splitFile,
        {
          dataset_name: datasetName,
          dataset_id: datasetId,
          label_column: labelColumn
        },
        "Uploading prepared split dataset..."
      );

      setText("custom-dataset-output", data);

      if (Array.isArray(data.profiles)) {
        const importedProfile = data.dataset?.profile || "";
        activeDatasetSource = "custom";

        refreshSelectorsAndCards(
          { profiles: data.profiles },
          getSelectedBuiltInDatasetKey(),
          importedProfile
        );

        setText("status-output", {
          ok: true,
          imported_dataset: data.dataset,
          custom_dataset_count: splitProfilesBySource(data.profiles).custom.length,
          custom_datasets: splitProfilesBySource(data.profiles).custom,
          effective_dataset: getEffectiveDatasetKey(),
          active_source: activeDatasetSource,
          message: data.message || "Custom dataset imported successfully."
        });
      }

      if (CUSTOM_DATASET_UI.splitFile) {
        CUSTOM_DATASET_UI.splitFile.value = "";
      }

      setFeedback("Custom dataset imported successfully.", "success");
    } catch (e) {
      setText("custom-dataset-output", { ok: false, error: e.message });
    }
  }

  async function importDatasetFromPcap() {
    const datasetName = (PCAP_DATASET_UI.name?.value || "").trim();
    const datasetId = (PCAP_DATASET_UI.datasetId?.value || "").trim();
    const label = (PCAP_DATASET_UI.label?.value || "").trim();
    const autoLabel = (PCAP_DATASET_UI.autoLabel?.value || "0").trim();
    const labelColumn = (PCAP_DATASET_UI.labelColumn?.value || "Attack Type").trim();
    const testSize = (PCAP_DATASET_UI.testSize?.value || "0.30").trim();
    const flowTimeout = (PCAP_DATASET_UI.flowTimeout?.value || "120").trim();
    const activityTimeout = (PCAP_DATASET_UI.activityTimeout?.value || "5").trim();

    if (!datasetName) {
      setText("pcap-dataset-output", { ok: false, error: "Dataset display name is required" });
      setFeedback("Operation failed: Dataset display name is required", "error");
      return;
    }

    if (!datasetId) {
      setText("pcap-dataset-output", { ok: false, error: "Dataset internal id is required" });
      setFeedback("Operation failed: Dataset internal id is required", "error");
      return;
    }

    if (autoLabel !== "1" && !label) {
      setText("pcap-dataset-output", { ok: false, error: "Provide a fixed label or enable auto-label" });
      setFeedback("Operation failed: Provide a fixed label or enable auto-label", "error");
      return;
    }

    const selectedFile = PCAP_DATASET_UI.file?.files?.[0];

    if (!selectedFile) {
      setText("pcap-dataset-output", { ok: false, error: "Select a PCAP file first" });
      setFeedback("Operation failed: Select a PCAP file first", "error");
      return;
    }

    try {
      const data = await formRequestWithExtraFields(
        `${API_BASE}/datasets/import-from-pcap`,
        PCAP_DATASET_UI.file,
        {
          dataset_name: datasetName,
          dataset_id: datasetId,
          label: label,
          auto_label: autoLabel,
          label_column: labelColumn,
          test_size: testSize,
          flow_timeout: flowTimeout,
          activity_timeout: activityTimeout
        },
        "Uploading PCAP and generating dataset..."
      );

      setText("pcap-dataset-output", data);

      if (Array.isArray(data.profiles)) {
        const importedProfile = data.dataset?.profile || "";
        activeDatasetSource = "custom";

        refreshSelectorsAndCards(
          { profiles: data.profiles },
          getSelectedBuiltInDatasetKey(),
          importedProfile
        );

        setText("status-output", {
          ok: true,
          generated_dataset: data.dataset,
          rows_total: data.rows_total,
          custom_dataset_count: splitProfilesBySource(data.profiles).custom.length,
          custom_datasets: splitProfilesBySource(data.profiles).custom,
          effective_dataset: getEffectiveDatasetKey(),
          active_source: activeDatasetSource,
          message: data.message || "Custom dataset generated from PCAP successfully."
        });
      }

      if (PCAP_DATASET_UI.file) {
        PCAP_DATASET_UI.file.value = "";
      }

      setFeedback("Custom dataset generated from PCAP successfully.", "success");
    } catch (e) {
      setText("pcap-dataset-output", { ok: false, error: e.message });
    }
  }

  const btnProfiles = document.getElementById("btn-profiles");
  const btnStatus = document.getElementById("btn-status");
  const btnEvaluate = document.getElementById("btn-evaluate");
  const btnTrain = document.getElementById("btn-train");
  const btnExportSample = document.getElementById("btn-export-sample");
  const btnPredictCsv = document.getElementById("btn-predict-csv");
  const btnExtractPcap = document.getElementById("btn-extract-pcap");
  const btnPredictPcap = document.getElementById("btn-predict-pcap");
  const datasetSelect = document.getElementById("dataset-select");

  if (btnProfiles) {
    btnProfiles.addEventListener("click", async () => {
      try {
        await loadProfiles();
      } catch (e) {
        setText("status-output", { ok: false, error: e.message });
      }
    });
  }

  if (btnStatus) {
    btnStatus.addEventListener("click", async () => {
      try {
        await loadStatus();
      } catch (e) {
        setText("status-output", { ok: false, error: e.message });
      }
    });
  }

  if (datasetSelect) {
    datasetSelect.addEventListener("change", () => {
      activeDatasetSource = "built_in";
      renderSelectedProfileCard();
    });
  }

  if (CUSTOM_DATASET_SELECTOR_UI.select) {
    CUSTOM_DATASET_SELECTOR_UI.select.addEventListener("change", () => {
      const profiles = Array.isArray(cachedProfiles?.profiles) ? cachedProfiles.profiles : [];
      const { custom } = splitProfilesBySource(profiles);
      const selectedCustomKey = getSelectedCustomDatasetKey();

      if (selectedCustomKey) {
        activeDatasetSource = "custom";
      } else {
        activeDatasetSource = "built_in";
      }

      const selectedCustomProfile = custom.find(p => p.profile === selectedCustomKey) || null;
      renderCustomDatasetCard(selectedCustomProfile);
      renderSelectedProfileCard();
    });
  }

  if (CUSTOM_DATASET_SELECTOR_UI.loadProfilesBtn) {
    CUSTOM_DATASET_SELECTOR_UI.loadProfilesBtn.addEventListener("click", async () => {
      try {
        await loadCustomProfiles();
      } catch (e) {
        setText("custom-dataset-output", { ok: false, error: e.message });
      }
    });
  }

  if (CUSTOM_DATASET_SELECTOR_UI.loadStatusBtn) {
    CUSTOM_DATASET_SELECTOR_UI.loadStatusBtn.addEventListener("click", async () => {
      try {
        await loadCustomStatus();
      } catch (e) {
        setText("custom-dataset-output", { ok: false, error: e.message });
      }
    });
  }

  if (btnEvaluate) {
    btnEvaluate.addEventListener("click", async () => {
      const dataset = getEffectiveDatasetKey();

      try {
        const data = await jsonRequest(
          `${API_BASE}/baseline/evaluate`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ dataset })
          },
          `Reproducing baseline results for ${dataset}...`
        );

        setText("train-output", data);
        buildEvaluationExplanation(data);
        renderTable("metrics-container", data.classification_rows || []);
        renderSelectedProfileCard();
      } catch (e) {
        setText("train-output", { ok: false, error: e.message });
      }
    });
  }

  if (btnTrain) {
    btnTrain.addEventListener("click", async () => {
      const dataset = getEffectiveDatasetKey();

      try {
        const data = await jsonRequest(
          `${API_BASE}/retrain`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ dataset, set_active: true })
          },
          `Retraining framework model for ${dataset}...`
        );

        setText("train-output", data);
        buildEvaluationExplanation(data);
        renderTable("metrics-container", data.classification_rows || []);
        renderSelectedProfileCard();
      } catch (e) {
        setText("train-output", { ok: false, error: e.message });
      }
    });
  }

  if (btnExportSample) {
    btnExportSample.addEventListener("click", async () => {
      const dataset = getEffectiveDatasetKey();

      try {
        const data = await jsonRequest(
          `${API_BASE}/baseline/export-sample-csv?dataset=${encodeURIComponent(dataset)}&split=test&rows=50&include_label=1`,
          {},
          `Exporting prepared framework CSV for ${dataset}...`
        );

        setText("train-output", data);
        renderBulletBox(
          "explanation-box",
          "Prepared CSV explanation",
          [
            `Dataset profile: ${dataset}`,
            `Rows exported: ${data.rows}`,
            `Mode: ${data.mode}`
          ],
          data.message || ""
        );
        renderTable("metrics-container", data.preview || []);
      } catch (e) {
        setText("train-output", { ok: false, error: e.message });
      }
    });
  }

  if (btnPredictCsv) {
    btnPredictCsv.addEventListener("click", async () => {
      try {
        const input = document.getElementById("csv-file");
        const data = await formRequest(
          `${API_BASE}/predict-csv`,
          input,
          "Uploading CSV and running framework inference..."
        );

        setText("csv-output", data);
        buildPredictionExplanation("csv-explanation", data);
        renderSummary("csv-summary", data.summary);
        renderTable("csv-results", data.results || []);
      } catch (e) {
        setText("csv-output", { ok: false, error: e.message });
        renderBulletBox("csv-explanation", "", [], "");
        renderSummary("csv-summary", null);
        renderTable("csv-results", []);
      }
    });
  }

  if (btnExtractPcap) {
    btnExtractPcap.addEventListener("click", async () => {
      try {
        const input = document.getElementById("pcap-file-extract");
        const data = await formRequest(
          `${API_BASE}/extract-from-pcap`,
          input,
          "Uploading PCAP and generating alternative feature CSV..."
        );

        setText("pcap-extract-output", data);
        renderBulletBox(
          "pcap-preview",
          "Alternative PCAP conversion",
          [
            `Generated rows: ${data.rows}`,
            `CSV file: ${data.csv_file}`,
            `Mode: ${data.mode}`
          ],
          data.warning || data.message || ""
        );
      } catch (e) {
        setText("pcap-extract-output", { ok: false, error: e.message });
        renderBulletBox("pcap-preview", "", [], "");
      }
    });
  }

  if (PCAP_DATASET_UI.importBtn) {
    PCAP_DATASET_UI.importBtn.addEventListener("click", importDatasetFromPcap);
  }

  if (btnPredictPcap) {
    btnPredictPcap.addEventListener("click", async () => {
      try {
        const input = document.getElementById("pcap-file-predict");
        const data = await formRequest(
          `${API_BASE}/predict-pcap`,
          input,
          "Uploading PCAP and running alternative inference..."
        );

        setText("pcap-predict-output", data);
        buildPredictionExplanation("pcap-explanation", data);
        renderSummary("pcap-summary", data.summary);
        renderTable("pcap-results", data.results || []);
      } catch (e) {
        setText("pcap-predict-output", { ok: false, error: e.message });
        renderBulletBox("pcap-explanation", "", [], "");
        renderSummary("pcap-summary", null);
        renderTable("pcap-results", []);
      }
    });
  }

  if (CUSTOM_DATASET_UI.importBtn) {
    CUSTOM_DATASET_UI.importBtn.addEventListener("click", importCustomDataset);
  }

  (async () => {
    try {
      await loadProfiles();
      setFeedback("Frontend loaded. Ready.", "success");
    } catch (e) {
      setFeedback(`Frontend loaded, but profile autoload failed: ${e.message}`, "error");
    }
  })();
});