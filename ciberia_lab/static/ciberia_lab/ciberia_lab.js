const API_BASE = "/api/ciberia";

function setText(id, value) {
  document.getElementById(id).textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function renderSummary(containerId, summary) {
  const el = document.getElementById(containerId);
  if (!summary) {
    el.innerHTML = "";
    return;
  }

  const entries = Object.entries(summary)
    .map(([k, v]) => `<div><strong>${k}</strong>: ${v}</div>`)
    .join("");

  el.innerHTML = `<div class="summary">${entries}</div>`;
}

function renderTable(containerId, rows, limit = 50) {
  const el = document.getElementById(containerId);
  if (!rows || rows.length === 0) {
    el.innerHTML = "";
    return;
  }

  const data = rows.slice(0, limit);
  const cols = Object.keys(data[0]);

  const head = cols.map(c => `<th>${c}</th>`).join("");
  const body = data.map(row => {
    const cells = cols.map(c => {
      const val = typeof row[c] === "object" ? JSON.stringify(row[c]) : row[c];
      return `<td>${val}</td>`;
    }).join("");
    return `<tr>${cells}</tr>`;
  }).join("");

  el.innerHTML = `
    <div class="small">Showing ${data.length} rows</div>
    <table>
      <thead><tr>${head}</tr></thead>
      <tbody>${body}</tbody>
    </table>
  `;
}

async function jsonRequest(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

async function formRequest(url, fileInput) {
  if (!fileInput.files || fileInput.files.length === 0) {
    throw new Error("Select a file first");
  }

  const form = new FormData();
  form.append("file", fileInput.files[0]);

  const res = await fetch(url, {
    method: "POST",
    body: form
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

document.getElementById("btn-health").addEventListener("click", async () => {
  try {
    const data = await jsonRequest(`${API_BASE}/health`);
    setText("status-output", data);
  } catch (e) {
    setText("status-output", { ok: false, error: e.message });
  }
});

document.getElementById("btn-status").addEventListener("click", async () => {
  try {
    const data = await jsonRequest(`${API_BASE}/status`);
    setText("status-output", data);
  } catch (e) {
    setText("status-output", { ok: false, error: e.message });
  }
});

document.getElementById("btn-train").addEventListener("click", async () => {
  const dataset = document.getElementById("dataset-select").value;
  try {
    const data = await jsonRequest(`${API_BASE}/train-default`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dataset, set_active: true })
    });
    setText("train-output", data);
    renderTable(
      "metrics-container",
      Object.entries(data.classification_report || {})
        .map(([k, v]) => ({
          label: k,
          precision: v.precision,
          recall: v.recall,
          f1_score: v["f1-score"],
          support: v.support
        }))
        .filter(x => x.precision !== undefined)
    );
  } catch (e) {
    setText("train-output", { ok: false, error: e.message });
  }
});

document.getElementById("btn-evaluate").addEventListener("click", async () => {
  const dataset = document.getElementById("dataset-select").value;
  try {
    const data = await jsonRequest(`${API_BASE}/evaluate-default`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dataset })
    });
    setText("train-output", data);
    renderTable(
      "metrics-container",
      Object.entries(data.classification_report || {})
        .map(([k, v]) => ({
          label: k,
          precision: v.precision,
          recall: v.recall,
          f1_score: v["f1-score"],
          support: v.support
        }))
        .filter(x => x.precision !== undefined)
    );
  } catch (e) {
    setText("train-output", { ok: false, error: e.message });
  }
});

document.getElementById("btn-export-sample").addEventListener("click", async () => {
  const dataset = document.getElementById("dataset-select").value;
  try {
    const data = await jsonRequest(`${API_BASE}/export-sample-csv?dataset=${encodeURIComponent(dataset)}&split=test&rows=50&include_label=1`);
    setText("train-output", data);
    renderTable("metrics-container", data.preview || []);
  } catch (e) {
    setText("train-output", { ok: false, error: e.message });
  }
});

document.getElementById("btn-predict-csv").addEventListener("click", async () => {
  try {
    const input = document.getElementById("csv-file");
    const data = await formRequest(`${API_BASE}/predict-csv`, input);
    setText("csv-output", data);
    renderSummary("csv-summary", data.summary);
    renderTable("csv-results", data.results || []);
  } catch (e) {
    setText("csv-output", { ok: false, error: e.message });
    renderSummary("csv-summary", null);
    renderTable("csv-results", []);
  }
});

document.getElementById("btn-extract-pcap").addEventListener("click", async () => {
  try {
    const input = document.getElementById("pcap-file-extract");
    const data = await formRequest(`${API_BASE}/extract-from-pcap`, input);
    setText("pcap-extract-output", data);
    renderTable("pcap-preview", data.preview || []);
  } catch (e) {
    setText("pcap-extract-output", { ok: false, error: e.message });
    renderTable("pcap-preview", []);
  }
});

document.getElementById("btn-predict-pcap").addEventListener("click", async () => {
  try {
    const input = document.getElementById("pcap-file-predict");
    const data = await formRequest(`${API_BASE}/predict-pcap`, input);
    setText("pcap-predict-output", data);
    renderSummary("pcap-summary", data.summary);
    renderTable("pcap-results", data.results || []);
  } catch (e) {
    setText("pcap-predict-output", { ok: false, error: e.message });
    renderSummary("pcap-summary", null);
    renderTable("pcap-results", []);
  }
});