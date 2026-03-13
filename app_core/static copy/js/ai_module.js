const overlay = document.getElementById("overlay");
const statusDiv = document.getElementById("status");
const overlayStatus = document.getElementById("overlay-status");
const deployBtn = document.getElementById("deployBtn");
const progressBar = document.getElementById("progress");
const logTerminal = document.getElementById("ai-log-terminal");

let logSource = null;
let UI_LOCKED = false;   //  GLOBAL LOCK

/* =========================
   UI helpers
========================= */
function setOverlay(show) {
  overlay.classList.toggle("hidden", !show);
  overlay.classList.toggle("flex", show);
}

/* =========================
   Logs stream
========================= */
function startLogStream() {
  if (logSource) return;

  logTerminal.textContent = "";
  logSource = new EventSource("/api/ai/logs");

  logSource.onmessage = (e) => {
    logTerminal.textContent += e.data + "\n";
    logTerminal.scrollTop = logTerminal.scrollHeight;
  };

  logSource.onerror = () => {
    logSource.close();
    logSource = null;
  };
}

/* =========================
   AI status
========================= */
async function pollStatus() {
  let d;

  try {
    const r = await fetch("/api/ai/status");
    d = await r.json();
  } catch (e) {
    if (!UI_LOCKED) {
      statusDiv.textContent = "Error connecting to the backend.";
    }
    return;
  }

  /* ======================================
      IF UI IS LOCKED → DO NOT CHANGE ANYTHING
     ONLY UPDATE PROGRESS / LOGS
  ====================================== */
  if (UI_LOCKED) {
    overlayStatus.textContent = d.message || "Deploying AI module…";

    if (typeof d.progress === "number") {
      progressBar.style.width = `${d.progress}%`;
    }

    // CORRECT FINISH
    if (d.installed && d.status?.gui?.url) {
      window.location.href = d.status.gui.url;
      return;
    }

    // CRITICAL ERROR (optional)
    if (!d.deploying && d.progress < 100) {
      overlayStatus.textContent = "Error during deployment.";
    }

    setTimeout(pollStatus, 2000);
    return;
  }

  /* =========================
     NORMAL STATE (NOT LOCKED)
  ========================= */
  statusDiv.textContent = d.message || "Checking status…";

  // ALREADY INSTALLED
  if (d.installed && d.status?.gui?.url) {
    window.location.href = d.status.gui.url;
    return;
  }

  // DEPLOYMENT ALREADY IN PROGRESS (e.g., page refresh)
  if (d.deploying) {
    UI_LOCKED = true;
    deployBtn.classList.add("hidden");
    setOverlay(true);
    startLogStream();
    pollStatus();
    return;
  }

  // NOT INSTALLED → request consent
  deployBtn.classList.remove("hidden");
}

/* =========================
   EXPLICIT CONSENT
========================= */
deployBtn.onclick = async () => {
  const ok = confirm(
    "The AI module does not exist.\n\nDo you confirm that you want to deploy it now?\n\n The system will remain locked until it finishes."
  );

  if (!ok) return;

  //  TOTAL LOCK
  UI_LOCKED = true;

  deployBtn.classList.add("hidden");
  statusDiv.textContent = "Deployment started…";
  overlayStatus.textContent = "Initializing deployment…";

  setOverlay(true);
  startLogStream();

  await fetch("/api/ai/deploy", { method: "POST" });

  pollStatus();
};

/* =========================
   INIT
========================= */
pollStatus();