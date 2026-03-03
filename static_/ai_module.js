const overlay = document.getElementById("overlay");
const statusDiv = document.getElementById("status");
const overlayStatus = document.getElementById("overlay-status");
const deployBtn = document.getElementById("deployBtn");
const progressBar = document.getElementById("progress");
const logTerminal = document.getElementById("ai-log-terminal");

let logSource = null;
let UI_LOCKED = false;   // 🔒 BLOQUEO GLOBAL

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
   Estado IA
========================= */
async function pollStatus() {
  let d;

  try {
    const r = await fetch("/api/ai/status");
    d = await r.json();
  } catch (e) {
    if (!UI_LOCKED) {
      statusDiv.textContent = "Error conectando con el backend.";
    }
    return;
  }

  /* ======================================
     🔒 SI LA UI ESTÁ BLOQUEADA → NO CAMBIAR NADA
     SOLO ACTUALIZAR PROGRESO / LOGS
  ====================================== */
  if (UI_LOCKED) {
    overlayStatus.textContent = d.message || "Desplegando módulo IA…";

    if (typeof d.progress === "number") {
      progressBar.style.width = `${d.progress}%`;
    }

    // FIN CORRECTO
    if (d.installed && d.status?.gui?.url) {
      window.location.href = d.status.gui.url;
      return;
    }

    // ERROR GRAVE (opcional)
    if (!d.deploying && d.progress < 100) {
      overlayStatus.textContent = "Error durante el despliegue.";
    }

    setTimeout(pollStatus, 2000);
    return;
  }

  /* =========================
     ESTADO NORMAL (NO BLOQUEADO)
  ========================= */
  statusDiv.textContent = d.message || "Comprobando estado…";

  // YA INSTALADO
  if (d.installed && d.status?.gui?.url) {
    window.location.href = d.status.gui.url;
    return;
  }

  // DESPLIEGUE YA EN CURSO (ej. refresh de página)
  if (d.deploying) {
    UI_LOCKED = true;
    deployBtn.classList.add("hidden");
    setOverlay(true);
    startLogStream();
    pollStatus();
    return;
  }

  // NO INSTALADO → pedir consentimiento
  deployBtn.classList.remove("hidden");
}

/* =========================
   CONSENTIMIENTO EXPLÍCITO
========================= */
deployBtn.onclick = async () => {
  const ok = confirm(
    "El módulo de IA no existe.\n\n¿Confirmas que deseas desplegarlo ahora?\n\n⚠️ El sistema quedará bloqueado hasta finalizar."
  );

  if (!ok) return;

  // 🔒 BLOQUEO TOTAL
  UI_LOCKED = true;

  deployBtn.classList.add("hidden");
  statusDiv.textContent = "Despliegue iniciado…";
  overlayStatus.textContent = "Inicializando despliegue…";

  setOverlay(true);
  startLogStream();

  await fetch("/api/ai/deploy", { method: "POST" });

  pollStatus();
};

/* =========================
   INIT
========================= */
pollStatus();
