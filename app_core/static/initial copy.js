
const API = "http://localhost:5001";

/* ======================
   UTILIDADES UI
   ====================== */
function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('opacity-100');
  setTimeout(() => toast.classList.remove('opacity-100'), 3000);
}

function showOverlay(show) {
  const overlay = document.getElementById('overlay');
  overlay.classList.toggle('hidden', !show);
}

function setProgress(pct) {
  const bar = document.getElementById('progress-bar-inner');
  bar.style.width = `${pct}%`;
}

function setStatus(text, subtext = '', type = 'idle') {
  const dot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const statusSub = document.getElementById('status-subtext');

  statusText.textContent = text;
  statusSub.textContent = subtext || '';

  if (type === 'ok') {
    dot.className = 'w-3 h-3 rounded-full bg-emerald-400 animate-pulse';
  } else if (type === 'warn') {
    dot.className = 'w-3 h-3 rounded-full bg-amber-400 animate-pulse';
  } else if (type === 'error') {
    dot.className = 'w-3 h-3 rounded-full bg-red-500 animate-pulse';
  } else {
    dot.className = 'w-3 h-3 rounded-full bg-rose-500 animate-pulse';
  }
}

/* ======================
   TERMINAL AVANZADA
   ====================== */
const termOutput = document.getElementById("terminal-output");

function nowTs() {
  const d = new Date();
  return d.toLocaleTimeString();
}

function terminalWrite(msg, colorClass = 'text-slate-100') {
  const line = document.createElement('div');
  line.className = `whitespace-pre ${colorClass}`;
  line.textContent = `[${nowTs()}]  ${msg}`;
  termOutput.appendChild(line);
  termOutput.scrollTop = termOutput.scrollHeight;
}

terminalWrite(" Terminal listo...");
setStatus("Configuración no guardada", "Modifica los campos y guarda antes de ejecutar.", "idle");

document.getElementById("clear-terminal").onclick = () => {
  termOutput.textContent = "";
  terminalWrite(" Terminal limpiado.", 'text-slate-400');
};

/* ======================
   MODAL DE CONFIRMACIÓN
   ====================== */
function showConfirm(title, message, onConfirm) {
  const modal = document.getElementById('confirm-modal');
  const titleEl = document.getElementById('confirm-title');
  const msgEl = document.getElementById('confirm-message');
  const btnCancel = document.getElementById('confirm-cancel');
  const btnAccept = document.getElementById('confirm-accept');

  titleEl.textContent = title;
  msgEl.textContent = message;
  modal.classList.remove('hidden');

  const clean = () => {
    modal.classList.add('hidden');
    btnCancel.removeEventListener('click', handleCancel);
    btnAccept.removeEventListener('click', handleAccept);
  };

  function handleCancel() {
    clean();
  }
  function handleAccept() {
    clean();
    if (typeof onConfirm === 'function') onConfirm();
  }

  btnCancel.addEventListener('click', handleCancel);
  btnAccept.addEventListener('click', handleAccept);
}

/* ======================
   ESTADO Y JSON
   ====================== */
let configGuardada = false;
const saveBtn = document.getElementById("save-config");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");

function actualizarEstado(guardado) {
  configGuardada = guardado;

  if (guardado) {
    setStatus("Configuración guardada", "Lista para ejecutar el generador.", "ok");
    setProgress(40);
  } else {
    setStatus("Configuración no guardada", "Pulsa en 'Guardar Configuración'.", "warn");
    setProgress(10);
  }
}

document.querySelectorAll(".editable, input[type='radio']")
  .forEach(el => {
    el.addEventListener("input", () => {
      actualizarEstado(false);
      terminalWrite(" Configuración modificada (no guardada)", 'text-amber-300');
    });
  });

function generarJSON() {
  const image_choice = document.querySelector("input[name='image_option']:checked").value;

  const flavors = {};
  document.querySelectorAll("table tbody tr").forEach(row => {
    const name = row.children[0].innerText.trim();
    const vcpus = row.children[1].querySelector("input").value;
    const ram = row.children[2].querySelector("input").value;
    const disk = row.children[3].querySelector("input").value;
    flavors[name] = { vcpus, ram, disk };
  });

  return {
    cleanup: true,
    image_choice,
    red_externa: document.getElementById("cidr_externa").value,
    red_privada: document.getElementById("cidr_privada").value,
    dns: document.getElementById("dns_nameservers").value,
    custom_ports: document.getElementById("custom_ports").value.trim()
      ? document.getElementById("custom_ports").value.trim().split(";")
      : [],
    flavors,
    network: true,
    flavors_enabled: true
  };
}

/* ======================
   GUARDAR
   ====================== */
saveBtn.onclick = () => {
  const cfg = generarJSON();
  actualizarEstado(true);
  terminalWrite(" Configuración guardada localmente:", 'text-emerald-300');
  terminalWrite(JSON.stringify(cfg, null, 2), 'text-slate-300');
  showToast(' Configuración guardada localmente.');
};

/* ======================
   BLOQUEO DE BOTONES
   ====================== */
function bloquearBotones() {
  const buttons = document.querySelectorAll("button");
  buttons.forEach(btn => {
    btn.disabled = true;
    btn.classList.add("opacity-50", "cursor-not-allowed");
  });
}

function desbloquearBotones() {
  const buttons = document.querySelectorAll("button");
  buttons.forEach(btn => {
    btn.disabled = false;
    btn.classList.remove("opacity-50", "cursor-not-allowed");
  });
}

/* ======================
   EJECUTAR GENERADOR
   ====================== */



document.getElementById("apply-config").onclick = () => {
  if (!configGuardada) {
    showToast(" Primero guarda la configuración.");
    terminalWrite(" Intento de ejecución sin guardar configuración.", 'text-amber-400');
    return;
  }

  const cfg = generarJSON();

  terminalWrite(" Enviando configuración al backend (nuevo generador)...", 'text-sky-300');
  setStatus("Ejecutando generador", "Contactando con el backend…", "warn");
  setProgress(60);

  bloquearBotones();
  showOverlay(true);

  fetch(`${API}/api/run_initial_environment_setup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cfg)
  })
  .then(async r => {
    const resp = await r.json();
    terminalWrite(" Respuesta backend:", 'text-sky-200');
    terminalWrite(JSON.stringify(resp, null, 2), 'text-slate-200');

 
if ((r.status !== 200 && r.status !== 202) || (resp.status !== "success" && resp.status !== "running")) {
    terminalWrite(" Error al iniciar el generador inicial", 'text-red-400');
    showToast(' Error al iniciar el generador inicial.');
    setStatus("Error al ejecutar el generador", "Revisa los logs en la terminal.", "error");
    setProgress(30);
    desbloquearBotones();
    showOverlay(false);
    return;
}


    // Éxito inmediato – el script sigue en background
    terminalWrite(" Generador iniciado en background.", 'text-emerald-300');
    showToast(' Generador inicial lanzado en segundo plano.');
    setStatus("Generador iniciado", "Backend ejecutando scripts…", "warn");
    setProgress(80);

    // (Opcional) iniciar SSE más adelante:
    // iniciarStream();

    desbloquearBotones();
    showOverlay(false);
  })
  .catch(err => {
    console.error(err);
    terminalWrite(` Error de conexión: ${err}`, 'text-red-400');
    showToast(' Error de conexión con el backend.');
    setStatus("Error de conexión", "No se pudo contactar con el backend.", "error");
    setProgress(20);
    desbloquearBotones();
    showOverlay(false);
  });
};





/* ======================
   SSErun-initial-generator-stream
   ====================== */
function iniciarStream() {
  const s = new EventSource(`${API}/api/run-initial-generator-stream`);

  s.onmessage = e => {
    terminalWrite(e.data, 'text-slate-100');
    if (e.data.includes("") || e.data.toLowerCase().includes("complete")) {
      setStatus("Generador finalizado", "Escenario inicial desplegado (si no hubo errores).", "ok");
      setProgress(100);
      desbloquearBotones();
      showOverlay(false);
    }
  };

  s.onerror = () => {
    terminalWrite(" Stream cerrado", 'text-red-400');
    s.close();
    desbloquearBotones();
    showOverlay(false);
  };
}

/* ======================
   DESTRUCCIÓN (CONFIRM + OVERLAY)
   ====================== */
async function destruirConfig() {
  bloquearBotones();
  showOverlay(true);
  terminalWrite('$  Iniciando destrucción del escenario...', 'text-yellow-300');
  showToast(' Destruyendo escenario... Esto puede tardar unos segundos.');
  setStatus("Destruyendo escenario", "Ejecutando scripts de limpieza en OpenStack…", "warn");
  setProgress(50);

  try {
    const response = await fetch(`${API}/api/destroy_initial_environment_setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });

    const data = await response.json();
    console.log("Respuesta del backend (destroy):", data);

    if (response.ok && data.status === "success") {
      if (data.stdout) terminalWrite(data.stdout, 'text-gray-300');
      terminalWrite(' Escenario destruido correctamente.', 'text-emerald-400');
      showToast(' Escenario destruido correctamente.');
      setStatus("Escenario destruido", "La infraestructura inicial ha sido limpiada.", "ok");
      setProgress(20);
    } else {
      terminalWrite('$  Error al destruir el escenario.', 'text-orange-400');
      if (data.stderr) terminalWrite(data.stderr, 'text-red-300');
      showToast(' No se pudo destruir completamente el escenario.');
      setStatus("Error al destruir", "Revisa los logs para más detalles.", "error");
      setProgress(30);
    }

  } catch (err) {
    console.error("Error al destruir el escenario:", err);
    terminalWrite(`$  Error al conectar con el backend: ${err}`, 'text-red-400');
    showToast(' Error de conexión con el backend.');
    setStatus("Error de conexión", "No se pudo contactar con el backend.", "error");
    setProgress(30);
  } finally {
    desbloquearBotones();
    showOverlay(false);
  }
}

document.getElementById("destroy-config").onclick = () => {
  showConfirm(
    '¿Destruir la configuración inicial?',
    ' Esta acción intentará eliminar los recursos desplegados en el escenario inicial. ¿Deseas continuar?',
    destruirConfig
  );
};


