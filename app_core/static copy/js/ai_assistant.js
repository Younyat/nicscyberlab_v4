/**
 * Envía la consulta del usuario al backend que ejecuta preguntarLLM.sh
 */
async function askAI() {
    const input = document.getElementById("ai-input");
    const windowEl = document.getElementById("ai-chat-window");
    const btn = document.getElementById("btn-ai-send");
    const prompt = input.value.trim();

    if (!prompt) return;

    // Bloquear UI mientras responde
    input.disabled = true;
    btn.disabled = true;
    btn.textContent = "PROCESANDO...";

    // Añadir mensaje del usuario al chat
    appendChatMessage("ANALISTA", prompt, "text-sky-400");
    input.value = "";

    try {
        const response = await fetch("/api/ai/ask", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt: prompt })
        });

        const data = await response.json();

        if (data.status === "success") {
            appendChatMessage("QWEN-IA", data.response, "text-emerald-400 bg-emerald-500/5 p-3 rounded-lg border border-emerald-500/10");
        } else {
            appendChatMessage("ERROR", data.details || data.error, "text-red-400");
        }
    } catch (err) {
        appendChatMessage("ERROR", "No se pudo conectar con el servicio de IA.", "text-red-500");
    } finally {
        input.disabled = false;
        btn.disabled = false;
        btn.textContent = "CONSULTAR";
        input.focus();
        windowEl.scrollTop = windowEl.scrollHeight;
    }
}

/**
 * Helper para renderizar mensajes en la terminal
 */
function appendChatMessage(role, message, cls) {
    const windowEl = document.getElementById("ai-chat-window");
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    const msgHtml = `
        <div class="animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div class="flex justify-between mb-1">
                <span class="text-[10px] font-bold uppercase tracking-widest ${cls.includes('red') ? 'text-red-500' : 'text-slate-500'}">[${role}]</span>
                <span class="text-[9px] text-slate-600">${time}</span>
            </div>
            <div class="${cls} leading-relaxed whitespace-pre-wrap">${message}</div>
        </div>
    `;
    
    windowEl.innerHTML += msgHtml;
    windowEl.scrollTop = windowEl.scrollHeight;
}

// Permitir enviar con la tecla Enter
document.getElementById("ai-input")?.addEventListener("keypress", (e) => {
    if (e.key === "Enter") askAI();
});