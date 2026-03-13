const socket = io({
    reconnectionAttempts: 3,
    reconnectionDelay: 1000
});
const terminal = document.getElementById("terminal");
const hostInput = document.getElementById("host");
const userInput = document.getElementById("user");
const keyInput = document.getElementById("key");
const btnConnect = document.getElementById("btnConnect");
const btnDisconnect = document.getElementById("btnDisconnect");
const cmdInput = document.getElementById("cmd");
const sendBtn = document.getElementById("send");

let sshConnected = false;

function print(text, cls = "line") {
    const d = document.createElement("div");
    d.className = cls;
    d.innerHTML = text;
    terminal.appendChild(d);
    terminal.scrollTop = terminal.scrollHeight;
}

btnConnect.onclick = () => {
    const host = hostInput.value.trim();
    const user = userInput.value.trim();
    const keyName = keyInput.value.trim();
    console.log("Enviando connect_ssh:", { host, user, keyName });
    if (!host || !user || !keyName) {
        print("[ERROR] Rellena host, user y key", "err");
        return;
    }
    socket.emit("connect_ssh", { host, user, keyName });
    print(`[INFO] Solicitando conexión SSH a ${user}@${host} con clave ${keyName}`, "info");
};

btnDisconnect.onclick = () => {
    socket.disconnect();
    sshConnected = false;
    sendBtn.disabled = true;
    print("[INFO] Socket desconectado (puedes recargar la página para reconectar).", "info");
};

sendBtn.onclick = () => {
    const cmd = cmdInput.value.trim();
    if (!cmd) return;
    print("$ " + cmd, "cmd");
    socket.emit("send_command", { command: cmd });
    cmdInput.value = "";
};

cmdInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendBtn.click();
});

socket.on("connect", () => {
    print("[INFO] Conectado al servidor WebSocket.", "info");
});

socket.on("disconnect", () => {
    sshConnected = false;
    sendBtn.disabled = true;
    print("[INFO] WebSocket desconectado.", "info");
});

socket.on("terminal_output", (msg) => {
    const text = msg.data || "";
    console.log("Recibido terminal_output:", text);
    if (text.startsWith("[SSH] Conectado a")) {
        sshConnected = true;
        sendBtn.disabled = false;
        print(text, "info");
    } else if (text.startsWith("[SSH] Conexión cerrada")) {
        sshConnected = false;
        sendBtn.disabled = true;
        print(text, "info");
    } else if (text.startsWith("[ERROR]")) {
        print(text, "err");
    } else if (text.startsWith("[INFO]")) {
        print(text, "info");
    } else {
        print(text);
    }
});