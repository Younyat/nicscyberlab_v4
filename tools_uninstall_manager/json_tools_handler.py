import os
import json
import re

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Carpeta donde residen los archivos JSON de las VMs
TOOLS_DIR = os.path.join(BASE, "tools-installer-tmp")

os.makedirs(TOOLS_DIR, exist_ok=True)

def safe_name(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name.lower())

def get_tools_json(instance: str) -> str:
    return os.path.join(TOOLS_DIR, f"{safe_name(instance)}_tools.json")

def load_tools(instance: str):
    """Retorna el diccionario de herramientas y el objeto JSON completo."""
    path = get_tools_json(instance)
    if not os.path.exists(path):
        return {}, None
    with open(path, "r") as f:
        data = json.load(f)
    return data.get("tools", {}), data

def check_tool_status(instance: str, tool: str):
    """Verifica si la herramienta existe y su estado es 'installed'."""
    tools, data = load_tools(instance)
    if not data:
        return False, "No se encontró el archivo JSON de la instancia.", {}
    
    status = tools.get(tool)
    if not status:
        return False, f"La herramienta '{tool}' no está registrada.", tools
    
    if status == "installed":
        return True, "OK", tools
    
    return False, f"No se puede desinstalar: el estado actual es '{status}'.", tools

def remove_tool_from_json(instance: str, tool: str):
    """Elimina la herramienta del diccionario y guarda los cambios."""
    tools, data = load_tools(instance)
    if data and tool in tools:
        del data["tools"][tool] # Elimina la clave del diccionario
        path = get_tools_json(instance)
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
        return True, data["tools"]
    return False, tools