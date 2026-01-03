# tools_uninstall_manager/json_tools_handler.py
import os
import json
import re

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(BASE, "tools-installer-tmp")

os.makedirs(TOOLS_DIR, exist_ok=True)


def safe_name(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name.lower())


def get_tools_json(instance: str) -> str:
    """
    Devuelve ruta absoluta del JSON de la instancia
    """
    filename = f"{safe_name(instance)}_tools.json"
    return os.path.join(TOOLS_DIR, filename)


def load_tools(instance: str):
    """
    Devuelve (tools_array, full_json) o ([], None si no existe)
    """
    path = get_tools_json(instance)

    if not os.path.exists(path):
        return [], None

    with open(path, "r") as f:
        data = json.load(f)

    return data.get("tools", []), data


def save_tools(instance: str, json_data: dict):
    """
    Sobrescribe el archivo JSON de tools
    """
    path = get_tools_json(instance)

    with open(path, "w") as f:
        json.dump(json_data, f, indent=4)

    return path


def remove_tool_from_json(instance: str, tool: str):
    """
    Borra la herramienta del JSON de la instancia.
    Retorna:
        (True, updatedTools) => se eliminó
        (False, existingTools) => no estaba
    """
    tools, data = load_tools(instance)

    if data is None:
        return False, []

    if tool not in tools:
        return False, tools

    tools.remove(tool)
    data["tools"] = tools

    save_tools(instance, data)
    return True, tools
