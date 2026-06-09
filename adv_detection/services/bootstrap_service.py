from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


REPO_URL = "https://github.com/nicslabdev/advDetection.git"


def get_module_root() -> Path:
    return Path(__file__).resolve().parents[1]


def get_vendor_root() -> Path:
    return get_module_root() / "vendor" / "advDetection"


def get_venv_root() -> Path:
    return get_module_root() / ".venv"


def get_venv_python() -> Path:
    venv_root = get_venv_root()
    return venv_root / "bin" / "python"


def get_venv_pip() -> Path:
    venv_root = get_venv_root()
    return venv_root / "bin" / "pip"


def get_venv_jupyter() -> Path:
    venv_root = get_venv_root()
    return venv_root / "bin" / "jupyter"


def run_cmd(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=True,
    )


def clone_repo_if_missing() -> dict[str, Any]:
    vendor_root = get_vendor_root()
    vendor_root.parent.mkdir(parents=True, exist_ok=True)

    if vendor_root.exists():
        return {
            "repo_cloned": False,
            "vendor_root": str(vendor_root),
        }

    run_cmd(["git", "clone", REPO_URL, str(vendor_root)])
    return {
        "repo_cloned": True,
        "vendor_root": str(vendor_root),
    }


def create_venv_if_missing() -> dict[str, Any]:
    venv_root = get_venv_root()

    if get_venv_python().exists():
        return {
            "venv_created": False,
            "venv_root": str(venv_root),
        }

    run_cmd(["python3", "-m", "venv", str(venv_root)])
    return {
        "venv_created": True,
        "venv_root": str(venv_root),
    }


def install_requirements_if_needed() -> dict[str, Any]:
    vendor_root = get_vendor_root()
    pip_bin = get_venv_pip()

    if not pip_bin.exists():
        raise FileNotFoundError(f"pip not found in venv: {pip_bin}")

    installed_marker = get_venv_root() / ".adv_detection_requirements_installed"

    if installed_marker.exists():
        return {
            "dependencies_installed": False,
            "marker": str(installed_marker),
        }

    run_cmd([str(pip_bin), "install", "--upgrade", "pip", "setuptools", "wheel"])

    req_candidates = [
        vendor_root / "requirements.txt",
        vendor_root / "test_efficiency_realtime" / "requirements.txt",
        vendor_root / "test_efficiency_realtime" / "requierements-updated.txt",
    ]

    installed_any_req = False
    for req in req_candidates:
        if req.exists():
            run_cmd([str(pip_bin), "install", "-r", str(req)])
            installed_any_req = True

    extra_packages = [
        "torch",
        "torchattacks",
        "pandas",
        "numpy",
        "scikit-learn",
        "jupyter",
        "nbconvert",
        "nbclient",
        "ipykernel",
    ]
    run_cmd([str(pip_bin), "install", *extra_packages])

    installed_marker.write_text("ok\n", encoding="utf-8")

    return {
        "dependencies_installed": True,
        "installed_any_requirements_file": installed_any_req,
        "marker": str(installed_marker),
    }


def ensure_module_ready() -> dict[str, Any]:
    repo_info = clone_repo_if_missing()
    venv_info = create_venv_if_missing()
    deps_info = install_requirements_if_needed()

    return {
        "ok": True,
        "repo": repo_info,
        "venv": venv_info,
        "deps": deps_info,
        "vendor_root": str(get_vendor_root()),
        "venv_python": str(get_venv_python()),
        "venv_jupyter": str(get_venv_jupyter()),
    }