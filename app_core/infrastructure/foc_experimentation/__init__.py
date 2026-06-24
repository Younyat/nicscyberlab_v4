from __future__ import annotations

from importlib import import_module

__all__ = ["experimentation_root", "experimentation_bp"]


def __getattr__(name: str):
    if name == "experimentation_root":
        return import_module(".config", __name__).CAMPAIGNS_ROOT
    if name == "experimentation_bp":
        return import_module("app_core.presentation.foc_experimentation_api").experimentation_bp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
