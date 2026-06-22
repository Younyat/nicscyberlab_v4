from __future__ import annotations

from importlib import import_module

__all__ = ["foc_bp", "regenerate_foc", "bootstrap_existing_context", "record_foc_event", "safe_notify_foc"]


def __getattr__(name: str):
    if name == "foc_bp":
        return import_module(".foc_endpoints", __name__).foc_bp
    if name == "regenerate_foc":
        return import_module(".foc_manifest_manager", __name__).regenerate_foc
    if name == "bootstrap_existing_context":
        return import_module(".foc_bootstrap", __name__).bootstrap_existing_context
    if name in {"record_foc_event", "safe_notify_foc"}:
        module = import_module(".foc_events", __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
