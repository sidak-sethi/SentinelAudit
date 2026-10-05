"""GUARD_* event log. A thin wrapper around communication/events.py that
fixes the component name and log file for the Guard."""
from communication import paths
from communication.events import emit as _emit, read_events as _read_events


def emit(event: str, status: str, details: str = "") -> dict:
    paths.ensure_directories()
    return _emit(paths.GUARD_EVENT_LOG, "GUARD", event, status, details)


def read_events() -> list:
    return _read_events(paths.GUARD_EVENT_LOG)
