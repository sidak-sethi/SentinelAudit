"""Shared JSON-lines event log mechanics used by both guard/events.py and
offline/events.py. Each component keeps its own log file and its own thin
emit()/read_events() wrapper around this module; this file only holds the
shared read/write code so it isn't duplicated between the two.
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()


def emit(log_path: Path, component: str, event: str, status: str, details: str = "") -> dict:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": component,
        "event": event,
        "status": status,
        "details": details,
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    return record


def read_events(log_path: Path) -> list:
    if not log_path.exists():
        return []
    with open(log_path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
