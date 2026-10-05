"""Guard: the one-way, deterministic security boundary between Online and
Offline.

Reads candidate packages from paths.ONLINE_OUTBOX, validates them with
validator.py (schema/type/size/format/hash + the deterministic injection
scan), and atomically transfers only approved packages into
paths.OFFLINE_INBOX.

There is no function anywhere in this module that writes back into
ONLINE_OUTBOX, and nothing here reaches into Offline's internals beyond
dropping a file into its inbox. Rejected packages are quarantined with
their reason for the audit trail and never reach Offline.
"""
import json
import os
import tempfile
from dataclasses import dataclass

from communication import paths
from guard import events
from guard.sanitizer import SUSPICIOUS
from guard.validator import validate_package


@dataclass
class GuardResult:
    status: str  # "APPROVED" | "REJECTED"
    threat_id: str | None
    reason: str | None = None
    destination: str | None = None


def process_package_bytes(raw_bytes: bytes, source_name: str = "<package>") -> GuardResult:
    events.emit("GUARD_PACKAGE_RECEIVED", "started", source_name)
    events.emit("GUARD_VALIDATION_STARTED", "started", source_name)

    result = validate_package(raw_bytes)

    if not result.ok:
        reason = "; ".join(result.errors)
        threat_id = (result.parsed or {}).get("threat_id") if result.parsed else None
        events.emit("GUARD_PACKAGE_REJECTED", "failure", reason)
        _quarantine(raw_bytes, source_name, reason)
        return GuardResult(status="REJECTED", threat_id=threat_id, reason=reason)

    if result.classification == SUSPICIOUS:
        events.emit("GUARD_PACKAGE_APPROVED", "success", "approved with SUSPICIOUS flag (soft heuristic only, logged for review)")
    else:
        events.emit("GUARD_PACKAGE_APPROVED", "success", source_name)

    threat_id = result.parsed["threat_id"]
    destination = _transfer_atomic(result.parsed, threat_id)
    events.emit("GUARD_TRANSFER_COMPLETE", "success", str(destination))
    return GuardResult(status="APPROVED", threat_id=threat_id, destination=str(destination))


def process_package_file(path) -> GuardResult:
    with open(path, "rb") as fh:
        raw_bytes = fh.read()
    return process_package_bytes(raw_bytes, source_name=os.path.basename(str(path)))


def _transfer_atomic(parsed: dict, threat_id: str):
    """Write to a temp file in the destination directory, then os.replace
    -- atomic on the same filesystem, so Offline can never observe a
    partially-written package."""
    paths.ensure_directories()
    destination = paths.OFFLINE_INBOX / f"{threat_id}.json"
    fd, tmp_path = tempfile.mkstemp(dir=str(paths.OFFLINE_INBOX), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(parsed, fh, indent=2, sort_keys=True)
        os.replace(tmp_path, destination)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    return destination


def _quarantine(raw_bytes: bytes, source_name: str, reason: str) -> None:
    paths.ensure_directories()
    safe_name = os.path.basename(source_name) or "package"
    destination = paths.GUARD_REJECTED / f"{safe_name}.rejected.json"
    record = {"reason": reason, "raw": raw_bytes.decode("utf-8", errors="replace")}
    with open(destination, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)


def watch_once() -> list:
    """Process every file currently sitting in ONLINE_OUTBOX, once, and
    consume it either way (an approved copy now lives in OFFLINE_INBOX; a
    rejected copy lives in GUARD_REJECTED with its reason)."""
    paths.ensure_directories()
    results = []
    if not paths.ONLINE_OUTBOX.exists():
        return results
    for entry in sorted(paths.ONLINE_OUTBOX.iterdir()):
        if entry.is_file() and entry.suffix == ".json":
            results.append(process_package_file(entry))
            entry.unlink()
    return results
