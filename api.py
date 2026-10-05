"""The only integration surface the Online teammate needs.

No internal Guard or Offline implementation detail is required to use
SentinelAuditor -- submit a valid threat package and read back events and
reports. These five functions are the entire contract described in the
project's integration plan; their shape must not change as Guard/Offline
internals evolve.
"""
from guard.events import read_events as _guard_events
from guard.guard import process_package_file
from offline.agent import start_offline_audit as _start_offline_audit
from offline.events import read_events as _offline_events
from offline.reports import get_latest_audit as _get_latest_audit


def submit_threat_package(path) -> dict:
    """Hand a threat-package file to the Guard. Returns APPROVED/REJECTED
    plus the reason when rejected. Approved packages land in the Offline
    inbox; rejected ones never do."""
    result = process_package_file(path)
    return {"status": result.status, "threat_id": result.threat_id, "reason": result.reason}


def get_guard_events() -> list:
    return _guard_events()


def get_offline_events() -> list:
    return _offline_events()


def get_latest_audit() -> dict | None:
    return _get_latest_audit()


def start_offline_audit(package_path=None) -> dict:
    """Run the full Offline phase sequence (analyze -> prove -> patch ->
    validate -> commit/rollback) against the oldest approved package in
    the inbox, or a specific package_path if given."""
    return _start_offline_audit(package_path)
