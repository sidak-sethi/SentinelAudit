"""Centralized, configurable filesystem paths for SentinelAuditor.

Every location the Guard or Offline agent touches is defined here, with an
environment-variable override, so there is exactly one place that decides
where data lives. Nothing outside this module should hardcode a path.
"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_path(var_name: str, default: Path) -> Path:
    raw = os.environ.get(var_name)
    return Path(raw).resolve() if raw else default.resolve()


WORKSPACE_ROOT = _env_path("SENTINEL_WORKSPACE", PROJECT_ROOT / "offline_workspace")

ONLINE_OUTBOX = _env_path("SENTINEL_ONLINE_OUTBOX", WORKSPACE_ROOT / "online_outbox")
GUARD_REJECTED = _env_path("SENTINEL_GUARD_REJECTED", WORKSPACE_ROOT / "guard_rejected")
OFFLINE_INBOX = _env_path("SENTINEL_OFFLINE_INBOX", WORKSPACE_ROOT / "offline_inbox")
TARGET_REPO = _env_path("SENTINEL_TARGET_REPO", WORKSPACE_ROOT / "target_repo")
REPORTS_DIR = _env_path("SENTINEL_REPORTS_DIR", WORKSPACE_ROOT / "reports")

GUARD_EVENT_LOG = _env_path("SENTINEL_GUARD_EVENT_LOG", WORKSPACE_ROOT / "guard_events.jsonl")
OFFLINE_EVENT_LOG = _env_path("SENTINEL_OFFLINE_EVENT_LOG", WORKSPACE_ROOT / "offline_events.jsonl")

# Relative to TARGET_REPO -- where generated security regression tests live.
SECURITY_TEST_DIR = "tests/security"


def ensure_directories() -> None:
    """Create every directory that must exist before Guard or Offline can
    run. Never creates or touches TARGET_REPO itself -- that is scaffolded
    explicitly by fixtures/setup_target_repo.py (it needs its own git init,
    not just an empty folder)."""
    for directory in (WORKSPACE_ROOT, ONLINE_OUTBOX, GUARD_REJECTED, OFFLINE_INBOX, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def set_target_repo(path) -> Path:
    """Point the Offline agent at a different repository at runtime --
    no env var, no process restart, no module reload needed.

    Every consumer (tools.py, repository.py, and anything that calls them)
    reads `paths.TARGET_REPO` as a module attribute at call time, not at
    import time, so reassigning it here is immediately visible everywhere.
    Used by offline/interactive.py and cli.py for interactive repo
    selection; the demo/Online-integration flow keeps using
    SENTINEL_TARGET_REPO / the default instead.
    """
    global TARGET_REPO
    TARGET_REPO = Path(path).resolve()
    return TARGET_REPO
