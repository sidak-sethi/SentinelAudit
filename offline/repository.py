"""Git plumbing restricted to offline_workspace/target_repo. Never touches
the Offline Auditor's own repository -- every command here runs with
cwd=paths.TARGET_REPO and goes through sandbox.run_command's allowlist.

Commits only ever happen once, at the very end of a successful patch
attempt (see offline/patcher.py); nothing is committed before every check
passes, so "rollback" is always just discarding uncommitted working-tree
changes -- never resetting history, never force-pushing, never deleting a
branch automatically.
"""
import re

from communication import paths
from offline.sandbox import run_command

BRANCH_NAME_RE = re.compile(r"^ai-security-fix/[A-Za-z0-9_\-:.]{1,100}$")


class GitSafetyError(RuntimeError):
    pass


def _repo_path():
    return paths.TARGET_REPO


def verify_git_repository() -> bool:
    return (_repo_path() / ".git").exists()


def verify_clean_worktree() -> bool:
    result = run_command(["git", "status", "--porcelain"], cwd=_repo_path())
    return result["returncode"] == 0 and result["stdout"].strip() == ""


def get_current_branch() -> str:
    result = run_command(["git", "status", "-b", "--porcelain"], cwd=_repo_path())
    first_line = (result["stdout"].splitlines() or [""])[0]
    name = first_line.lstrip("#").strip().split("...")[0].strip()
    return name or "main"


def get_default_branch() -> str | None:
    result = run_command(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=_repo_path())
    if result["returncode"] != 0:
        return None
    ref = result["stdout"].strip()
    return ref.removeprefix("origin/") or None


def create_fix_branch(threat_id: str) -> str:
    branch = f"ai-security-fix/{threat_id}"
    if not BRANCH_NAME_RE.match(branch):
        raise GitSafetyError(f"invalid branch name for threat_id={threat_id!r}")

    result = run_command(["git", "switch", "-c", branch], cwd=_repo_path())
    if result["returncode"] != 0:
        # The branch may already exist from a prior attempt in this run.
        retry = run_command(["git", "switch", branch], cwd=_repo_path())
        if retry["returncode"] != 0:
            raise GitSafetyError(
                f"could not create or switch to branch {branch}: {result['stderr']} / {retry['stderr']}"
            )
    return branch


def discard_working_tree_changes() -> None:
    run_command(["git", "checkout", "--", "."], cwd=_repo_path())


def diff() -> str:
    result = run_command(["git", "diff"], cwd=_repo_path())
    return result["stdout"]


def changed_files() -> set:
    result = run_command(["git", "diff", "--name-only"], cwd=_repo_path())
    return {line.strip().replace("\\", "/") for line in result["stdout"].splitlines() if line.strip()}


def status() -> str:
    result = run_command(["git", "status", "--porcelain"], cwd=_repo_path())
    return result["stdout"]


def commit(message: str) -> None:
    run_command(["git", "add", "-A"], cwd=_repo_path())
    result = run_command(["git", "commit", "-m", message], cwd=_repo_path())
    if result["returncode"] != 0:
        raise GitSafetyError(f"git commit failed: {result['stderr']}")


def commit_path(path: str, message: str) -> None:
    """Commit exactly one path, not everything uncommitted -- used when
    multiple findings from the same scan can each have their own pending,
    unrelated file (their generated security test) sitting uncommitted at
    once; `commit()`'s `git add -A` would wrongly bundle them together."""
    run_command(["git", "add", path], cwd=_repo_path())
    result = run_command(["git", "commit", "-m", message], cwd=_repo_path())
    if result["returncode"] != 0:
        raise GitSafetyError(f"git commit failed: {result['stderr']}")


def ensure_on_branch(branch_name: str) -> None:
    """Switch to `branch_name` if not already on it. Used to pull the
    worktree back to the true base branch before starting a new patch
    attempt, in case a previous fix in the same session left it checked
    out on a different branch (see offline/interactive.py)."""
    if get_current_branch() != branch_name:
        run_command(["git", "switch", branch_name], cwd=_repo_path())


def rollback_to_base(base_branch: str) -> None:
    discard_working_tree_changes()
    run_command(["git", "switch", base_branch], cwd=_repo_path())
