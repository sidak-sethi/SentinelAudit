"""Explicit, path-and-command-guarded tools exposed to Gemma.

Gemma never gets raw shell access -- every operation here is a narrow
Python function with its own validation. Every path argument is resolved
against offline_workspace/target_repo and rejected (PATH_REJECTED) if it
escapes that root in any way: traversal, absolute paths, drive/UNC
escapes, or symlink escapes.
"""
import hashlib
import re
from pathlib import Path

from communication import paths
from offline import languages, repository

MAX_READ_BYTES = 200_000


def active_profile() -> languages.LanguageProfile:
    """The language profile for the currently-selected target repo,
    defaulting to Python when detection is ambiguous -- preserves exact
    existing behavior for the fixtures/demo/Online-integration flow,
    which never calls the explicit language-selection gate at all."""
    return languages.detect_language(paths.TARGET_REPO) or languages.PYTHON


class PathRejectedError(RuntimeError):
    """Raised for any path that resolves outside offline_workspace/target_repo.
    Callers should treat this exactly like the PATH_REJECTED outcome
    described in the Offline tool-security model."""


def resolve_safe_path(relative_path: str) -> Path:
    root = paths.TARGET_REPO.resolve()
    if not isinstance(relative_path, str) or relative_path == "":
        raise PathRejectedError("PATH_REJECTED: empty path")

    raw = relative_path.replace("\\", "/")
    if raw.startswith("/") or raw.startswith("//") or re.match(r"^[A-Za-z]:", raw):
        raise PathRejectedError(f"PATH_REJECTED: absolute path not allowed: {relative_path}")

    candidate = (root / raw).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise PathRejectedError(f"PATH_REJECTED: path escapes target repository: {relative_path}") from None
    return candidate


def list_files(subdir: str = ".") -> list:
    base = paths.TARGET_REPO.resolve() if subdir in (".", "") else resolve_safe_path(subdir)
    root = paths.TARGET_REPO.resolve()
    results = []
    for entry in base.rglob("*"):
        if ".git" in entry.parts:
            continue
        if entry.is_file():
            results.append(str(entry.relative_to(root)).replace("\\", "/"))
    return sorted(results)


def read_file(path: str) -> str:
    target = resolve_safe_path(path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file: {path}")
    data = target.read_bytes()[:MAX_READ_BYTES]
    return data.decode("utf-8", errors="replace")


def write_file(path: str, content: str) -> None:
    target = resolve_safe_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def search_code(pattern: str, subdir: str = ".") -> list:
    try:
        regex = re.compile(pattern)
    except re.error:
        return []
    matches = []
    for rel_path in list_files(subdir):
        try:
            text = read_file(rel_path)
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                matches.append({"path": rel_path, "line": lineno, "text": line.strip()[:300]})
    return matches


def get_file_metadata(path: str) -> dict:
    target = resolve_safe_path(path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file: {path}")
    stat = target.stat()
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return {"path": path, "size": stat.st_size, "mtime": stat.st_mtime, "sha256": digest}


def git_status() -> str:
    return repository.status()


def git_diff() -> str:
    return repository.diff()


def create_branch(name: str) -> str:
    return repository.create_fix_branch(name)


def run_tests() -> dict:
    return active_profile().run_normal_tests(paths.TARGET_REPO)


def run_security_test(test_path: str) -> dict:
    resolved = resolve_safe_path(test_path)
    relative = str(resolved.relative_to(paths.TARGET_REPO.resolve())).replace("\\", "/")
    return active_profile().run_security_test(paths.TARGET_REPO, relative)


def git_commit(message: str) -> None:
    repository.commit(message)


def git_revert() -> None:
    repository.discard_working_tree_changes()
