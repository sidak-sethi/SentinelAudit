"""Interactive, human-driven entry point: pick a repository at runtime,
scan it for vulnerabilities, and only patch the ones a person explicitly
approves.

This is a separate surface from api.py (which is the fixed, narrow
contract for the Online teammate's threat-package-driven flow) -- cli.py
is the only intended caller of this module. It reuses the existing engine
untouched: scanning goes through the same Guard, the same
auditor.run_audit() proof step, and the same patcher.run_patch_loop() as
the threat-package flow, so nothing here weakens any safety property.
"""
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from communication import paths
from guard.guard import process_package_bytes
from offline import auditor, languages, patcher, prepared_patcher, reports, repository, scanner

# The branch select_repo()/init_git_repo() found the repo on, remembered
# so apply_fix() can always cut a fix branch from the TRUE base -- not
# from wherever a previous fix in the same session happened to leave the
# worktree checked out (every successful fix stays on its own
# ai-security-fix/<id> branch; without this, a second fix in the same
# session would branch off the first fix instead of off the real base).
_base_branch: str | None = None
_base_branch_repo: str | None = None


@dataclass
class RepoSelection:
    status: str  # "ready" | "needs_git_init" | "dirty_worktree" | "unsupported_language"
    path: Path
    detail: str | None = None


@dataclass
class ScanFinding:
    """One lead from Gemma's scan, all the way through whatever happened
    to it -- never silently dropped. `status` is one of:
    "confirmed" (audit.status == "vulnerable", a real test proved it),
    "not_applicable", "uncertain", "ai_error" (all from auditor.run_audit),
    or "guard_rejected" (the Guard's deterministic checks flagged the
    finding's own wording -- this can be a false positive, since
    describing a real vulnerability and attempting one can use similar
    vocabulary; it is surfaced, not hidden, specifically so that is
    checkable)."""
    raw: dict
    package: dict
    status: str
    reason: str
    audit: object = None  # proof result, or deferred-audit context for HTTP scans


def select_repo(path) -> RepoSelection:
    """Point the Offline agent at `path` for this process. Never inits
    git or touches the worktree itself -- it only reports what state the
    repo is in so the caller (cli.py) can decide, with the user's
    explicit confirmation, what to do about it."""
    global _base_branch, _base_branch_repo
    resolved = paths.set_target_repo(path)
    repo_key = str(resolved)
    language = languages.detect_unsupported_language(resolved)
    if language is not None:
        return RepoSelection(status="unsupported_language", path=resolved, detail=language)
    if not repository.verify_git_repository():
        _base_branch = None
        _base_branch_repo = repo_key
        return RepoSelection(status="needs_git_init", path=resolved)
    cleanup_generated_security_tests(resolved)
    if not repository.verify_clean_worktree():
        return RepoSelection(status="dirty_worktree", path=resolved)
    if _base_branch_repo != repo_key or _base_branch is None:
        current = repository.get_current_branch()
        default_branch = repository.get_default_branch()
        _base_branch = default_branch or (current if not current.startswith("ai-security-fix/") else None)
        _base_branch_repo = repo_key
    return RepoSelection(status="ready", path=resolved)


def cleanup_generated_security_tests(repo_path) -> None:
    """Remove only untracked audit tests carrying the generator marker.

    Test files are temporary evidence for an audit. A process restart or an
    unsupported patch template must not leave those artifacts blocking the
    next scan, while unrelated user files remain untouched.
    """
    import subprocess

    repo = Path(repo_path)
    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=str(repo), capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        return
    marker = "SentinelAudit generated security regression test"
    for raw_path in result.stdout.split("\0"):
        relative = raw_path.replace("\\", "/")
        if not relative.startswith("tests/security/"):
            continue
        try:
            target = (repo / raw_path).resolve(strict=True)
            target.relative_to(repo.resolve())
            if target.is_file() and marker in target.read_text(encoding="utf-8", errors="replace")[:512]:
                target.unlink()
        except (OSError, ValueError):
            continue


def init_git_repo() -> None:
    """Only called after the user explicitly agrees (see cli.py). Adds a
    .git directory and one commit of the current state -- additive and
    reversible (deleting .git undoes it), never touches file contents.

    This is a human-confirmed setup action, not something Gemma can
    trigger, so it uses subprocess directly instead of
    offline.sandbox.run_command -- the same way fixtures/setup_target_repo.py
    does. The sandbox's command allowlist exists to constrain what Gemma
    can invoke autonomously (it never calls "git init"); it is not a
    blanket restriction on every git operation in this codebase.
    """
    global _base_branch, _base_branch_repo
    import subprocess
    repo = paths.TARGET_REPO
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True, text=True)

    # Without this, running the normal/security test suites (which this
    # tool does repeatedly) leaves __pycache__/.pytest_cache bytecode as
    # untracked, dirtying the worktree for no reason the user caused.
    gitignore = repo / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("__pycache__/\n*.pyc\n.pytest_cache/\n", encoding="utf-8")

    subprocess.run(["git", "add", "-A"], cwd=str(repo), check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial import for SentinelAuditor audit"],
        cwd=str(repo), check=True, capture_output=True, text=True,
    )
    _base_branch = repository.get_current_branch()
    _base_branch_repo = str(repo.resolve())


def find_vulnerabilities(repo_path=None, verify_findings: bool = True) -> list:
    """Scan the (already-selected, or newly selected if repo_path is
    given) repository, turn every raw Gemma finding into a signed
    synthetic threat package and push it through the Guard exactly like
    an Online-sourced package. `verify_findings=False` keeps dashboard
    scans quick by deferring the real auditor.run_audit() proof step until
    a user asks to recheck and patch an individual candidate.

    Returns a ScanFinding for EVERY lead Gemma proposed, whatever happened
    to it -- nothing is dropped. Only entries with status == "confirmed"
    actually reproduced with a real test; the rest carry their own reason
    (not_applicable, uncertain, ai_error, or guard_rejected) so the caller
    can show the user what was found and why it did or didn't go further,
    instead of a bare "nothing confirmed"."""
    if repo_path is not None:
        paths.set_target_repo(repo_path)
        global _base_branch, _base_branch_repo
        _base_branch = repository.get_current_branch() if repository.verify_git_repository() else None
        _base_branch_repo = str(paths.TARGET_REPO.resolve())
    paths.ensure_directories()

    # A previous apply_fix() in this session may have left the worktree
    # checked out on a fix branch rather than the true base -- always
    # scan from the base, so results reflect the real starting point.
    if _base_branch is not None:
        repository.ensure_on_branch(_base_branch)

    raw_findings = scanner.scan_repository()
    results = []
    finding_reports = []

    for index, finding in enumerate(raw_findings, start=1):
        package = scanner.build_finding_package(finding, index)
        raw_bytes = json.dumps(package).encode("utf-8")

        guard_result = process_package_bytes(raw_bytes, source_name=f"{package['threat_id']}.json")
        if guard_result.status != "APPROVED":
            scan_finding = ScanFinding(
                raw=finding, package=package, status="guard_rejected",
                reason=guard_result.reason or "rejected by Guard",
            )
            results.append(scan_finding)
            finding_reports.append(reports.build_finding_report(
                package=package, status="guard_rejected", reason=scan_finding.reason,
            ))
            continue  # even a self-generated finding must pass the Guard

        if verify_findings:
            package_path = paths.OFFLINE_INBOX / f"{package['threat_id']}.json"
            # The scan already named the affected file(s) -- read them
            # directly rather than hoping a freshly-guessed search pattern
            # happens to match the same content again.
            audit_result = auditor.run_audit(package_path, known_affected_files=finding.get("affected_files"))
            status = "confirmed" if audit_result.status == "vulnerable" else audit_result.status

            if status == "confirmed":
                # Commit just this finding's generated test, by exact path --
                # not `git add -A`, which would also sweep up any other
                # confirmed finding's still-pending test from this same scan.
                # This keeps the worktree clean between findings and each
                # fix's eventual diff limited to its own patch.
                repository.commit_path(audit_result.test_path, f"Add security regression test for {audit_result.threat_id}")
        else:
            # Preserve the normal report shape and patch cache while making
            # clear that this candidate has not yet passed a proof test.
            status = "uncertain"
            audit_result = auditor.AuditResult(
                status=status,
                threat_id=package["threat_id"],
                confidence=None,
                reasoning="Fast scan candidate; a proof audit runs when you select Recheck & patch.",
                package=package,
                affected_files=list(finding.get("affected_files") or []),
                affected_lines=list(finding.get("affected_lines") or []),
            )

        scan_finding = ScanFinding(
            raw=finding, package=package, status=status,
            reason=audit_result.reasoning, audit=audit_result,
        )
        results.append(scan_finding)
        finding_reports.append(reports.build_finding_report(
            package=package, status=status, reason=audit_result.reasoning, audit=audit_result,
        ))

    # ONE file for this codebase, overwritten with this run's full
    # findings list -- never a new file per finding or per run.
    reports.write_run_report(finding_reports, full_rescan=True)

    return results


def recheck_finding(audit_result):
    """Run the normal Guard-approved audit again for one previously
    unconfirmed finding. A patch may follow only if the generated security
    test now reproduces the vulnerability.
    """
    package = audit_result.package or {}
    if not package:
        raise ValueError("the finding has no saved threat package to recheck")
    paths.ensure_directories()
    with tempfile.TemporaryDirectory(prefix="sentinel-reaudit-", dir=paths.OFFLINE_INBOX) as directory:
        package_path = Path(directory) / "finding.json"
        package_path.write_text(json.dumps(package), encoding="utf-8")
        return auditor.run_audit(
            package_path,
            known_affected_files=audit_result.affected_files or package.get("affected_files"),
        )


def apply_fix(audit_result):
    """Run the existing patch/test/validate/commit loop for one
    already-confirmed finding, and update its entry in the same
    per-codebase report file -- called only after the user explicitly
    approves this specific finding."""
    patch_result = patcher.run_patch_loop(audit_result, base_branch=_base_branch)
    enriched = reports.build_finding_report(
        package=audit_result.package or {}, status="confirmed",
        reason=audit_result.reasoning, audit=audit_result, patch_result=patch_result,
    )
    reports.write_run_report([enriched], full_rescan=False)
    reports.append_patch_history(enriched)
    return patch_result


def apply_prepared_fix(audit_result, expected_remote: str):
    """Apply a matching local template, validate and commit it, then push
    only its fix branch to the exact GitHub repository entered at scan time."""
    import subprocess

    repo = Path(paths.TARGET_REPO)
    actual = subprocess.run(
        ["git", "remote", "get-url", "origin"], cwd=str(repo),
        capture_output=True, text=True, timeout=15,
    )
    if actual.returncode != 0 or _normalize_remote(actual.stdout.strip()) != _normalize_remote(expected_remote):
        raise repository.GitSafetyError("The repository origin no longer matches the GitHub URL submitted for this scan.")

    result = prepared_patcher.run_prepared_patch(audit_result, base_branch=_base_branch)
    push_result = {"status": "not_pushed"}
    if result.status == "fixed":
        push_result = push_fix_branch(result.branch, expected_remote, repo)

    enriched = reports.build_finding_report(
        package=audit_result.package or {}, status="confirmed",
        reason=audit_result.reasoning, audit=audit_result, patch_result=result,
    )
    enriched["push_result"] = push_result
    reports.write_run_report([enriched], full_rescan=False)
    reports.append_patch_history(enriched)
    return result, push_result


def push_fix_branch(branch: str, expected_remote: str, repo_path=None) -> dict:
    import os
    import subprocess

    repo = Path(repo_path) if repo_path else Path(paths.TARGET_REPO)
    actual = subprocess.run(
        ["git", "remote", "get-url", "origin"], cwd=str(repo),
        capture_output=True, text=True, timeout=15,
    )
    if actual.returncode != 0 or _normalize_remote(actual.stdout.strip()) != _normalize_remote(expected_remote):
        return {"status": "push_failed", "branch": branch, "message": "The repository origin no longer matches the GitHub URL submitted for this scan."}
    try:
        pushed = subprocess.run(
            ["git", "push", "-u", "origin", branch], cwd=str(repo),
            capture_output=True, text=True, timeout=180, shell=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        return ({"status": "pushed", "branch": branch, "remote": expected_remote}
                if pushed.returncode == 0 else
                {"status": "push_failed", "branch": branch,
                 "message": (pushed.stderr.strip() or "git push failed")[-1200:]})
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "push_failed", "branch": branch, "message": str(exc)}


def _normalize_remote(value: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(value.strip())
    path = parsed.path.rstrip("/").removesuffix(".git")
    return f"{(parsed.hostname or '').lower()}{path.lower()}"


def push_and_create_pr(patch_result, target_branch: str, repo_path=None) -> dict:
    """Push the already-committed fix branch to 'origin' and open a
    GitHub Pull Request against `target_branch`, via the `gh` CLI.

    This is a human-confirmed action (see cli.py's explicit [y/N] before
    calling this), never something Gemma or any other part of this
    codebase triggers on its own -- the same reasoning as init_git_repo:
    pushing to a real remote and opening a PR are visible, hard-to-undo
    actions on shared state, so they use subprocess directly rather than
    the Gemma-facing sandbox, and only after the fix already passed every
    local check (patch_result.status == "fixed").

    Never pushes to `target_branch` itself, never force-pushes, never
    touches any branch but the fix branch -- the PR is a *request* to
    merge, reviewed and merged by a human on GitHub, not a direct write
    to the target branch.
    """
    if patch_result.status != "fixed":
        return {"status": "error", "message": "can only open a PR for a finding whose patch_status is 'fixed'"}

    import subprocess
    repo = Path(repo_path) if repo_path else paths.TARGET_REPO
    branch = patch_result.branch

    remotes = subprocess.run(["git", "remote"], cwd=str(repo), capture_output=True, text=True)
    if "origin" not in remotes.stdout.split():
        return {"status": "error", "message": "no 'origin' remote configured for this repository"}

    push = subprocess.run(
        ["git", "push", "-u", "origin", branch], cwd=str(repo), capture_output=True, text=True,
    )
    if push.returncode != 0:
        return {"status": "push_failed", "message": push.stderr.strip()}

    title = f"AI security fix: {patch_result.threat_id}"
    body = patch_result.reasoning or "Automated security fix from SentinelAuditor."
    pr = subprocess.run(
        ["gh", "pr", "create", "--base", target_branch, "--head", branch, "--title", title, "--body", body],
        cwd=str(repo), capture_output=True, text=True,
    )
    if pr.returncode != 0:
        return {"status": "pr_failed", "message": pr.stderr.strip()}

    return {"status": "pr_created", "url": pr.stdout.strip()}
