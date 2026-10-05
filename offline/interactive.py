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
from dataclasses import dataclass
from pathlib import Path

from communication import paths
from guard.guard import process_package_bytes
from offline import auditor, languages, patcher, reports, repository, scanner

# The branch select_repo()/init_git_repo() found the repo on, remembered
# so apply_fix() can always cut a fix branch from the TRUE base -- not
# from wherever a previous fix in the same session happened to leave the
# worktree checked out (every successful fix stays on its own
# ai-security-fix/<id> branch; without this, a second fix in the same
# session would branch off the first fix instead of off the real base).
_base_branch: str | None = None


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
    audit: object = None  # auditor.AuditResult, when the proof step ran


def select_repo(path) -> RepoSelection:
    """Point the Offline agent at `path` for this process. Never inits
    git or touches the worktree itself -- it only reports what state the
    repo is in so the caller (cli.py) can decide, with the user's
    explicit confirmation, what to do about it."""
    global _base_branch
    resolved = paths.set_target_repo(path)
    language = languages.detect_unsupported_language(resolved)
    if language is not None:
        return RepoSelection(status="unsupported_language", path=resolved, detail=language)
    if not repository.verify_git_repository():
        _base_branch = None
        return RepoSelection(status="needs_git_init", path=resolved)
    if not repository.verify_clean_worktree():
        return RepoSelection(status="dirty_worktree", path=resolved)
    _base_branch = repository.get_current_branch()
    return RepoSelection(status="ready", path=resolved)


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
    global _base_branch
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


def find_vulnerabilities(repo_path=None) -> list:
    """Scan the (already-selected, or newly selected if repo_path is
    given) repository, turn every raw Gemma finding into a signed
    synthetic threat package, push it through the Guard exactly like an
    Online-sourced package, and -- for every one the Guard approves --
    run the real auditor.run_audit() proof step.

    Returns a ScanFinding for EVERY lead Gemma proposed, whatever happened
    to it -- nothing is dropped. Only entries with status == "confirmed"
    actually reproduced with a real test; the rest carry their own reason
    (not_applicable, uncertain, ai_error, or guard_rejected) so the caller
    can show the user what was found and why it did or didn't go further,
    instead of a bare "nothing confirmed"."""
    if repo_path is not None:
        paths.set_target_repo(repo_path)
        global _base_branch
        _base_branch = repository.get_current_branch() if repository.verify_git_repository() else None
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
            # This is what keeps the worktree clean between findings
            # (fixing the "dirty_worktree on next scan" issue) and keeps
            # each fix's eventual diff limited to its own patch.
            repository.commit_path(audit_result.test_path, f"Add security regression test for {audit_result.threat_id}")

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
    return patch_result


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
