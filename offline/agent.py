"""Top-level phase orchestration: receive an approved package from
offline_inbox, run the audit (auditor.py), and if a vulnerability is
confirmed, run the patch loop (patcher.py). Always produces a report,
whatever the outcome -- vulnerable+fixed, vulnerable+unresolved,
not_applicable, uncertain, or ai_error.
"""
from communication import paths
from offline import auditor, patcher, reports, repository


def start_offline_audit(package_path=None) -> dict:
    paths.ensure_directories()

    if package_path is None:
        package_path = _oldest_inbox_package()
        if package_path is None:
            return {"status": "no_pending_packages"}

    # Section 30: verify the repository is a real git repo with a clean
    # worktree BEFORE anything -- including the generated security test --
    # is written to it.
    if not repository.verify_git_repository():
        raise repository.GitSafetyError("target repository is not a git repository")
    if not repository.verify_clean_worktree():
        raise repository.GitSafetyError("target repository worktree is not clean; refusing to start")

    audit = auditor.run_audit(package_path)

    patch_result = None
    if audit.status == "vulnerable":
        patch_result = patcher.run_patch_loop(audit)

    # The RETURN value keeps this exact shape -- it's part of api.py's
    # documented contract for the Online teammate and must not change.
    structured = {
        "threat_id": audit.threat_id,
        "audit_status": audit.status,
        "patch_status": patch_result.status if patch_result else None,
        "affected_files": audit.affected_files,
        "reasoning": audit.reasoning,
        "test_path": audit.test_path,
        "branch": patch_result.branch if patch_result else None,
        "diff": patch_result.diff if patch_result else None,
        "files_changed": patch_result.files_changed if patch_result else [],
        "attempts": patch_result.attempts if patch_result else 0,
        "final_audit": patch_result.final_audit if patch_result else None,
    }

    # What gets SAVED to disk (and so what api.get_latest_audit() and the
    # HTTP API in api_server.py actually serve) is the richer, code-level
    # report -- same builder the interactive scan+fix flow uses, so a
    # dashboard sees the same shape regardless of which flow produced it.
    # One threat-package check upserts its own entry into the single
    # per-codebase report file (full_rescan=False) rather than replacing
    # every other finding already recorded for this repository.
    enriched = reports.build_finding_report(
        package=audit.package or {},
        status="confirmed" if audit.status == "vulnerable" else audit.status,
        reason=audit.reasoning,
        audit=audit,
        patch_result=patch_result,
    )
    reports.write_run_report([enriched], repo_path=paths.TARGET_REPO, full_rescan=False)
    return structured


def _oldest_inbox_package():
    candidates = sorted(paths.OFFLINE_INBOX.glob("*.json"), key=lambda p: p.stat().st_mtime)
    return candidates[0] if candidates else None
