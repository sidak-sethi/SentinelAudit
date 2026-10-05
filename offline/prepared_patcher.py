"""Apply deterministic, locally prepared security fixes for known patterns."""
import subprocess

from communication import paths
from offline import patcher, prepared_patches, repository, tools
from offline.auditor import interpret_pytest_result
from offline.events import emit
from offline.sandbox import combined_output


def run_prepared_patch(audit, base_branch: str | None = None):
    threat_id = audit.threat_id
    base_branch = base_branch or repository.get_current_branch()
    replacements, reasoning = prepared_patches.prepare(audit)
    if not replacements:
        _discard_untracked_test(audit.test_path)
        return patcher.PatchResult(
            "unresolved", threat_id, attempts=1, reasoning=reasoning,
            final_audit={"status": "not_supported", "reasoning": reasoning},
        )

    branch = repository.create_fix_branch(threat_id)
    try:
        if audit.test_path and not repository.verify_clean_worktree():
            repository.commit_path(audit.test_path, f"Add security regression test for {threat_id}")

        for path, contents in replacements.items():
            tools.write_file(path, contents)
        expected = set(replacements)
        unexpected = repository.changed_files() - expected
        if unexpected:
            raise RuntimeError(f"Prepared patch touched unexpected files: {sorted(unexpected)}")

        normal = tools.run_tests()
        if normal["returncode"] not in tools.active_profile().normal_test_pass_codes:
            raise RuntimeError(f"Existing test suite failed: {combined_output(normal)}")
        if not audit.test_path:
            raise RuntimeError("The audit did not produce a security regression test.")
        security = tools.run_security_test(audit.test_path)
        if interpret_pytest_result(security) != "PASSED":
            raise RuntimeError(f"Security regression test failed after patch: {combined_output(security)}")

        diff_text = repository.diff()
        repository.commit(f"Security fix: {threat_id}\n\n{reasoning}")
        code = {path: tools.read_file(path) for path in replacements}
        emit("PREPARED_PATCH_ACCEPTED", "success", threat_id)
        return patcher.PatchResult(
            "fixed", threat_id, branch=branch, diff=diff_text, attempts=1,
            final_audit={"status": "fixed", "reasoning": reasoning, "method": "prepared_rule"},
            reasoning=reasoning, files_changed=list(replacements), patched_code=code,
        )
    except Exception as exc:
        repository.rollback_to_base(base_branch)
        emit("PREPARED_PATCH_REJECTED", "failure", str(exc))
        return patcher.PatchResult(
            "unresolved", threat_id, branch=branch, attempts=1,
            reasoning=str(exc), final_audit={"status": "not_fixed", "reasoning": str(exc)},
        )


def _discard_untracked_test(test_path: str | None) -> None:
    if not test_path:
        return
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", test_path],
        cwd=str(paths.TARGET_REPO), capture_output=True, text=True,
    )
    if tracked.returncode != 0:
        try:
            tools.resolve_safe_path(test_path).unlink(missing_ok=True)
        except tools.PathRejectedError:
            pass
