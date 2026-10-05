"""Phases 11-17: given a confirmed vulnerability, have Gemma 4 propose a
structured, minimal patch, apply it under strict path control, validate it
with real tests, and commit only if every check passes.

Gemma never returns shell commands or a free-form diff -- only a
structured object naming the files to modify and their new content. The
Python patcher is solely responsible for applying it, and only after every
path is confirmed to be inside target_repo AND one of the files the
auditor already identified as relevant.

Nothing is committed until normal tests, the security regression test, and
a final Gemma audit all pass. Any failure discards the uncommitted working
tree changes and retries, capped at MAX_PATCH_ATTEMPTS so the loop can
never run forever; if every attempt fails the result is UNRESOLVED, with
the diagnostic report preserved, and the repository is left on a clean
rollback to the pre-audit branch.
"""
import json
import os
import posixpath

from offline import gemma_client, repository, tools
from offline.auditor import SYSTEM_PROMPT, _untrusted_block, interpret_pytest_result
from offline.events import emit
from offline.sandbox import combined_output

MAX_PATCH_ATTEMPTS = int(os.environ.get("MAX_PATCH_ATTEMPTS", "3"))


class PatchResult:
    def __init__(self, status, threat_id, branch=None, diff="", attempts=0,
                 final_audit=None, reasoning="", files_changed=None, patched_code=None):
        self.status = status  # "fixed" | "unresolved"
        self.threat_id = threat_id
        self.branch = branch
        self.diff = diff
        self.attempts = attempts
        self.final_audit = final_audit or {}
        self.reasoning = reasoning
        self.files_changed = files_changed or []
        self.patched_code = patched_code or {}  # {path: full file content}, only set when status == "fixed"


def _normalize_path(path: str) -> str:
    """Gemma 4 (especially a small local tag) doesn't reliably echo back a
    file path in exactly the same form it was given -- a leading './', or
    backslashes on Windows, are common. Normalize before comparing against
    the affected-files allowlist so a cosmetic difference doesn't get
    rejected as a surprise target."""
    return posixpath.normpath(path.replace("\\", "/"))


def _safe_for_read(path: str) -> bool:
    try:
        tools.resolve_safe_path(path)
        return True
    except tools.PathRejectedError:
        return False


def _propose_patch(audit, previous_failure: str | None) -> dict:
    failure_note = f"\n\nA previous patch attempt was rejected for this reason: {previous_failure}" if previous_failure else ""
    current_contents = {f: tools.read_file(f) for f in audit.affected_files if _safe_for_read(f)}
    user_prompt = f"""{_untrusted_block('THREAT PACKAGE', json.dumps(audit.package, indent=2))}

Confirmed vulnerability hypothesis: {audit.vulnerability_hypothesis}
Affected files you already identified: {audit.affected_files}
Current content of those files:
{json.dumps(current_contents, indent=2)[:12000]}
{failure_note}

Propose the MINIMAL patch to fix this vulnerability. Respond with JSON matching exactly:
{{
  "files_to_modify": [{{"path": "relative/path.py", "new_content": "full new file content"}}],
  "reason": "...",
  "security_effect": "..."
}}
Only include files that actually need to change, and only from the affected files list above.
Do not rewrite unrelated files."""
    return gemma_client.generate_json(SYSTEM_PROMPT, user_prompt, num_predict=4096)


def _apply_patch(patch: dict, allowed_files: set) -> list:
    applied = []
    for entry in patch.get("files_to_modify", []):
        raw_path = entry.get("path", "")
        normalized = _normalize_path(raw_path)
        if normalized not in allowed_files:
            raise tools.PathRejectedError(f"PATH_REJECTED: patch touches unexpected file: {raw_path}")
        tools.write_file(normalized, entry.get("new_content", ""))
        applied.append(normalized)
    return applied


def _final_audit(audit, patch: dict, diff_text: str, normal_tests: dict, security_test: dict) -> dict:
    user_prompt = f"""{_untrusted_block('THREAT PACKAGE', json.dumps(audit.package, indent=2))}

Original vulnerability hypothesis: {audit.vulnerability_hypothesis}
Patch reason given: {patch.get('reason', '')}
Git diff actually applied:
{diff_text[:8000]}
Normal test suite result: returncode={normal_tests['returncode']}
Security regression test result: returncode={security_test['returncode']}

Answer honestly: Is the original vulnerability fixed? Did the patch introduce another
vulnerability? Did behavior unrelated to the vulnerability change? Does the security test
actually validate the fix? Is the patch minimal?

Respond with JSON matching exactly:
{{
  "status": "fixed|not_fixed|uncertain",
  "reasoning": "...",
  "remaining_risk": ["..."],
  "recommendation": "..."
}}"""
    return gemma_client.generate_json(SYSTEM_PROMPT, user_prompt)


def run_patch_loop(audit, base_branch: str | None = None) -> PatchResult:
    """`base_branch`, when given, is the known-good branch to cut the fix
    branch from -- pass it explicitly when a previous fix in the same
    interactive session may have left the worktree checked out somewhere
    other than the true base (see offline/interactive.py). When omitted,
    falls back to whatever is currently checked out, as before."""
    threat_id = audit.threat_id

    if not repository.verify_git_repository():
        raise repository.GitSafetyError("target repository is not a git repository")

    if base_branch is not None:
        repository.ensure_on_branch(base_branch)

    # The generated security regression test (written by auditor.py) is the
    # only uncommitted change at this point -- verify_clean_worktree() for
    # the *original* state already ran in agent.py before the audit touched
    # anything. Commit the test on its own so each patch attempt's diff
    # reflects only the patch itself.
    base_branch = base_branch or repository.get_current_branch()
    branch = repository.create_fix_branch(threat_id)
    if not repository.verify_clean_worktree():
        repository.commit(f"Add security regression test for {threat_id}")
    allowed_files = {_normalize_path(f) for f in audit.affected_files}

    previous_failure = None
    for attempt in range(1, MAX_PATCH_ATTEMPTS + 1):
        emit("OFFLINE_PATCH_STARTED", "started", f"attempt {attempt}/{MAX_PATCH_ATTEMPTS}")

        try:
            patch = _propose_patch(audit, previous_failure)
            applied = _apply_patch(patch, allowed_files)
        except (gemma_client.GemmaUnavailableError, gemma_client.GemmaResponseError, tools.PathRejectedError) as exc:
            previous_failure = str(exc)
            emit("OFFLINE_PATCH_REJECTED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue

        diff_text = repository.diff()
        unexpected = repository.changed_files() - allowed_files
        if unexpected:
            previous_failure = f"patch touched unexpected files: {sorted(unexpected)}"
            emit("OFFLINE_PATCH_REJECTED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue

        emit("OFFLINE_PATCH_APPLIED", "success", f"files: {applied}")

        emit("OFFLINE_TEST_STARTED", "started", "normal test suite")
        normal_tests = tools.run_tests()
        # pytest exit code 5 ("no tests collected") or an equivalent
        # "nothing configured" result for other languages is completely
        # normal for an arbitrary real repo with no pre-existing test
        # suite, and not a sign the patch broke anything -- see each
        # LanguageProfile's own normal_test_pass_codes.
        if normal_tests["returncode"] not in tools.active_profile().normal_test_pass_codes:
            previous_failure = f"normal test suite failed after patch: {combined_output(normal_tests)}"
            emit("OFFLINE_TEST_FAILED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue
        emit("OFFLINE_TEST_PASSED", "success", "normal test suite")

        emit("OFFLINE_TEST_STARTED", "started", "security regression test")
        security_test = tools.run_security_test(audit.test_path)
        if interpret_pytest_result(security_test) != "PASSED":
            previous_failure = f"security regression test still fails after patch: {combined_output(security_test)}"
            emit("OFFLINE_TEST_FAILED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue
        emit("OFFLINE_TEST_PASSED", "success", "security regression test")

        emit("OFFLINE_REAUDIT_STARTED", "started", threat_id)
        try:
            final = _final_audit(audit, patch, diff_text, normal_tests, security_test)
        except (gemma_client.GemmaUnavailableError, gemma_client.GemmaResponseError) as exc:
            previous_failure = f"final audit failed: {exc}"
            emit("OFFLINE_PATCH_REJECTED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue

        if final.get("status") != "fixed":
            previous_failure = f"final Gemma audit did not confirm fix: {final.get('reasoning', '')}"
            emit("OFFLINE_PATCH_REJECTED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue

        try:
            repository.commit(f"AI security fix: {threat_id}\n\n{patch.get('reason', '')}")
        except repository.GitSafetyError as exc:
            previous_failure = f"commit failed (patch likely produced no real change): {exc}"
            emit("OFFLINE_PATCH_REJECTED", "failure", previous_failure)
            repository.discard_working_tree_changes()
            continue

        emit("OFFLINE_PATCH_ACCEPTED", "success", threat_id)
        patched_code = {}
        for changed_path in applied:
            try:
                patched_code[changed_path] = tools.read_file(changed_path)
            except (FileNotFoundError, tools.PathRejectedError):
                continue
        return PatchResult(
            status="fixed", threat_id=threat_id, branch=branch, diff=diff_text,
            attempts=attempt, final_audit=final, reasoning=patch.get("reason", ""),
            files_changed=applied, patched_code=patched_code,
        )

    emit("OFFLINE_ROLLBACK", "success", f"unresolved after {MAX_PATCH_ATTEMPTS} attempt(s)")
    repository.rollback_to_base(base_branch)
    return PatchResult(
        status="unresolved", threat_id=threat_id, branch=branch,
        attempts=MAX_PATCH_ATTEMPTS, reasoning=previous_failure or "unknown failure",
    )
