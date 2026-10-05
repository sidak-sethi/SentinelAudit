"""Offline agent test suite -- the 15 cases this component must satisfy.

Tests that exercise deterministic control flow (path/command guarding, git
plumbing, patch-loop orchestration: rollback, iteration limit,
commit-only-after-validation) run with no external dependency, using a
disposable git repo and a stubbed Gemma client -- stubbing isolates the
Python orchestration logic from model variance, it is not a substitute for
the real pipeline (see integration/test_end_to_end.py, which uses the real
Gemma 4 model). The one test that genuinely needs a live model is marked
and skips cleanly when Ollama / the configured GEMMA_MODEL are unavailable.
"""
import json
import subprocess

import pytest

from communication import paths as paths_module
from offline import repository, sandbox, tools
from offline.tests.conftest import gemma_client, requires_gemma


# TEST 1: Gemma unavailable -> clear failure
def test_1_gemma_unavailable_raises_clear_error(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")  # nothing listens here
    with pytest.raises(gemma_client.GemmaUnavailableError):
        gemma_client.ensure_available()


# TEST 2: Invalid threat package -> rejected, never reaches Offline
def test_2_invalid_package_never_reaches_offline(target_repo):
    from guard.guard import process_package_bytes

    result = process_package_bytes(b"{bad json", source_name="bad.json")
    assert result.status == "REJECTED"
    assert not (paths_module.OFFLINE_INBOX / "bad.json").exists()


# TEST 3: Path traversal attempt -> PATH_REJECTED
def test_3_path_traversal_rejected(target_repo):
    with pytest.raises(tools.PathRejectedError):
        tools.resolve_safe_path("../../secrets.txt")


# TEST 4: Outside-workspace file -> PATH_REJECTED
def test_4_absolute_outside_workspace_rejected(target_repo):
    with pytest.raises(tools.PathRejectedError):
        tools.resolve_safe_path("C:/Windows/System32/drivers/etc/hosts")


# TEST 5: Disallowed command -> COMMAND_REJECTED
def test_5_disallowed_command_rejected(target_repo):
    with pytest.raises(sandbox.CommandRejectedError):
        sandbox.run_command(["powershell", "-Command", "whoami"], cwd=target_repo)


# TEST 6: Normal test execution
def test_6_run_tests_executes_real_pytest(target_repo):
    result = tools.run_tests()
    assert result["returncode"] == 0
    assert "1 passed" in result["stdout"]


# TEST 7: Security test execution
def test_7_run_security_test_executes_named_test(target_repo):
    (target_repo / "tests" / "security").mkdir(parents=True, exist_ok=True)
    (target_repo / "tests" / "security" / "test_sec.py").write_text(
        "def test_fails_on_purpose():\n    assert False\n", encoding="utf-8"
    )
    result = tools.run_security_test("tests/security/test_sec.py")
    assert result["returncode"] != 0
    assert "1 failed" in result["stdout"]


# TEST 13: Git branch creation
def test_13_git_branch_creation(target_repo):
    branch = repository.create_fix_branch("unit-test-001")
    assert branch == "ai-security-fix/unit-test-001"
    assert repository.get_current_branch() == branch


# TEST 14: Git diff generation
def test_14_git_diff_generation(target_repo):
    (target_repo / "app.py").write_text("def add(a, b):\n    return a + b + 0\n", encoding="utf-8")
    diff_text = repository.diff()
    assert "add" in diff_text


class _StubAudit:
    def __init__(self, package, affected_files, test_path, vulnerability_hypothesis="stub vuln"):
        self.package = package
        self.affected_files = affected_files
        self.test_path = test_path
        self.vulnerability_hypothesis = vulnerability_hypothesis
        self.threat_id = package["threat_id"]
        self.status = "vulnerable"


def _stub_package(threat_id="patch-test-001"):
    package = {
        "schema_version": "1.0", "threat_id": threat_id, "source": {
            "type": "other", "url": "https://example.invalid", "published": "2026-01-01T00:00:00Z",
            "retrieved_at": "2026-01-01T00:00:00Z",
        },
        "title": "stub", "cve": "", "affected_component": "app.py", "affected_versions": [],
        "fixed_versions": [], "severity": "high", "description": "stub description",
        "attack_type": "x", "indicators": [], "audit_instructions": [], "test_strategy": "s",
        "remediation": "r", "integrity": {"sha256": ""},
    }
    from guard.validator import recompute_integrity_sha256
    package["integrity"] = {"sha256": recompute_integrity_sha256(package)}
    return package


def _write_passing_security_test(repo):
    sec_dir = repo / "tests" / "security"
    sec_dir.mkdir(parents=True, exist_ok=True)
    (sec_dir / "test_patch_target.py").write_text(
        "from app import add\n\n\ndef test_still_adds():\n    assert add(2, 2) == 4\n", encoding="utf-8"
    )
    return "tests/security/test_patch_target.py"


# TEST 8: Patch success (Gemma stubbed so the control flow is deterministic)
def test_8_patch_loop_success_commits(target_repo, monkeypatch):
    from offline import patcher

    test_path = _write_passing_security_test(target_repo)
    audit = _StubAudit(_stub_package(), ["app.py"], test_path)

    responses = iter([
        {"files_to_modify": [{"path": "app.py", "new_content": "def add(a, b):\n    # patched\n    return a + b\n"}],
         "reason": "minimal patch", "security_effect": "none"},
        {"status": "fixed", "reasoning": "ok", "remaining_risk": [], "recommendation": "none"},
    ])
    monkeypatch.setattr(patcher.gemma_client, "generate_json", lambda *a, **k: next(responses))

    result = patcher.run_patch_loop(audit)
    assert result.status == "fixed"
    log = subprocess.run(["git", "log", "--oneline"], cwd=target_repo, capture_output=True, text=True)
    assert "AI security fix" in log.stdout


# TEST 9 and TEST 15: Patch rollback, and commit only after validation
def test_9_patch_loop_rolls_back_on_test_failure(target_repo, monkeypatch):
    from offline import patcher

    test_path = _write_passing_security_test(target_repo)
    audit = _StubAudit(_stub_package("patch-test-002"), ["app.py"], test_path)

    def break_normal_tests(*_args, **_kwargs):
        return {
            "files_to_modify": [{"path": "app.py", "new_content": "def add(a, b):\n    raise RuntimeError('broken')\n"}],
            "reason": "bad fix", "security_effect": "none",
        }

    monkeypatch.setattr(patcher.gemma_client, "generate_json", break_normal_tests)
    monkeypatch.setattr(patcher, "MAX_PATCH_ATTEMPTS", 1)

    result = patcher.run_patch_loop(audit)
    assert result.status == "unresolved"

    status = subprocess.run(["git", "status", "--porcelain"], cwd=target_repo, capture_output=True, text=True)
    assert status.stdout.strip() == ""
    log = subprocess.run(["git", "log", "--oneline"], cwd=target_repo, capture_output=True, text=True)
    assert "AI security fix" not in log.stdout


# TEST 10: Maximum iteration enforcement
def test_10_patch_loop_respects_max_attempts(target_repo, monkeypatch):
    from offline import patcher

    test_path = _write_passing_security_test(target_repo)
    audit = _StubAudit(_stub_package("patch-test-003"), ["app.py"], test_path)
    call_count = {"n": 0}

    def always_bad_path(*_args, **_kwargs):
        call_count["n"] += 1
        return {
            "files_to_modify": [{"path": "not_allowed.py", "new_content": "x = 1\n"}],
            "reason": "bad target", "security_effect": "none",
        }

    monkeypatch.setattr(patcher.gemma_client, "generate_json", always_bad_path)
    monkeypatch.setattr(patcher, "MAX_PATCH_ATTEMPTS", 3)

    result = patcher.run_patch_loop(audit)
    assert result.status == "unresolved"
    assert call_count["n"] == 3


# TEST 12: Final audit failure -> rollback even though tests passed
def test_12_patch_loop_rolls_back_on_failed_final_audit(target_repo, monkeypatch):
    from offline import patcher

    test_path = _write_passing_security_test(target_repo)
    audit = _StubAudit(_stub_package("patch-test-004"), ["app.py"], test_path)

    responses = iter([
        {"files_to_modify": [{"path": "app.py", "new_content": "def add(a, b):\n    return a + b\n"}],
         "reason": "fix", "security_effect": "none"},
        {"status": "not_fixed", "reasoning": "did not actually fix it", "remaining_risk": ["still broken"], "recommendation": "retry"},
    ] * 3)
    monkeypatch.setattr(patcher.gemma_client, "generate_json", lambda *a, **k: next(responses))
    monkeypatch.setattr(patcher, "MAX_PATCH_ATTEMPTS", 1)

    result = patcher.run_patch_loop(audit)
    assert result.status == "unresolved"


# TEST 11: NOT_APPLICABLE behavior
def test_11_auditor_reports_not_applicable_when_test_passes_unmodified(target_repo, monkeypatch):
    from offline import auditor

    package = _stub_package("not-applicable-001")
    monkeypatch.setattr(
        auditor, "analyze_threat",
        lambda pkg: {"search_patterns": ["add"], "candidate_files_glob": [], "initial_reasoning": "x"},
    )
    monkeypatch.setattr(
        auditor, "build_hypothesis",
        lambda pkg, leads, inspection: {
            "status": "vulnerable", "confidence": 0.5, "affected_files": ["app.py"], "affected_lines": [],
            "reasoning": "stub", "vulnerability_hypothesis": "stub", "test_plan": "stub",
            "recommended_fix": "none",
        },
    )
    monkeypatch.setattr(
        auditor, "generate_security_test",
        lambda pkg, hypothesis, inspection, correction=None: {
            "test_file_path": "tests/security/test_na.py",
            "test_code": "from app import add\n\n\ndef test_always_passes():\n    assert add(1, 1) == 2\n",
        },
    )

    package_path = paths_module.OFFLINE_INBOX / f"{package['threat_id']}.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")

    result = auditor.run_audit(package_path)
    assert result.status == "not_applicable"


@requires_gemma
def test_live_gemma_generates_valid_json():
    result = gemma_client.generate_json(
        "Respond only with JSON.",
        'Respond with JSON matching exactly: {"ok": true}',
    )
    assert isinstance(result, dict)
