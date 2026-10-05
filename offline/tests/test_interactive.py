"""Tests for the interactive dynamic-repo-selection feature:
- communication.paths.set_target_repo switches the active repo at runtime
  with no env var and no reload.
- offline/patcher.py treats pytest exit code 5 ("no tests collected") as
  a pass, so repos with no pre-existing test suite are not auto-rejected.
- offline/interactive.find_vulnerabilities's structural flow: scan ->
  synthetic package -> Guard -> real proof step, with Gemma stubbed so
  the orchestration is deterministic (the real model is already
  exercised live in integration/test_end_to_end.py).
"""
import subprocess

import pytest

from communication import paths as paths_module
from offline import interactive, repository


def test_select_repo_refuses_genuinely_unsupported_language(tmp_path):
    repo = tmp_path / "go_repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module demo\n", encoding="utf-8")
    (repo / "main.go").write_text("package main\n", encoding="utf-8")

    selection = interactive.select_repo(repo)
    assert selection.status == "unsupported_language"
    assert selection.detail == "Go"


def test_select_repo_accepts_javascript_project(tmp_path):
    repo = tmp_path / "node_repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "demo"}', encoding="utf-8")
    (repo / "server.js").write_text("console.log('hi');\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)

    selection = interactive.select_repo(repo)
    assert selection.status == "ready"


def test_select_repo_accepts_python_project_even_with_package_json(tmp_path):
    """A Python marker or any .py file present means it's not refused,
    even alongside an unrelated package.json (e.g. a mixed-language repo
    with a small JS frontend)."""
    repo = tmp_path / "mixed_repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "frontend"}', encoding="utf-8")
    (repo / "app.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    import subprocess as sp
    sp.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    sp.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    sp.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)

    selection = interactive.select_repo(repo)
    assert selection.status == "ready"


def test_set_target_repo_switches_at_runtime(tmp_path):
    first = tmp_path / "repo_a"
    second = tmp_path / "repo_b"
    first.mkdir()
    second.mkdir()

    paths_module.set_target_repo(first)
    assert paths_module.TARGET_REPO == first.resolve()

    paths_module.set_target_repo(second)
    assert paths_module.TARGET_REPO == second.resolve()


def test_patcher_treats_no_tests_collected_as_pass(target_repo, monkeypatch):
    """A repo with zero test files (pytest exit code 5) must not have
    every patch attempt rejected just because there was nothing to run."""
    from offline import patcher

    # Remove the only existing test so pytest collects nothing.
    (target_repo / "tests" / "test_app.py").unlink()

    sec_dir = target_repo / "tests" / "security"
    sec_dir.mkdir(parents=True, exist_ok=True)
    (sec_dir / "test_patch_target.py").write_text(
        "from app import add\n\n\ndef test_still_adds():\n    assert add(2, 2) == 4\n", encoding="utf-8"
    )

    class _StubAudit:
        package = {
            "schema_version": "1.0", "threat_id": "no-tests-001", "source": {}, "title": "t",
            "cve": "", "affected_component": "app.py", "affected_versions": [], "fixed_versions": [],
            "severity": "high", "description": "d", "attack_type": "x", "indicators": [],
            "audit_instructions": [], "test_strategy": "s", "remediation": "r", "integrity": {"sha256": ""},
        }
        affected_files = ["app.py"]
        test_path = "tests/security/test_patch_target.py"
        vulnerability_hypothesis = "stub vuln"
        threat_id = "no-tests-001"
        status = "vulnerable"

    responses = iter([
        {"files_to_modify": [{"path": "app.py", "new_content": "def add(a, b):\n    # patched\n    return a + b\n"}],
         "reason": "minimal patch", "security_effect": "none"},
        {"status": "fixed", "reasoning": "ok", "remaining_risk": [], "recommendation": "none"},
    ])
    monkeypatch.setattr(patcher.gemma_client, "generate_json", lambda *a, **k: next(responses))

    result = patcher.run_patch_loop(_StubAudit())
    assert result.status == "fixed"


def test_find_vulnerabilities_structural_flow(target_repo, monkeypatch):
    """scan -> synthetic package -> Guard -> real proof, with Gemma
    stubbed for both the scan and the proof step."""
    from offline import auditor, interactive, scanner

    finding = {
        "title": "SQL injection in add endpoint (stub)",
        "severity": "high",
        "attack_type": "sql_injection",
        "affected_files": ["app.py"],
        "affected_lines": [1],
        "vulnerability_hypothesis": "stub hypothesis",
        "recommended_fix": "use parameterized queries",
        "test_plan": "prove the vulnerable behavior",
    }
    monkeypatch.setattr(scanner, "scan_repository", lambda: [finding])

    monkeypatch.setattr(
        auditor, "analyze_threat",
        lambda pkg: {"search_patterns": ["add"], "candidate_files_glob": [], "initial_reasoning": "x"},
    )
    monkeypatch.setattr(
        auditor, "build_hypothesis",
        lambda pkg, leads, inspection: {
            "status": "vulnerable", "confidence": 0.9, "affected_files": ["app.py"], "affected_lines": [1],
            "reasoning": "stub", "vulnerability_hypothesis": "stub", "test_plan": "stub",
            "recommended_fix": "none",
        },
    )
    monkeypatch.setattr(
        auditor, "generate_security_test",
        lambda pkg, hypothesis, inspection, correction=None: {
            "test_file_path": "tests/security/test_manual_scan.py",
            "test_code": "from app import add\n\n\ndef test_fails_on_purpose():\n    assert False\n",
        },
    )

    results = interactive.find_vulnerabilities(target_repo)

    assert len(results) == 1
    assert results[0].status == "confirmed"
    assert results[0].audit.status == "vulnerable"
    assert results[0].audit.threat_id.startswith("manual-scan-001-")

    # Regression: a confirmed-but-not-yet-fixed finding's generated test
    # must not be left as an uncommitted change -- otherwise the next
    # select_repo() call reports dirty_worktree even though the user
    # never touched anything.
    assert repository.verify_clean_worktree()


def test_rescan_after_declined_fix_is_not_dirty(target_repo, monkeypatch):
    """The exact regression reported: scan confirms a finding, the user
    never applies the fix, and re-selecting the same repo must still see
    a clean worktree (not "dirty_worktree")."""
    from offline import auditor, interactive, scanner

    finding = {
        "title": "SQL injection in add endpoint (stub)",
        "severity": "high",
        "attack_type": "sql_injection",
        "affected_files": ["app.py"],
        "vulnerability_hypothesis": "stub hypothesis",
        "recommended_fix": "use parameterized queries",
        "test_plan": "prove the vulnerable behavior",
    }
    monkeypatch.setattr(scanner, "scan_repository", lambda: [finding])
    monkeypatch.setattr(
        auditor, "analyze_threat",
        lambda pkg: {"search_patterns": ["add"], "candidate_files_glob": [], "initial_reasoning": "x"},
    )
    monkeypatch.setattr(
        auditor, "build_hypothesis",
        lambda pkg, leads, inspection: {
            "status": "vulnerable", "confidence": 0.9, "affected_files": ["app.py"], "affected_lines": [],
            "reasoning": "stub", "vulnerability_hypothesis": "stub", "test_plan": "stub",
            "recommended_fix": "none",
        },
    )
    monkeypatch.setattr(
        auditor, "generate_security_test",
        lambda pkg, hypothesis, inspection, correction=None: {
            "test_file_path": "tests/security/test_manual_scan.py",
            "test_code": "from app import add\n\n\ndef test_fails_on_purpose():\n    assert False\n",
        },
    )

    results = interactive.find_vulnerabilities(target_repo)
    assert results[0].status == "confirmed"

    # Simulate the user declining to fix it and re-running the CLI later.
    selection = interactive.select_repo(target_repo)
    assert selection.status == "ready"

    # The synthetic finding went through the real Guard and left a trail.
    from guard.events import read_events
    guard_events = [e["event"] for e in read_events()]
    assert "GUARD_PACKAGE_APPROVED" in guard_events


def test_find_vulnerabilities_surfaces_unconfirmed_findings_with_reason(target_repo, monkeypatch):
    """A Gemma-proposed finding that the real proof step can't reproduce
    must still be reported -- with its status and reason -- not silently
    dropped."""
    from offline import auditor, interactive, scanner

    finding = {
        "title": "Imaginary issue",
        "severity": "low",
        "attack_type": "other",
        "affected_files": ["app.py"],
        "vulnerability_hypothesis": "does not actually hold",
        "recommended_fix": "n/a",
        "test_plan": "n/a",
    }
    monkeypatch.setattr(scanner, "scan_repository", lambda: [finding])
    monkeypatch.setattr(
        auditor, "analyze_threat",
        lambda pkg: {"search_patterns": ["add"], "candidate_files_glob": [], "initial_reasoning": "x"},
    )
    monkeypatch.setattr(
        auditor, "build_hypothesis",
        lambda pkg, leads, inspection: {
            "status": "not_applicable", "confidence": 0.1, "affected_files": [], "affected_lines": [],
            "reasoning": "does not hold up", "vulnerability_hypothesis": "", "test_plan": "",
            "recommended_fix": "",
        },
    )

    results = interactive.find_vulnerabilities(target_repo)
    assert len(results) == 1
    assert results[0].status == "not_applicable"
    assert results[0].reason == "does not hold up"
    assert [f for f in results if f.status == "confirmed"] == []


class _StubPatchResult:
    def __init__(self, status="fixed", branch="ai-security-fix/t1", threat_id="t1", reasoning="fix reason"):
        self.status = status
        self.branch = branch
        self.threat_id = threat_id
        self.reasoning = reasoning


def test_push_and_create_pr_refuses_unless_fixed(target_repo):
    result = interactive.push_and_create_pr(_StubPatchResult(status="unresolved"), "main")
    assert result["status"] == "error"


def test_push_and_create_pr_refuses_without_origin_remote(target_repo):
    result = interactive.push_and_create_pr(_StubPatchResult(), "main", repo_path=target_repo)
    assert result["status"] == "error"
    assert "origin" in result["message"]


def test_push_and_create_pr_success(target_repo, monkeypatch):
    calls = []

    def fake_run(argv, cwd, capture_output, text):
        calls.append(argv)
        if argv[:2] == ["git", "remote"]:
            return subprocess.CompletedProcess(argv, 0, stdout="origin\n", stderr="")
        if argv[:2] == ["git", "push"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if argv[:2] == ["gh", "pr"]:
            return subprocess.CompletedProcess(argv, 0, stdout="https://github.com/example/repo/pull/1\n", stderr="")
        raise AssertionError(f"unexpected call: {argv}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = interactive.push_and_create_pr(_StubPatchResult(), "main", repo_path=target_repo)
    assert result["status"] == "pr_created"
    assert result["url"] == "https://github.com/example/repo/pull/1"
    assert ["git", "push", "-u", "origin", "ai-security-fix/t1"] in calls
    assert any(c[:2] == ["gh", "pr"] for c in calls)
