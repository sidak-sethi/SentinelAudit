"""Tests for the one-file-per-codebase report persistence model
(offline/reports.py): every run against the same repository overwrites
the same file; different repositories get different files; a
full-rescan replaces all findings while a single-finding upsert merges
in by threat_id without erasing the others.
"""
import importlib

import pytest

from communication import paths as paths_module
from offline import reports


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE", str(tmp_path))
    importlib.reload(paths_module)
    paths_module.ensure_directories()
    yield paths_module
    importlib.reload(paths_module)


def _finding(threat_id, status="not_applicable", **overrides):
    base = {
        "threat_id": threat_id, "title": threat_id, "cve": None, "attack_type": "x",
        "severity": "low", "source": {}, "status": status, "patch_status": None,
        "repository": "r", "branch": None, "affected_files": [], "affected_lines": [],
        "confidence": None, "vulnerability_hypothesis": "", "recommended_fix": "",
        "security_test_path": None, "code": {}, "diff": None, "patch_attempts": 0,
        "final_audit": None, "reason": "", "timestamp": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def test_same_codebase_produces_one_file_across_multiple_runs(workspace, tmp_path):
    repo = tmp_path / "repo_a"
    repo.mkdir()

    reports.write_run_report([_finding("t1")], repo_path=repo, full_rescan=True)
    reports.write_run_report([_finding("t2")], repo_path=repo, full_rescan=True)
    reports.write_run_report([_finding("t3")], repo_path=repo, full_rescan=True)

    json_files = list(workspace.REPORTS_DIR.glob("*.json"))
    assert len(json_files) == 1

    run = reports.get_run_report(repo_path=repo)
    assert [f["threat_id"] for f in run["findings"]] == ["t3"]


def test_different_codebases_get_different_files(workspace, tmp_path):
    repo_a = tmp_path / "repo_a"
    repo_b = tmp_path / "repo_b"
    repo_a.mkdir()
    repo_b.mkdir()

    reports.write_run_report([_finding("t1")], repo_path=repo_a, full_rescan=True)
    reports.write_run_report([_finding("t2")], repo_path=repo_b, full_rescan=True)

    assert len(list(workspace.REPORTS_DIR.glob("*.json"))) == 2
    assert reports.get_run_report(repo_path=repo_a)["findings"][0]["threat_id"] == "t1"
    assert reports.get_run_report(repo_path=repo_b)["findings"][0]["threat_id"] == "t2"


def test_full_rescan_replaces_all_findings(workspace, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    reports.write_run_report([_finding("old-1"), _finding("old-2")], repo_path=repo, full_rescan=True)
    reports.write_run_report([_finding("new-1")], repo_path=repo, full_rescan=True)

    run = reports.get_run_report(repo_path=repo)
    assert [f["threat_id"] for f in run["findings"]] == ["new-1"]


def test_upsert_merges_without_erasing_other_findings(workspace, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    reports.write_run_report([_finding("a"), _finding("b")], repo_path=repo, full_rescan=True)
    reports.write_run_report([_finding("a", status="confirmed", patch_status="fixed")], repo_path=repo, full_rescan=False)

    run = reports.get_run_report(repo_path=repo)
    by_id = {f["threat_id"]: f for f in run["findings"]}
    assert set(by_id) == {"a", "b"}
    assert by_id["a"]["patch_status"] == "fixed"
    assert by_id["b"]["status"] == "not_applicable"


def test_get_latest_audit_returns_most_recent_single_finding(workspace, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    reports.write_run_report(
        [_finding("a", timestamp="2026-01-01T00:00:00+00:00"),
         _finding("b", timestamp="2026-01-02T00:00:00+00:00")],
        repo_path=repo, full_rescan=True,
    )

    latest = reports.get_latest_audit(repo_path=repo)
    assert latest["threat_id"] == "b"
