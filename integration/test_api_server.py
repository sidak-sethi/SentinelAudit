"""Structural tests for api_server.py -- the HTTP surface over the
interactive scan+fix engine. Gemma itself is stubbed (the real model is
already exercised live elsewhere); these tests check the HTTP
request/response contract: status codes, the needs_git_init /
dirty_worktree gates, and that every finding (not just confirmed ones)
comes back with its status and reason.
"""
import importlib

import pytest

import api_server
from communication import paths as paths_module
from offline import interactive


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE", str(tmp_path))
    importlib.reload(paths_module)
    paths_module.ensure_directories()
    api_server._findings_cache.clear()
    with api_server.app.test_client() as test_client:
        yield test_client
    importlib.reload(paths_module)


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert "gemma_model_tag" in response.get_json()


def test_scan_requires_repo_path(client):
    response = client.post("/scan", json={})
    assert response.status_code == 400


def test_scan_needs_git_init_gate(client, tmp_path):
    plain_dir = tmp_path / "not_a_repo"
    plain_dir.mkdir()
    response = client.post("/scan", json={"repo_path": str(plain_dir)})
    assert response.status_code == 409
    assert response.get_json()["status"] == "needs_git_init"


def test_scan_refuses_genuinely_unsupported_language(client, tmp_path):
    go_repo = tmp_path / "go_repo"
    go_repo.mkdir()
    (go_repo / "go.mod").write_text("module demo\n", encoding="utf-8")
    response = client.post("/scan", json={"repo_path": str(go_repo)})
    assert response.status_code == 422
    assert response.get_json()["status"] == "unsupported_language"


def test_scan_reports_every_finding_not_just_confirmed(client, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    import subprocess
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)

    unconfirmed = interactive.ScanFinding(
        raw={"title": "Imaginary issue", "affected_files": ["app.py"]},
        package={"threat_id": "manual-scan-001-imaginary", "title": "Imaginary issue",
                 "severity": "low", "attack_type": "other", "description": "x",
                 "remediation": "", "source": {}},
        status="not_applicable", reason="does not hold up", audit=None,
    )
    monkeypatch.setattr(interactive, "find_vulnerabilities", lambda: [unconfirmed])

    response = client.post("/scan", json={"repo_path": str(repo)})
    assert response.status_code == 200
    body = response.get_json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "not_applicable"
    assert body["findings"][0]["reason"] == "does not hold up"


def test_fix_without_prior_scan_is_404(client):
    response = client.post("/fixes/does-not-exist")
    assert response.status_code == 404


def test_audits_list_is_empty_initially(client):
    response = client.get("/audits")
    assert response.status_code == 200
    assert response.get_json() == []
