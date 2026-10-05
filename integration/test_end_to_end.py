"""End-to-end acceptance scenarios (see the approved implementation plan's
Verification section). Scenarios B, D, F, G need no AI model and always
run; Scenarios A and C exercise the real Gemma 4 pipeline end-to-end and
skip cleanly when Ollama / the configured GEMMA_MODEL are not available --
they are never simulated.
"""
import importlib

import pytest

from communication import paths as paths_module
from offline import gemma_client, sandbox, tools


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE", str(tmp_path))
    importlib.reload(paths_module)
    paths_module.ensure_directories()
    yield paths_module
    importlib.reload(paths_module)


def gemma_available() -> bool:
    try:
        return gemma_client.check_ollama_available() and gemma_client.check_model_available()
    except Exception:
        return False


requires_gemma = pytest.mark.skipif(not gemma_available(), reason="Ollama / configured Gemma 4 model not available")


def test_scenario_b_injection_rejected(workspace):
    """Malicious package -> Guard detects injection -> rejected -> never
    enters offline_inbox -> Offline never runs."""
    import api
    from fixtures import malicious_package

    malicious_package.write_to_outbox()
    source = next(workspace.ONLINE_OUTBOX.glob("*.json"))

    result = api.submit_threat_package(source)

    assert result["status"] == "REJECTED"
    assert list(workspace.OFFLINE_INBOX.glob("*.json")) == []


def test_scenario_d_model_unavailable(workspace, monkeypatch):
    """Ollama/model missing -> clear GEMMA 4 unavailable error -> no fake
    result, no patch."""
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
    with pytest.raises(gemma_client.GemmaUnavailableError):
        gemma_client.generate_json("sys", "user")


def test_scenario_f_path_escape(workspace):
    """Gemma-requested path outside target_repo -> PATH_REJECTED."""
    with pytest.raises(tools.PathRejectedError):
        tools.resolve_safe_path("../outside.txt")


def test_scenario_g_command_escape(workspace):
    """Gemma-requested disallowed command -> COMMAND_REJECTED."""
    with pytest.raises(sandbox.CommandRejectedError):
        sandbox.run_command(["curl", "http://example.com"], cwd=workspace.TARGET_REPO)


@requires_gemma
def test_scenario_a_full_pipeline_fixes_sqli(workspace):
    """The guaranteed demo: LOCAL DEMO MODE SQLi package all the way
    through to a real commit on ai-security-fix/<id>."""
    import api
    from fixtures import setup_target_repo, sqli_demo_package

    setup_target_repo.setup_target_repo()
    sqli_demo_package.write_to_outbox()
    source = next(workspace.ONLINE_OUTBOX.glob("*.json"))

    submit_result = api.submit_threat_package(source)
    assert submit_result["status"] == "APPROVED"

    audit_result = api.start_offline_audit()
    assert audit_result["audit_status"] == "vulnerable"
    assert audit_result["patch_status"] == "fixed"

    latest = api.get_latest_audit()
    assert latest["threat_id"] == submit_result["threat_id"]


@requires_gemma
def test_scenario_c_not_applicable(workspace):
    """A valid, well-formed package describing a threat that does not
    apply to the fixture repo -> NOT_APPLICABLE, no source changes, no
    invented match."""
    import api
    from fixtures import not_applicable_package, setup_target_repo

    setup_target_repo.setup_target_repo()
    not_applicable_package.write_to_outbox()
    source = next(workspace.ONLINE_OUTBOX.glob("*.json"))

    submit_result = api.submit_threat_package(source)
    assert submit_result["status"] == "APPROVED"

    audit_result = api.start_offline_audit()
    assert audit_result["audit_status"] == "not_applicable"
    assert audit_result["patch_status"] is None
