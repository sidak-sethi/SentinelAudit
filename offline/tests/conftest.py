"""Shared fixtures for the Offline test suite."""
import importlib
import subprocess

import pytest

from communication import paths as paths_module
from offline import gemma_client


@pytest.fixture
def target_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACE", str(tmp_path))
    importlib.reload(paths_module)
    paths_module.ensure_directories()

    repo = paths_module.TARGET_REPO
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "tests").mkdir(parents=True, exist_ok=True)
    (repo / "tests" / "test_app.py").write_text(
        "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n", encoding="utf-8"
    )
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.pytest_cache/\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True)

    yield repo
    importlib.reload(paths_module)


def gemma_available() -> bool:
    try:
        return gemma_client.check_ollama_available() and gemma_client.check_model_available()
    except Exception:
        return False


requires_gemma = pytest.mark.skipif(not gemma_available(), reason="Ollama / configured Gemma 4 model not available")
