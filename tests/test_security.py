from pathlib import Path


def test_env_file_is_gitignored():
    gitignore = Path(".gitignore")
    assert gitignore.exists()
    patterns = {line.strip() for line in gitignore.read_text(encoding="utf-8").splitlines()}
    assert ".env" in patterns


def test_fixture_is_not_real_exploit():
    text = Path("fixtures/reproducible_python_case/attack.py").read_text(encoding="utf-8")
    assert "CVE-2099" not in text
