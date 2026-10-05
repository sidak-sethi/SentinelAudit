"""TEST FIXTURE ONLY -- scaffolds the disposable, intentionally vulnerable
demo repository used to prove the Guard + Offline pipeline end-to-end.

This is NOT part of the Online system. It exists so Guard/Offline can be
built, demoed, and tested without a live advisory.
"""
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from communication import paths

APP_PY = '''import sqlite3
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
DB_PATH = Path(__file__).parent / "users.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [("alice", "alice@example.com"), ("bob", "bob@example.com")],
    )
    conn.commit()
    conn.close()


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = get_connection()
    cursor = conn.cursor()
    # VULNERABLE: user input is interpolated directly into the SQL string.
    cursor.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'")
    rows = cursor.fetchall()
    conn.close()
    return {"results": [{"id": r[0], "name": r[1], "email": r[2]} for r in rows]}


if __name__ == "__main__":
    init_db()
    app.run()
'''

TEST_APP_PY = '''from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app, init_db


def test_search_returns_matching_user():
    init_db()
    client = app.test_client()
    resp = client.get("/search", query_string={"name": "alice"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert any(u["name"] == "alice" for u in data["results"])
'''

REQUIREMENTS_TXT = "flask\n"
GITIGNORE = "users.db\n__pycache__/\n*.pyc\n"


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=str(cwd), check=True, capture_output=True, text=True)


def _force_remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def setup_target_repo() -> Path:
    repo = paths.TARGET_REPO
    if repo.exists():
        shutil.rmtree(repo, onexc=_force_remove_readonly)
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "tests").mkdir(parents=True, exist_ok=True)

    (repo / "app.py").write_text(APP_PY, encoding="utf-8")
    (repo / "tests" / "test_app.py").write_text(TEST_APP_PY, encoding="utf-8")
    (repo / "requirements.txt").write_text(REQUIREMENTS_TXT, encoding="utf-8")
    (repo / ".gitignore").write_text(GITIGNORE, encoding="utf-8")

    _run(["git", "init"], cwd=repo)
    _run(["git", "add", "-A"], cwd=repo)
    _run(["git", "commit", "-m", "Initial commit: vulnerable demo Flask app"], cwd=repo)
    return repo


if __name__ == "__main__":
    scaffolded_path = setup_target_repo()
    print(f"Target repo scaffolded at {scaffolded_path}")
