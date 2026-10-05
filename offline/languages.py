"""Per-language test execution, result interpretation, and prompt rules.

This is the one place that knows HOW to run and interpret a security
test in a given language, so auditor.py/patcher.py/tools.py stay
language-agnostic -- they ask the active LanguageProfile to do it rather
than hardcoding pytest (or anything else).

Adding a new language means adding one more LanguageProfile here, not
touching the audit/patch control flow.
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path

from offline import sandbox

# ---------------------------------------------------------------------------
# Shared: which exception "type name" means the test's own security
# assertion actually fired (a real logic outcome) vs. the test being
# mechanically broken (worth exactly one corrective retry, same as a
# malformed-JSON response) vs. anything else (inconclusive).
# ---------------------------------------------------------------------------


@dataclass
class LanguageProfile:
    name: str
    test_file_extension: str  # e.g. ".py" or ".js"
    test_writing_rules: str  # language-specific rules block for the generate_security_test prompt
    normal_test_pass_codes: set  # exit codes that mean "nothing broke" for THIS language's test runner

    def run_security_test(self, repo_path, rel_path: str) -> dict:
        raise NotImplementedError

    def run_normal_tests(self, repo_path) -> dict:
        raise NotImplementedError

    def interpret_result(self, result: dict) -> str:
        """Returns "PASSED" | "FAILED_ASSERTION" | "ERROR"."""
        raise NotImplementedError

    def is_mechanical_error(self, result: dict) -> bool:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Python / pytest
# ---------------------------------------------------------------------------

_PYTEST_EXCEPTION_TYPE_RE = re.compile(r"^E\s+([A-Za-z_][\w.]*)\s*:", re.MULTILINE)
_PYTHON_MECHANICAL_ERROR_TYPES = {
    "SyntaxError", "IndentationError", "TabError", "NameError",
    "ImportError", "ModuleNotFoundError", "AttributeError",
}


class PythonProfile(LanguageProfile):
    def __init__(self):
        super().__init__(
            name="Python",
            test_file_extension=".py",
            test_writing_rules="""1. Assert the SAFE/expected outcome, not the attack succeeding. The test must FAIL (raise
   AssertionError) when run against the CURRENT, vulnerable code, and PASS when run against
   correctly patched code. For example: assert that a malicious input does NOT return extra
   rows / does NOT execute / does NOT bypass a check -- never assert that the attack
   succeeds as the passing condition. Getting this backwards means a correct fix will look
   like it failed.
2. The test must be fully self-contained. If the application needs any setup or
   initialization (for example a function that creates database tables), call it yourself
   inside the test -- do not assume prior state exists, since the test may run standalone or
   as part of the full suite in either order.
3. Use only what you can see in the real file contents above (the actual function/route
   names, the actual way to construct a client or connection) -- do not invent an API that
   is not shown.
4. Keep it as short as it can be while still proving the vulnerability -- one focused test
   function, not a whole suite. Write plain pytest (a `def test_...():` function with
   `assert`), not unittest.TestCase.""",
            normal_test_pass_codes={0, 5},  # 5 == "no tests collected", not a failure
        )

    def run_security_test(self, repo_path, rel_path: str) -> dict:
        return sandbox.run_command(["python", "-m", "pytest", "-q", rel_path], cwd=repo_path, timeout=60)

    def run_normal_tests(self, repo_path) -> dict:
        return sandbox.run_command(["python", "-m", "pytest", "-q"], cwd=repo_path, timeout=120)

    def interpret_result(self, result: dict) -> str:
        if result.get("timed_out"):
            return "ERROR"
        if result["returncode"] == 0:
            return "PASSED"

        stdout = result.get("stdout", "")
        typed_exceptions = _PYTEST_EXCEPTION_TYPE_RE.findall(stdout)
        if typed_exceptions:
            return "FAILED_ASSERTION" if typed_exceptions[-1] == "AssertionError" else "ERROR"

        summary = ""
        for line in reversed([l for l in stdout.splitlines() if l.strip()]):
            low = line.lower()
            if "passed" in low or "failed" in low or "error" in low:
                summary = low
                break
        if "error" in summary and "failed" not in summary:
            return "ERROR"
        if "failed" in summary:
            return "FAILED_ASSERTION"
        return "ERROR"

    def is_mechanical_error(self, result: dict) -> bool:
        typed = _PYTEST_EXCEPTION_TYPE_RE.findall(result.get("stdout", ""))
        return bool(typed) and typed[-1].rsplit(".", 1)[-1] in _PYTHON_MECHANICAL_ERROR_TYPES


# ---------------------------------------------------------------------------
# JavaScript / Node.js
# ---------------------------------------------------------------------------

_NODE_MECHANICAL_ERROR_TYPES = ("SyntaxError", "ReferenceError", "TypeError", "Cannot find module")


class JavaScriptProfile(LanguageProfile):
    def __init__(self):
        super().__init__(
            name="JavaScript/TypeScript",
            test_file_extension=".js",
            test_writing_rules="""1. Write a plain, self-contained Node.js script -- NOT a jest/mocha/vitest test file, and
   do not require any test framework or dependency that isn't already in package.json.
   Use only Node's built-in `assert` module (`require('assert')`) and built-in `http` or
   the global `fetch` for any HTTP calls.
2. If testing an Express (or similar) app, follow this EXACT pattern for the server and the
   request -- getting the ephemeral port wrong (using it before it is assigned, or building
   the URL before the `listen` callback has fired) is the most common mistake:
   ```
   const { createServer } = require('./server.js'); // adjust to the real export
   const server = createServer().listen(0, () => {
     const port = server.address().port; // only valid INSIDE this callback
     const url = `http://localhost:${port}/your-path?param=value`;
     fetch(url).then(res => res.text()).then(text => {
       // your assert.* calls here
       server.close();
     }).catch(err => { server.close(); throw err; });
   });
   ```
   Never read `server.address()` or build the URL outside that callback -- the port does not
   exist yet. Always call `server.close()` on both the success and the catch/error path.
3. Assert the SAFE/expected outcome, not the attack succeeding -- same rule as above for
   Python: the script must throw (an uncaught `assert` failure exits non-zero automatically)
   when the vulnerability is present, and exit cleanly (code 0) when it is fixed. Never
   assert that the attack succeeds as the passing condition.
4. Use only what you can see in the real file contents above (the actual route paths,
   exported names, require paths) -- do not invent an API that is not shown.
5. Keep it short -- one focused script that proves the vulnerability, not a whole suite.
6. As a safety net against the script hanging if something above goes wrong, add this
   near the top, and call `process.exit(1)` from inside it if the script is still running
   after a few seconds instead of letting it hang indefinitely:
   `const safety = setTimeout(() => { console.error('test did not exit in time'); process.exit(1); }, 5000); safety.unref();`
   Then call `clearTimeout(safety)` once your assertions and `server.close()` are done.""",
            normal_test_pass_codes={0},
        )

    def run_security_test(self, repo_path, rel_path: str) -> dict:
        return sandbox.run_command(["node", rel_path], cwd=repo_path, timeout=60)

    def run_normal_tests(self, repo_path) -> dict:
        """Only actually runs `npm test` if package.json defines a real
        test script -- otherwise there's nothing to run, and that is not
        a failure (mirrors pytest's "no tests collected" being a pass,
        not a reason to reject every patch from a repo with no existing
        tests)."""
        package_json = Path(repo_path) / "package.json"
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                data = {}
            test_script = (data.get("scripts") or {}).get("test", "")
            if test_script and "no test specified" not in test_script:
                return sandbox.run_command(["npm", "test"], cwd=repo_path, timeout=120)
        return {"returncode": 0, "stdout": "(no package.json test script configured -- nothing to run)",
                "stderr": "", "timed_out": False}

    def interpret_result(self, result: dict) -> str:
        if result.get("timed_out"):
            return "ERROR"
        if result["returncode"] == 0:
            return "PASSED"
        combined = result.get("stderr", "") + "\n" + result.get("stdout", "")
        if "AssertionError" in combined:
            return "FAILED_ASSERTION"
        return "ERROR"

    def is_mechanical_error(self, result: dict) -> bool:
        combined = result.get("stderr", "") + result.get("stdout", "")
        if "AssertionError" in combined:
            return False
        return any(marker in combined for marker in _NODE_MECHANICAL_ERROR_TYPES)


PYTHON = PythonProfile()
JAVASCRIPT = JavaScriptProfile()

_PYTHON_MARKERS = {"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"}
_JAVASCRIPT_MARKERS = {"package.json"}
_OTHER_LANGUAGE_MARKERS = {
    "go.mod": "Go",
    "Gemfile": "Ruby",
    "pom.xml": "Java (Maven)",
    "build.gradle": "Java/Kotlin (Gradle)",
    "composer.json": "PHP",
    "Cargo.toml": "Rust",
}


def detect_language(repo_path) -> LanguageProfile | None:
    """The profile to use for running/interpreting tests in this repo.
    Prefers an explicit marker file; falls back to counting source
    files. Returns None only if nothing recognizable is found (callers
    should default to PYTHON in that case to preserve existing
    behavior, e.g. the Online-integration/demo flow, which never calls
    detect_unsupported_language at all)."""
    repo_path = Path(repo_path)
    if any((repo_path / marker).exists() for marker in _PYTHON_MARKERS):
        return PYTHON
    if any((repo_path / marker).exists() for marker in _JAVASCRIPT_MARKERS):
        return JAVASCRIPT

    python_files = len(list(repo_path.rglob("*.py")))
    js_files = len(list(repo_path.rglob("*.js"))) + len(list(repo_path.rglob("*.ts")))
    if python_files == 0 and js_files == 0:
        return None
    return PYTHON if python_files >= js_files else JAVASCRIPT


def detect_unsupported_language(repo_path) -> str | None:
    """Returns a human-readable language name if `repo_path` looks like
    a genuinely unsupported (neither Python nor JS/TS) project, else
    None. Used by offline/interactive.select_repo to refuse clearly
    upfront instead of producing confusing per-finding failures."""
    repo_path = Path(repo_path)
    if detect_language(repo_path) is not None:
        return None
    for marker, language in _OTHER_LANGUAGE_MARKERS.items():
        if (repo_path / marker).exists():
            return language
    return None
