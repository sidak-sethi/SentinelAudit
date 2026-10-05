"""Vulnerability scanning without a pre-supplied threat package.

This is the entry point for interactive use (see offline/interactive.py
and cli.py): instead of starting from an Online-sourced threat package,
Gemma 4 is asked to look at the currently-selected repository (see
communication.paths.set_target_repo) and propose its own list of
candidate findings. Each candidate is then turned into a synthetic,
schema-valid, signed threat package -- the exact same shape
fixtures/*_package.py produce -- so every downstream component (Guard,
auditor, patcher) treats a self-found issue exactly like an
Online-sourced one, with no special-casing anywhere else in the pipeline.

Gemma's scan is a LEAD GENERATOR, not an oracle: nothing here is reported
back to the user as a confirmed vulnerability. offline/interactive.py
feeds every candidate through auditor.run_audit(), which only confirms a
finding after it genuinely reproduces it with a real generated test.
"""
import json
import os
from pathlib import Path
from datetime import datetime, timezone

from communication import paths
from guard.validator import recompute_integrity_sha256
from offline import gemma_client, tools
from offline.auditor import SYSTEM_PROMPT, _untrusted_block

# Directories/extensions that are never worth sending to the model --
# keeps the prompt bounded and avoids wasting the scan on vendored code,
# binaries, or lockfiles.
SKIP_DIR_NAMES = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    "vendor", "target", "site-packages", "coverage", "htmlcov", ".tox",
    ".next", ".nuxt", ".cache", ".turbo", "bower_components", "Pods",
}
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rs", ".html", ".sql", ".sh",
    ".yaml", ".yml", ".json", ".env",
}

# Kept deliberately bounded: gemma4:e2b has a limited context/generation
# budget, and a prompt this scan builds competes with the findings list
# it has to generate in response. An unfiltered file list (node_modules,
# vendor dirs, build output, ...) was the dominant, observed cause of
# truncated/invalid JSON output on a real repo -- now that file_list
# itself is filtered and capped (see MAX_FILE_LIST_ENTRIES below), there
# is more budget to actually look at file *contents*, which matters for
# coverage: a vulnerable file that never gets sampled can never be found.
MAX_FILES = 25
MAX_BYTES_PER_FILE = 2500
MAX_TOTAL_PROMPT_CHARS = 20_000
try:
    # Every candidate is audited serially, so a lower default shortens the
    # slowest part of a scan while still leaving a knob for broader scans.
    MAX_FINDINGS = max(1, min(8, int(os.environ.get("SENTINEL_MAX_SCAN_FINDINGS", "5"))))
except ValueError:
    MAX_FINDINGS = 5


# Path keywords that correlate with where real vulnerabilities tend to
# live. Used only to rank which files get sampled first when a repo has
# more relevant files than MAX_FILES -- without this, alphabetical
# truncation can cut out the one file that actually matters.
PRIORITY_KEYWORDS = (
    "auth", "login", "admin", "password", "secret", "token", "session",
    "sql", "query", "exec", "eval", "command", "shell", "upload", "download",
    "file", "path", "template", "render", "redirect", "cors", "csrf", "jwt",
    "crypto", "hash", "random", "pickle", "yaml", "xml", "deserialize",
    "user", "search", "api", "route", "controller", "handler", "middleware",
    "config", "db", "database", "model",
)


def _priority_score(path: str) -> int:
    lower = path.lower()
    return sum(1 for keyword in PRIORITY_KEYWORDS if keyword in lower)


def _repository_files() -> list:
    """List files once, pruning generated/vendor trees during traversal.

    tools.list_files() walks every descendant before the scanner can filter
    node_modules, virtualenvs, build output, and other ignored directories.
    Pruning in os.walk avoids spending time statting those trees at all.
    """
    root = paths.TARGET_REPO.resolve()
    results = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIR_NAMES)
        for filename in filenames:
            relative = (Path(current) / filename).relative_to(root)
            results.append(str(relative).replace("\\", "/"))
    return sorted(results)


def _relevant_files(file_paths: list | None = None) -> list:
    candidates = []
    for path in file_paths if file_paths is not None else _repository_files():
        basename = path.rsplit("/", 1)[-1]
        if "." not in basename:
            continue
        suffix = "." + basename.rsplit(".", 1)[-1]
        if suffix not in SOURCE_EXTENSIONS:
            continue
        candidates.append(path)
    # Stable sort: higher keyword score first, original (alphabetical)
    # order preserved among ties.
    candidates.sort(key=lambda p: -_priority_score(p))
    return candidates[:MAX_FILES]


MAX_FILE_LIST_ENTRIES = 200


def _filtered_file_list(file_paths: list | None = None) -> list:
    """The full file list, unlike _relevant_files(), is used only as
    orientation context for Gemma -- but for a real repo it can run into
    the thousands (node_modules, vendor dirs, build output, ...), which
    alone is enough to blow the prompt budget and truncate the response.
    Apply the same skip-dir filtering and a hard cap."""
    file_paths = file_paths if file_paths is not None else _repository_files()
    return file_paths[:MAX_FILE_LIST_ENTRIES]


def _sample_repository() -> dict:
    file_paths = _repository_files()
    file_list = _filtered_file_list(file_paths)
    sampled = {}
    total_chars = 0
    for path in _relevant_files(file_paths):
        try:
            content = tools.read_file(path)
        except (FileNotFoundError, UnicodeDecodeError):
            continue
        content = content[:MAX_BYTES_PER_FILE]
        if total_chars + len(content) > MAX_TOTAL_PROMPT_CHARS:
            break
        sampled[path] = content
        total_chars += len(content)
    return {"file_list": file_list, "file_contents": sampled}


def scan_repository() -> list:
    """Ask Gemma 4 to propose candidate vulnerabilities in the currently
    selected repository (communication.paths.TARGET_REPO). Returns a list
    of raw finding dicts -- unproven leads, not confirmed vulnerabilities."""
    sample = _sample_repository()

    user_prompt = f"""Real repository file list (ground truth, trusted):
{json.dumps(sample['file_list'], indent=2)}

Real file contents, sampled from the repository (ground truth, trusted):
{json.dumps(sample['file_contents'], indent=2)[:MAX_TOTAL_PROMPT_CHARS]}

You are reviewing this repository for security vulnerabilities with no specific threat
report to start from. List the concrete, specific vulnerabilities you can find grounded
in the actual code shown above -- do not speculate about files you have not seen.

Report at most {MAX_FINDINGS} findings, the most significant ones first. Keep every text
field to one or two sentences -- you have a limited response budget and a cut-off,
truncated response is useless. Prefer fewer, concise, well-grounded findings over an
exhaustive list.

Respond with JSON matching exactly:
{{
  "findings": [
    {{
      "title": "short title",
      "severity": "low|medium|high|critical",
      "attack_type": "e.g. sql_injection, command_injection, xss, path_traversal, hardcoded_secret, ...",
      "affected_files": ["path", ...],
      "affected_lines": [0],
      "vulnerability_hypothesis": "one or two sentences",
      "recommended_fix": "one or two sentences",
      "test_plan": "one sentence describing a test that would prove this"
    }}
  ]
}}

If you find nothing concrete, respond with {{"findings": []}}. Never invent a finding not
grounded in the file contents shown above."""
    result = gemma_client.generate_json(SYSTEM_PROMPT, user_prompt, num_predict=2048)
    return result.get("findings", []) if isinstance(result, dict) else []


def build_finding_package(finding: dict, index: int) -> dict:
    """Turn one raw Gemma finding into a synthetic, schema-valid, signed
    threat package -- same shape and signing helper as fixtures/*_package.py,
    so it goes through the Guard and the rest of the pipeline exactly like
    an Online-sourced package."""
    now = datetime.now(timezone.utc).isoformat()
    slug = "".join(ch if ch.isalnum() else "-" for ch in finding.get("title", "finding"))[:40].strip("-").lower() or "finding"
    package = {
        "schema_version": "1.0",
        "threat_id": f"manual-scan-{index:03d}-{slug}",
        "source": {
            "type": "other",
            "url": "https://local-scan.invalid/offline-gemma-self-scan",
            "published": now,
            "retrieved_at": now,
        },
        "title": finding.get("title", "Untitled finding")[:300],
        "cve": "",
        "affected_component": ", ".join(finding.get("affected_files", []))[:300] or "unknown",
        "affected_versions": [],
        "fixed_versions": [],
        "severity": finding.get("severity") if finding.get("severity") in
        {"low", "medium", "high", "critical"} else "medium",
        "description": (finding.get("vulnerability_hypothesis") or finding.get("title") or "")[:8000],
        "attack_type": (finding.get("attack_type") or "other")[:128],
        "indicators": [],
        "audit_instructions": [],
        "test_strategy": (finding.get("test_plan") or "")[:4000],
        "remediation": (finding.get("recommended_fix") or "")[:4000],
        "integrity": {"sha256": ""},
    }
    package["integrity"] = {"sha256": recompute_integrity_sha256(package)}
    return package
