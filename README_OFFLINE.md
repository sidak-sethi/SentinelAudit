# SentinelAuditor — Guard + Offline Security Engineer

This repository contains **only** the Guard and Offline halves of
SentinelAuditor. There is no Online threat-intelligence system here, no
Online Gemma, and no code that discovers, scrapes, or synthesizes
real-world threats — that is a separate teammate's system, integrated
later purely through the five functions in [`api.py`](api.py). Everything
in `fixtures/` is a local test fixture that stands in for the Online
system during development; it is not a reimplementation of it.

## 1. Architecture

```
ONLINE (not in this repo)
   |
   | threat package (untrusted data)
   v
GUARD            -- fully deterministic, no AI model
   |
   | approved package only
   v
OFFLINE_INBOX
   |
   v
OFFLINE GEMMA 4  -- local-only, via Ollama
   |
   v
LOCAL TARGET REPO (offline_workspace/target_repo)
   |
   v
TEST -> PATCH -> TEST -> RE-AUDIT -> COMMIT or ROLLBACK
```

- **Guard** (`guard/`) is a pure Python validation/allowlisting pipeline.
  It never calls an AI model — the security boundary must not depend on a
  model's judgment.
- **Offline** (`offline/`) uses a local Gemma 4 model (via Ollama) to
  analyze a vetted threat, inspect the real target repository, prove a
  vulnerability with a failing test, generate a structured patch, and
  validate it before committing.
- **communication/** defines the shared schema and every configurable
  filesystem path both halves use.

## 2. Guard

The Guard (`guard/guard.py`) is the only component allowed to move data
from `online_outbox/` to `offline_inbox/`. There is no reverse path: no
function anywhere in this codebase writes from Offline back into
`online_outbox/`.

For every package it:
1. Parses and validates JSON/schema/types/sizes (`guard/validator.py`,
   `guard/policy.py`, `communication/schema.py`).
2. Runs a deterministic keyword/pattern scan for prompt-injection and
   instruction-smuggling (`guard/sanitizer.py`) — SAFE / SUSPICIOUS /
   REJECTED. A hard-reject match always rejects the package; a softer
   suspicious match is logged but does not by itself reject.
3. Recomputes the package's sha256 (excluding the `integrity` field
   itself) and rejects a mismatch (tampered package).
4. Rejects unknown top-level fields and a blocklist of field names
   (`commands`, `shell`, `exec`, `webhook`, `secrets`, `system_prompt`,
   ...) at any nesting depth — never silently stripped, always rejected
   with a reason.
5. On approval, writes the package to a temp file inside `offline_inbox/`
   and `os.replace`s it into place — atomic on the same filesystem, so
   Offline can never observe a partially-written package.
6. Records every step as a `GUARD_*` event (`guard/events.py`).

Rejected packages are quarantined in `offline_workspace/guard_rejected/`
with their rejection reason and never reach `offline_inbox/`.

## 3. One-way communication

```
online_outbox/  --(Guard validates)-->  offline_inbox/
```

Offline (`offline/agent.py`) only ever reads from `offline_inbox/`. There
is no code path in `offline/` that writes to `online_outbox/` or that
could be used to send anything back toward Online.

## 4. Isolation model (read this before claiming anything about it)

The Offline agent makes exactly one kind of network call: to
`OLLAMA_HOST` (default `http://localhost:11434`), which is checked against
a loopback allowlist by default (`offline/gemma_client.py`). No other
network code exists anywhere in the Offline execution path — no
`requests`, `httpx`, raw `socket`, or `webbrowser` usage.

**This prototype implements the application-level isolation boundary.**
It is an *isolated offline security environment*, not a certified air
gap. Production deployment should additionally enforce OS/network-level
isolation or firewall rules; Python code alone cannot guarantee that a
host with internet connectivity is truly air-gapped.

## 5. Gemma 4 / Ollama setup

```
ollama pull gemma4:e2b
```

Environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint (must be loopback by default) |
| `GEMMA_MODEL` | `gemma4:e2b` | Exact model tag to use |
| `MAX_PATCH_ATTEMPTS` | `3` | Cap on patch attempts before `UNRESOLVED` |
| `SENTINEL_WORKSPACE` | `./offline_workspace` | Root for all runtime data |

`GEMMA_MODEL` is the **only** way to change models, and only to another
tag you explicitly pull yourself (e.g. a larger Gemma 4 variant if your
hardware supports it). There is no automatic fallback: if the configured
tag isn't pulled, every AI operation fails with a clear error instead of
silently using a different model. Every model call logs both
`MODEL: GEMMA 4` and `MODEL_TAG: <configured tag>`.

## 6. Running it

```bash
pip install -r requirements.txt

# Scaffold the disposable demo repo (SQLi in a tiny Flask app)
python fixtures/setup_target_repo.py

# Guard tests -- no external dependencies
python -m pytest guard/tests -v

# Offline tests -- Gemma-dependent cases skip cleanly if Ollama/the model
# aren't available; everything else (path/command guards, git plumbing,
# patch-loop rollback/iteration-limit/commit-gating) always runs
python -m pytest offline/tests -v

# Build the two "Online" demo fixtures and the mismatched one
python fixtures/sqli_demo_package.py
python fixtures/malicious_package.py
python fixtures/not_applicable_package.py
```

```python
import api

for name in ("demo-sqli-001", "demo-malicious-001", "demo-not-applicable-001"):
    ...  # or just watch the whole outbox:

import communication.paths as paths
for f in sorted(paths.ONLINE_OUTBOX.glob("*.json")):
    print(f.name, api.submit_threat_package(f))

print(api.start_offline_audit())   # audits+patches the SQLi package
print(api.get_latest_audit())
print(api.get_guard_events())
print(api.get_offline_events())
```

## 7. LOCAL DEMO MODE vs LIVE INTERNET MODE

The guaranteed demo does not depend on a live advisory matching the demo
repository. `fixtures/sqli_demo_package.py` builds a hand-authored,
correctly-signed threat package describing the exact SQLi class present
in the fixture repo — **LOCAL DEMO MODE**. Once the Online teammate's real
pipeline is integrated, a real advisory (**LIVE INTERNET MODE**) goes
through the identical code path. If a real advisory doesn't actually
apply to whatever repository is configured, the correct, required outcome
is `NOT_APPLICABLE` (`fixtures/not_applicable_package.py` exercises this
honestly) — the agent never invents a match to make a demo look
successful.

## 8. Threat Package schema

See `communication/schema.py` for the authoritative field list. Summary:

```json
{
  "schema_version": "1.0",
  "threat_id": "unique-id",
  "source": {"type": "nvd|github|cisa|other", "url": "...", "published": "...", "retrieved_at": "..."},
  "title": "...",
  "cve": "CVE-YYYY-NNNN",
  "affected_component": "...",
  "affected_versions": [],
  "fixed_versions": [],
  "severity": "low|medium|high|critical",
  "description": "...",
  "attack_type": "...",
  "indicators": [],
  "audit_instructions": [],
  "test_strategy": "...",
  "remediation": "...",
  "integrity": {"sha256": "..."}
}
```

Every field is treated as **data**, never as instructions — including
`audit_instructions`, `remediation`, and `test_strategy`. Gemma's system
prompt is static and never templated from package content.

## 9. Security model summary

- Guard is fully deterministic; no AI model is the final security
  authority anywhere in the Guard.
- Offline tool access is a narrow, explicit set of Python functions
  (`offline/tools.py`), never raw shell access.
- Every filesystem path Gemma requests is resolved and checked against
  `offline_workspace/target_repo`; anything that escapes it returns
  `PATH_REJECTED`.
- Every subprocess call goes through an explicit command allowlist
  (`offline/sandbox.py`); anything else returns `COMMAND_REJECTED`.
- Nothing is committed until normal tests, the security regression test,
  and a final Gemma audit all pass. Failed attempts roll back to the
  pre-audit state; branches are never auto-deleted; only
  `offline_workspace/target_repo/` is ever modified, never this repo.
- `MAX_PATCH_ATTEMPTS` bounds the patch loop so it can never run forever.

## 10. Limitations

- This is an application-level isolation boundary, not a certified air
  gap (see section 4).
- The pytest-outcome classifier that distinguishes a genuine failing
  assertion from a test setup/collection error (`offline/auditor.py:
  interpret_pytest_result`) is a heuristic over pytest's text summary
  line, not a guarantee for every possible pytest failure mode.
- Gemma's structured JSON outputs are retried once on malformed JSON and
  otherwise fail loudly; there is no guarantee a given Gemma 4 tag will
  reliably produce the exact JSON shape requested.
- **Python and JavaScript/TypeScript target repos only.**
  `offline/languages.py` is the one place that knows how to run and
  interpret a security test for a given language (Python via
  `pytest`, JS/TS via a plain Node script run with `node`, using only
  built-in `assert`/`http`/`fetch` -- never a test framework that might
  not be installed in the target repo). Any other language (`go.mod`,
  `Gemfile`, `pom.xml`, `Cargo.toml`, etc. with no Python/JS markers) is
  refused upfront by `offline/interactive.select_repo` with status
  `"unsupported_language"` rather than attempted and producing confusing
  per-finding failures. Adding a third language means adding one more
  `LanguageProfile` to `offline/languages.py` -- the audit/patch control
  flow itself does not need to change.

## 11. Scan your own repository interactively

For hands-on use (not the Online-integration flow), point SentinelAuditor
at any repository and let Gemma 4 find and optionally fix real issues in
it, with no threat package needed:

```bash
python cli.py scan /path/to/some/repo
```

What happens:
1. The repo is selected at runtime (`communication.paths.set_target_repo`
   — no env var, no restart). If it isn't a git repo yet, you're asked
   before one is initialized (`git init` + one commit of the current
   state — additive, never touches file contents, reversible by deleting
   `.git`). If the worktree is dirty, it refuses and tells you to commit
   or stash first.
2. Gemma 4 samples the repo (skipping vendor/binary/lock files, bounded
   file count and size) and proposes candidate vulnerabilities — a lead
   generator, not an oracle.
3. Every candidate is turned into a synthetic, signed threat package and
   pushed through the same deterministic Guard as an Online-sourced
   package, then through the same `auditor.run_audit()` proof step used
   everywhere else: a real test is generated and run. **Every** lead is
   reported, not just confirmed ones — each with its status
   (`confirmed` / `not_applicable` / `uncertain` / `ai_error` /
   `guard_rejected`) and the actual reason, so you can see what Gemma
   suspected even when it couldn't be proven.
4. Each finding is printed (hypothesis, affected files, suggested fix,
   attack type, and why it landed where it did) and a structured JSON
   report is saved for it under `offline_workspace/reports/` either way.
   For `confirmed` findings only, you're asked whether to fix it now;
   declining leaves the repository untouched for that finding.
5. Accepting runs the same patch/test/validate/commit loop as everywhere
   else in this codebase — nothing is committed until normal tests, the
   security regression test, and a final Gemma audit all pass.

This mode is implemented in `offline/scanner.py` (the scan) and
`offline/interactive.py` (orchestration); `api.py`'s five
Online-integration functions are untouched by it.

### Opening a pull request for an accepted fix

By default a fix stays local, committed only to its own
`ai-security-fix/<id>` branch — nothing is ever pushed anywhere on its
own. If you want the fix sent up as a real GitHub Pull Request instead of
staying local, pass `--pr-base`:

```bash
python cli.py scan /path/to/some/repo --pr-base main
```

After a fix is accepted, you're asked a **second**, separate
confirmation — "Push branch '...' and open a pull request against
'main'?" — before anything leaves your machine. On yes, it runs `git
push -u origin <fix-branch>` and `gh pr create --base main --head
<fix-branch>` (requires the repo to already have an `origin` remote and
the `gh` CLI authenticated) and prints the PR URL. It never pushes to or
otherwise touches `main` itself — the PR is a request a human reviews
and merges on GitHub, exactly like any other PR.

The same capability is available over the HTTP API: `POST
/fixes/<threat_id>` with body `{"pr_base": "main"}` pushes and opens the
PR as part of that one call (there is no separate confirmation step for
an API call the way the CLI has one — passing `pr_base` *is* the explicit
request).

## 12. HTTP API (for a dashboard or another service)

`api_server.py` is a minimal Flask server over the same
`offline/interactive.py` engine as `cli.py`, for anything that wants
these results delivered over the network as JSON instead of printed to a
terminal:

```bash
python api_server.py          # listens on http://127.0.0.1:5001
```

| Method & path | What it does |
|---|---|
| `GET /health` | Guard status, Ollama reachability, whether the configured `GEMMA_MODEL` tag is actually pulled. |
| `POST /scan` | Body `{"repo_path": "...", "confirm_git_init": false}`. Scans the repo and returns **every** finding (see below), not only confirmed ones. Returns `409` with `status: "needs_git_init"` or `"dirty_worktree"` instead of silently acting — re-POST with `confirm_git_init: true` to proceed past the former. |
| `POST /fixes/<threat_id>` | Applies the patch/test/validate/commit loop for a finding that came back `confirmed` from a prior `/scan` call *in this server run* (the cache is in-memory, not persisted across restarts). |
| `GET /audits` | Lists every codebase ever scanned (repository, last_run, finding/confirmed/fixed counts), newest first — one entry per codebase, not per finding. |
| `GET /audits/<threat_id>` | Searches across every codebase's report for one finding by id. |
| `GET /events/guard`, `GET /events/offline` | The same event logs `api.get_guard_events()`/`get_offline_events()` expose. |

### Where the JSON actually lives

**One JSON (+ companion `.txt`) file per codebase**, under
`offline_workspace/reports/`, named deterministically from the repository
path (so re-scanning the same repo always resolves to the same file).
Every run **overwrites** that one file — a full scan (`cli.py scan` /
`POST /scan`) replaces its findings list with the current run's results;
applying a fix afterward updates just that finding's entry in place.
Nothing here ever creates a new timestamped file per finding or per run.

```python
from offline import reports
reports.get_run_report()                 # the aggregate for the currently-selected repo
reports.get_run_report(repo_path="...")   # for a specific repo, regardless of what's selected
```

The file itself is this envelope:

```json
{
  "repository": "C:\\path\\to\\repo",
  "last_run": "2026-01-01T00:00:00+00:00",
  "findings": [ /* one entry per finding, shape below */ ]
}
```

And every finding (inside that `"findings"` list, or from `/scan`,
`/fixes`, or `/audits/<threat_id>`) is this JSON shape:

```json
{
  "threat_id": "manual-scan-001-sql-injection-in-search",
  "title": "SQL Injection in /search",
  "attack_type": "sql_injection",
  "severity": "high",
  "status": "confirmed",
  "patch_status": "fixed",
  "repository": "C:\\path\\to\\repo",
  "branch": "ai-security-fix/manual-scan-001-sql-injection-in-search",
  "affected_files": ["app.py"],
  "affected_lines": [63],
  "vulnerability_hypothesis": "...",
  "recommended_fix": "...",
  "security_test_path": "tests/security/test_search_sqli.py",
  "code": {
    "app.py": {
      "before": "<full original file content -- the vulnerable snippet>",
      "after": "<full patched file content -- only set once patch_status is \"fixed\">"
    }
  },
  "diff": "<unified diff text -- only set once patch_status is \"fixed\">",
  "reason": "...",
  "timestamp": "2026-01-01T00:00:00+00:00"
}
```

`code.<file>.after` and `diff` are only ever populated once a patch has
actually been applied, tested, and committed — an attempted-but-rejected
patch is never reported as the fix, matching the honesty requirement
everywhere else in this codebase. This same report shape is what
`cli.py` now also saves to disk for every finding (confirmed or not), so
the CLI and the API always agree.

## 13. Integration for the Online teammate

The entire contract is five functions in [`api.py`](api.py):

```python
submit_threat_package(path) -> {"status": "APPROVED"|"REJECTED", "threat_id": ..., "reason": ...}
get_guard_events() -> list[dict]
get_offline_events() -> list[dict]
get_latest_audit() -> dict | None
start_offline_audit(package_path=None) -> dict
```

The Online system only needs to produce a valid threat package (matching
the schema above) and call `submit_threat_package`, either by writing the
file into the directory `communication.paths.ONLINE_OUTBOX` points at and
calling `submit_threat_package` on it, or by handing `submit_threat_package`
a path directly. It needs no knowledge of Guard or Offline internals.
