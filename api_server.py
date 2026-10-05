"""Minimal HTTP API over the interactive scan+fix engine, so a dashboard
or another service can trigger a scan and receive the same structured,
code-level findings the CLI prints -- as JSON, over the network.

This is a separate surface from api.py (the fixed, narrow contract for
the Online teammate's threat-package-driven flow) and from cli.py (the
human terminal tool). It reuses the same offline/interactive.py engine as
both, so nothing about the safety model changes here: the Guard still
validates every self-found finding, auditor.run_audit() still proves each
one with a real generated test before it is reported as confirmed, and
patcher.run_patch_loop() still gates every commit on real tests passing.
Every finding (confirmed or not) is reported with its actual status and
reason -- nothing is silently dropped, matching cli.py's behavior.

Run with:
    python api_server.py
"""
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from flask import Flask, jsonify, request

from communication import paths
from offline import gemma_client, interactive, reports

app = Flask(__name__)

# Confirmed findings from the most recent /scan calls, keyed by repo path
# and threat_id,
# so a later POST /fixes/<threat_id> has the AuditResult it needs (the
# saved JSON report alone isn't enough to re-run a patch attempt against
# -- it needs the live object, not just its serialized summary). This is
# server-process-lifetime only, not persisted; that's acceptable for a
# demo/dashboard use case and is documented in README_OFFLINE.md.
_findings_cache: dict = {}
_lock = threading.Lock()
_PATCHABLE_STATUSES = {"confirmed", "not_applicable", "uncertain", "ai_error"}


def _github_repository_path(repository_url: str):
    """Clone one submitted public GitHub repository into the managed
    workspace. Existing checkouts are reused without reset/pull so local
    patch branches and developer changes are never overwritten.
    """
    try:
        parsed = urlsplit(repository_url.strip())
        port = parsed.port
    except ValueError:
        return None, {"error": "The GitHub URL is malformed."}, 400, False
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if (parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username
            or parsed.password or port is not None or parsed.query or parsed.fragment
            or len(parts) != 2):
        return None, {"error": "Use a public GitHub URL like https://github.com/owner/repository."}, 400, False

    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo)
            or owner in {".", ".."} or repo in {".", ".."}):
        return None, {"error": "The GitHub URL contains an invalid owner or repository name."}, 400, False

    canonical_url = f"https://github.com/{owner}/{repo}.git"
    identity = f"{owner.lower()}/{repo.lower()}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:10]
    safe_name = re.sub(r"[^A-Za-z0-9_-]", "-", repo).strip("-") or "repository"
    destination = paths.REPOSITORIES_DIR / f"{safe_name}-{digest}"
    paths.REPOSITORIES_DIR.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if (destination / ".git").exists():
            return destination, None, None, False
        return None, {"error": "A non-repository directory already exists at the managed clone path."}, 409, False

    try:
        with tempfile.TemporaryDirectory(prefix=f".{safe_name}-", dir=paths.REPOSITORIES_DIR) as staging:
            checkout = os.path.join(staging, "checkout")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--no-tags", "--", canonical_url, checkout],
                capture_output=True, text=True, timeout=180, shell=False,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
                     "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": ""},
            )
            if result.returncode != 0:
                message = result.stderr.strip() or "git clone did not complete successfully"
                return None, {"error": f"Could not clone the public repository: {message[-1200:]}"}, 502, False
            os.replace(checkout, destination)
    except subprocess.TimeoutExpired:
        return None, {"error": "Repository clone timed out after 180 seconds."}, 504, False
    except FileNotFoundError:
        return None, {"error": "Git is required on the backend host to clone GitHub repositories."}, 503, False
    return destination, None, None, True


@app.route("/health", methods=["GET"])
def health():
    ollama_reachable, model_pulled = gemma_client.check_runtime_status()
    return jsonify({
        "guard": "ok",
        "gemma_model_tag": gemma_client.get_gemma_model(),
        "ollama_reachable": ollama_reachable,
        "model_pulled": model_pulled,
    })


@app.route("/scan", methods=["POST"])
def scan():
    """Body: {"repo_path": "..."} or
    {"repository_url": "https://github.com/owner/repository"}.

    If the repo isn't a git repository yet, this returns 409 with
    status "needs_git_init" instead of silently initializing one --
    the caller must re-POST with confirm_git_init: true, mirroring
    cli.py's [y/N] prompt as an explicit, auditable flag instead of an
    interactive prompt that an HTTP client can't answer.
    """
    body = request.get_json(force=True, silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    repo_path = body.get("repo_path")
    repository_url = body.get("repository_url")
    if repository_url and not isinstance(repository_url, str):
        return jsonify({"error": "repository_url must be a string"}), 400
    if not repo_path and not repository_url:
        return jsonify({"error": "repository_url or repo_path is required"}), 400

    with _lock:
        cloned = False
        if repository_url:
            repo_path, error, code, cloned = _github_repository_path(repository_url)
            if error:
                return jsonify(error), code
        selection = interactive.select_repo(repo_path)

        if selection.status == "unsupported_language":
            return jsonify({
                "status": "unsupported_language",
                "language": selection.detail,
                "message": f"{selection.path} looks like a {selection.detail} project. This tool "
                           "currently supports Python and JavaScript/TypeScript repos only.",
            }), 422

        if selection.status == "needs_git_init":
            if not body.get("confirm_git_init"):
                return jsonify({
                    "status": "needs_git_init",
                    "message": f"{selection.path} is not a git repository yet. "
                               "Re-POST with confirm_git_init: true to proceed.",
                }), 409
            interactive.init_git_repo()
        elif selection.status == "dirty_worktree":
            return jsonify({
                "status": "dirty_worktree",
                "message": f"{selection.path} has uncommitted changes. Commit or stash them first.",
            }), 409

        repo_key = str(selection.path)
        for cache_key in [key for key in _findings_cache if key[0] == repo_key]:
            del _findings_cache[cache_key]

        try:
            findings = interactive.find_vulnerabilities()
        except gemma_client.GemmaResponseError as exc:
            return jsonify({"status": "scan_failed", "error": str(exc)}), 502
        except gemma_client.GemmaUnavailableError as exc:
            return jsonify({"status": "scan_failed", "error": str(exc)}), 503

        results = []
        for finding in findings:
            report = reports.build_finding_report(
                package=finding.package, status=finding.status,
                reason=finding.reason, audit=finding.audit,
            )
            report["patch_available"] = finding.audit is not None and finding.status in _PATCHABLE_STATUSES
            if report["patch_available"]:
                _findings_cache[(repo_key, finding.audit.threat_id)] = {
                    "audit": finding.audit,
                    "repository": str(selection.path),
                    "status": finding.status,
                }
            results.append(report)

    return jsonify({"repository": str(selection.path), "repository_url": repository_url, "cloned": cloned, "findings": results})


@app.route("/fixes/<threat_id>", methods=["POST"])
def fix(threat_id):
    """Recheck an unconfirmed finding from the latest /scan, then apply the
    patch/test/validate/commit loop only if it is confirmed. Returns the
    same report shape as /scan's findings, now with code.after and diff
    populated if (and only if) the fix was actually accepted.

    Body (optional): {"pr_base": "main"} -- if given AND the fix is
    accepted, pushes the fix branch to 'origin' and opens a GitHub PR
    against that branch via the gh CLI (see
    offline.interactive.push_and_create_pr). There is no separate
    confirmation step here the way cli.py has one -- calling this
    endpoint with pr_base set IS the explicit request to push and open
    a PR; omit pr_base to keep the fix local only, which is the default.
    """
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    pr_base = body.get("pr_base")
    requested_repository = body.get("repository")

    with _lock:
        if requested_repository:
            cached = _findings_cache.get((str(requested_repository), threat_id))
        else:
            matches = [value for (repo, finding_id), value in _findings_cache.items() if finding_id == threat_id]
            cached = matches[0] if len(matches) == 1 else None
            if len(matches) > 1:
                return jsonify({
                    "error": "This finding id exists in multiple repositories; include the repository field in the request.",
                    "status": "ambiguous_finding",
                }), 409
        if cached is None:
            return jsonify({
                "error": f"no recheckable finding cached for '{threat_id}' -- run POST /scan first "
                         "(the cache is per server run, not persisted across restarts)",
            }), 404
        audit_result = cached["audit"]
        selection = interactive.select_repo(cached["repository"])
        if selection.status != "ready":
            return jsonify({
                "error": f"The cached repository is not ready for patching ({selection.status}). Commit or stash its local changes and rescan.",
                "status": selection.status,
            }), 409
        if cached["status"] != "confirmed":
            try:
                audit_result = interactive.recheck_finding(audit_result)
            except gemma_client.GemmaResponseError as exc:
                return jsonify({"error": str(exc), "status": "recheck_failed"}), 502
            except gemma_client.GemmaUnavailableError as exc:
                return jsonify({"error": str(exc), "status": "recheck_failed"}), 503
            refreshed_status = "confirmed" if audit_result.status == "vulnerable" else audit_result.status
            cached.update({"audit": audit_result, "status": refreshed_status})
            if refreshed_status != "confirmed":
                report = reports.build_finding_report(
                    package=audit_result.package or {}, status=refreshed_status,
                    reason=audit_result.reasoning, audit=audit_result,
                )
                report["patch_available"] = refreshed_status in _PATCHABLE_STATUSES
                reports.write_run_report([report], full_rescan=False)
                return jsonify(report)
        patch_result = interactive.apply_fix(audit_result)
        report = reports.build_finding_report(
            package=audit_result.package or {}, status="confirmed",
            reason=audit_result.reasoning, audit=audit_result, patch_result=patch_result,
        )
        if patch_result.status == "fixed" and pr_base:
            report["pull_request"] = interactive.push_and_create_pr(patch_result, pr_base)
        report["patch_available"] = patch_result.status != "fixed"
    return jsonify(report)


@app.route("/audits", methods=["GET"])
def list_audits():
    """One entry per codebase ever scanned (one JSON file per codebase,
    see offline/reports.py) -- not one per finding. Each entry summarizes
    that codebase's most recent run; fetch the full findings list for one
    codebase via POST /scan (re-run) or GET /audits/<threat_id> for a
    specific finding within it."""
    paths.ensure_directories()
    entries = []
    for json_path in sorted(paths.REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        run = json.loads(json_path.read_text(encoding="utf-8"))
        findings = run.get("findings", [])
        entries.append({
            "repository": run.get("repository"),
            "last_run": run.get("last_run"),
            "finding_count": len(findings),
            "confirmed_count": sum(1 for f in findings if f.get("status") == "confirmed"),
            "fixed_count": sum(1 for f in findings if f.get("patch_status") == "fixed"),
        })
    return jsonify(entries)


@app.route("/findings", methods=["GET"])
def list_findings():
    """Return every finding from the latest persisted run for each repo,
    newest first, in the shape consumed by the dashboard.
    """
    paths.ensure_directories()
    findings = []
    with _lock:
        patchable = set(_findings_cache)
    for json_path in sorted(paths.REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            run = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for finding in run.get("findings", []):
            if not finding.get("repository"):
                finding["repository"] = run.get("repository")
            finding["patch_available"] = (
                finding.get("status") in _PATCHABLE_STATUSES
                and (str(finding.get("repository")), finding.get("threat_id")) in patchable
            )
            findings.append(finding)
    findings.sort(key=lambda finding: finding.get("timestamp") or "", reverse=True)
    return jsonify(findings)


@app.route("/patch-history", methods=["GET"])
def patch_history():
    """Return historical patch attempts, including attempts in the latest
    persisted reports written before the append-only history file existed.
    """
    paths.ensure_directories()
    history = reports.read_patch_history()
    known = {
        (str(entry.get("repository") or ""), entry.get("threat_id"), entry.get("timestamp"))
        for entry in history
    }
    for json_path in paths.REPORTS_DIR.glob("*.json"):
        try:
            run = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for finding in run.get("findings", []):
            if not finding.get("patch_status"):
                continue
            if not finding.get("repository"):
                finding["repository"] = run.get("repository")
            key = (str(finding.get("repository") or ""), finding.get("threat_id"), finding.get("timestamp"))
            if key not in known:
                finding["patch_available"] = False
                history.append(finding)
                known.add(key)
    history.sort(key=lambda finding: finding.get("timestamp") or "", reverse=True)
    return jsonify(history)


@app.route("/audits/<threat_id>", methods=["GET"])
def get_audit(threat_id):
    """Find one finding by threat_id, searching across every codebase's
    report file (there is no longer a file keyed by threat_id -- each
    file is keyed by codebase and holds a list of findings)."""
    paths.ensure_directories()
    for json_path in paths.REPORTS_DIR.glob("*.json"):
        run = json.loads(json_path.read_text(encoding="utf-8"))
        for finding in run.get("findings", []):
            if finding.get("threat_id") == threat_id:
                return jsonify(finding)
    return jsonify({"error": "not found"}), 404


@app.route("/events/guard", methods=["GET"])
def guard_events():
    from guard.events import read_events
    return jsonify(read_events())


@app.route("/events/offline", methods=["GET"])
def offline_events():
    from offline.events import read_events
    return jsonify(read_events())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
