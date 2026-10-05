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
import asyncio
import json
import os
import re
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
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
_online_lock = threading.Lock()
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


def _canonical_github_remote(repository_url: str | None) -> str | None:
    if not repository_url:
        return None
    parsed = urlsplit(repository_url.strip())
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if parsed.scheme != "https" or parsed.hostname != "github.com" or len(parts) != 2:
        return None
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    return f"https://github.com/{parts[0]}/{repo}.git"


@app.route("/health", methods=["GET"])
def health():
    ollama_reachable, model_pulled = gemma_client.check_runtime_status()
    return jsonify({
        "guard": "ok",
        "gemma_model_tag": gemma_client.get_gemma_model(),
        "ollama_reachable": ollama_reachable,
        "model_pulled": model_pulled,
    })


@app.route("/online/status", methods=["GET"])
def online_status():
    """Expose Online pipeline readiness and Guard-approved queue size."""
    from app.config import get_settings

    settings = get_settings()
    queued = sorted(paths.OFFLINE_INBOX.glob("*.json"))
    api_key_ready = bool(settings.llm_api_key and (settings.llm_triage_api_key or settings.llm_api_key))
    return jsonify({
        "configured": api_key_ready,
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "queued_count": len(queued),
    })


@app.route("/online/queue", methods=["GET"])
def online_queue():
    """Return Guard-approved Online packages awaiting local audit."""
    paths.ensure_directories()
    packages = []
    for package_path in sorted(paths.OFFLINE_INBOX.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            package = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        packages.append({
            "threat_id": package.get("threat_id"),
            "title": package.get("title"),
            "cve": package.get("cve") or None,
            "severity": package.get("severity"),
            "source": package.get("source") or {},
            "affected_component": package.get("affected_component"),
            "affected_versions": package.get("affected_versions") or [],
            "fixed_versions": package.get("fixed_versions") or [],
            "description": package.get("description"),
            "remediation": package.get("remediation"),
            "queued_at": datetime.fromtimestamp(package_path.stat().st_mtime, timezone.utc).isoformat(),
            "audits": _audit_records(package.get("threat_id")),
        })
    return jsonify({"queued_count": len(packages), "packages": packages})


def _audit_records(threat_id: str | None) -> list[dict]:
    if not threat_id:
        return []
    records = []
    for report_path in paths.REPORTS_DIR.glob("*.json"):
        try:
            run = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for finding in run.get("findings", []):
            if finding.get("threat_id") == threat_id:
                records.append({
                    "repository": run.get("repository") or finding.get("repository"),
                    "status": finding.get("status"),
                    "patch_status": finding.get("patch_status"),
                    "timestamp": finding.get("timestamp"),
                })
    return records


@app.route("/online/cycle", methods=["POST"])
def online_cycle():
    """Run one user-triggered Online collection/research pass.

    Exported files go through the normal Guard watcher and stay queued for
    the separate local audit/patch flow. This route never starts that flow.
    """
    from app.config import get_settings
    from app.main import run_cycle
    from guard.guard import watch_once

    settings = get_settings()
    if not settings.llm_api_key:
        return jsonify({"error": "Configure LLM_API_KEY before running the Online pipeline."}), 503
    if not _online_lock.acquire(blocking=False):
        return jsonify({"error": "An Online intelligence cycle is already running.", "status": "busy"}), 409

    try:
        cycle = asyncio.run(run_cycle())
        guard_results = watch_once()
        return jsonify({
            "cycle": cycle,
            "guard": [{"status": result.status, "threat_id": result.threat_id, "reason": result.reason} for result in guard_results],
            "queued_count": len(list(paths.OFFLINE_INBOX.glob("*.json"))),
            "message": "Guard-approved threat packages are queued for local audit. No repository audit or patch was started.",
        })
    except Exception as exc:
        return jsonify({"error": f"Online cycle failed: {exc}"}), 502
    finally:
        _online_lock.release()


@app.route("/online/audit/<threat_id>", methods=["POST"])
def audit_online_package(threat_id):
    """Explicitly audit one queued advisory against a selected repository.

    The normal Offline workflow may apply a local, tested fix after the audit
    confirms the finding. This route never pushes changes to a remote.
    """
    from offline import agent
    from guard.validator import validate_package

    body = request.get_json(silent=True) or {}
    repository_path = body.get("repository") if isinstance(body, dict) else None
    if not isinstance(repository_path, str) or not repository_path.strip():
        return jsonify({"error": "Select a repository to audit this package against."}), 400
    if not re.fullmatch(r"[A-Za-z0-9_:.\-]{1,128}", threat_id):
        return jsonify({"error": "Invalid threat id."}), 400

    package_path = paths.OFFLINE_INBOX / f"{threat_id}.json"
    if not package_path.is_file():
        return jsonify({"error": "No Guard-approved queued package exists for this threat."}), 404
    validation = validate_package(package_path.read_bytes())
    if not validation.ok or (validation.parsed or {}).get("threat_id") != threat_id:
        return jsonify({"error": "The queued package failed its integrity or schema recheck."}), 409

    with _lock:
        selection = interactive.select_repo(repository_path)
        if selection.status != "ready":
            return jsonify({
                "error": f"The selected repository is not ready for audit ({selection.status}).",
                "status": selection.status,
            }), 409
        existing = next((record for record in _audit_records(threat_id) if record["repository"] == str(selection.path)), None)
        if existing and (existing.get("patch_status") or existing.get("status") == "confirmed"):
            return jsonify({"error": "This threat package already has a saved audit for the selected repository.", "audit": existing}), 409
        try:
            result = agent.start_offline_audit(package_path)
        except Exception as exc:
            return jsonify({"error": f"Offline audit failed: {exc}"}), 502
    return jsonify({"audit": result, "repository": str(selection.path)})


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
            # Keep the dashboard's initial scan to one Gemma scan call plus
            # deterministic Guard checks. The proof audit is deferred until
            # the user requests Recheck & patch for a specific finding.
            findings = interactive.find_vulnerabilities(verify_findings=False)
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
                    "remote_url": _canonical_github_remote(repository_url),
                }
            results.append(report)

    return jsonify({"repository": str(selection.path), "repository_url": repository_url, "cloned": cloned, "findings": results})


@app.route("/fixes/<threat_id>", methods=["POST"])
def fix(threat_id):
    """Recheck an unconfirmed finding from the latest /scan, then apply the
    patch/test/validate/commit loop only if it is confirmed. Returns the
    same report shape as /scan's findings, now with code.after and diff
    populated if (and only if) the fix was actually accepted.

    A matching prepared local fix is tested and committed, then its fix
    branch is pushed to the exact GitHub URL used in the scan. No default
    branch is modified and no pull request is opened.
    """
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
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
        if not cached.get("remote_url"):
            return jsonify({
                "error": "Patch and push requires scanning a GitHub repository URL in the dashboard first.",
                "status": "repository_url_required",
            }), 409
        audit_result = cached["audit"]
        selection = interactive.select_repo(cached["repository"])
        if selection.status != "ready":
            return jsonify({
                "error": f"The cached repository is not ready for patching ({selection.status}). Commit or stash its local changes and rescan.",
                "status": selection.status,
            }), 409
        previous_patch = cached.get("patch_result")
        if previous_patch is not None and previous_patch.status == "fixed" and cached.get("push_result", {}).get("status") != "pushed":
            push_result = interactive.push_fix_branch(
                previous_patch.branch, cached["remote_url"], cached["repository"],
            )
            cached["push_result"] = push_result
            report = reports.build_finding_report(
                package=audit_result.package or {}, status="confirmed",
                reason=previous_patch.reasoning or audit_result.reasoning,
                audit=audit_result, patch_result=previous_patch,
            )
            report["push_result"] = push_result
            report["patch_available"] = push_result["status"] != "pushed"
            reports.write_run_report([report], full_rescan=False)
            reports.append_patch_history(report)
            return jsonify(report)
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
        try:
            patch_result, push_result = interactive.apply_prepared_fix(audit_result, cached["remote_url"])
        except Exception as exc:
            return jsonify({"error": str(exc), "status": "patch_preflight_failed"}), 409
        report = reports.build_finding_report(
            package=audit_result.package or {}, status="confirmed",
            reason=patch_result.reasoning or audit_result.reasoning,
            audit=audit_result, patch_result=patch_result,
        )
        report["push_result"] = push_result
        report["patch_available"] = patch_result.status != "fixed"
        cached["patch_result"] = patch_result
        cached["push_result"] = push_result
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
