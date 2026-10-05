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
import json
import threading

from flask import Flask, jsonify, request

from communication import paths
from offline import gemma_client, interactive, reports

app = Flask(__name__)

# Confirmed findings from the most recent /scan calls, keyed by threat_id,
# so a later POST /fixes/<threat_id> has the AuditResult it needs (the
# saved JSON report alone isn't enough to re-run a patch attempt against
# -- it needs the live object, not just its serialized summary). This is
# server-process-lifetime only, not persisted; that's acceptable for a
# demo/dashboard use case and is documented in README_OFFLINE.md.
_findings_cache: dict = {}
_lock = threading.Lock()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "guard": "ok",
        "gemma_model_tag": gemma_client.get_gemma_model(),
        "ollama_reachable": gemma_client.check_ollama_available(),
        "model_pulled": gemma_client.check_model_available(),
    })


@app.route("/scan", methods=["POST"])
def scan():
    """Body: {"repo_path": "...", "confirm_git_init": false}.

    If the repo isn't a git repository yet, this returns 409 with
    status "needs_git_init" instead of silently initializing one --
    the caller must re-POST with confirm_git_init: true, mirroring
    cli.py's [y/N] prompt as an explicit, auditable flag instead of an
    interactive prompt that an HTTP client can't answer.
    """
    body = request.get_json(force=True, silent=True) or {}
    repo_path = body.get("repo_path")
    if not repo_path:
        return jsonify({"error": "repo_path is required"}), 400

    with _lock:
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
            if finding.status == "confirmed":
                _findings_cache[finding.audit.threat_id] = finding.audit
            results.append(report)

    return jsonify({"repository": str(selection.path), "findings": results})


@app.route("/fixes/<threat_id>", methods=["POST"])
def fix(threat_id):
    """Apply the patch/test/validate/commit loop for one already-confirmed
    finding from a prior /scan call in this server's lifetime. Returns the
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
    pr_base = body.get("pr_base")

    with _lock:
        audit_result = _findings_cache.get(threat_id)
        if audit_result is None:
            return jsonify({
                "error": f"no confirmed finding cached for '{threat_id}' -- run POST /scan first "
                         "(the cache is per server run, not persisted across restarts)",
            }), 404
        patch_result = interactive.apply_fix(audit_result)
        report = reports.build_finding_report(
            package=audit_result.package or {}, status="confirmed",
            reason=audit_result.reasoning, audit=audit_result, patch_result=patch_result,
        )
        if patch_result.status == "fixed" and pr_base:
            report["pull_request"] = interactive.push_and_create_pr(patch_result, pr_base)
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
