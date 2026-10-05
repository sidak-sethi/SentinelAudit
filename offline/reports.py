"""Audit report generation (section 23 format) and get_latest_audit() for
the integration API.

Persistence model: ONE JSON (+ companion .txt) file per codebase, named
deterministically from the repository path, overwritten every time a
check is run against that repository -- never a new timestamped file per
finding or per run. A run's findings fully replace the previous ones for
that codebase (a fresh scan supersedes stale results); a single
threat-package check (the Online-integration flow, one finding at a
time) upserts just its own entry into the same file instead, so repeated
single-threat checks don't erase each other."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from communication import paths


def build_report(audit, patch_result=None) -> str:
    threat = audit.package or {}
    lines = [
        f"THREAT: {threat.get('cve') or threat.get('threat_id', 'unknown')}",
        f"STATUS: {'FIXED' if patch_result and patch_result.status == 'fixed' else audit.status.upper()}",
        "",
        f"Source: {(threat.get('source') or {}).get('url', 'n/a')}",
        f"Affected component: {threat.get('affected_component', 'n/a')}",
        f"Repository: {paths.TARGET_REPO}",
        f"Branch: {patch_result.branch if patch_result else 'n/a'}",
        f"Vulnerability status: {audit.status}",
        "",
        "Vulnerability:",
        audit.vulnerability_hypothesis or audit.reasoning or "n/a",
        "",
        "Affected files:",
        ", ".join(audit.affected_files) or "none",
        "",
        "Security test:",
        audit.test_path or "n/a",
        "",
        "Before result:",
        "FAIL -- vulnerability reproduced" if audit.status == "vulnerable" else "N/A",
        "",
    ]

    if patch_result:
        lines += [
            "Patch:",
            ", ".join(patch_result.files_changed) or "none",
            "",
            "Git diff:",
            patch_result.diff or "(none)",
            "",
            "Normal test result:",
            "PASS" if patch_result.status == "fixed" else "FAILED or not reached",
            "",
            "Security test result:",
            "PASS" if patch_result.status == "fixed" else "FAILED or not reached",
            "",
            "Final Gemma 4 audit:",
            (patch_result.final_audit.get("status") or "n/a").upper(),
            "",
            "Final status:",
            "PATCH ACCEPTED" if patch_result.status == "fixed" else f"PATCH {patch_result.status.upper()}: {patch_result.reasoning}",
        ]
    else:
        lines += ["Final status:", audit.status.upper()]

    lines.append("")
    lines.append(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    return "\n".join(lines)


def build_finding_report(package: dict, status: str, reason: str = "", audit=None, patch_result=None) -> dict:
    """The full structured JSON for one finding -- the single source of
    truth both cli.py's on-disk reports and the HTTP API (api_server.py)
    use, so a human running the CLI and a dashboard calling the API see
    exactly the same shape.

    `status` is one of "confirmed" | "not_applicable" | "uncertain" |
    "ai_error" | "guard_rejected". `code[path]["after"]` and `diff` are
    only ever populated when patch_result.status == "fixed" -- an
    attempted-but-not-yet-validated patch is never reported as the fix.
    """
    affected_files = (audit.affected_files if audit else None) or list((audit.original_code if audit else {}) or {})
    fixed = bool(patch_result and patch_result.status == "fixed")

    code = {}
    if audit and audit.original_code:
        for path, before in audit.original_code.items():
            code[path] = {
                "before": before,
                "after": patch_result.patched_code.get(path) if fixed else None,
            }

    return {
        "threat_id": package.get("threat_id"),
        "title": package.get("title"),
        "cve": package.get("cve") or None,
        "attack_type": package.get("attack_type"),
        "severity": package.get("severity"),
        "source": package.get("source"),
        "status": status,
        "patch_status": patch_result.status if patch_result else None,
        "repository": str(paths.TARGET_REPO),
        "branch": patch_result.branch if patch_result else None,
        "affected_files": affected_files,
        "affected_lines": (audit.affected_lines if audit else []) or [],
        "confidence": (audit.confidence if audit else None),
        "vulnerability_hypothesis": (audit.vulnerability_hypothesis if audit else "") or package.get("description", ""),
        "recommended_fix": package.get("remediation"),
        "security_test_path": audit.test_path if audit else None,
        "code": code,
        "diff": patch_result.diff if fixed else None,
        "patch_attempts": patch_result.attempts if patch_result else 0,
        "final_audit": patch_result.final_audit if patch_result else None,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _repo_slug(repo_path) -> str:
    resolved = str(Path(repo_path).resolve())
    name = Path(resolved).name or "repo"
    safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name).strip("-") or "repo"
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:10]
    return f"{safe_name}-{digest}"


def repo_report_paths(repo_path=None):
    """The one JSON (+ companion .txt) file for this codebase. Always the
    same path for the same resolved repo path -- that's what makes "one
    file per codebase, overwritten on every run" possible."""
    paths.ensure_directories()
    repo_path = repo_path or paths.TARGET_REPO
    base = paths.REPORTS_DIR / _repo_slug(repo_path)
    return base.with_suffix(".json"), base.with_suffix(".txt")


def get_run_report(repo_path=None) -> dict | None:
    json_path, _ = repo_report_paths(repo_path)
    if not json_path.exists():
        return None
    return json.loads(json_path.read_text(encoding="utf-8"))


def _render_run_text(run: dict) -> str:
    lines = [
        "SentinelAuditor scan report",
        f"Repository: {run.get('repository', 'n/a')}",
        f"Last run: {run.get('last_run', 'n/a')}",
        f"Findings: {len(run.get('findings', []))}",
        "",
    ]
    for finding in run.get("findings", []):
        lines += [
            "-" * 70,
            f"[{(finding.get('status') or '?').upper()}] {finding.get('title', '?')} ({finding.get('threat_id', '?')})",
            f"Patch status: {finding.get('patch_status') or 'n/a'}",
            f"Affected files: {', '.join(finding.get('affected_files', [])) or 'none'}",
            "",
            finding.get("vulnerability_hypothesis", "") or "",
            "",
        ]
    return "\n".join(lines)


def write_run_report(findings: list, repo_path=None, full_rescan: bool = True) -> dict:
    """Write the single aggregate report for this codebase.

    `full_rescan=True` (a complete interactive scan): `findings` fully
    replaces whatever was there before -- a fresh scan supersedes stale
    results. `full_rescan=False` (one threat-package check, or applying a
    fix for one specific finding): each entry in `findings` is merged in
    by threat_id, leaving every other existing entry untouched.

    Either way this OVERWRITES the same one file for this codebase --
    never creates a new timestamped file.
    """
    json_path, txt_path = repo_report_paths(repo_path)
    repo_path = repo_path or paths.TARGET_REPO

    if full_rescan:
        merged = list(findings)
    else:
        existing = get_run_report(repo_path)
        by_id = {f["threat_id"]: f for f in (existing or {}).get("findings", [])}
        for finding in findings:
            by_id[finding["threat_id"]] = finding
        merged = list(by_id.values())

    run = {
        "repository": str(repo_path),
        "last_run": datetime.now(timezone.utc).isoformat(),
        "findings": merged,
    }
    json_path.write_text(json.dumps(run, indent=2, default=str), encoding="utf-8")
    txt_path.write_text(_render_run_text(run), encoding="utf-8")
    return run


def get_latest_audit(repo_path=None) -> dict | None:
    """The single most recently processed finding for this codebase (by
    its own timestamp) -- kept as a single-finding dict, matching the
    shape api.py's Online-integration contract has always returned, even
    though storage underneath is now the one-file-per-codebase model."""
    run = get_run_report(repo_path)
    if not run or not run.get("findings"):
        return None
    return max(run["findings"], key=lambda f: f.get("timestamp", ""))
