"""Interactive terminal tool: point SentinelAuditor at any repository,
see what Gemma 4 genuinely confirms as vulnerable (proven with a real
generated test, not just asserted), and approve fixes one at a time.

Usage:
    python cli.py scan <path-to-repo>

This is a human-facing convenience on top of offline/interactive.py. It
never modifies a repository without the user's explicit, per-action
confirmation: not when the path isn't a git repo yet, and not when
deciding whether to apply any given fix.
"""
import argparse
import sys

from communication import paths
from offline import gemma_client, interactive


def _confirm(prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


_STATUS_LABELS = {
    "confirmed": "CONFIRMED -- a real generated test reproduces this",
    "not_applicable": "NOT REPRODUCIBLE -- the generated test did not catch this",
    "uncertain": "INCONCLUSIVE -- the generated test had a setup error, not a real signal either way",
    "ai_error": "ANALYSIS FAILED -- Gemma could not complete the analysis",
    "guard_rejected": "FLAGGED BY GUARD -- not processed further (see note below; may be a false positive)",
}


def _print_scan_finding(scan_finding, index: int, total: int) -> None:
    raw = scan_finding.raw
    package = scan_finding.package
    print()
    print("=" * 70)
    print(f"[{index}/{total}] {raw.get('title', package['title'])}")
    print("=" * 70)
    print(f"Status: {_STATUS_LABELS.get(scan_finding.status, scan_finding.status.upper())}")
    print(f"Attack type: {raw.get('attack_type', package.get('attack_type', 'unknown'))}  |  "
          f"Severity (Gemma's estimate): {raw.get('severity', package.get('severity', 'unknown'))}")
    print(f"Affected files: {', '.join(raw.get('affected_files', [])) or 'unknown'}")
    if raw.get("affected_lines"):
        print(f"Affected lines (approximate): {raw['affected_lines']}")
    print()
    print("Gemma's hypothesis:")
    print(f"  {raw.get('vulnerability_hypothesis', package.get('description', ''))}")
    if raw.get("recommended_fix"):
        print()
        print("Suggested fix:")
        print(f"  {raw['recommended_fix']}")

    if scan_finding.status == "confirmed":
        print()
        print("Security test that proved it:")
        print(f"  {scan_finding.audit.test_path}")
    elif scan_finding.status == "guard_rejected":
        print()
        print("Guard's reason (this blocks a self-found lead the same way it would an external")
        print("one -- if this reads like a false positive from vulnerability vocabulary rather")
        print("than an actual injection attempt, that is a known tradeoff, not a bug):")
        print(f"  {scan_finding.reason}")
    elif scan_finding.reason:
        print()
        print("Why it wasn't confirmed:")
        print(f"  {scan_finding.reason[:1500]}")


def _print_patch_result(result) -> None:
    print()
    if result.status == "fixed":
        print(f"PATCH ACCEPTED on branch {result.branch} (attempt {result.attempts})")
        print("Files changed:", ", ".join(result.files_changed) or "none")
        print()
        print("Diff:")
        print(result.diff or "(empty)")
    else:
        print(f"PATCH {result.status.upper()} after {result.attempts} attempt(s): {result.reasoning}")


def run_scan(repo_path: str, pr_base: str | None = None) -> int:
    try:
        gemma_client.ensure_available()
    except gemma_client.GemmaUnavailableError as exc:
        print(str(exc))
        return 1

    selection = interactive.select_repo(repo_path)

    if selection.status == "unsupported_language":
        print(f"{selection.path} looks like a {selection.detail} project.")
        print("This tool currently writes and runs tests in Python or JavaScript/TypeScript "
              "only (see README_OFFLINE.md's Limitations section) -- scanning anything else "
              "would just produce confusing per-finding failures instead of real results.")
        return 1

    if selection.status == "needs_git_init":
        print(f"{selection.path} is not a git repository yet.")
        if not _confirm("Initialize git here so SentinelAuditor can track changes safely?"):
            print("Aborted -- nothing was touched.")
            return 1
        interactive.init_git_repo()
    elif selection.status == "dirty_worktree":
        print(f"{selection.path} has uncommitted changes. Commit or stash them first, then re-run.")
        return 1

    print(f"Scanning {selection.path} ...")
    try:
        findings = interactive.find_vulnerabilities()
    except gemma_client.GemmaResponseError as exc:
        print(f"Scan failed: Gemma did not return usable JSON ({exc}).")
        print("This can happen on larger repositories if the model runs out of generation "
              "budget for a single response. Try again, or scan a smaller subdirectory.")
        return 1
    except gemma_client.GemmaUnavailableError as exc:
        print(f"Scan failed: {exc}")
        return 1

    if not findings:
        print("Gemma's scan did not surface any candidate issues at all in the sampled files.")
        print("This can mean the repo is genuinely clean in what was sampled, or that the")
        print("vulnerable file wasn't among the files sampled (see offline/scanner.py's")
        print("MAX_FILES) -- try scanning a narrower subdirectory containing the suspect code.")
        return 0

    print(f"\nGemma proposed {len(findings)} candidate issue(s):")
    for index, finding in enumerate(findings, start=1):
        _print_scan_finding(finding, index, len(findings))

    confirmed = [f for f in findings if f.status == "confirmed"]
    if not confirmed:
        print("\nNone of the above were confirmed with a reproducing test -- no changes made.")
        print("See the per-finding reasons above for why each one stopped where it did.")
        return 0

    print(f"\n{len(confirmed)} of those are CONFIRMED (reproduced with a real test).")
    for finding in confirmed:
        audit_result = finding.audit
        print()
        print(f"--- {audit_result.threat_id} ---")
        if _confirm("Fix this now?"):
            patch_result = interactive.apply_fix(audit_result)
            _print_patch_result(patch_result)
            if patch_result.status == "fixed" and pr_base:
                if _confirm(f"Push branch '{patch_result.branch}' and open a pull request against '{pr_base}'?"):
                    pr_result = interactive.push_and_create_pr(patch_result, pr_base)
                    if pr_result["status"] == "pr_created":
                        print(f"Pull request opened: {pr_result['url']}")
                    else:
                        print(f"{pr_result['status'].upper()}: {pr_result['message']}")
                else:
                    print("Skipped -- commit stays local on its branch, nothing pushed.")
        else:
            print("Skipped -- repository left unmodified for this finding.")

    print(f"\nReports saved under {paths.REPORTS_DIR}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cli.py", description="SentinelAuditor interactive scan + fix")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository for vulnerabilities and optionally fix them")
    scan_parser.add_argument("repo_path", help="Path to the git repository to audit")
    scan_parser.add_argument(
        "--pr-base", default=None, metavar="BRANCH",
        help="After a fix is accepted, offer to push its branch and open a GitHub PR "
             "against BRANCH (e.g. main) via the 'origin' remote and the gh CLI. "
             "Omit to never push or open a PR -- the default is fixes stay local.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args.repo_path, pr_base=args.pr_base)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
