"""Subprocess execution with an explicit command allowlist, timeouts,
captured output, and a controlled working directory.

Nothing in this module ever uses shell=True or builds a command from a
string -- every call is an argv list checked against ALLOWED_PROGRAMS
before it runs. Anything else returns COMMAND_REJECTED.
"""
import shutil
import subprocess

ALLOWED_PROGRAMS = {
    "pytest": None,
    "python": {"requires_args_prefix": ["-m", "pytest"]},
    "git": {"subcommands": {"status", "diff", "checkout", "switch", "add", "commit", "symbolic-ref"}},
    # "node <file>" runs exactly one script, no flags, no eval/require
    # chains on the command line -- the script's own content is still
    # path-and-content controlled the same way a pytest file is.
    "node": {"single_script_arg": True},
    # "npm test"/"npm run test" only -- never "npm install"/"npm run
    # <arbitrary>", which could run anything defined in package.json.
    "npm": {"allowed_invocations": {("test",), ("run", "test")}},
}

DEFAULT_TIMEOUT = 60


class CommandRejectedError(RuntimeError):
    """Raised for any command that is not on the explicit allowlist.
    Callers should treat this exactly like the COMMAND_REJECTED outcome
    described in the Offline tool-security model."""


def _validate_argv(argv: list) -> None:
    if not argv or not isinstance(argv, list):
        raise CommandRejectedError("COMMAND_REJECTED: empty or non-list command")

    program = argv[0]
    rule = ALLOWED_PROGRAMS.get(program)
    if program not in ALLOWED_PROGRAMS:
        raise CommandRejectedError(f"COMMAND_REJECTED: program '{program}' is not allowlisted")

    if program == "python":
        if argv[1:3] != rule["requires_args_prefix"]:
            raise CommandRejectedError("COMMAND_REJECTED: only 'python -m pytest ...' is allowed")

    if program == "git":
        if len(argv) < 2 or argv[1] not in rule["subcommands"]:
            raise CommandRejectedError(f"COMMAND_REJECTED: git subcommand '{argv[1:2]}' is not allowlisted")

    if program == "node":
        if len(argv) != 2 or argv[1].startswith("-"):
            raise CommandRejectedError("COMMAND_REJECTED: only 'node <script.js>' with no flags is allowed")

    if program == "npm":
        if tuple(argv[1:]) not in rule["allowed_invocations"]:
            raise CommandRejectedError("COMMAND_REJECTED: only 'npm test' or 'npm run test' is allowed")


def run_command(argv: list, cwd, timeout: int = DEFAULT_TIMEOUT) -> dict:
    _validate_argv(argv)
    # Validation above checks the ORIGINAL program name (e.g. "npm")
    # against the allowlist; resolving to a full path only changes how
    # the already-approved program gets launched. Needed on Windows,
    # where some tools (npm) are a .cmd wrapper that CreateProcess can
    # only run when given its full, extension-included path -- a bare
    # name works for an actual .exe (git, python, node) but not for npm.
    resolved = shutil.which(argv[0])
    launch_argv = [resolved, *argv[1:]] if resolved else argv
    try:
        completed = subprocess.run(
            launch_argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": -1,
            "stdout": exc.stdout or "",
            "stderr": f"TIMEOUT after {timeout}s: {exc}",
            "timed_out": True,
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "timed_out": False,
    }


def combined_output(result: dict, limit: int = 2000) -> str:
    """stdout and stderr together, tail-truncated -- diagnostic messages
    must never read stdout alone: pytest puts failures in stdout, but
    Node routes most runtime errors (a bad require, an uncaught
    exception outside the test's own try block) to stderr, and reading
    only stdout silently drops the actual error from any report."""
    combined = (result.get("stdout") or "") + (result.get("stderr") or "")
    return combined[-limit:]
