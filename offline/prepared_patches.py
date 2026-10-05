"""Deterministic fixes for vulnerability patterns currently supported by the dashboard.

Each rule builds a complete replacement for an already-affected source file.
Unsupported findings intentionally return no patch; they are never given an
unrelated template just to make a push appear successful.
"""
from __future__ import annotations

import ast
import json
import re

from offline import tools


_SECRET_NAME = (
    r"(?:JWT_SECRET|SECRET_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|SECRET|TOKEN|PRIVATE_KEY|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)"
)
_PY_SECRET_ASSIGNMENT = re.compile(
    rf"(?m)^(?P<indent>[ \t]*)(?P<name>{_SECRET_NAME})(?P<assign>[ \t]*=[ \t]*)"
    r"(?P<quote>['\"])(?P<value>[^'\"\n]+)(?P=quote)(?P<tail>[ \t]*(?:#.*)?)$"
)
_JS_SECRET_ASSIGNMENT = re.compile(
    rf"(?m)^(?P<prefix>[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+)"
    rf"(?P<name>{_SECRET_NAME})(?P<assign>[ \t]*=[ \t]*)"
    r"(?P<quote>['\"])(?P<value>[^'\"\n]+)(?P=quote)(?P<tail>[ \t]*;?[ \t]*(?://.*)?)$"
)
_SQLITE_FSTRING = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<call>(?:[A-Za-z_]\w*\.)+execute)"
    r"\(f(?P<quote>['\"])(?P<sql>.*?)(?P=quote)\)(?P<tail>[ \t]*(?:#.*)?)$"
)


def _insert_python_os_import(source: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "import os\n" + source

    if any(
        isinstance(node, ast.Import)
        and any(alias.name == "os" and alias.asname is None for alias in node.names)
        for node in ast.walk(tree)
    ):
        return source

    lines = source.splitlines(keepends=True)
    insertion = 0
    if lines and lines[0].startswith("#!"):
        insertion = 1
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(
        getattr(tree.body[0], "value", None), ast.Constant
    ) and isinstance(tree.body[0].value.value, str):
        insertion = max(insertion, tree.body[0].end_lineno or 0)
    else:
        while insertion < len(lines) and (
            not lines[insertion].strip()
            or lines[insertion].lstrip().startswith("#")
        ):
            insertion += 1

    if insertion and insertion <= len(lines) and lines[insertion - 1].strip():
        lines.insert(insertion, "\n")
        insertion += 1
    lines.insert(insertion, "import os\n")
    if insertion + 1 < len(lines) and lines[insertion + 1].strip():
        lines.insert(insertion + 1, "\n")
    return "".join(lines)


def _replace_hardcoded_secret(path: str, source: str) -> str | None:
    if path.lower().endswith(".py"):
        matches = list(_PY_SECRET_ASSIGNMENT.finditer(source))
        if not matches:
            return None
        updated = _PY_SECRET_ASSIGNMENT.sub(
            lambda match: (
                f"{match.group('indent')}{match.group('name')}{match.group('assign')}"
                f"os.environ.get({json.dumps(match.group('name').upper())}){match.group('tail')}"
            ),
            source,
        )
        return _insert_python_os_import(updated)

    if path.lower().endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        if not _JS_SECRET_ASSIGNMENT.search(source):
            return None
        return _JS_SECRET_ASSIGNMENT.sub(
            lambda match: (
                f"{match.group('prefix')}{match.group('name')}{match.group('assign')}"
                f"process.env.{match.group('name').upper()}{match.group('tail')}"
            ),
            source,
        )
    return None


def _replace_sqlite_fstring(source: str) -> str | None:
    if "sqlite3" not in source:
        return None
    changed = False

    def replace_call(match: re.Match) -> str:
        nonlocal changed
        sql = match.group("sql")
        parameters: list[str] = []

        def quoted_parameter(found: re.Match) -> str:
            parameters.append(found.group(2))
            return "?"

        sql = re.sub(r"(['\"])\{([A-Za-z_]\w*)\}\1", quoted_parameter, sql)

        def parameter(found: re.Match) -> str:
            parameters.append(found.group(1))
            return "?"

        sql = re.sub(r"\{([A-Za-z_]\w*)\}", parameter, sql)
        if not parameters or re.search(r"\{[^}]*\}", sql):
            return match.group(0)

        args = ", ".join(parameters)
        args_tuple = f"({args},)" if len(parameters) == 1 else f"({args})"
        changed = True
        return (
            f"{match.group('indent')}{match.group('call')}"
            f"({json.dumps(sql)}, {args_tuple}){match.group('tail')}"
        )

    updated = _SQLITE_FSTRING.sub(replace_call, source)
    return updated if changed else None


def prepare(audit) -> tuple[dict[str, str], str]:
    """Build full replacement source files for a supported, confirmed issue."""
    package = audit.package or {}
    title = str(package.get("title") or "").lower()
    attack_type = str(package.get("attack_type") or "").lower()
    hypothesis = str(audit.vulnerability_hypothesis or package.get("description") or "").lower()
    evidence = f"{title} {attack_type} {hypothesis}"
    affected = list(audit.affected_files or (audit.original_code or {}).keys())
    replacements: dict[str, str] = {}

    for path in affected:
        try:
            source = tools.read_file(path)
        except (OSError, UnicodeError, tools.PathRejectedError):
            continue

        updated = None
        if "secret" in evidence or "credential" in evidence or "hardcoded" in attack_type:
            updated = _replace_hardcoded_secret(path, source)
            if updated is not None:
                replacements[path] = updated
        if updated is None and ("sql injection" in evidence or "sql_injection" in evidence):
            updated = _replace_sqlite_fstring(source)
            if updated is not None:
                replacements[path] = updated

    if not replacements:
        return {}, "No prepared fix template matches this finding and its affected files."
    if "secret" in evidence or "credential" in evidence or "hardcoded" in attack_type:
        return replacements, "Replaced hardcoded secret assignments with environment-variable lookups."
    return replacements, "Replaced interpolated SQLite query values with bound parameters."
