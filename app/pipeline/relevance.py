from __future__ import annotations

import re

from app.models.source_event import SourceEvent


# Markers that are safe to interpret from free-form advisory text because they
# are strongly associated with the Python ecosystem.
PYTHON_TEXT_MARKERS = (
    r"\bpython\b",
    r"\bpypi\b",
    r"\bpip\s+install\b",
    r"\bpython\s+(?:package|module|library|application|project)\b",
    r"\bsite-packages\b",
    r"\bpyproject\.toml\b",
    r"\brequirements\.txt\b",
    r"\bsetup\.py\b",
    r"(?:^|[^a-z0-9_])python/[a-z0-9_./-]+",
)

# Framework/library names are matched as whole words. They are deliberately
# separate from package names like `requests`, which is also a common English
# word and must not be treated as Python evidence when it appears in prose.
KNOWN_PYTHON_PROJECT_MARKERS = {
    "django",
    "flask",
    "fastapi",
    "jinja",
    "jinja2",
    "sqlalchemy",
    "urllib3",
    "tornado",
    "twisted",
    "celery",
    "paramiko",
    "cryptography",
    "setuptools",
    "virtualenv",
    "poetry",
    "pipenv",
    "sglang",
}

KNOWN_PYTHON_CPE_PACKAGES = {
    "django",
    "flask",
    "fastapi",
    "jinja",
    "urllib3",
    "requests",
}


def _contains_whole_word(text: str, value: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9_]){re.escape(value)}(?![a-z0-9_])", text))


def _looks_like_python_text(text: str) -> bool:
    lowered = text.lower()
    if any(re.search(pattern, lowered) for pattern in PYTHON_TEXT_MARKERS):
        return True
    return any(
        _contains_whole_word(lowered, marker)
        for marker in KNOWN_PYTHON_PROJECT_MARKERS
    )


def _structured_python_evidence(event: SourceEvent) -> bool:
    structured = " ".join(
        [
            *event.affected_technology,
            *event.affected_packages,
            *event.identifiers.get("CPE", []),
        ]
    ).lower()

    # Explicit package metadata is much stronger evidence than prose.
    if any(
        _contains_whole_word(structured, marker)
        for marker in KNOWN_PYTHON_CPE_PACKAGES
    ):
        return True

    if any(
        _contains_whole_word(structured, marker)
        for marker in ("python", "pypi", *KNOWN_PYTHON_PROJECT_MARKERS)
    ):
        return True

    for reference in event.references:
        lowered = reference.lower()
        if "pypi.org" in lowered or "python.org" in lowered:
            return True

    return bool(
        re.search(
            r"cpe:2\.3:a:[^:]+:(?:django|flask|fastapi|python|jinja|urllib3|requests):",
            structured,
        )
    )


def is_python_relevant(event: SourceEvent) -> bool:
    if _structured_python_evidence(event):
        return True

    # Use free-form advisory text only for unambiguous Python markers. Do not
    # scan for generic package names such as `requests` across prose.
    free_form = " ".join(
        [
            event.summary,
            event.description,
        ]
    )
    return _looks_like_python_text(free_form)
