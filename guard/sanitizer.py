"""Deterministic prompt-injection / instruction-smuggling scanner.

This is NOT an AI classifier and never calls one -- the Guard must not rely
on an LLM as the final security authority. It is a conservative, fully
explainable keyword/pattern scan over every string value in a threat
package.

Classification is one of SAFE / SUSPICIOUS / REJECTED:
- a HARD_REJECT_PATTERNS match always yields REJECTED.
- a SOFT_SUSPICIOUS_PATTERNS match yields SUSPICIOUS, which the Guard logs
  but does not by itself reject (it is a weaker heuristic signal reserved
  for future tightening, not a proven injection attempt).
"""
import re

SAFE, SUSPICIOUS, REJECTED = "SAFE", "SUSPICIOUS", "REJECTED"

HARD_REJECT_PATTERNS = [
    r"ignore (all |any )?previous instructions",
    r"ignore (all |any )?prior instructions",
    r"disregard (the |all )?(system|above|previous) instructions",
    r"reveal (the )?system prompt",
    r"send (the )?source code",
    r"upload (the )?files?",
    r"send secrets",
    r"execute this command",
    r"run powershell",
    r"\brun cmd\b",
    r"open a reverse shell",
    r"reverse shell",
    r"connect to \S+",
    r"download and execute",
    r"disable security",
    r"modify (the )?guard",
    r"change your instructions",
    r"exfiltrate",
    r"send data to this server",
    r"you are now",
    r"new instructions\s*:",
]
HARD_REJECT_RE = [re.compile(pattern, re.IGNORECASE) for pattern in HARD_REJECT_PATTERNS]

SOFT_SUSPICIOUS_PATTERNS = [
    r"\bsudo\b",
    r"\bcurl\b",
    r"\bwget\b",
    r"base64 -d",
    r"\beval\(",
]
SOFT_SUSPICIOUS_RE = [re.compile(pattern, re.IGNORECASE) for pattern in SOFT_SUSPICIOUS_PATTERNS]


def classify_text(text: str):
    """Return (classification, matched_pattern_or_None) for one string."""
    if not isinstance(text, str) or not text:
        return SAFE, None
    for pattern in HARD_REJECT_RE:
        if pattern.search(text):
            return REJECTED, pattern.pattern
    for pattern in SOFT_SUSPICIOUS_RE:
        if pattern.search(text):
            return SUSPICIOUS, pattern.pattern
    return SAFE, None


def scan_package(data) -> dict:
    """Recursively scan every string value in a parsed package.

    Returns {"classification": worst finding across the whole package,
    "findings": [{"path", "pattern", "classification"}, ...]}.
    """
    findings = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]")
        elif isinstance(node, str):
            classification, pattern = classify_text(node)
            if classification != SAFE:
                findings.append({"path": path, "pattern": pattern, "classification": classification})

    walk(data, "$")

    worst = SAFE
    for finding in findings:
        if finding["classification"] == REJECTED:
            worst = REJECTED
            break
        if finding["classification"] == SUSPICIOUS and worst != REJECTED:
            worst = SUSPICIOUS

    return {"classification": worst, "findings": findings}
