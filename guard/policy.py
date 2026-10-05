"""Deterministic policy constants for the Guard: size limits, string-length
limits, field-name blocklist, and format regexes. No AI model is used here
or anywhere else in the Guard -- the security boundary must not depend on
a model's judgment.
"""
import re

MAX_PACKAGE_SIZE_BYTES = 64 * 1024

MAX_STRING_LENGTH = {
    "schema_version": 16,
    "threat_id": 128,
    "title": 300,
    "cve": 32,
    "affected_component": 300,
    "severity": 32,
    "description": 8000,
    "attack_type": 128,
    "test_strategy": 4000,
    "remediation": 4000,
}
DEFAULT_MAX_STRING_LENGTH = 4000

MAX_LIST_ITEMS = 50
MAX_LIST_ITEM_LENGTH = 1000

THREAT_ID_RE = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Field names that must never appear anywhere in a threat package, at any
# nesting depth -- these would smuggle executable intent across the Guard.
DISALLOWED_FIELD_NAMES = {
    "commands", "command", "shell", "exec", "execute", "callback", "webhook",
    "upload", "credentials", "credential", "secrets", "secret", "network",
    "environment", "env", "system_prompt", "systemprompt",
}
