"""Deterministic schema/type/size/format/integrity validation for threat
packages. This is the authoritative Guard security-boundary logic. No AI
model is involved in this module or anywhere else in the Guard.
"""
import hashlib
import json
from dataclasses import dataclass, field

from communication import schema
from guard import policy
from guard.sanitizer import scan_package, REJECTED as SANITIZER_REJECTED


@dataclass
class ValidationResult:
    ok: bool
    errors: list = field(default_factory=list)
    classification: str = "SAFE"
    parsed: dict | None = None


def recompute_integrity_sha256(data: dict) -> str:
    """Canonical hash over the package with the integrity field excluded,
    so a tampered sha256 is detectable and the hash is reproducible by
    anyone building a package (see fixtures/*.py)."""
    without_integrity = {k: v for k, v in data.items() if k != "integrity"}
    canonical = json.dumps(without_integrity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_disallowed_fields(node, path: str = "$") -> list:
    errors = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in policy.DISALLOWED_FIELD_NAMES:
                errors.append(f"disallowed field '{key}' at {path}")
            errors.extend(_check_disallowed_fields(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            errors.extend(_check_disallowed_fields(item, f"{path}[{index}]"))
    return errors


def _check_string_length(field_name: str, value: str, errors: list) -> None:
    limit = policy.MAX_STRING_LENGTH.get(field_name, policy.DEFAULT_MAX_STRING_LENGTH)
    if len(value) > limit:
        errors.append(f"field '{field_name}' exceeds max length {limit}")


def _check_list(field_name: str, value: list, errors: list) -> None:
    if len(value) > policy.MAX_LIST_ITEMS:
        errors.append(f"field '{field_name}' exceeds max item count {policy.MAX_LIST_ITEMS}")
    for item in value:
        if isinstance(item, str) and len(item) > policy.MAX_LIST_ITEM_LENGTH:
            errors.append(f"an item in '{field_name}' exceeds max item length {policy.MAX_LIST_ITEM_LENGTH}")


def validate_package(raw_bytes: bytes) -> ValidationResult:
    if len(raw_bytes) > policy.MAX_PACKAGE_SIZE_BYTES:
        return ValidationResult(ok=False, errors=[f"package exceeds max size {policy.MAX_PACKAGE_SIZE_BYTES} bytes"])

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return ValidationResult(ok=False, errors=[f"malformed JSON: {exc}"])

    if not isinstance(data, dict):
        return ValidationResult(ok=False, errors=["package root must be a JSON object"])

    errors: list = []

    # Allowlist: reject unknown top-level fields outright. Never silently strip.
    unknown = set(data) - schema.ALL_ALLOWED_TOP_LEVEL
    if unknown:
        errors.append(f"unexpected top-level field(s): {sorted(unknown)}")

    # Disallowed field names anywhere in the structure (any nesting depth).
    errors.extend(_check_disallowed_fields(data))

    # Required fields.
    missing = schema.REQUIRED_TOP_LEVEL_FIELDS - set(data)
    if missing:
        errors.append(f"missing required field(s): {sorted(missing)}")

    # Type + length/size checks for whatever top-level fields are present.
    for field_name, value in data.items():
        expected_type = schema.TOP_LEVEL_FIELDS.get(field_name)
        if expected_type is None:
            continue  # already flagged above as unexpected
        if not isinstance(value, expected_type):
            errors.append(f"field '{field_name}' must be of type {expected_type.__name__}")
            continue
        if expected_type is str:
            _check_string_length(field_name, value, errors)
        elif expected_type is list:
            _check_list(field_name, value, errors)

    threat_id = data.get("threat_id")
    if isinstance(threat_id, str) and not policy.THREAT_ID_RE.match(threat_id):
        errors.append("threat_id has invalid format")

    cve = data.get("cve")
    if isinstance(cve, str) and cve and not policy.CVE_RE.match(cve):
        errors.append("cve has invalid format")

    severity = data.get("severity")
    if isinstance(severity, str) and severity.lower() not in schema.ALLOWED_SEVERITIES:
        errors.append(f"severity must be one of {sorted(schema.ALLOWED_SEVERITIES)}")

    source = data.get("source")
    if isinstance(source, dict):
        unknown_source = set(source) - set(schema.SOURCE_FIELDS)
        if unknown_source:
            errors.append(f"unexpected source field(s): {sorted(unknown_source)}")
        missing_source = schema.REQUIRED_SOURCE_FIELDS - set(source)
        if missing_source:
            errors.append(f"missing required source field(s): {sorted(missing_source)}")
        for key, value in source.items():
            expected = schema.SOURCE_FIELDS.get(key)
            if expected and not isinstance(value, expected):
                errors.append(f"source field '{key}' must be of type {expected.__name__}")
        source_type = source.get("type")
        if isinstance(source_type, str) and source_type not in schema.ALLOWED_SOURCE_TYPES:
            errors.append(f"source.type must be one of {sorted(schema.ALLOWED_SOURCE_TYPES)}")
        url = source.get("url")
        if isinstance(url, str) and not (url.startswith("http://") or url.startswith("https://")):
            errors.append("source.url must be an http(s) URL")
        for timestamp_field in ("published", "retrieved_at"):
            timestamp = source.get(timestamp_field)
            if isinstance(timestamp, str) and timestamp and not policy.TIMESTAMP_RE.match(timestamp):
                errors.append(f"source.{timestamp_field} has invalid timestamp format")
    elif "source" in data:
        errors.append("source must be an object")

    integrity = data.get("integrity")
    if isinstance(integrity, dict):
        unknown_integrity = set(integrity) - set(schema.INTEGRITY_FIELDS)
        if unknown_integrity:
            errors.append(f"unexpected integrity field(s): {sorted(unknown_integrity)}")
        missing_integrity = schema.REQUIRED_INTEGRITY_FIELDS - set(integrity)
        if missing_integrity:
            errors.append(f"missing required integrity field(s): {sorted(missing_integrity)}")
        sha256_value = integrity.get("sha256")
        if isinstance(sha256_value, str):
            if not policy.SHA256_RE.match(sha256_value):
                errors.append("integrity.sha256 is not a valid sha256 hex digest")
            else:
                expected = recompute_integrity_sha256(data)
                if sha256_value != expected:
                    errors.append("integrity.sha256 does not match recomputed package hash (tampered)")

    if errors:
        return ValidationResult(ok=False, errors=errors, parsed=data)

    scan = scan_package(data)
    if scan["classification"] == SANITIZER_REJECTED:
        reasons = [f"{finding['path']}: matched suspicious pattern" for finding in scan["findings"]]
        return ValidationResult(
            ok=False,
            errors=[f"suspicious content rejected: {reason}" for reason in reasons],
            classification=scan["classification"],
            parsed=data,
        )

    return ValidationResult(ok=True, errors=[], classification=scan["classification"], parsed=data)
