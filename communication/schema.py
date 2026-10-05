"""Threat Package schema definition -- the untrusted-data contract between
the Online system and the Guard. This module defines structure only;
guard/validator.py is what actually enforces it.

The Guard treats every field here as DATA, never as instructions, no
matter what the field happens to contain.
"""

SCHEMA_VERSION = "1.0"

# field_name -> expected Python type
TOP_LEVEL_FIELDS = {
    "schema_version": str,
    "threat_id": str,
    "source": dict,
    "title": str,
    "cve": str,
    "affected_component": str,
    "affected_versions": list,
    "fixed_versions": list,
    "severity": str,
    "description": str,
    "attack_type": str,
    "indicators": list,
    "audit_instructions": list,
    "test_strategy": str,
    "remediation": str,
    "integrity": dict,
}

REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "threat_id",
    "source",
    "title",
    "affected_component",
    "severity",
    "description",
    "integrity",
}

ALL_ALLOWED_TOP_LEVEL = set(TOP_LEVEL_FIELDS)

SOURCE_FIELDS = {
    "type": str,
    "url": str,
    "published": str,
    "retrieved_at": str,
}
REQUIRED_SOURCE_FIELDS = {"type", "url", "retrieved_at"}
ALLOWED_SOURCE_TYPES = {"nvd", "github", "cisa", "other"}

INTEGRITY_FIELDS = {"sha256": str}
REQUIRED_INTEGRITY_FIELDS = {"sha256"}

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
