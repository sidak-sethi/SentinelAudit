"""Translate Online research results into the existing Guard contract.

The richer Online model is never written directly to the Guard outbox. This
adapter deliberately emits only the allowlisted v1 fields and signs that
exact payload with the same canonical hash used by the Guard validator.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.models.threat_package import ThreatPackage
from guard.validator import recompute_integrity_sha256


_SOURCE_TYPES = {
    "nvd": "nvd",
    "github advisories": "github",
    "github advisory": "github",
    "github_advisory": "github",
    "github": "github",
    "cisa kev": "cisa",
    "cisa_kev": "cisa",
    "cisa": "cisa",
}


def _source_url(package: ThreatPackage) -> str:
    candidate = str(package.source.get("url") or "").strip()
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return candidate
    except ValueError:
        pass
    if package.cve:
        return f"https://nvd.nist.gov/vuln/detail/{package.cve}"
    return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def to_guard_package(package: ThreatPackage) -> dict:
    """Return an exact, integrity-signed ``communication/schema.py`` object."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    source = {
        "type": _SOURCE_TYPES.get(str(package.source.get("type") or "").strip().lower(), "other"),
        "url": _source_url(package),
        "retrieved_at": str(package.source.get("retrieved_at") or now),
    }
    published = package.source.get("published")
    if published:
        source["published"] = str(published)

    severity = str(package.severity or "").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "low"

    payload = {
        "schema_version": "1.0",
        "threat_id": package.threat_id,
        "source": source,
        "title": package.title,
        "cve": package.cve or "",
        "affected_component": package.affected_component or "unknown",
        "affected_versions": package.affected_versions,
        "fixed_versions": package.fixed_versions,
        "severity": severity,
        "description": package.vulnerability_hypothesis or package.title,
        "attack_type": package.attack_type or "unknown",
        "indicators": package.indicators,
        # Human-readable research suggestions are data; the Guard does not
        # execute these fields. Leave command-like audit instructions empty.
        "audit_instructions": [],
        "test_strategy": package.test_strategy or "Verify the reported behavior against the affected component.",
        "remediation": package.recommended_fix or "Review the upstream fixed version and apply the vendor guidance.",
    }
    payload["integrity"] = {"sha256": recompute_integrity_sha256(payload)}
    return payload
