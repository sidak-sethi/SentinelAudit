"""TEST FIXTURE ONLY -- stands in for the real Online teammate's output
during development. LOCAL DEMO MODE: a hand-authored, valid threat package
describing the SQL injection in fixtures/setup_target_repo.py's demo Flask
app, with a correctly computed integrity hash, dropped into online_outbox/
for the Guard to pick up.

This fixture is what makes the guaranteed demo independent of whether a
live advisory happens to apply to the fixture repo -- see Scenario A.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from communication import paths
from guard.validator import recompute_integrity_sha256

PACKAGE = {
    "schema_version": "1.0",
    "threat_id": "demo-sqli-001",
    "source": {
        "type": "other",
        "url": "https://example.invalid/advisories/demo-sqli-001",
        "published": "2026-01-01T00:00:00Z",
        "retrieved_at": "2026-01-01T00:00:00Z",
    },
    "title": "SQL Injection in user search endpoint",
    "cve": "",
    "affected_component": "app.py /search endpoint",
    "affected_versions": ["demo"],
    "fixed_versions": [],
    "severity": "high",
    "description": (
        "The /search endpoint builds a SQL query by directly interpolating the "
        "'name' request parameter into a string, allowing an attacker to inject "
        "arbitrary SQL and read data outside the intended query."
    ),
    "attack_type": "sql_injection",
    "indicators": ["name parameter contains SQL metacharacters such as a single quote followed by boolean logic"],
    "audit_instructions": [
        "Inspect how the /search endpoint builds its SQL query and whether user input reaches it unescaped."
    ],
    "test_strategy": (
        "Send a name value containing a single quote and SQL boolean logic, and confirm whether it "
        "changes the result set in a way that proves the query is not parameterized."
    ),
    "remediation": "Use parameterized queries instead of string interpolation for the SQL statement.",
    "integrity": {"sha256": ""},
}


def build() -> dict:
    package = json.loads(json.dumps(PACKAGE))
    package["source"]["retrieved_at"] = datetime.now(timezone.utc).isoformat()
    package["integrity"] = {"sha256": recompute_integrity_sha256(package)}
    return package


def write_to_outbox() -> None:
    paths.ensure_directories()
    package = build()
    destination = paths.ONLINE_OUTBOX / f"{package['threat_id']}.json"
    destination.write_text(json.dumps(package, indent=2), encoding="utf-8")


if __name__ == "__main__":
    write_to_outbox()
    print("Wrote LOCAL DEMO MODE SQLi threat package to online_outbox/")
