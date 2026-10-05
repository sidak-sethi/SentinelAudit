import json

import pytest

from app.models.threat_triage import ThreatTriage
from app.models.threat_package import ThreatPackage


def test_triage_validation():
    item = ThreatTriage(
        should_deep_analyze=True,
        confidence=0.9,
        reason="uncertain",
    )
    assert item.confidence == 0.9


def make_package() -> ThreatPackage:
    return ThreatPackage(
        package_id="PKG-TEST123456",
        threat_id="manual-scan-005-hardcoded-jwt-secret",
        title="Hardcoded JWT Secret",
        cve=None,
        attack_type="hardcoded_secret",
        severity="medium",
        source={
            "type": "other",
            "url": "https://local-scan.invalid/offline-gemma-self-scan",
            "published": "2026-10-05T08:28:20.454907Z",
            "retrieved_at": "2026-10-05T08:28:20.454907Z",
        },
        status="ai_error",
        patch_status=None,
        repository=r"C:\repo",
        branch=None,
        affected_files=[],
        affected_lines=[],
        confidence=0.0,
        vulnerability_hypothesis="A sensitive cryptographic secret is hardcoded.",
        recommended_fix="Load the secret from a secure environment variable.",
        security_test_path=None,
        code={},
        diff=None,
        patch_attempts=0,
        final_audit=None,
        reason="Gemma did not return valid JSON after 2 attempt(s).",
    )


def test_package_serializes_to_offline_contract():
    payload = make_package().model_dump(mode="json")

    assert set(payload) == {
        "threat_id",
        "title",
        "cve",
        "attack_type",
        "severity",
        "source",
        "status",
        "patch_status",
        "repository",
        "branch",
        "affected_files",
        "affected_lines",
        "confidence",
        "vulnerability_hypothesis",
        "recommended_fix",
        "security_test_path",
        "code",
        "diff",
        "patch_attempts",
        "final_audit",
        "reason",
        "timestamp",
    }
    assert "package_id" not in payload
    assert json.loads(json.dumps(payload)) == payload


def test_package_rejects_bad_status():
    with pytest.raises(ValueError):
        data = make_package().model_dump()
        data["status"] = "BAD_STATUS"
        ThreatPackage(**data)
