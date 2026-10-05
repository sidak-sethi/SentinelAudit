from pathlib import Path
import json

from app.models.source_event import SourceEvent
from app.models.threat_analysis import (
    AttackAssessment,
    CountermeasureAssessment,
    ExploitAssessment,
    ThreatAnalysis,
)
from app.models.research_evidence import (
    ResearchEvidence,
    ResearchTarget,
    ReproductionStatus,
)
from app.packaging.builder import ThreatPackageBuilder
from app.pipeline.correlate import ThreatGroup
from app.transfer.exporter import AtomicExporter


def test_atomic_export_uses_offline_contract(tmp_path: Path):
    event = SourceEvent(
        event_id="nvd:CVE-2026-0001",
        source="NVD",
        source_type="vulnerability_database",
        identifiers={"CVE": ["CVE-2026-0001"]},
        affected_packages=["examplepkg"],
        affected_versions=["1.0.0"],
        summary="Example vulnerability",
        description="Example Python vulnerability.",
        references=["https://example.invalid/CVE-2026-0001"],
        severity="MEDIUM",
        cvss_score=5.0,
    )
    group = ThreatGroup(threat_id="CVE-2026-0001", events=[event])
    analysis = ThreatAnalysis(
        affected_technology=["Python"],
        affected_packages=["examplepkg"],
        affected_versions=["1.0.0"],
        attack=AttackAssessment(
            class_name="authorization bypass",
            impact="unauthorized access",
        ),
        exploit=ExploitAssessment(),
        countermeasure=CountermeasureAssessment(
            root_cause="improper authorization check",
            candidate_patch_description="Use exact authorization comparison.",
        ),
        test_strategy=[],
        confidence=0.8,
        analysis_model="test-model",
    )
    research = ResearchEvidence(
        target=ResearchTarget(ecosystem="Python", package="examplepkg"),
        reproduction_attempted=False,
        reproduction_status=ReproductionStatus.INCONCLUSIVE,
    )

    package = ThreatPackageBuilder().build(group, analysis, research)
    path = AtomicExporter(tmp_path).export(package)
    payload = json.loads(path.read_text(encoding="utf-8"))

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
    assert payload["threat_id"] == "CVE-2026-0001"
    assert payload["cve"] == "CVE-2026-0001"
    assert payload["title"] == "Authorization Bypass"
    assert payload["attack_type"] == "authorization_bypass"
    assert payload["severity"] == "medium"
    assert payload["status"] == "uncertain"
    assert payload["patch_status"] is None
    assert payload["patch_attempts"] == 0
    assert payload["final_audit"] is None
    assert path.name.startswith("PKG-")
    assert not list(tmp_path.glob("*.tmp"))
