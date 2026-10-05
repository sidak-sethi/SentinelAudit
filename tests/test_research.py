import pytest
from pathlib import Path

from app.config import Settings
from app.models.threat_analysis import AttackAssessment, CountermeasureAssessment, ExploitAssessment, ThreatAnalysis
from app.models.source_event import SourceEvent
from app.pipeline.correlate import ThreatGroup
from app.research.engine import ResearchEngine


@pytest.mark.asyncio
async def test_fixture_research(tmp_path: Path):
    settings = Settings(sandbox_backend="local", allow_local_sandbox=True, research_work_dir=tmp_path)
    group = ThreatGroup(
        threat_id="CVE-2099-0001",
        events=[SourceEvent(event_id="x", source="fixture", source_type="fixture", identifiers={"CVE":["CVE-2099-0001"]}, affected_technology=["Python"], affected_packages=["fixturepkg"], affected_versions=["1.0.0"], summary="x", description="x", references=[])],
    )
    analysis = ThreatAnalysis(
        affected_technology=["Python"], affected_packages=["fixturepkg"], affected_versions=["1.0.0"],
        attack=AttackAssessment(), exploit=ExploitAssessment(),
        countermeasure=CountermeasureAssessment(strategy="exact equality", candidate_patch_description="replace prefix with equality"),
        test_strategy=[], confidence=1.0, analysis_model="fixture"
    )
    # The live target resolver is intentionally generic; inject the fixture artifact through the analysis path by patching the resolver.
    engine = ResearchEngine(settings)
    original = engine.target_resolver.resolve
    def resolve(g, a):
        target = original(g, a)
        return target.model_copy(update={"source_artifact":"fixture://reproducible_python_case"})
    engine.target_resolver.resolve = resolve
    result = await engine.research(group, analysis)
    assert result.reproduction_status.value == "REPRODUCED"
    assert result.verification is not None
    assert result.verification.result.value == "VERIFIED"
