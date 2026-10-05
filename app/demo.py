from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings
from app.llm.client import CircuitBreaker, LLMResult, LLMRequestTelemetry
from app.models.threat_analysis import AttackAssessment, CountermeasureAssessment, ExploitAssessment, ThreatAnalysis
from app.models.threat_triage import ThreatTriage
from app.models.source_event import SourceEvent
from app.pipeline.correlate import ThreatGroup
from app.research.engine import ResearchEngine


class FixtureLLMProvider:
    model = "fixture-model"

    async def generate_json(self, system_prompt: str, user_prompt: str, response_model):
        if response_model is ThreatTriage:
            return ThreatTriage(should_deep_analyze=True, confidence=0.99, reason="Fixture explicitly tests the research loop.")
        return ThreatAnalysis(
            affected_technology=["Python"],
            affected_packages=["fixturepkg"],
            affected_versions=["1.0.0"],
            attack=AttackAssessment(
                class_name="authorization bypass",
                entry_condition="attacker-controlled token suffix",
                attack_path=["input token", "prefix comparison", "authorization decision"],
                preconditions=["reachable authorization check"],
                impact="unauthorized access",
                indicators=["unexpected authorization success"],
            ),
            exploit=ExploitAssessment(
                reproduction_method="fixture attack.py executed in disposable sandbox",
                vulnerable_behavior="prefix comparison accepts attacker-controlled suffix",
                verification_conditions=["attacker-crafted suffix must be rejected after patch"],
                reproduction_evidence=[],
            ),
            countermeasure=CountermeasureAssessment(
                strategy="exact-token comparison",
                root_cause="prefix comparison instead of exact equality",
                affected_code_pattern="startswith authorization check",
                mitigation=["compare the complete token"],
                candidate_patch_description="replace prefix comparison with exact equality",
                patch_validation="UNVERIFIED",
                upstream_fixed_versions=[],
            ),
            test_strategy=["reproduce before patch", "apply exact equality patch", "rerun attack", "run regression tests"],
            confidence=0.99,
            analysis_model="fixture-model",
        )

    async def close(self):
        return None


def demo_settings(base: Settings) -> Settings:
    return base.model_copy(update={
        "demo_mode": True,
        "sandbox_backend": "local",
        "allow_local_sandbox": True,
        "research_work_dir": Path("./data/research-demo"),
        "outgoing_dir": Path("./data/outgoing"),
        "state_file": Path("./data/state.json"),
    })


async def run_demo(settings: Settings):
    settings = demo_settings(settings)
    settings.prepare_dirs()
    raw = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "relevant_python_event.json").read_text(encoding="utf-8"))
    event = SourceEvent.model_validate(raw)
    group = ThreatGroup(threat_id="CVE-2099-0001", events=[event])
    provider = FixtureLLMProvider()
    from app.llm.client import ResilientLLMClient
    triage_client = ResilientLLMClient(provider, "fixture", "triage", 1, 0, 0, 0, CircuitBreaker(60))
    analysis_client = ResilientLLMClient(provider, "fixture", "analysis", 1, 0, 0, 0, CircuitBreaker(60))
    from app.llm.analyzer import ThreatAnalyzer
    analyzer = ThreatAnalyzer(triage_client, analysis_client)
    triage = await analyzer.triage(group)
    analysis = await analyzer.analyze(group, triage.value)
    research_engine = ResearchEngine(settings)
    original_resolve = research_engine.target_resolver.resolve
    def demo_resolve(g, a):
        target = original_resolve(g, a)
        return target.model_copy(update={"source_artifact": "fixture://reproducible_python_case", "runtime_version": "3.11"})
    research_engine.target_resolver.resolve = demo_resolve
    research = await research_engine.research(group, analysis.value)
    from app.packaging.builder import ThreatPackageBuilder
    from app.transfer.exporter import AtomicExporter
    package = ThreatPackageBuilder().build(group, analysis.value, research)
    path = AtomicExporter(settings.outgoing_dir).export(package)
    await analyzer.close()
    print(f"[DEMO] triage={triage.value.model_dump()}")
    print(f"[DEMO] reproduction={research.reproduction_status.value}")
    print(f"[DEMO] verification={research.verification.result.value if research.verification else 'NOT_TESTED'}")
    print(f"[DEMO] exported={path}")
    return path
