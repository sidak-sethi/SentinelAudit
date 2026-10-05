from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.models.research_evidence import ResearchEvidence, ResearchTarget
from app.models.threat_analysis import ThreatAnalysis
from app.pipeline.correlate import ThreatGroup
from app.research.artifact_resolver import ArtifactResolver
from app.research.countermeasure import CountermeasureEngine
from app.research.environment_builder import EnvironmentBuilder
from app.research.evidence import EvidenceAssembler
from app.research.patch_verifier import PatchVerifier
from app.research.reproducer import ReproductionResult, Reproducer
from app.research.root_cause import RootCauseAnalyzer
from app.research.sandbox import DockerSandbox, LocalSandbox, Sandbox
from app.research.target_resolver import TargetResolver


class ResearchEngine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.work_dir = settings.research_work_dir
        self.target_resolver = TargetResolver()
        self.artifact_resolver = ArtifactResolver(self.work_dir)
        self.environment_builder = EnvironmentBuilder(
            self.work_dir,
            settings.sandbox_network,
            settings.sandbox_cpu_limit,
            settings.sandbox_memory_limit_mb,
            settings.sandbox_pids_limit,
        )
        self.reproducer = Reproducer()
        self.root_cause = RootCauseAnalyzer()
        self.countermeasure = CountermeasureEngine()
        self.patch_verifier = PatchVerifier()
        self.evidence = EvidenceAssembler()

    def _sandbox(self) -> Sandbox:
        if self.settings.sandbox_backend == "local":
            return LocalSandbox(self.settings.allow_local_sandbox)
        return DockerSandbox(
            self.settings.sandbox_cpu_limit,
            self.settings.sandbox_memory_limit_mb,
            self.settings.sandbox_pids_limit,
            self.settings.sandbox_network,
        )

    async def research(self, group: ThreatGroup, analysis: ThreatAnalysis) -> ResearchEvidence:
        target = self.target_resolver.resolve(group, analysis)
        target = await self.artifact_resolver.resolve(target)
        environment = self.environment_builder.build(target)
        sandbox = self._sandbox()
        reproduction = await self.reproducer.reproduce(target, environment, sandbox, self.work_dir)
        root_cause = self.root_cause.analyze(reproduction.logs) if reproduction.logs else None
        countermeasure = self.countermeasure.propose(analysis)
        verification = None
        if target.source_artifact and target.source_artifact.startswith("fixture://") and reproduction.status.value == "REPRODUCED":
            fixture_name = target.source_artifact.removeprefix("fixture://")
            verification = self.patch_verifier.verify_fixture(fixture_name, environment, sandbox, self.work_dir)
            countermeasure = countermeasure.model_copy(update={"applied": verification.result.value == "VERIFIED", "status": verification.result})
        return self.evidence.assemble(target, environment, reproduction, root_cause, countermeasure, verification)
