from __future__ import annotations

from urllib.parse import urlparse

from app.models.research_evidence import ResearchTarget
from app.models.threat_analysis import ThreatAnalysis
from app.pipeline.correlate import ThreatGroup


class TargetResolver:
    def resolve(self, group: ThreatGroup, analysis: ThreatAnalysis) -> ResearchTarget:
        package = (analysis.affected_packages or group.packages or ["unknown"])[0]
        ecosystem = (analysis.affected_technology or ["Python"])[0]
        repository = None
        for ref in group.references:
            parsed = urlparse(ref)
            if parsed.netloc.endswith("github.com"):
                repository = ref
                break
        vulnerable_version = (analysis.affected_versions or [None])[0]
        fixed = (analysis.countermeasure.upstream_fixed_versions or [None])[0]
        return ResearchTarget(
            ecosystem=ecosystem,
            package=package,
            repository=repository,
            vulnerable_version=vulnerable_version,
            fixed_version=fixed,
            source_artifact=None,
            runtime_version=None,
            environment_requirements=[],
        )
