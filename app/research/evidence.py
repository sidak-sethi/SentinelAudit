from __future__ import annotations

from app.models.research_evidence import CountermeasureEvidence, ResearchEvidence, ResearchTarget


class EvidenceAssembler:
    def assemble(
        self,
        target: ResearchTarget,
        environment,
        reproduction,
        root_cause,
        countermeasure: CountermeasureEvidence | None,
        verification,
    ) -> ResearchEvidence:
        return ResearchEvidence(
            target=target,
            environment=environment,
            vulnerable_version=target.vulnerable_version,
            fixed_version=target.fixed_version,
            reproduction_attempted=True,
            reproduction_status=reproduction.status,
            reproduction_observations=reproduction.observations,
            execution_logs=reproduction.logs,
            root_cause=root_cause,
            countermeasure=countermeasure,
            verification=verification,
        )
