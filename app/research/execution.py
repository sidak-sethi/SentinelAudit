from __future__ import annotations

from app.models.research_evidence import ExecutionEvidence, EnvironmentIdentity
from app.research.sandbox import SandboxResult


def to_execution_evidence(
    result: SandboxResult,
    environment: EnvironmentIdentity,
    observed_behavior: str,
    expected_behavior: str,
    artifact_identity: str | None = None,
) -> ExecutionEvidence:
    return ExecutionEvidence(
        execution_id=result.execution_id,
        start_time=result.start_time,
        end_time=result.end_time,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        observed_behavior=observed_behavior,
        expected_behavior=expected_behavior,
        artifact_identity=artifact_identity,
        environment_identity=environment.os_base,
    )
