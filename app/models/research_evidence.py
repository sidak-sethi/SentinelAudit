from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReproductionStatus(str, Enum):
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"


class ResearchTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str
    package: str
    repository: str | None = None
    vulnerable_version: str | None = None
    fixed_version: str | None = None
    source_artifact: str | None = None
    runtime_version: str | None = None
    environment_requirements: list[str] = Field(default_factory=list)


class EnvironmentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    python_version: str | None = None
    os_base: str
    package_version: str | None = None
    dependency_versions: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    environment_variables: list[str] = Field(default_factory=list)
    network_policy: str
    resource_limits: dict[str, str | int | float] = Field(default_factory=dict)


class ExecutionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str
    start_time: datetime
    end_time: datetime
    exit_code: int | None
    stdout: str
    stderr: str
    observed_behavior: str
    expected_behavior: str
    artifact_identity: str | None = None
    environment_identity: str


class RootCauseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_location: str | None = None
    execution_path: list[str] = Field(default_factory=list)
    explanation: str


class CountermeasureEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate: str
    applied: bool
    status: VerificationStatus


class VerificationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_before: list[ExecutionEvidence] = Field(default_factory=list)
    attack_after: list[ExecutionEvidence] = Field(default_factory=list)
    regression_tests: list[ExecutionEvidence] = Field(default_factory=list)
    result: VerificationStatus


class ResearchEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: ResearchTarget
    environment: EnvironmentIdentity | None = None
    vulnerable_version: str | None = None
    fixed_version: str | None = None
    reproduction_attempted: bool
    reproduction_status: ReproductionStatus
    reproduction_observations: list[str] = Field(default_factory=list)
    execution_logs: list[ExecutionEvidence] = Field(default_factory=list)
    root_cause: RootCauseEvidence | None = None
    countermeasure: CountermeasureEvidence | None = None
    verification: VerificationEvidence | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
