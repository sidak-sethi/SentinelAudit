from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

ThreatStatus = Literal[
    "confirmed",
    "not_applicable",
    "uncertain",
    "ai_error",
    "guard_rejected",
]

PatchStatus = Literal["fixed", "unresolved"]
FinalAuditStatus = Literal["fixed", "not_fixed", "uncertain"]


class ThreatPackage(BaseModel):
    """JSON contract consumed by the offline SentinelAudit Guard agent.

    ``package_id`` is retained internally only so the existing atomic exporter
    can continue generating a stable filename. It is explicitly excluded from
    the serialized JSON payload because the offline contract does not contain it.
    """

    model_config = ConfigDict(extra="forbid")

    package_id: str = Field(exclude=True)
    threat_id: str
    title: str
    cve: str | None = None
    attack_type: str
    severity: str

    source: dict[str, Any]

    status: ThreatStatus
    patch_status: PatchStatus | None = None

    repository: str | None = None
    branch: str | None = None

    affected_files: list[str] = Field(default_factory=list)
    affected_lines: list[int] = Field(default_factory=list)

    confidence: float = Field(ge=0.0, le=1.0)
    vulnerability_hypothesis: str
    recommended_fix: str

    security_test_path: str | None = None
    code: dict[str, dict[str, str | None]] = Field(default_factory=dict)
    diff: str | None = None

    patch_attempts: int = Field(default=0, ge=0)
    final_audit: FinalAuditStatus | None = None

    reason: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("package_id")
    @classmethod
    def package_id_format(cls, value: str) -> str:
        if not value.startswith("PKG-"):
            raise ValueError("package_id must start with PKG-")
        return value

    @classmethod
    def new_id(cls) -> str:
        return f"PKG-{uuid4().hex[:12].upper()}"
