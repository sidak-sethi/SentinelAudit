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
    """Richer internal Online result before adapting it to the Guard JSON.

    ``package_id`` is retained internally only so the existing atomic exporter
    can continue generating a stable filename. The exporter emits only the
    Guard's exact allowlisted contract; these additional research fields stay
    inside the Online model.
    """

    model_config = ConfigDict(extra="forbid")

    package_id: str = Field(exclude=True)
    threat_id: str
    title: str
    cve: str | None = None
    attack_type: str
    severity: str

    # Evidence that the Guard's narrow contract needs but the dashboard
    # result shape does not expose directly.
    affected_component: str = "unknown"
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    test_strategy: str = ""

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
