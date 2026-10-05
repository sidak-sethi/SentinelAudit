from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SourceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    source: str
    source_type: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    published_at: datetime | None = None
    identifiers: dict[str, list[str]] = Field(default_factory=dict)
    affected_technology: list[str] = Field(default_factory=list)
    affected_packages: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    summary: str = ""
    description: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    severity: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    extra: dict[str, Any] = Field(default_factory=dict)

    def all_identifiers(self) -> set[str]:
        result: set[str] = set()
        for values in self.identifiers.values():
            result.update(v.upper() for v in values if v)
        return result

    def canonical_ids(self) -> list[str]:
        return sorted(self.all_identifiers())
