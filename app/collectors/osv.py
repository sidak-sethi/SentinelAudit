from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

import httpx

from app.models.source_event import SourceEvent


class OSVCollector:
    name = "osv"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.base = "https://api.osv.dev/v1/vulns"

    async def collect(self, start: datetime, end: datetime) -> list[SourceEvent]:
        return []

    async def enrich_identifiers(self, identifiers: Iterable[str]) -> list[SourceEvent]:
        ids = [i for i in identifiers if i]
        if not ids:
            return []
        events: list[SourceEvent] = []
        async with httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": "SentinelAudit/0.1"}) as client:
            for vuln_id in sorted(set(ids)):
                try:
                    response = await client.get(f"{self.base}/{vuln_id}")
                    if response.status_code == 404:
                        continue
                    response.raise_for_status()
                    event = self._normalize(response.json())
                    if event:
                        events.append(event)
                except httpx.HTTPError:
                    continue
        return events

    def _normalize(self, payload: dict) -> SourceEvent | None:
        vuln_id = payload.get("id")
        if not vuln_id:
            return None
        aliases = [a for a in payload.get("aliases") or [] if a]
        published = self._dt(payload.get("published"))
        modified = self._dt(payload.get("modified")) or datetime.now(timezone.utc)
        refs = [x.get("url") for x in payload.get("references") or [] if x.get("url")]
        packages: list[str] = []
        versions: list[str] = []
        technologies = [payload.get("package", {}).get("ecosystem", "OSV")]
        for affected in payload.get("affected") or []:
            package = affected.get("package") or {}
            if package.get("name"):
                packages.append(package["name"])
            for r in (affected.get("ranges") or []):
                for event in r.get("events") or []:
                    versions.extend(v for k, v in event.items() if v)
            versions.extend(str(v) for v in affected.get("versions") or [])
        return SourceEvent(
            event_id=f"osv:{vuln_id}",
            source="OSV",
            source_type="vulnerability_database",
            observed_at=modified,
            published_at=published,
            identifiers={"OSV": [vuln_id], **({"CVE": [x for x in aliases if x.upper().startswith("CVE-")]} if any(x.upper().startswith("CVE-") for x in aliases) else {})},
            affected_technology=technologies,
            affected_packages=sorted(set(packages)),
            affected_versions=sorted(set(versions)),
            summary=(payload.get("summary") or "")[:500],
            description=payload.get("details") or payload.get("summary") or "",
            evidence=[{"type": "osv_record", "id": vuln_id}],
            references=sorted(set(refs)),
            extra={"aliases": aliases, "database_specific": payload.get("database_specific", {})},
        )

    @staticmethod
    def _dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
