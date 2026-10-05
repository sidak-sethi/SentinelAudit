from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

import httpx

from app.models.source_event import SourceEvent


class GitHubAdvisoriesCollector:
    name = "github_advisories"

    def __init__(self, token: str = "", timeout: float = 30.0):
        self.token = token
        self.timeout = timeout

    async def collect(self, start: datetime, end: datetime) -> list[SourceEvent]:
        return []

    async def enrich_identifiers(self, identifiers: Iterable[str]) -> list[SourceEvent]:
        ghsas = sorted({i.upper() for i in identifiers if i.upper().startswith("GHSA-")})
        if not ghsas:
            return []
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "SentinelAudit/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        results: list[SourceEvent] = []
        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            for ghsa in ghsas:
                try:
                    response = await client.get(f"https://api.github.com/advisories/{ghsa}")
                    if response.status_code == 404:
                        continue
                    response.raise_for_status()
                    data = response.json()
                    event = self._normalize(data)
                    if event:
                        results.append(event)
                except httpx.HTTPError:
                    continue
        return results

    def _normalize(self, data: dict) -> SourceEvent | None:
        ghsa_id = data.get("ghsa_id")
        if not ghsa_id:
            return None
        published = self._dt(data.get("published_at"))
        modified = self._dt(data.get("updated_at")) or datetime.now(timezone.utc)
        refs: list[str] = []
        if data.get("html_url"):
            refs.append(data["html_url"])
        packages = []
        for vuln in data.get("vulnerabilities") or []:
            package = vuln.get("package") or {}
            if package.get("name"):
                packages.append(package["name"])
        cve = data.get("cve_id")
        identifiers = {"GHSA": [ghsa_id]}
        if cve:
            identifiers["CVE"] = [cve]
        return SourceEvent(
            event_id=f"github:{ghsa_id}",
            source="GitHub Security Advisories",
            source_type="security_advisory",
            observed_at=modified,
            published_at=published,
            identifiers=identifiers,
            affected_technology=[data.get("ecosystem") or "unknown"],
            affected_packages=sorted(set(packages)),
            affected_versions=[],
            summary=(data.get("summary") or "")[:500],
            description=data.get("description") or "",
            evidence=[{"type": "github_advisory", "id": ghsa_id}],
            references=refs,
            severity=(data.get("severity") or "").upper() or None,
            extra={"withdrawn_at": data.get("withdrawn_at"), "cvss": data.get("cvss")},
        )

    @staticmethod
    def _dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
