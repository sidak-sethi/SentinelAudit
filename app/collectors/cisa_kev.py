from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.models.source_event import SourceEvent


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCollector:
    name = "cisa_kev"

    def __init__(self, timeout: float = 45.0):
        self.timeout = timeout
        self._cache: dict[str, dict] | None = None

    async def collect(self, start: datetime, end: datetime) -> list[SourceEvent]:
        payload = await self._fetch()
        events = []
        for item in payload.get("vulnerabilities") or []:
            date_added = self._dt(item.get("dateAdded"))
            if date_added and start.astimezone(timezone.utc) <= date_added <= end.astimezone(timezone.utc):
                event = self._normalize(item)
                if event:
                    events.append(event)
        return events

    async def enrich_cves(self, cves: set[str]) -> list[SourceEvent]:
        payload = await self._fetch()
        lookup = {str(item.get("cveID", "")).upper(): item for item in payload.get("vulnerabilities") or []}
        return [self._normalize(lookup[cve]) for cve in sorted(cves) if cve in lookup]

    async def _fetch(self) -> dict:
        if self._cache is not None:
            return {"vulnerabilities": list(self._cache.values())}
        async with httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": "SentinelAudit/0.1"}) as client:
            response = await client.get(KEV_URL)
            response.raise_for_status()
            payload = response.json()
        self._cache = {str(x.get("cveID")): x for x in payload.get("vulnerabilities") or [] if x.get("cveID")}
        return payload

    def _normalize(self, item: dict) -> SourceEvent | None:
        cve = item.get("cveID")
        if not cve:
            return None
        date_added = self._dt(item.get("dateAdded"))
        ref = item.get("notes") or item.get("requiredAction") or ""
        return SourceEvent(
            event_id=f"cisa-kev:{cve}",
            source="CISA KEV",
            source_type="exploitation_catalog",
            observed_at=date_added or datetime.now(timezone.utc),
            published_at=date_added,
            identifiers={"CVE": [cve]},
            affected_technology=[item.get("vendorProject", ""), item.get("product", "")],
            affected_packages=[],
            affected_versions=[],
            summary=f"Known exploited vulnerability: {item.get('vulnerabilityName', cve)}",
            description=f"Vendor/product: {item.get('vendorProject', '')} / {item.get('product', '')}. Required action: {item.get('requiredAction', '')}",
            evidence=[{"type": "cisa_kev", "id": cve, "notes": ref}],
            references=[],
            extra={"dueDate": item.get("dueDate"), "knownRansomwareCampaignUse": item.get("knownRansomwareCampaignUse")},
        )

    @staticmethod
    def _dt(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
