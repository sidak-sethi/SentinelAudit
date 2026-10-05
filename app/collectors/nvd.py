from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.source_event import SourceEvent


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCollector:
    name = "nvd"

    def __init__(self, api_key: str = "", page_size: int = 200, page_delay: float = 1.0, timeout: float = 45.0):
        self.api_key = api_key
        self.page_size = page_size
        self.page_delay = page_delay
        self.timeout = timeout

    async def collect(self, start: datetime, end: datetime) -> list[SourceEvent]:
        headers = {"User-Agent": "SentinelAudit/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params_base = {
            "lastModStartDate": self._nvd_time(start),
            "lastModEndDate": self._nvd_time(end),
            "resultsPerPage": self.page_size,
        }
        events: list[SourceEvent] = []
        start_index = 0
        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            while True:
                params = {**params_base, "startIndex": start_index}
                payload = await self._request_json(client, params)
                vulnerabilities = payload.get("vulnerabilities", [])
                for item in vulnerabilities:
                    event = self._normalize(item)
                    if event:
                        events.append(event)
                total = int(payload.get("totalResults", len(events)))
                start_index += len(vulnerabilities)
                if not vulnerabilities or start_index >= total:
                    break
                if self.page_delay:
                    await asyncio.sleep(self.page_delay)
        return events

    async def collect_cve(self, cve_id: str) -> list[SourceEvent]:
        """Retrieve one specific CVE from the NVD CVE API."""
        cve_id = cve_id.strip().upper()

        if not cve_id.startswith("CVE-"):
            raise ValueError(f"Invalid CVE identifier: {cve_id}")

        headers = {"User-Agent": "SentinelAudit/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "cveId": cve_id,
            "resultsPerPage": 1,
            "startIndex": 0,
        }

        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            payload = await self._request_json(client, params)

        vulnerabilities = payload.get("vulnerabilities", [])
        events: list[SourceEvent] = []

        for item in vulnerabilities:
            event = self._normalize(item)
            if event:
                events.append(event)

        return events

    @staticmethod
    def _nvd_time(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    async def _request_json(self, client: httpx.AsyncClient, params: dict[str, Any]) -> dict[str, Any]:
        delays = [1.0, 2.0, 4.0, 8.0]
        for attempt in range(len(delays) + 1):
            try:
                response = await client.get(NVD_URL, params=params)
                if response.status_code in {429, 500, 502, 503, 504}:
                    if attempt >= len(delays):
                        response.raise_for_status()
                    await asyncio.sleep(delays[attempt])
                    continue
                response.raise_for_status()
                return response.json()
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt >= len(delays):
                    raise
                await asyncio.sleep(delays[attempt])
        raise RuntimeError("unreachable")

    def _normalize(self, item: dict[str, Any]) -> SourceEvent | None:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            return None
        descriptions = cve.get("descriptions") or []
        english = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        published = self._parse_dt(cve.get("published"))
        modified = self._parse_dt(cve.get("lastModified")) or datetime.now(timezone.utc)
        refs: list[str] = []
        for ref in cve.get("references") or []:
            url = ref.get("url")
            if url:
                refs.append(url)
        weaknesses = []
        for weakness in cve.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                if desc.get("value"):
                    weaknesses.append(desc["value"])
        versions: list[str] = []
        packages: list[str] = []
        technologies: list[str] = []
        configurations = cve.get("configurations") or []
        if isinstance(configurations, dict):
            configurations = [configurations]
        for config in configurations:
            self._collect_cpes(config.get("nodes") or [], technologies, packages, versions)
        cvss = self._extract_cvss(cve)
        severity = None
        if cvss is not None:
            severity = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
        return SourceEvent(
            event_id=f"nvd:{cve_id}",
            source="NVD",
            source_type="vulnerability_database",
            observed_at=modified,
            published_at=published,
            identifiers={"CVE": [cve_id], "CWE": weaknesses},
            affected_technology=sorted(set(technologies)),
            affected_packages=sorted(set(packages)),
            affected_versions=sorted(set(versions)),
            summary=english[:500],
            description=english,
            evidence=[{"type": "nvd_record", "id": cve_id}],
            references=sorted(set(refs)),
            severity=severity,
            cvss_score=cvss,
            extra={"nvd": {"id": cve_id}},
        )


    def _collect_cpes(self, nodes: list[dict[str, Any]], technologies: list[str], packages: list[str], versions: list[str]) -> None:
        for node in nodes:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria", "")
                if criteria:
                    parts = criteria.split(":")
                    if len(parts) >= 6:
                        vendor, product, exact_version = parts[3], parts[4], parts[5]
                        technologies.extend(x for x in [vendor, product] if x and x != "*" and x not in technologies)
                        if exact_version and exact_version != "*":
                            versions.append(exact_version)
                        if vendor == "python" or product in {"python", "requests", "django", "flask", "fastapi", "jinja2", "urllib3"}:
                            packages.append(product)
                ver = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                if ver:
                    versions.append(str(ver))
                ver = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                if ver:
                    versions.append(str(ver))
            self._collect_cpes(node.get("children") or [], technologies, packages, versions)
    @staticmethod
    def _extract_cvss(cve: dict[str, Any]) -> float | None:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                score = ((entries[0].get("cvssData") or {}).get("baseScore"))
                if score is not None:
                    return float(score)
        return None

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
