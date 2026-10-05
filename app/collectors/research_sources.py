from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

import httpx

from app.models.source_event import SourceEvent


class ResearchSourcesCollector:
    name = "research_sources"

    def __init__(self, urls: list[str], timeout: float = 30.0):
        self.urls = [u for u in urls if u]
        self.timeout = timeout

    async def collect(self, start: datetime, end: datetime) -> list[SourceEvent]:
        results: list[SourceEvent] = []
        async with httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": "SentinelAudit/0.1"}) as client:
            for url in self.urls:
                try:
                    response = await client.get(url)
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "")
                    if "json" in content_type or url.lower().endswith(".json"):
                        results.extend(self._parse_json(url, response.text))
                    elif "xml" in content_type or url.lower().endswith((".xml", "/rss", "/atom")):
                        results.extend(self._parse_xml(url, response.text))
                except (httpx.HTTPError, ValueError, ET.ParseError):
                    continue
        return results

    def _parse_json(self, url: str, text: str) -> list[SourceEvent]:
        data = json.loads(text)
        records = data if isinstance(data, list) else data.get("items") or data.get("entries") or [data]
        return [self._event(url, r) for r in records if isinstance(r, dict)]

    def _parse_xml(self, url: str, text: str) -> list[SourceEvent]:
        root = ET.fromstring(text)
        events = []
        for item in root.iter():
            if item.tag.endswith("item") or item.tag.endswith("entry"):
                values = {child.tag.split("}")[-1]: (child.text or "").strip() for child in item}
                events.append(self._event(url, values))
        return events

    def _event(self, url: str, record: dict) -> SourceEvent:
        title = str(record.get("title") or record.get("name") or "Untrusted security research item")
        description = str(record.get("description") or record.get("summary") or record.get("details") or "")
        link = record.get("link") or record.get("url") or url
        source_host = urlparse(url).netloc
        identifiers = {"CVE": [x for x in self._extract_ids(title + " " + description) if x.startswith("CVE-")]}
        ghsa = [x for x in self._extract_ids(title + " " + description) if x.startswith("GHSA-")]
        if ghsa:
            identifiers["GHSA"] = ghsa
        stable_id = hashlib.sha256(
            f"{source_host}|{title}|{link}".encode("utf-8")
        ).hexdigest()[:16]
        return SourceEvent(
            event_id=f"research:{source_host}:{stable_id}",
            source=source_host or "research",
            source_type="untrusted_research",
            observed_at=datetime.now(timezone.utc),
            identifiers=identifiers,
            affected_technology=[],
            affected_packages=[],
            affected_versions=[],
            summary=title[:500],
            description=description,
            evidence=[{"type": "external_research", "url": url, "content_untrusted": True}],
            references=[str(link)],
        )

    @staticmethod
    def _extract_ids(text: str) -> list[str]:
        tokens = {token.strip(".,:;()[]{}<>\"'") for token in text.replace("/", " ").split()}
        return sorted({token.upper() for token in tokens if token.upper().startswith(("CVE-", "GHSA-", "OSV-"))})
