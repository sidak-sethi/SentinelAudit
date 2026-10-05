from __future__ import annotations

import json
from pathlib import Path

import httpx

from app.models.research_evidence import ResearchTarget


class ArtifactResolver:
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def resolve(self, target: ResearchTarget) -> ResearchTarget:
        if target.source_artifact:
            return target
        if target.package == "unknown" or not target.vulnerable_version:
            return target
        if target.ecosystem.lower() not in {"python", "pypi"}:
            return target
        metadata_url = f"https://pypi.org/pypi/{target.package}/{target.vulnerable_version}/json"
        try:
            async with httpx.AsyncClient(timeout=30.0, headers={"User-Agent": "SentinelAudit/0.1"}) as client:
                response = await client.get(metadata_url)
                response.raise_for_status()
                data = response.json()
            urls = [x.get("url") for x in data.get("urls") or [] if x.get("url")]
            sdist = next((u for u in urls if u.endswith((".tar.gz", ".zip"))), None)
            if sdist:
                target = target.model_copy(update={"source_artifact": sdist})
            return target
        except httpx.HTTPError:
            return target

    async def download(self, target: ResearchTarget) -> Path | None:
        if not target.source_artifact or not target.source_artifact.startswith("http"):
            return None
        filename = Path(target.source_artifact.split("?", 1)[0]).name
        destination = self.work_dir / filename
        async with httpx.AsyncClient(timeout=60.0, headers={"User-Agent": "SentinelAudit/0.1"}) as client:
            response = await client.get(target.source_artifact)
            response.raise_for_status()
            destination.write_bytes(response.content)
        return destination
