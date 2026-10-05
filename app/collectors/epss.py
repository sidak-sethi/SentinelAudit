from __future__ import annotations

import httpx


class EPSSCollector:
    name = "epss"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def enrich(self, cves: list[str]) -> dict[str, float]:
        values: dict[str, float] = {}
        if not cves:
            return values
        async with httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": "SentinelAudit/0.1"}) as client:
            for offset in range(0, len(cves), 100):
                batch = cves[offset:offset + 100]
                response = await client.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(batch)})
                response.raise_for_status()
                payload = response.json()
                for row in payload.get("data") or []:
                    try:
                        values[row["cve"].upper()] = float(row["epss"])
                    except (KeyError, TypeError, ValueError):
                        continue
        return values
