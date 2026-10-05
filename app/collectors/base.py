from __future__ import annotations

from datetime import datetime
from typing import Protocol, Sequence

from app.models.source_event import SourceEvent


class Collector(Protocol):
    name: str

    async def collect(self, start: datetime, end: datetime) -> Sequence[SourceEvent]:
        ...
