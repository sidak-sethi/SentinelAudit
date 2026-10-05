from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.source_event import SourceEvent


@dataclass
class ThreatGroup:
    threat_id: str
    events: list[SourceEvent]

    @property
    def identifiers(self) -> set[str]:
        result: set[str] = set()
        for event in self.events:
            result.update(event.all_identifiers())
        return result

    @property
    def references(self) -> list[str]:
        return sorted({ref for event in self.events for ref in event.references})

    @property
    def packages(self) -> list[str]:
        return sorted({p for event in self.events for p in event.affected_packages})

    @property
    def descriptions(self) -> str:
        return "\n\n".join(f"[{event.source}] {event.summary}\n{event.description}" for event in self.events)

    def to_state(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "events": [event.model_dump(mode="json") for event in self.events],
        }

    @classmethod
    def from_state(cls, payload: dict[str, Any]) -> "ThreatGroup":
        return cls(
            threat_id=str(payload["threat_id"]),
            events=[SourceEvent.model_validate(item) for item in payload.get("events", [])],
        )


def correlate(events: list[SourceEvent]) -> list[ThreatGroup]:
    parent: dict[int, int] = {}
    group_by_id: dict[str, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> int:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra
        return ra

    for index, event in enumerate(events):
        parent[index] = index
        ids = event.all_identifiers()
        matched_roots = {find(group_by_id[i]) for i in ids if i in group_by_id}
        if matched_roots:
            root = min(matched_roots)
            for other in matched_roots:
                root = union(root, other)
            root = union(index, root)
        else:
            root = index
        for identifier in ids:
            existing = group_by_id.get(identifier)
            if existing is not None:
                root = union(root, existing)
            group_by_id[identifier] = root

    buckets: dict[int, list[SourceEvent]] = {}
    for index, event in enumerate(events):
        buckets.setdefault(find(index), []).append(event)

    groups: list[ThreatGroup] = []
    for group_events in buckets.values():
        threat_id = _threat_id(group_events[0])
        groups.append(ThreatGroup(threat_id=threat_id, events=group_events))
    return groups


def _threat_id(event: SourceEvent) -> str:
    ids = event.canonical_ids()
    if ids:
        priority = [i for i in ids if i.startswith("CVE-")]
        return priority[0] if priority else ids[0]
    return event.event_id
