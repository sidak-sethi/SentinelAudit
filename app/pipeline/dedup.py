from __future__ import annotations

from collections import OrderedDict

from app.models.source_event import SourceEvent


def deduplicate(events: list[SourceEvent]) -> list[SourceEvent]:
    by_key: OrderedDict[str, SourceEvent] = OrderedDict()
    for event in events:
        ids = event.canonical_ids()
        key = ids[0] if ids else event.event_id
        if key not in by_key:
            by_key[key] = event
        else:
            by_key[key] = merge_events(by_key[key], event)
    return list(by_key.values())


def merge_events(left: SourceEvent, right: SourceEvent) -> SourceEvent:
    identifiers = {k: sorted(set(v)) for k, v in left.identifiers.items()}
    for key, values in right.identifiers.items():
        identifiers[key] = sorted(set(identifiers.get(key, [])) | set(values))
    return left.model_copy(update={
        "published_at": left.published_at or right.published_at,
        "identifiers": identifiers,
        "affected_technology": sorted(set(left.affected_technology) | set(right.affected_technology)),
        "affected_packages": sorted(set(left.affected_packages) | set(right.affected_packages)),
        "affected_versions": sorted(set(left.affected_versions) | set(right.affected_versions)),
        "description": left.description or right.description,
        "evidence": left.evidence + right.evidence,
        "references": sorted(set(left.references) | set(right.references)),
        "severity": left.severity or right.severity,
        "cvss_score": left.cvss_score if left.cvss_score is not None else right.cvss_score,
        "extra": {**right.extra, **left.extra},
    })
