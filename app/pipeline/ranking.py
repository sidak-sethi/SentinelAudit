from __future__ import annotations

from app.pipeline.correlate import ThreatGroup


def rank_group(group: ThreatGroup) -> tuple[int, float, int]:
    kev = any(e.source == "CISA KEV" for e in group.events)
    cvss = max((e.cvss_score or 0.0) for e in group.events)
    evidence_count = len(group.events)
    return (1 if kev else 0, cvss, evidence_count)


def sort_groups(groups: list[ThreatGroup]) -> list[ThreatGroup]:
    return sorted(groups, key=rank_group, reverse=True)
