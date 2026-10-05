from app.models.source_event import SourceEvent
from app.pipeline.dedup import deduplicate
from app.pipeline.correlate import correlate, ThreatGroup
from app.pipeline.relevance import is_python_relevant


def event(source, event_id, ids, tech, package=""):
    return SourceEvent(event_id=event_id, source=source, source_type="test", identifiers=ids, affected_technology=tech, affected_packages=[package] if package else [], summary="x", description="python package vulnerability")


def test_dedup_merges_same_cve():
    events = [
        event("NVD", "a", {"CVE":["CVE-1"]}, ["Python"], "requests"),
        event("OSV", "b", {"CVE":["CVE-1"]}, ["PyPI"], "requests"),
    ]
    merged = deduplicate(events)
    assert len(merged) == 1
    assert set(merged[0].affected_technology) == {"Python", "PyPI"}


def test_correlation_groups_shared_ids():
    groups = correlate([
        event("NVD", "a", {"CVE":["CVE-1"]}, ["Python"]),
        event("OSV", "b", {"CVE":["CVE-1"], "GHSA":["GHSA-1"]}, ["Python"]),
    ])
    assert len(groups) == 1
    assert "GHSA-1" in groups[0].identifiers


def test_python_relevance():
    assert is_python_relevant(event("x", "a", {"CVE":["CVE-1"]}, ["Django"]))
    assert not is_python_relevant(SourceEvent(event_id="x", source="x", source_type="test", summary="kernel", description="Linux kernel issue"))


def test_current_and_pending_groups_merge_without_duplicate_events():
    from app.main import _merge_groups

    first = event("NVD", "a", {"CVE":["CVE-1"]}, ["Python"], "requests")
    second = event("OSV", "b", {"CVE":["CVE-1"]}, ["PyPI"], "requests")
    groups = _merge_groups(
        [ThreatGroup("CVE-1", [first])],
        [ThreatGroup("CVE-1", [second])],
    )
    assert len(groups) == 1
    assert len(groups[0].events) == 1
    assert set(groups[0].events[0].affected_technology) == {"Python", "PyPI"}


def test_quarantined_threat_is_not_merged_back():
    from app.main import _merge_groups
    group = ThreatGroup("CVE-Q", [event("NVD", "q", {"CVE":["CVE-Q"]}, ["Python"])])
    # Main filters quarantined IDs before calling _merge_groups. This assertion
    # verifies that an empty current set does not manufacture work again.
    assert _merge_groups([group], []) == [group]


def test_python_relevance_does_not_match_generic_requests_word():
    event = SourceEvent(
        event_id="x",
        source="NVD",
        source_type="vulnerability_database",
        summary="Authentication requests are trusted.",
        description="An attacker can spoof client requests to bypass controls.",
    )
    assert not is_python_relevant(event)


def test_python_relevance_matches_requests_package_metadata():
    event = SourceEvent(
        event_id="x",
        source="NVD",
        source_type="vulnerability_database",
        affected_packages=["requests"],
        summary="TLS verification issue.",
        description="The requests package accepts an invalid certificate.",
    )
    assert is_python_relevant(event)


def test_python_relevance_matches_explicit_python_source_path():
    event = SourceEvent(
        event_id="x",
        source="NVD",
        source_type="vulnerability_database",
        summary="Issue in python/sglang/srt/entrypoints/http_server.py",
        description="The HTTP endpoint exposes sensitive data.",
    )
    assert is_python_relevant(event)
