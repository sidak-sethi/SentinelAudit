from app.collectors.research_sources import ResearchSourcesCollector


def test_research_event_id_is_deterministic():
    collector = ResearchSourcesCollector(["https://example.com/feed.xml"])
    record = {"title": "Python security note", "description": "Details", "link": "https://example.com/item"}
    first = collector._event("https://example.com/feed.xml", record)
    second = collector._event("https://example.com/feed.xml", record)
    assert first.event_id == second.event_id
