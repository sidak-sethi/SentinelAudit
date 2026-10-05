from datetime import datetime, timezone

from app.models.source_event import SourceEvent
from app.pipeline.correlate import ThreatGroup
from app.storage.state import StateStore


def _group(threat_id="CVE-1"):
    return ThreatGroup(
        threat_id=threat_id,
        events=[
            SourceEvent(
                event_id=f"event:{threat_id}",
                source="test",
                source_type="test",
                identifiers={"CVE": [threat_id]},
                summary="x",
                description="x",
            )
        ],
    )


def test_checkpoint_does_not_advance_on_failure(tmp_path):
    store = StateStore(tmp_path / "state.json")
    first = datetime(2026, 10, 5, tzinfo=timezone.utc)
    second = datetime(2026, 10, 5, 1, tzinfo=timezone.utc)
    store.save_checkpoint(first, [])
    store.save_checkpoint(second, ["CVE-1"])
    state = store.load()
    assert state["last_successful_run"] == "2026-10-05T00:00:00Z"
    assert state["failed_threats"] == []
    store.record_failures(["CVE-2"])
    assert store.load()["failed_threats"] == ["CVE-2"]


def test_pending_retry_metadata_and_quarantine(tmp_path):
    store = StateStore(tmp_path / "state.json")
    group = _group()
    when = datetime(2026, 10, 5, 2, tzinfo=timezone.utc)

    records = store.update_pending_records([group], {"CVE-1": "analysis: boom"}, when)
    assert records[0].retry_count == 1
    assert records[0].status == "retry"
    store.save_checkpoint(when, [], pending_records=records)

    records = store.update_pending_records([group], {"CVE-1": "analysis: boom"}, when)
    store.save_checkpoint(when, [], pending_records=records)
    records = store.update_pending_records([group], {"CVE-1": "analysis: boom"}, when)

    assert records[0].retry_count == 3
    assert records[0].status == "quarantined"
    store.save_checkpoint(when, [], pending_records=records)

    assert store.load_pending_groups() == []
    persisted = store.load_pending_records()
    assert len(persisted) == 1
    assert persisted[0].status == "quarantined"
    assert persisted[0].last_error == "analysis: boom"


def test_legacy_pending_entry_loads_with_default_metadata(tmp_path):
    store = StateStore(tmp_path / "state.json")
    group = _group("CVE-OLD")
    store.save_checkpoint(datetime(2026, 10, 5, tzinfo=timezone.utc), [], pending_groups=[group])
    raw = store.load()
    assert raw["pending_threats"][0]["retry_count"] == 0
    records = store.load_pending_records()
    assert records[0].status == "pending"
    assert records[0].retry_count == 0
