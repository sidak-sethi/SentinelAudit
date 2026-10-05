from datetime import datetime, timezone
from pathlib import Path

import pytest

import app.main as main
from app.config import Settings
from app.llm.client import LLMRequestTelemetry, LLMResult
from app.models.source_event import SourceEvent
from app.models.threat_triage import ThreatTriage
from app.pipeline.correlate import ThreatGroup
from app.storage.state import StateStore


class FakeNVD:
    name = "nvd"

    def __init__(self, *args, **kwargs):
        pass

    async def collect(self, start, end):
        return [
            SourceEvent(
                event_id="nvd:test",
                source="NVD",
                source_type="test",
                identifiers={"CVE": ["CVE-TEST"]},
                affected_technology=["Python"],
                summary="test",
                description="python vulnerability",
            )
        ]


class FakeResearchFeed:
    name = "research_sources"

    def __init__(self, urls):
        pass

    async def collect(self, start, end):
        return []


class AlwaysFailAnalyzer:
    @classmethod
    def from_settings(cls, settings):
        return cls()

    async def triage_many(self, groups):
        rows = []
        for group in groups:
            telemetry = LLMRequestTelemetry(
                request_id="test",
                provider="fake",
                model="fake-20b",
                stage="triage",
                threat_id=group.threat_id,
                started_at=datetime.now(timezone.utc),
                latency=0.001,
            )
            rows.append(
                (
                    group,
                    LLMResult(
                        value=ThreatTriage(
                            should_deep_analyze=True,
                            confidence=1.0,
                            reason="test",
                        ),
                        telemetry=telemetry,
                    ),
                    None,
                )
            )
        return rows

    async def analyze_many(self, items):
        return [
            (group, None, RuntimeError("structured output truncated"))
            for group, _ in items
        ]

    async def close(self):
        pass


class NoWorkAnalyzer:
    @classmethod
    def from_settings(cls, settings):
        raise AssertionError("LLM provider should not initialize when there is no work")


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(
        state_file=tmp_path / "state.json",
        outgoing_dir=tmp_path / "outgoing",
        research_work_dir=tmp_path / "research",
        research_source_urls="fake://feed",
        enable_osv=False,
        enable_cisa_kev=False,
        enable_epss=False,
        enable_github_advisories=False,
    )
    settings.prepare_dirs()
    return settings


def test_enqueue_threat_group_adds_new_pending(tmp_path):
    state = StateStore(tmp_path / "state.json")

    group = ThreatGroup(
        threat_id="CVE-TEST-ENQUEUE",
        events=[
            SourceEvent(
                event_id="nvd:CVE-TEST-ENQUEUE",
                source="NVD",
                source_type="vulnerability_database",
                identifiers={"CVE": ["CVE-TEST-ENQUEUE"]},
                summary="Python package vulnerability",
                description="Python package issue.",
                affected_packages=["requests"],
            )
        ],
    )

    assert state.enqueue_threat_group(group) is True
    assert state.enqueue_threat_group(group) is False

    pending = state.load_pending_records()

    assert len(pending) == 1
    assert pending[0].group.threat_id == "CVE-TEST-ENQUEUE"


@pytest.mark.asyncio
async def test_main_quarantines_repeated_analysis_failure(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "NVDCollector", FakeNVD)
    monkeypatch.setattr(main, "ResearchSourcesCollector", FakeResearchFeed)
    monkeypatch.setattr(main, "ThreatAnalyzer", AlwaysFailAnalyzer)

    for _ in range(3):
        result = await main.run_cycle()
        assert result["failed"] == ["CVE-TEST"]

    state = StateStore(settings.state_file)
    records = state.load_pending_records()
    assert [(r.group.threat_id, r.retry_count, r.status) for r in records] == [
        ("CVE-TEST", 3, "quarantined")
    ]

    fourth = await main.run_cycle()
    assert fourth["processed_groups"] == 0
    assert fourth["pending_groups"] == 0
    assert fourth["quarantined_groups"] == 1


@pytest.mark.asyncio
async def test_main_does_not_initialize_llm_without_work(monkeypatch, tmp_path):
    settings = _settings(tmp_path)

    class EmptyNVD(FakeNVD):
        async def collect(self, start, end):
            return []

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "NVDCollector", EmptyNVD)
    monkeypatch.setattr(main, "ResearchSourcesCollector", FakeResearchFeed)
    monkeypatch.setattr(main, "ThreatAnalyzer", NoWorkAnalyzer)

    result = await main.run_cycle()
    assert result["processed_groups"] == 0
    assert StateStore(settings.state_file).load()["last_successful_run"] is not None

class FakeRequeueNVD:
    name = "nvd"

    def __init__(self, *args, **kwargs):
        pass

    async def collect_cve(self, cve_id):
        assert cve_id.upper() == "CVE-2026-105245"
        return [
            SourceEvent(
                event_id="nvd:CVE-2026-105245",
                source="NVD",
                source_type="vulnerability_database",
                identifiers={"CVE": ["CVE-2026-105245"]},
                affected_packages=["sglang"],
                affected_technology=["Python"],
                summary="sglang vulnerability",
                description=(
                    "A Python vulnerability in sglang. "
                    "The issue may be exploited remotely."
                ),
                severity="LOW",
                cvss_score=2.9,
            )
        ]


@pytest.mark.asyncio
async def test_requeue_cve_adds_python_threat(monkeypatch, tmp_path):
    settings = _settings(tmp_path)

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "NVDCollector", FakeRequeueNVD)

    result = await main.requeue_cve("CVE-2026-105245")

    assert result == {
        "threat_id": "CVE-2026-105245",
        "queued": True,
    }

    records = StateStore(settings.state_file).load_pending_records()

    assert len(records) == 1
    assert records[0].group.threat_id == "CVE-2026-105245"
    assert records[0].status == "pending"


@pytest.mark.asyncio
async def test_requeue_cve_is_idempotent(monkeypatch, tmp_path):
    settings = _settings(tmp_path)

    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "NVDCollector", FakeRequeueNVD)

    first = await main.requeue_cve("CVE-2026-105245")
    second = await main.requeue_cve("CVE-2026-105245")

    assert first["queued"] is True
    assert second["queued"] is False

    records = StateStore(settings.state_file).load_pending_records()

    assert len(records) == 1

