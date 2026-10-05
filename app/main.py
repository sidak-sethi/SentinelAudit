from __future__ import annotations

import argparse
import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

from app.collectors.cisa_kev import CISAKEVCollector
from app.collectors.epss import EPSSCollector
from app.collectors.github_advisories import GitHubAdvisoriesCollector
from app.collectors.nvd import NVDCollector
from app.collectors.osv import OSVCollector
from app.collectors.research_sources import ResearchSourcesCollector
from app.config import get_settings
from app.demo import run_demo
from app.llm.analyzer import ThreatAnalyzer
from app.observability.metrics import Metrics
from app.packaging.builder import ThreatPackageBuilder
from app.pipeline.correlate import ThreatGroup, correlate
from app.pipeline.dedup import deduplicate
from app.pipeline.ranking import sort_groups
from app.pipeline.relevance import is_python_relevant
from app.research.engine import ResearchEngine
from app.storage.state import PendingThreat, StateStore
from app.transfer.exporter import AtomicExporter

logger = logging.getLogger("sentinelaudit")


_FORCE_DEEP_PATTERNS = (
    r"\bexploit(?:ed|able|ability)?\b",
    r"\b(?:poc|proof[- ]of[- ]concept)\b",
    r"\bpublic(?:ly)? disclosed\b",
    r"\bremote(?:ly)?\b",
    r"\b(?:api[_ -]?key|access token|credential|secret|password)\b",
    r"\b(?:authentication|authorization)\b",
    r"\bssrf\b",
    r"\b(?:code execution|command injection|path traversal)\b",
)


def _should_force_deep_analysis(group: ThreatGroup) -> bool:
    """Prevent triage from dropping a clearly actionable Python threat.

    The group has already passed Python relevance filtering before this
    safeguard is called. Therefore package metadata is not required here;
    NVD frequently leaves affected_packages empty while the description
    contains strong Python-specific and exploitation evidence.
    """
    if not any(is_python_relevant(event) for event in group.events):
        return False

    evidence = group.descriptions.lower()

    matches = sum(
        bool(re.search(pattern, evidence))
        for pattern in _FORCE_DEEP_PATTERNS
    )

    return matches >= 2

def _merge_groups(
    pending_groups: list[ThreatGroup],
    current_groups: list[ThreatGroup],
) -> list[ThreatGroup]:
    """Merge persisted pending groups with newly discovered groups.

    Persisted pending work wins over newly discovered duplicates. This prevents
    duplicate processing when the same source window is observed again.
    """
    by_id: dict[str, ThreatGroup] = {}

    for group in pending_groups + current_groups:
        existing = by_id.get(group.threat_id)
        if existing is None:
            by_id[group.threat_id] = group
            continue

        events = deduplicate(existing.events + group.events)
        by_id[group.threat_id] = ThreatGroup(
            threat_id=group.threat_id,
            events=events,
        )

    return list(by_id.values())


def _order_groups(
    pending_groups: list[ThreatGroup],
    all_groups: list[ThreatGroup],
) -> list[ThreatGroup]:
    """Prioritize persisted work, then apply normal threat ranking."""
    pending_ids = {group.threat_id for group in pending_groups}
    ranked = sort_groups(all_groups)
    return sorted(
        ranked,
        key=lambda group: (
            0 if group.threat_id in pending_ids else 1,
            -int(any(event.source == "CISA KEV" for event in group.events)),
            -max((event.cvss_score or 0.0) for event in group.events),
            -len(group.events),
            group.threat_id,
        ),
    )


async def requeue_cve(cve_id: str) -> dict[str, object]:
    """Fetch one CVE from NVD and place it into the persistent queue."""
    settings = get_settings()
    state = StateStore(settings.state_file)

    collector = NVDCollector(
        settings.nvd_api_key,
        settings.max_events_per_page,
        settings.nvd_page_delay_seconds,
    )

    events = await collector.collect_cve(cve_id)

    if not events:
        raise RuntimeError(
            f"{cve_id} was not found in the NVD response"
        )

    relevant_events = [
        event
        for event in events
        if is_python_relevant(event)
    ]

    if not relevant_events:
        raise RuntimeError(
            f"{cve_id} was retrieved from NVD but is not "
            "currently classified as Python-relevant"
        )

    groups = correlate(relevant_events)

    if not groups:
        raise RuntimeError(
            f"{cve_id} could not be converted into a ThreatGroup"
        )

    # One CVE should normally correspond to one ThreatGroup. Sort to make the
    # behavior deterministic if future correlation rules emit multiple groups.
    group = sort_groups(groups)[0]

    queued = state.enqueue_threat_group(group)

    if queued:
        logger.info("[STATE] requeued %s", group.threat_id)
    else:
        logger.info("[STATE] %s is already present in the queue", group.threat_id)

    return {
        "threat_id": group.threat_id,
        "queued": queued,
    }


async def run_cycle():
    settings = get_settings()
    state = StateStore(settings.state_file)
    state_data = state.load()
    pending_records = state.load_pending_records()
    pending_groups = [
        record.group
        for record in pending_records
        if record.status in state.ACTIVE_STATUSES
    ]
    quarantined_ids = {
        record.group.threat_id
        for record in pending_records
        if record.status == "quarantined"
    }

    previous = state_data.get("last_successful_run")
    end = datetime.now(timezone.utc)

    if previous:
        start = datetime.fromisoformat(previous.replace("Z", "+00:00"))
    else:
        start = end - timedelta(hours=settings.initial_lookback_hours)

    logger.info(
        "[ONLINE] Fetching sources from %s to %s",
        start.isoformat(),
        end.isoformat(),
    )

    collectors = [
        NVDCollector(
            settings.nvd_api_key,
            settings.max_events_per_page,
            settings.nvd_page_delay_seconds,
        )
    ]

    if settings.research_source_urls:
        collectors.append(
            ResearchSourcesCollector(
                [
                    url.strip()
                    for url in settings.research_source_urls.split(",")
                    if url.strip()
                ]
            )
        )

    metrics = Metrics()
    raw_events_count = 0
    events = []
    collection_failures: list[str] = []

    for collector in collectors:
        try:
            batch = list(await collector.collect(start, end))
            events.extend(batch)
            raw_events_count += len(batch)
            metrics.inc("source_events_received", len(batch))
            logger.info(
                "[ONLINE] %s events: %d",
                collector.name,
                len(batch),
            )
        except Exception:
            collection_failures.append(collector.name)
            logger.exception("collector %s failed", collector.name)

    events = deduplicate(events)
    metrics.inc("source_events_deduplicated", len(events))

    relevant = [
        event
        for event in events
        if is_python_relevant(event)
    ]
    metrics.inc("python_relevant_events", len(relevant))

    current_groups = [
        group
        for group in sort_groups(correlate(relevant))
        if group.threat_id not in quarantined_ids
    ]
    metrics.inc("correlated_groups", len(current_groups))

    logger.info(
        "[ONLINE] events=%d deduped=%d python_relevant=%d new_groups=%d pending=%d",
        raw_events_count,
        len(events),
        len(relevant),
        len(current_groups),
        len(pending_groups),
    )

    cves = {
        identifier
        for event in relevant
        for identifier in event.identifiers.get("CVE", [])
    }

    enrich_events = []
    enrichment_failures: list[str] = []

    if settings.enable_osv:
        try:
            enrich_events.extend(
                await OSVCollector().enrich_identifiers(cves)
            )
        except Exception:
            enrichment_failures.append("osv")
            logger.exception("OSV enrichment failed")

    if settings.enable_github_advisories:
        try:
            ghsas = {
                identifier
                for event in relevant
                for identifier in event.identifiers.get("GHSA", [])
            }
            enrich_events.extend(
                await GitHubAdvisoriesCollector(
                    settings.github_token
                ).enrich_identifiers(ghsas)
            )
        except Exception:
            enrichment_failures.append("github_advisories")
            logger.exception("GitHub advisory enrichment failed")

    if settings.enable_cisa_kev:
        try:
            enrich_events.extend(
                await CISAKEVCollector().enrich_cves(cves)
            )
        except Exception:
            enrichment_failures.append("cisa_kev")
            logger.exception("CISA KEV enrichment failed")

    if settings.enable_epss and cves:
        try:
            epss = await EPSSCollector().enrich(sorted(cves))
            for event in relevant:
                for cve in event.identifiers.get("CVE", []):
                    if cve in epss:
                        event.extra["epss"] = epss[cve]
        except Exception:
            enrichment_failures.append("epss")
            logger.exception("EPSS enrichment failed")

    if enrich_events:
        current_groups = [
            group
            for group in sort_groups(correlate(relevant + enrich_events))
            if group.threat_id not in quarantined_ids
        ]

    all_groups = _merge_groups(
        pending_groups,
        current_groups,
    )
    ordered_groups = _order_groups(
        pending_groups,
        all_groups,
    )

    max_groups = settings.max_python_threat_groups_per_cycle
    selected_groups = ordered_groups[:max_groups]
    deferred_groups = ordered_groups[max_groups:]

    logger.info(
        "[ONLINE] processing=%d total=%d deferred=%d cap=%d",
        len(selected_groups),
        len(ordered_groups),
        len(deferred_groups),
        max_groups,
    )

    failed: list[str] = []
    failure_errors: dict[str, str] = {}
    completed_ids: set[str] = set()

    if selected_groups:
        analyzer = ThreatAnalyzer.from_settings(settings)
        research_engine = ResearchEngine(settings)
        builder = ThreatPackageBuilder()
        exporter = AtomicExporter(settings.outgoing_dir)

        try:
            triage_results = await analyzer.triage_many(selected_groups)
            analysis_inputs = []

            for group, result, error in triage_results:
                metrics.inc("triage_requests")

                if error is not None:
                    failed.append(group.threat_id)
                    failure_errors[group.threat_id] = f"triage: {error}"
                    logger.error(
                        "threat %s triage failed: %s",
                        group.threat_id,
                        error,
                        exc_info=(type(error), error, error.__traceback__),
                    )
                    continue

                metrics.observe(
                    "triage_latency",
                    result.telemetry.latency or 0.0,
                )

                force_deep = (
                    not result.value.should_deep_analyze
                    and _should_force_deep_analysis(group)
                )

                if result.value.should_deep_analyze or force_deep:
                    metrics.inc("triage_accepts")
                    if force_deep:
                        logger.warning(
                            "[TRIAGE] %s discard overridden by deterministic "
                            "exploitability safeguard: %s",
                            group.threat_id,
                            result.value.reason,
                        )
                    analysis_inputs.append((group, result.value))
                elif result.value.confidence >= settings.llm_triage_min_confidence:
                    metrics.inc("triage_discards")
                    completed_ids.add(group.threat_id)
                    logger.info(
                        "[TRIAGE] %s discarded: %s",
                        group.threat_id,
                        result.value.reason,
                    )
                else:
                    metrics.inc("triage_uncertain")
                    analysis_inputs.append((group, result.value))

            analysis_results = await analyzer.analyze_many(analysis_inputs)

            for group, result, error in analysis_results:
                metrics.inc("analysis_requests")

                if error is not None:
                    metrics.inc("analysis_failures")
                    failed.append(group.threat_id)
                    failure_errors[group.threat_id] = f"analysis: {error}"
                    logger.error(
                        "threat %s analysis failed: %s",
                        group.threat_id,
                        error,
                        exc_info=(type(error), error, error.__traceback__),
                    )
                    continue

                metrics.inc("analysis_successes")
                metrics.observe(
                    "analysis_latency",
                    result.telemetry.latency or 0.0,
                )

                try:
                    metrics.inc("research_targets")
                    research = await research_engine.research(
                        group,
                        result.value,
                    )

                    if research.reproduction_status.value == "REPRODUCED":
                        metrics.inc("research_reproductions")

                    if research.verification and research.verification.result.value == "VERIFIED":
                        metrics.inc("research_verifications")

                    package = builder.build(
                        group,
                        result.value,
                        research,
                    )
                    metrics.inc("packages_created")

                    path = exporter.export(package)
                    metrics.inc("packages_exported")
                    completed_ids.add(group.threat_id)

                    logger.info(
                        "[EXPORT] %s -> %s",
                        group.threat_id,
                        path,
                    )
                except Exception as exc:
                    failed.append(group.threat_id)
                    failure_errors[group.threat_id] = f"research/package: {exc}"
                    logger.exception(
                        "threat %s research/package failed",
                        group.threat_id,
                    )
        finally:
            await analyzer.close()

    metrics.inc("retry_count", len(failure_errors))
    failed_ids = set(failed)

    # Anything not selected remains pending. Selected threats that failed also
    # remain pending so a later cycle can retry them.
    pending_after_cycle = [
        group
        for group in ordered_groups
        if group.threat_id not in completed_ids
    ]

    # Keep failed IDs explicitly in the pending set even if future changes to
    # completion handling accidentally classify them otherwise.
    pending_by_id = {group.threat_id: group for group in pending_after_cycle}
    for group in selected_groups:
        if group.threat_id in failed_ids:
            pending_by_id[group.threat_id] = group

    pending_after_cycle = list(pending_by_id.values())

    pending_records_after = state.update_pending_records(
        pending_after_cycle,
        failure_errors,
        end,
        max_retries=StateStore.MAX_RETRIES,
    )
    quarantined_this_cycle = [
        record.group.threat_id
        for record in pending_records_after
        if record.status == "quarantined"
        and record.group.threat_id in failure_errors
    ]
    if quarantined_this_cycle:
        logger.error(
            "[STATE] quarantined after %d failed attempts: %s",
            StateStore.MAX_RETRIES,
            quarantined_this_cycle,
        )

    active_pending_records = [
        record
        for record in pending_records_after
        if record.status in state.ACTIVE_STATUSES
    ]
    if collection_failures or enrichment_failures:
        all_failures = (
            failed
            + [f"collector:{name}" for name in collection_failures]
            + [f"enrichment:{name}" for name in enrichment_failures]
        )
        state.record_failures(
            all_failures,
            pending_records=pending_records_after,
        )
        logger.error(
            "[STATE] checkpoint not advanced; failures=%s pending=%d quarantined=%d",
            all_failures,
            len(active_pending_records),
            len(pending_records_after) - len(active_pending_records),
        )
    elif failed:
        # The source checkpoint can still advance because the failed threat is
        # retained in pending_threats and will be retried independently.
        state.save_checkpoint(
            end,
            [],
            pending_records=pending_records_after,
        )
        metrics.inc("checkpoint_updates")
        logger.warning(
            "[STATE] checkpoint advanced with %d active pending threats (%d quarantined)",
            len(active_pending_records),
            len(pending_records_after) - len(active_pending_records),
        )
    else:
        state.save_checkpoint(
            end,
            [],
            pending_records=pending_records_after,
        )
        metrics.inc("checkpoint_updates")
        logger.info(
            "[STATE] checkpoint advanced to %s pending=%d quarantined=%d metrics=%s",
            end.isoformat(),
            len(active_pending_records),
            len(pending_records_after) - len(active_pending_records),
            metrics.snapshot(),
        )

    return {
        "events": len(events),
        "relevant": len(relevant),
        "groups": len(all_groups),
        "processed_groups": len(selected_groups),
        "deferred_groups": len(deferred_groups),
        "pending_groups": len(active_pending_records),
        "quarantined_groups": len(pending_records_after) - len(active_pending_records),
        "failed": failed,
    }


async def main_async(args):
    settings = get_settings()

    logging.basicConfig(
        level=getattr(
            logging,
            settings.log_level.upper(),
            logging.INFO,
        ),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.demo:
        await run_demo(settings)
        return

    if args.requeue_cve:
        result = await requeue_cve(args.requeue_cve)
        logger.info("[STATE] requeue result: %s", result)
        return

    if args.continuous:
        while True:
            try:
                await run_cycle()
            except Exception:
                logger.exception("cycle failed")

            await asyncio.sleep(
                settings.poll_interval_seconds
            )
    else:
        await run_cycle()


def parse_args():
    parser = argparse.ArgumentParser(
        description="SentinelAudit Online"
    )

    mode = parser.add_mutually_exclusive_group()

    mode.add_argument(
        "--demo",
        action="store_true",
        help="run deterministic full-pipeline fixture",
    )

    mode.add_argument(
        "--continuous",
        action="store_true",
        help="poll continuously",
    )

    mode.add_argument(
        "--once",
        action="store_true",
        help="run a single live cycle",
    )

    mode.add_argument(
        "--requeue-cve",
        metavar="CVE_ID",
        help="fetch one CVE from NVD and add it to the persistent queue",
    )

    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(
        main_async(parse_args())
    )
