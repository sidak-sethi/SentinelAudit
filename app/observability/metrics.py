from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from threading import Lock


METRIC_NAMES = (
    "source_events_received",
    "source_events_deduplicated",
    "python_relevant_events",
    "correlated_groups",
    "triage_requests",
    "triage_accepts",
    "triage_discards",
    "triage_uncertain",
    "triage_latency",
    "analysis_requests",
    "analysis_successes",
    "analysis_failures",
    "analysis_latency",
    "retry_count",
    "429_count",
    "503_count",
    "circuit_breaker_events",
    "research_targets",
    "research_reproductions",
    "research_verifications",
    "packages_created",
    "packages_exported",
    "checkpoint_updates",
)


@dataclass
class Metrics:
    values: Counter = field(default_factory=Counter)
    _lock: Lock = field(default_factory=Lock)

    def inc(self, name: str, amount: int = 1) -> None:
        if name not in METRIC_NAMES:
            raise KeyError(f"Unknown metric: {name}")
        with self._lock:
            self.values[name] += amount

    def observe(self, name: str, value: float) -> None:
        # Store latency sums as counters; callers can expose richer histograms later.
        self.inc(name, int(value * 1000))

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {name: self.values.get(name, 0) for name in METRIC_NAMES}
