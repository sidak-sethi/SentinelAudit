from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from app.models.source_event import SourceEvent
from app.pipeline.correlate import ThreatGroup

PendingStatus = Literal["pending", "retry", "quarantined"]


@dataclass
class PendingThreat:
    group: ThreatGroup
    retry_count: int = 0
    last_error: str | None = None
    last_attempt_at: datetime | None = None
    status: PendingStatus = "pending"

    def to_state(self) -> dict[str, Any]:
        return {
            "threat_id": self.group.threat_id,
            "events": [
                event.model_dump(mode="json")
                for event in self.group.events
            ],
            "retry_count": self.retry_count,
            "last_error": self.last_error,
            "last_attempt_at": (
                self.last_attempt_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                if self.last_attempt_at
                else None
            ),
            "status": self.status,
        }


class StateStore:
    """Atomic persistent state for checkpoints and deferred threat groups."""

    MAX_RETRIES = 3
    ACTIVE_STATUSES = {"pending", "retry"}

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def enqueue_threat_group(self, group: ThreatGroup) -> bool:
        """Add a threat group to the pending queue if it is not already present.

        Returns True when a new record was added, False when the threat already
        exists in pending or quarantined state.
        """
        state = self.load()
        records = self.load_pending_records()

        existing_ids = {
            record.group.threat_id
            for record in records
        }

        if group.threat_id in existing_ids:
            return False

        state.setdefault("pending_threats", [])
        state["pending_threats"].append(
            PendingThreat(group=group).to_state()
        )

        self._atomic_write(state)
        return True

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "last_successful_run": None,
                "failed_threats": [],
                "pending_threats": [],
            }

        state = json.loads(self.path.read_text(encoding="utf-8"))
        state.setdefault("failed_threats", [])
        state.setdefault("pending_threats", [])
        return state

    def load_pending_records(self) -> list[PendingThreat]:
        records: list[PendingThreat] = []
        for item in self.load().get("pending_threats", []):
            try:
                group = self._group_from_state(item)
                retry_count = max(0, int(item.get("retry_count", 0)))
                status = str(item.get("status", "pending")).lower()
                if status not in {"pending", "retry", "quarantined"}:
                    status = "pending"
                last_attempt_at = self._parse_datetime(item.get("last_attempt_at"))
                records.append(
                    PendingThreat(
                        group=group,
                        retry_count=retry_count,
                        last_error=(str(item["last_error"])[:2000] if item.get("last_error") is not None else None),
                        last_attempt_at=last_attempt_at,
                        status=status,
                    )
                )
            except Exception:
                continue
        return records

    def load_pending_groups(self) -> list[ThreatGroup]:
        return [
            record.group
            for record in self.load_pending_records()
            if record.status in self.ACTIVE_STATUSES
        ]

    def update_pending_records(
        self,
        pending_groups: list[ThreatGroup],
        failures: dict[str, str],
        when: datetime,
        max_retries: int = MAX_RETRIES,
    ) -> list[PendingThreat]:
        existing = {record.group.threat_id: record for record in self.load_pending_records()}
        updated: dict[str, PendingThreat] = {}

        for group in pending_groups:
            prior = existing.get(group.threat_id)
            if group.threat_id in failures:
                retry_count = (prior.retry_count if prior else 0) + 1
                status: PendingStatus = "quarantined" if retry_count >= max_retries else "retry"
                updated[group.threat_id] = PendingThreat(
                    group=group,
                    retry_count=retry_count,
                    last_error=failures[group.threat_id][:2000],
                    last_attempt_at=when.astimezone(timezone.utc),
                    status=status,
                )
            elif prior is not None:
                updated[group.threat_id] = PendingThreat(
                    group=group,
                    retry_count=prior.retry_count,
                    last_error=prior.last_error,
                    last_attempt_at=prior.last_attempt_at,
                    status=prior.status,
                )
            else:
                updated[group.threat_id] = PendingThreat(group=group)

        for record in existing.values():
            if record.status == "quarantined" and record.group.threat_id not in updated:
                updated[record.group.threat_id] = record

        return list(updated.values())

    def save_checkpoint(
        self,
        when: datetime,
        failed_threats: list[str],
        pending_groups: list[ThreatGroup] | None = None,
        pending_records: list[PendingThreat] | None = None,
    ) -> None:
        if failed_threats:
            return

        state = self.load()
        state["last_successful_run"] = (
            when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        state["failed_threats"] = []
        state["pending_threats"] = self._serialize_pending(
            pending_records, pending_groups
        )
        self._atomic_write(state)

    def record_failures(
        self,
        failed_threats: list[str],
        pending_groups: list[ThreatGroup] | None = None,
        pending_records: list[PendingThreat] | None = None,
    ) -> None:
        state = self.load()
        state["failed_threats"] = sorted(set(failed_threats))

        if pending_groups is not None or pending_records is not None:
            state["pending_threats"] = self._serialize_pending(
                pending_records, pending_groups
            )

        self._atomic_write(state)

    @staticmethod
    def _serialize_pending(
        pending_records: list[PendingThreat] | None,
        pending_groups: list[ThreatGroup] | None,
    ) -> list[dict[str, Any]]:
        if pending_records is not None:
            return [record.to_state() for record in pending_records]
        return [
            PendingThreat(group=group).to_state()
            for group in (pending_groups or [])
        ]

    @classmethod
    def _group_from_state(cls, data: dict[str, Any]) -> ThreatGroup:
        events = [
            SourceEvent.model_validate(event)
            for event in data.get("events", [])
        ]

        if not events:
            raise ValueError("Pending threat group contains no events")

        return ThreatGroup(
            threat_id=str(data["threat_id"]),
            events=events,
        )

    @classmethod
    def _parse_datetime(cls, value: Any) -> datetime | None:
        if value in (None, ""):
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None

    def _atomic_write(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=self.path.parent,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
