from __future__ import annotations

import re
from datetime import datetime, timezone

from app.models.research_evidence import (
    ReproductionStatus,
    ResearchEvidence,
    VerificationStatus,
)
from app.models.threat_analysis import ThreatAnalysis
from app.models.threat_package import ThreatPackage, ThreatStatus
from app.pipeline.correlate import ThreatGroup


class ThreatPackageBuilder:
    """Build the exact JSON contract expected by the offline Guard agent."""

    _SEVERITY_RANK = {
        "UNKNOWN": 0,
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def build(
        self,
        group: ThreatGroup,
        analysis: ThreatAnalysis,
        research: ResearchEvidence,
    ) -> ThreatPackage:
        primary = self._primary_event(group)
        cve = self._cve(group)

        source_reference = primary.references[0] if primary.references else ""
        source = {
            "type": self._source_type(primary.source),
            "url": source_reference,
            "published": self._iso(primary.published_at or primary.observed_at),
            "retrieved_at": self._iso(datetime.now(timezone.utc)),
        }

        title = self._title(group, analysis)
        attack_type = self._attack_type(analysis.attack.class_name)
        severity = self._severity(group)

        status = self._status(research)
        patch_status = self._patch_status(research)
        patch_attempts = self._patch_attempts(research)

        affected_files, affected_lines = self._affected_location(research)
        repository = research.target.repository if research.target else None

        recommended_fix = self._recommended_fix(analysis)
        hypothesis = self._hypothesis(analysis)

        final_audit = self._final_audit(patch_status, patch_attempts)

        return ThreatPackage(
            package_id=ThreatPackage.new_id(),
            threat_id=group.threat_id,
            title=title,
            cve=cve,
            attack_type=attack_type,
            severity=severity,
            source=source,
            status=status,
            patch_status=patch_status,
            repository=repository,
            branch=None,
            affected_files=affected_files,
            affected_lines=affected_lines,
            confidence=analysis.confidence,
            vulnerability_hypothesis=hypothesis,
            recommended_fix=recommended_fix,
            security_test_path=None,
            code={},
            diff=None,
            patch_attempts=patch_attempts,
            final_audit=final_audit,
            reason=self._reason(research, status),
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    def _primary_event(group: ThreatGroup):
        return sorted(
            group.events,
            key=lambda event: (
                0 if event.references else 1,
                -(event.cvss_score or 0.0),
                event.source,
                event.event_id,
            ),
        )[0]

    @staticmethod
    def _cve(group: ThreatGroup) -> str | None:
        cves = sorted(
            {
                value.upper()
                for event in group.events
                for value in event.identifiers.get("CVE", [])
                if value
            }
        )
        return cves[0] if cves else None

    @staticmethod
    def _source_type(source: str) -> str:
        normalized = source.strip().lower()
        mapping = {
            "nvd": "nvd",
            "osv": "osv",
            "github advisories": "github_advisory",
            "github advisory": "github_advisory",
            "cisa kev": "cisa_kev",
            "epss": "epss",
        }
        return mapping.get(normalized, "other")

    @staticmethod
    def _iso(value: datetime) -> str:
        return (
            value.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _title(group: ThreatGroup, analysis: ThreatAnalysis) -> str:
        class_name = analysis.attack.class_name.strip()
        if class_name and class_name.lower() not in {"unknown", "not established"}:
            return class_name.replace("_", " ").strip().title()

        summary = next(
            (event.summary.strip() for event in group.events if event.summary.strip()),
            group.threat_id,
        )
        return summary[:180]

    @staticmethod
    def _attack_type(class_name: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9]+", " ", class_name.strip()).strip().lower()
        return value.replace(" ", "_") or "unknown"

    def _severity(self, group: ThreatGroup) -> str:
        candidates = [
            (event.severity or "UNKNOWN").upper()
            for event in group.events
        ]
        if not candidates:
            return "unknown"
        return max(
            candidates,
            key=lambda value: self._SEVERITY_RANK.get(value, 0),
        ).lower()

    @staticmethod
    def _status(research: ResearchEvidence) -> ThreatStatus:
        if research.reproduction_status == ReproductionStatus.REPRODUCED:
            return "confirmed"
        if research.reproduction_status == ReproductionStatus.NOT_APPLICABLE:
            return "not_applicable"
        return "uncertain"

    @staticmethod
    def _patch_status(
        research: ResearchEvidence,
    ) -> str | None:
        if not research.countermeasure or not research.countermeasure.applied:
            return None

        if (
            research.verification
            and research.verification.result == VerificationStatus.VERIFIED
        ):
            return "fixed"

        if (
            research.verification
            and research.verification.result == VerificationStatus.FAILED
        ):
            return "unresolved"

        return None

    @staticmethod
    def _patch_attempts(research: ResearchEvidence) -> int:
        return 1 if research.countermeasure and research.countermeasure.applied else 0

    @staticmethod
    def _final_audit(
        patch_status: str | None,
        patch_attempts: int,
    ) -> str | None:
        if patch_attempts == 0:
            return None
        if patch_status == "fixed":
            return "fixed"
        if patch_status == "unresolved":
            return "not_fixed"
        return "uncertain"

    @staticmethod
    def _affected_location(
        research: ResearchEvidence,
    ) -> tuple[list[str], list[int]]:
        if not research.root_cause or not research.root_cause.source_location:
            return [], []

        location = research.root_cause.source_location.strip()
        if not location:
            return [], []

        # Accept common ``path.py:123`` and ``path.py:123-130`` forms. A
        # symbolic location such as ``app.py:authorize`` becomes a file-only
        # location rather than being incorrectly treated as a line number.
        match = re.match(r"^(.*?):(\d+)(?:-(\d+))?$", location)
        if match:
            path, start, end = match.groups()
            start_line = int(start)
            end_line = int(end or start)
            return [path], list(range(start_line, end_line + 1))

        path = location.split(":", 1)[0]
        return ([path] if path else []), []

    @staticmethod
    def _recommended_fix(analysis: ThreatAnalysis) -> str:
        candidate = analysis.countermeasure.candidate_patch_description.strip()
        if candidate and candidate.lower() not in {"unknown", "not established"}:
            return candidate

        mitigation = [
            item.strip()
            for item in analysis.countermeasure.mitigation
            if item.strip()
        ]
        if mitigation:
            return mitigation[0]
        return "not established"

    @staticmethod
    def _hypothesis(analysis: ThreatAnalysis) -> str:
        root_cause = analysis.countermeasure.root_cause.strip()
        impact = analysis.attack.impact.strip()
        class_name = analysis.attack.class_name.strip()

        if root_cause and root_cause.lower() not in {"unknown", "not established"}:
            if impact and impact.lower() not in {"unknown", "not established"}:
                return f"{root_cause}; impact: {impact}."
            return root_cause

        if class_name and class_name.lower() not in {"unknown", "not established"}:
            return f"Potential {class_name} vulnerability based on supplied evidence."

        return "not established"

    @staticmethod
    def _reason(research: ResearchEvidence, status: ThreatStatus) -> str:
        if status == "confirmed":
            return "Vulnerability reproduced in the controlled research environment."
        if status == "not_applicable":
            return "Research target was determined not applicable for reproduction."
        if research.reproduction_attempted:
            return "Analysis completed, but deterministic reproduction or verification was not established."
        return "Analysis completed, but reproduction was not established."
