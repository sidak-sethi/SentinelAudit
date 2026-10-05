from __future__ import annotations

from app.models.research_evidence import CountermeasureEvidence, VerificationStatus
from app.models.threat_analysis import ThreatAnalysis


class CountermeasureEngine:
    def propose(self, analysis: ThreatAnalysis) -> CountermeasureEvidence:
        candidate = analysis.countermeasure.candidate_patch_description
        if not candidate or candidate == "not established":
            candidate = analysis.countermeasure.strategy or "upgrade to a verified fixed version"
        return CountermeasureEvidence(candidate=candidate, applied=False, status=VerificationStatus.NOT_TESTED)
