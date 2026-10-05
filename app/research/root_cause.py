from __future__ import annotations

from app.models.research_evidence import ExecutionEvidence, RootCauseEvidence
from app.research.tracer import Tracer


class RootCauseAnalyzer:
    def __init__(self):
        self.tracer = Tracer()

    def analyze(self, executions: list[ExecutionEvidence]) -> RootCauseEvidence | None:
        return self.tracer.infer(executions)
