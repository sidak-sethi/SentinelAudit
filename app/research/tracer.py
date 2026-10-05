from __future__ import annotations

from app.models.research_evidence import ExecutionEvidence, RootCauseEvidence


class Tracer:
    def infer(self, executions: list[ExecutionEvidence]) -> RootCauseEvidence | None:
        if not executions:
            return None
        joined = "\n".join((e.stdout + "\n" + e.stderr).strip() for e in executions)
        marker = "root_cause="
        source_location = None
        explanation = "Observed execution evidence is available; no source-level root-cause marker was emitted."
        for line in joined.splitlines():
            if line.startswith(marker):
                explanation = line.removeprefix(marker).strip() or explanation
            if line.startswith("source_location="):
                source_location = line.split("=", 1)[1].strip() or None
        return RootCauseEvidence(
            source_location=source_location,
            execution_path=[],
            explanation=explanation,
        )
