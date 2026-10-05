from __future__ import annotations

import json
import shutil
from pathlib import Path

from app.config import Settings
from app.models.research_evidence import EnvironmentIdentity, ExecutionEvidence, ResearchTarget, ReproductionStatus
from app.research.execution import to_execution_evidence
from app.research.sandbox import Sandbox


class ReproductionResult:
    def __init__(self, status: ReproductionStatus, observations: list[str], logs: list[ExecutionEvidence]):
        self.status = status
        self.observations = observations
        self.logs = logs


class Reproducer:
    async def reproduce(self, target: ResearchTarget, environment: EnvironmentIdentity, sandbox: Sandbox, work_dir: Path) -> ReproductionResult:
        if target.source_artifact and target.source_artifact.startswith("fixture://"):
            return self._fixture(target, environment, sandbox, work_dir)
        return ReproductionResult(ReproductionStatus.INCONCLUSIVE, ["No deterministic reproducer is attached to this live research target."], [])

    def _fixture(self, target: ResearchTarget, environment: EnvironmentIdentity, sandbox: Sandbox, work_dir: Path) -> ReproductionResult:
        fixture_name = target.source_artifact.removeprefix("fixture://")
        source_dir = Path(__file__).resolve().parents[2] / "fixtures" / fixture_name
        if not source_dir.exists():
            return ReproductionResult(ReproductionStatus.INCONCLUSIVE, [f"Fixture not found: {fixture_name}"], [])
        run_dir = work_dir / f"fixture-{fixture_name}"
        if run_dir.exists():
            shutil.rmtree(run_dir)
        shutil.copytree(source_dir, run_dir)
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        result = sandbox.run(manifest["reproduce_command"], run_dir, timeout=30)
        evidence = to_execution_evidence(
            result,
            environment,
            observed_behavior=result.stdout.strip() or result.stderr.strip() or "no observable output",
            expected_behavior=manifest["expected_behavior"],
            artifact_identity=fixture_name,
        )
        if result.exit_code == manifest.get("success_exit_code", 0) and manifest["expected_behavior"] in result.stdout:
            return ReproductionResult(ReproductionStatus.REPRODUCED, [manifest["expected_behavior"]], [evidence])
        return ReproductionResult(ReproductionStatus.NOT_REPRODUCED, [evidence.observed_behavior], [evidence])
