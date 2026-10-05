from __future__ import annotations

import json
import shutil
from pathlib import Path

from app.models.research_evidence import CountermeasureEvidence, EnvironmentIdentity, ExecutionEvidence, VerificationEvidence, VerificationStatus
from app.research.execution import to_execution_evidence
from app.research.sandbox import Sandbox


class PatchVerifier:
    def verify_fixture(self, fixture_name: str, environment: EnvironmentIdentity, sandbox: Sandbox, work_dir: Path) -> VerificationEvidence:
        source_dir = Path(__file__).resolve().parents[2] / "fixtures" / fixture_name
        run_dir = work_dir / f"verify-{fixture_name}"
        if run_dir.exists():
            shutil.rmtree(run_dir)
        shutil.copytree(source_dir, run_dir)
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

        before_result = sandbox.run(manifest["reproduce_command"], run_dir, timeout=30)
        before = to_execution_evidence(
            before_result, environment,
            before_result.stdout.strip() or before_result.stderr.strip() or "no observable output",
            manifest["expected_behavior"], fixture_name,
        )

        patch_result = sandbox.run(manifest["apply_patch_command"], run_dir, timeout=30)
        patch_evidence = to_execution_evidence(
            patch_result, environment,
            patch_result.stdout.strip() or patch_result.stderr.strip() or "patch command produced no output",
            "patch applied",
            fixture_name,
        )

        after_result = sandbox.run(manifest["reproduce_command"], run_dir, timeout=30)
        after = to_execution_evidence(
            after_result, environment,
            after_result.stdout.strip() or after_result.stderr.strip() or "no observable output",
            manifest["patched_expected_behavior"],
            fixture_name,
        )

        regression_result = sandbox.run(manifest["regression_command"], run_dir, timeout=30)
        regression = to_execution_evidence(
            regression_result, environment,
            regression_result.stdout.strip() or regression_result.stderr.strip() or "no observable output",
            "regression tests pass",
            fixture_name,
        )
        verified = patch_result.exit_code == 0 and after_result.exit_code == 0 and regression_result.exit_code == 0 and "SAFE" in after_result.stdout and "PASS" in regression_result.stdout
        status = VerificationStatus.VERIFIED if verified else VerificationStatus.FAILED
        return VerificationEvidence(
            attack_before=[before, patch_evidence],
            attack_after=[after],
            regression_tests=[regression],
            result=status,
        )
