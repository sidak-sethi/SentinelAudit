from __future__ import annotations

import json
from pathlib import Path

from app.models.research_evidence import EnvironmentIdentity, ResearchTarget


class EnvironmentBuilder:
    def __init__(self, work_dir: Path, sandbox_network: bool, cpu_limit: float, memory_mb: int, pids_limit: int):
        self.work_dir = work_dir
        self.sandbox_network = sandbox_network
        self.cpu_limit = cpu_limit
        self.memory_mb = memory_mb
        self.pids_limit = pids_limit

    def build(self, target: ResearchTarget) -> EnvironmentIdentity:
        identity = EnvironmentIdentity(
            python_version=target.runtime_version or "3.11",
            os_base="python:3.11-slim" if target.ecosystem.lower() in {"python", "pypi"} else "unknown",
            package_version=target.vulnerable_version,
            dependency_versions={},
            configuration={},
            environment_variables=[],
            network_policy="enabled" if self.sandbox_network else "disabled",
            resource_limits={"cpu": self.cpu_limit, "memory_mb": self.memory_mb, "pids": self.pids_limit},
        )
        self.work_dir.mkdir(parents=True, exist_ok=True)
        (self.work_dir / "environment.json").write_text(json.dumps(identity.model_dump(mode="json"), indent=2), encoding="utf-8")
        return identity
