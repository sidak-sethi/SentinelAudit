from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from uuid import uuid4


@dataclass
class SandboxResult:
    execution_id: str
    start_time: str
    end_time: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool


class Sandbox:
    def run(self, command: Sequence[str], work_dir: Path, timeout: float) -> SandboxResult:
        raise NotImplementedError


class LocalSandbox(Sandbox):
    def __init__(self, allowed: bool = False):
        if not allowed:
            raise ValueError("Local sandbox is disabled. Set ALLOW_LOCAL_SANDBOX=true only for development.")

    def run(self, command: Sequence[str], work_dir: Path, timeout: float) -> SandboxResult:
        return _run_subprocess(list(command), work_dir, timeout, env=os.environ.copy())


class DockerSandbox(Sandbox):
    def __init__(self, cpu_limit: float, memory_mb: int, pids_limit: int, network: bool = False, image: str = "python:3.11-slim"):
        self.cpu_limit = cpu_limit
        self.memory_mb = memory_mb
        self.pids_limit = pids_limit
        self.network = network
        self.image = image

    def run(self, command: Sequence[str], work_dir: Path, timeout: float) -> SandboxResult:
        if shutil.which("docker") is None:
            raise RuntimeError("Docker backend selected but docker executable was not found on PATH")
        work_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            "docker", "run", "--rm",
            "--cpus", str(self.cpu_limit),
            "--memory", f"{self.memory_mb}m",
            "--pids-limit", str(self.pids_limit),
        ]
        if not self.network:
            cmd += ["--network", "none"]
        mount_target = "/work"
        cmd += ["-v", f"{work_dir.resolve()}:{mount_target}:rw", "-w", mount_target, self.image]
        cmd += list(command)
        return _run_subprocess(cmd, work_dir, timeout, env=None)


def _run_subprocess(command: list[str], work_dir: Path, timeout: float, env: dict[str, str] | None) -> SandboxResult:
    execution_id = f"exec-{uuid4().hex[:12]}"
    started = time.time()
    start_time = _iso(started)
    try:
        completed = subprocess.run(
            command,
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        ended = time.time()
        return SandboxResult(execution_id, start_time, _iso(ended), completed.returncode, completed.stdout[-20000:], completed.stderr[-20000:], False)
    except subprocess.TimeoutExpired as exc:
        ended = time.time()
        stdout = (exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "")[-20000:] if isinstance(exc.stderr, str) else ""
        return SandboxResult(execution_id, start_time, _iso(ended), None, stdout, stderr, True)


def _iso(timestamp: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
