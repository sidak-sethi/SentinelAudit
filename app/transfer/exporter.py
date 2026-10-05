from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from app.models.threat_package import ThreatPackage
from app.transfer.guard_adapter import to_guard_package


class AtomicExporter:
    def __init__(self, outgoing_dir: Path):
        self.outgoing_dir = outgoing_dir
        self.outgoing_dir.mkdir(parents=True, exist_ok=True)

    def export(self, package: ThreatPackage) -> Path:
        payload = to_guard_package(package)
        final_path = self.outgoing_dir / f"{package.package_id}.json"
        fd, tmp = tempfile.mkstemp(prefix=final_path.name, suffix=".json.tmp", dir=self.outgoing_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, final_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return final_path
