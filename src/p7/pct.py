"""Proxmox `pct` wrapper — all host-side container operations."""
from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class PctResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Pct:
    """Shell out to `pct`. Set `dry_run=True` to echo instead of execute."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def _run(self, argv: list[str]) -> PctResult:
        cmd = ["pct", *argv]
        log.info("pct: %s", shlex.join(cmd))
        if self.dry_run:
            return PctResult(0, "<dry-run>", "")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return PctResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())

    def snapshot(self, ctid: int, name: str) -> PctResult:
        return self._run(["snapshot", str(ctid), name])

    def rollback(self, ctid: int, name: str) -> PctResult:
        return self._run(["rollback", str(ctid), name])

    def reboot(self, ctid: int) -> PctResult:
        return self._run(["reboot", str(ctid)])

    def exec(self, ctid: int, *cmd: str) -> PctResult:
        return self._run(["exec", str(ctid), "--", *cmd])
