"""Orchestrator — glues the detect→snapshot→patch→verify→rollback loop."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .classifier import ChangeLevel, allowed, classify
from .dojo import DojoClient, Finding
from .healthcheck import Healthchecker, HealthReport
from .patcher import AptPatcher
from .pct import Pct

log = logging.getLogger(__name__)


@dataclass
class PatchOutcome:
    finding_id: int
    pkg: str
    from_version: str
    to_version: str
    level: ChangeLevel
    applied: bool
    rolled_back: bool
    health: HealthReport
    note: str = ""


class Orchestrator:
    """Run one autopatch cycle for a single CT target."""

    def __init__(
        self,
        dojo: DojoClient,
        pct: Pct,
        healthchecks: dict[int, list[str]],
        max_change: ChangeLevel = ChangeLevel.PATCH,
        skip_hosts: set[int] | None = None,
    ) -> None:
        self.dojo = dojo
        self.pct = pct
        self.patcher = AptPatcher(pct)
        self.checker = Healthchecker(pct)
        self.healthchecks = healthchecks
        self.max_change = max_change
        self.skip_hosts = skip_hosts or set()

    def _findings_for(self, ctid: int) -> list[Finding]:
        """Pull High+ findings whose host hint matches ctid."""
        ctid_s = str(ctid)
        out: list[Finding] = []
        for f in self.dojo.iter_high_findings():
            if not f.is_patchable:
                continue
            host = (f.host or "").lower()
            if ctid_s in host or f"ct{ctid_s}" in host:
                out.append(f)
        return out

    def run(self, ctid: int) -> list[PatchOutcome]:
        """Process every applicable finding for ctid. Returns per-finding outcomes."""
        if ctid in self.skip_hosts:
            log.warning("ct%s on skip list — aborting", ctid)
            return []

        outcomes: list[PatchOutcome] = []
        findings = self._findings_for(ctid)
        log.info("ct%s: %d patchable findings", ctid, len(findings))
        self.patcher.update_index(ctid)

        for f in findings:
            cur = self.patcher.installed_version(ctid, f.component_name) or f.component_version
            level = classify(cur, f.fix_available)
            if not allowed(level, self.max_change):
                log.info("ct%s skip %s %s→%s (%s)", ctid, f.component_name, cur, f.fix_available, level)
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, f.fix_available, level,
                    applied=False, rolled_back=False, health=HealthReport(ok=True),
                    note=f"skipped: {level} > max {self.max_change}",
                ))
                continue

            snap = f"p7-pre-{int(time.time())}-{f.id}"
            if not self.pct.snapshot(ctid, snap).ok:
                log.error("ct%s snapshot failed, aborting %s", ctid, f.component_name)
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, f.fix_available, level,
                    applied=False, rolled_back=False, health=HealthReport(ok=False),
                    note="snapshot failed",
                ))
                continue

            patch_res = self.patcher.apply(ctid, f.component_name, f.fix_available)
            if not patch_res.ok:
                log.error("ct%s apt install failed: %s", ctid, patch_res.stderr)
                self.pct.rollback(ctid, snap)
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, f.fix_available, level,
                    applied=False, rolled_back=True, health=HealthReport(ok=False),
                    note=f"apt failed: {patch_res.stderr[:200]}",
                ))
                continue

            health = self.checker.check(ctid, self.healthchecks.get(ctid, []))
            if not health.ok:
                log.error("ct%s healthcheck failed: %s — rolling back", ctid, health.failed)
                self.pct.rollback(ctid, snap)
                self.pct.reboot(ctid)
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, f.fix_available, level,
                    applied=False, rolled_back=True, health=health,
                    note=f"rolled back; failed services: {health.failed}",
                ))
                continue

            outcomes.append(PatchOutcome(
                f.id, f.component_name, cur, f.fix_available, level,
                applied=True, rolled_back=False, health=health,
                note=f"patched; snapshot={snap}",
            ))

        return outcomes
