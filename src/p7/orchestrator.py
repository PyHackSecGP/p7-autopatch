"""Orchestrator — detect → classify → snapshot → patch → verify → rollback → writeback."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .classifier import ChangeLevel, allowed, classify
from .dojo import DojoClient, Finding
from .healthcheck import Healthchecker, HealthReport
from .notify import NullNotifier, Notifier
from .patcher import Patcher, select_patcher
from .pct import Pct
from .trivy import TrivyVerifier

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
        backend: str = "apt",
        product_id: int | None = None,
        notifier: Notifier | None = None,
        verify_cves: bool = False,
        writeback: bool = False,
    ) -> None:
        self.dojo = dojo
        self.pct = pct
        self.patcher: Patcher = select_patcher(backend, pct)
        self.checker = Healthchecker(pct)
        self.trivy = TrivyVerifier(pct)
        self.healthchecks = healthchecks
        self.max_change = max_change
        self.skip_hosts = skip_hosts or set()
        self.product_id = product_id
        self.notifier = notifier or NullNotifier()
        self.verify_cves = verify_cves
        self.writeback = writeback

    def _findings_for(self, ctid: int) -> list[Finding]:
        """Pull High+ findings whose host hint matches ctid."""
        ctid_s = str(ctid)
        out: list[Finding] = []
        for f in self.dojo.iter_high_findings(limit=1000, product_id=self.product_id):
            if not f.is_patchable:
                continue
            if self.product_id is not None:
                out.append(f)
                continue
            host = (f.host or "").lower()
            if ctid_s in host or f"ct{ctid_s}" in host:
                out.append(f)
        return out

    def run(self, ctid: int) -> list[PatchOutcome]:
        """Process every applicable finding for ctid. Returns per-finding outcomes."""
        if ctid in self.skip_hosts:
            log.warning("ct%s on skip list — aborting", ctid)
            self.notifier.send(f"P7 skip: ct{ctid} on SKIP_HOSTS")
            return []

        outcomes: list[PatchOutcome] = []
        findings = self._findings_for(ctid)
        log.info("ct%s backend=%s: %d patchable findings", ctid, self.patcher.name, len(findings))
        self.patcher.update_index(ctid)

        for f in findings:
            fix = (f.fix_available or "").split(",")[0].strip()
            cur = self.patcher.installed_version(ctid, f.component_name) or f.component_version
            level = classify(cur, fix)
            if not allowed(level, self.max_change):
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, fix, level,
                    applied=False, rolled_back=False, health=HealthReport(ok=True),
                    note=f"skipped: {level.value} > max {self.max_change.value}",
                ))
                continue

            snap = f"p7-pre-{int(time.time())}-{f.id}"
            if not self.pct.snapshot(ctid, snap).ok:
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, fix, level,
                    applied=False, rolled_back=False, health=HealthReport(ok=False),
                    note="snapshot failed",
                ))
                continue

            patch_res = self.patcher.apply(ctid, f.component_name, fix)
            if not patch_res.ok:
                self.pct.rollback(ctid, snap)
                self.notifier.send(f"P7 ROLLBACK: ct{ctid} {f.component_name} apt-install failed")
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, fix, level,
                    applied=False, rolled_back=True, health=HealthReport(ok=False),
                    note=f"patcher failed: {patch_res.stderr[:200]}",
                ))
                continue

            health = self.checker.check(ctid, self.healthchecks.get(ctid, []))
            if not health.ok:
                self.pct.rollback(ctid, snap)
                self.pct.reboot(ctid)
                self.notifier.send(f"P7 ROLLBACK: ct{ctid} {f.component_name} healthcheck failed {health.failed}")
                outcomes.append(PatchOutcome(
                    f.id, f.component_name, cur, fix, level,
                    applied=False, rolled_back=True, health=health,
                    note=f"rolled back; failed services: {health.failed}",
                ))
                continue

            if self.verify_cves and f.cve:
                cleared, _ = self.trivy.rescan_rootfs(ctid, f.cve)
                if not cleared:
                    self.pct.rollback(ctid, snap)
                    self.pct.reboot(ctid)
                    self.notifier.send(f"P7 ROLLBACK: ct{ctid} {f.cve} still present after patch of {f.component_name}")
                    outcomes.append(PatchOutcome(
                        f.id, f.component_name, cur, fix, level,
                        applied=False, rolled_back=True, health=health,
                        note=f"trivy rescan still shows {f.cve}; rolled back",
                    ))
                    continue

            note_text = f"P7 autopatched {f.component_name} {cur}->{fix} ({level.value}); snapshot={snap}; healthcheck OK"
            if self.writeback and not self.pct.dry_run:
                self.dojo.mitigate(f.id, note_text)

            outcomes.append(PatchOutcome(
                f.id, f.component_name, cur, fix, level,
                applied=True, rolled_back=False, health=health,
                note=note_text,
            ))

        if outcomes:
            applied = sum(1 for o in outcomes if o.applied)
            rb = sum(1 for o in outcomes if o.rolled_back)
            self.notifier.send(f"P7 ct{ctid} done: {applied} applied, {rb} rolled back, {len(outcomes) - applied - rb} skipped")
        return outcomes
