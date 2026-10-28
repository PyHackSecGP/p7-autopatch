"""Post-patch verification — systemctl is-active for a per-CT service list."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .pct import Pct

log = logging.getLogger(__name__)


@dataclass
class HealthReport:
    ok: bool
    failed: list[str] = field(default_factory=list)


def parse_healthcheck_env(raw: str) -> dict[int, list[str]]:
    """Parse HEALTHCHECKS env var: '209:ssh;205:docker,uwsgi' -> {209:['ssh'], ...}."""
    out: dict[int, list[str]] = {}
    for chunk in filter(None, (c.strip() for c in raw.split(";"))):
        if ":" not in chunk:
            continue
        ctid_s, svcs = chunk.split(":", 1)
        try:
            ctid = int(ctid_s)
        except ValueError:
            continue
        out[ctid] = [s.strip() for s in svcs.split(",") if s.strip()]
    return out


class Healthchecker:
    """Verify a list of systemd units are active inside a CT."""

    def __init__(self, pct: Pct) -> None:
        self.pct = pct

    def check(self, ctid: int, services: list[str]) -> HealthReport:
        """Return HealthReport with failed services (empty = all green)."""
        if not services:
            return HealthReport(ok=True)
        failed: list[str] = []
        for svc in services:
            res = self.pct.exec(ctid, "systemctl", "is-active", svc)
            if not res.ok or res.stdout.strip() != "active":
                failed.append(svc)
                log.warning("healthcheck fail: ct%s svc=%s stdout=%r", ctid, svc, res.stdout)
        return HealthReport(ok=not failed, failed=failed)
