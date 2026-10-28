"""APT patch applier — pins exact version inside target CT via pct exec."""
from __future__ import annotations

import logging

from .pct import Pct, PctResult

log = logging.getLogger(__name__)


class AptPatcher:
    """apt-get install pkg=version inside an LXC via pct exec."""

    def __init__(self, pct: Pct) -> None:
        self.pct = pct

    def update_index(self, ctid: int) -> PctResult:
        return self.pct.exec(ctid, "apt-get", "update", "-qq")

    def apply(self, ctid: int, pkg: str, version: str) -> PctResult:
        """Install pkg at exact version. Returns PctResult; .ok = success."""
        env = ["DEBIAN_FRONTEND=noninteractive"]
        return self.pct.exec(
            ctid,
            "env", *env,
            "apt-get", "install", "-y",
            "--no-install-recommends",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
            f"{pkg}={version}",
        )

    def installed_version(self, ctid: int, pkg: str) -> str | None:
        """Return installed version via dpkg-query or None if absent."""
        res = self.pct.exec(ctid, "dpkg-query", "-W", "-f=${Version}", pkg)
        if not res.ok or not res.stdout:
            return None
        return res.stdout.strip() or None
