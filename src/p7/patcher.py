"""Package patchers — apt for Debian/Ubuntu, apk for Alpine. Both via pct exec."""
from __future__ import annotations

import logging
from typing import Protocol

from .pct import Pct, PctResult

log = logging.getLogger(__name__)


class Patcher(Protocol):
    """Common interface for all backend patchers."""

    name: str

    def update_index(self, ctid: int) -> PctResult: ...
    def apply(self, ctid: int, pkg: str, version: str) -> PctResult: ...
    def installed_version(self, ctid: int, pkg: str) -> str | None: ...


class AptPatcher:
    """apt-get install pkg=version inside an LXC via pct exec."""

    name = "apt"

    def __init__(self, pct: Pct) -> None:
        self.pct = pct

    def update_index(self, ctid: int) -> PctResult:
        return self.pct.exec(ctid, "apt-get", "update", "-qq")

    def apply(self, ctid: int, pkg: str, version: str) -> PctResult:
        return self.pct.exec(
            ctid,
            "env", "DEBIAN_FRONTEND=noninteractive",
            "apt-get", "install", "-y",
            "--no-install-recommends",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
            f"{pkg}={version}",
        )

    def installed_version(self, ctid: int, pkg: str) -> str | None:
        res = self.pct.exec(ctid, "dpkg-query", "-W", "-f=${Version}", pkg)
        if not res.ok or not res.stdout:
            return None
        return res.stdout.strip() or None


class ApkPatcher:
    """apk upgrade for Alpine. Alpine pins happen via `apk add pkg=version`."""

    name = "apk"

    def __init__(self, pct: Pct) -> None:
        self.pct = pct

    def update_index(self, ctid: int) -> PctResult:
        return self.pct.exec(ctid, "apk", "update")

    def apply(self, ctid: int, pkg: str, version: str) -> PctResult:
        return self.pct.exec(ctid, "apk", "add", "--no-cache", f"{pkg}={version}")

    def installed_version(self, ctid: int, pkg: str) -> str | None:
        res = self.pct.exec(ctid, "apk", "info", "-v", pkg)
        if not res.ok or not res.stdout:
            return None
        line = res.stdout.strip().splitlines()[0]
        prefix = f"{pkg}-"
        if line.startswith(prefix):
            return line[len(prefix):]
        return None


def select_patcher(backend: str, pct: Pct) -> Patcher:
    """Return a Patcher by backend name ('apt' or 'apk')."""
    backend = backend.lower()
    if backend == "apt":
        return AptPatcher(pct)
    if backend == "apk":
        return ApkPatcher(pct)
    raise ValueError(f"unknown backend: {backend!r}")
