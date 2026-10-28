"""Semver diff classifier — decides patch/minor/major change level."""
from __future__ import annotations

import re
from enum import Enum

_SEMVER_RE = re.compile(r"(\d+)(?:[.\-_](\d+))?(?:[.\-_](\d+))?")


class ChangeLevel(str, Enum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


def _parse(version: str) -> tuple[int, int, int] | None:
    """Return (major, minor, patch) tuple or None if unparseable.

    Debian-style versions like `1.2.3-1ubuntu0.4` collapse to (1, 2, 3).
    """
    if not version:
        return None
    m = _SEMVER_RE.search(version)
    if not m:
        return None
    major, minor, patch = m.group(1), m.group(2), m.group(3)
    return (int(major), int(minor or 0), int(patch or 0))


def classify(current: str, target: str) -> ChangeLevel:
    """Classify version jump by semver component that changed first."""
    cur = _parse(current)
    tgt = _parse(target)
    if cur is None or tgt is None:
        return ChangeLevel.UNKNOWN
    if cur[0] != tgt[0]:
        return ChangeLevel.MAJOR
    if cur[1] != tgt[1]:
        return ChangeLevel.MINOR
    if cur[2] != tgt[2]:
        return ChangeLevel.PATCH
    return ChangeLevel.UNKNOWN  # equal versions


def allowed(level: ChangeLevel, max_change: ChangeLevel) -> bool:
    """True if `level` is at or below `max_change` on the risk ladder."""
    rank = {
        ChangeLevel.PATCH: 1,
        ChangeLevel.MINOR: 2,
        ChangeLevel.MAJOR: 3,
        ChangeLevel.UNKNOWN: 99,
    }
    return rank[level] <= rank[max_change]
