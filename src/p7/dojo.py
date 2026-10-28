"""DefectDojo API client — pulls High+ findings with fix versions."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterator

import requests

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Finding:
    """One DefectDojo finding that may become a patch target."""
    id: int
    title: str
    severity: str
    component_name: str | None
    component_version: str | None
    fix_available: str | None  # fix version string from DefectDojo mitigation field
    cve: str | None
    host: str | None            # product/engagement name used as host hint

    @property
    def is_patchable(self) -> bool:
        """Finding has enough info to attempt an apt install pkg=version."""
        return bool(self.component_name and self.component_version and self.fix_available)


class DojoClient:
    """Minimal DefectDojo REST client — scoped to findings-list reads."""

    def __init__(self, base_url: str, token: str, timeout: int = 15) -> None:
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Token {token}",
            "Accept": "application/json",
        })

    def iter_high_findings(self, limit: int = 200) -> Iterator[Finding]:
        """Yield active, un-mitigated High/Critical findings."""
        url = f"{self.base}/api/v2/findings/"
        params = {
            "severity": "High,Critical",
            "active": "true",
            "is_mitigated": "false",
            "limit": limit,
        }
        resp = self._session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()
        for raw in resp.json().get("results", []):
            yield Finding(
                id=raw["id"],
                title=raw.get("title", ""),
                severity=raw.get("severity", ""),
                component_name=raw.get("component_name"),
                component_version=raw.get("component_version"),
                fix_available=raw.get("mitigation") or raw.get("fix_available"),
                cve=raw.get("cve"),
                host=(raw.get("engagement") or {}).get("name") if isinstance(raw.get("engagement"), dict) else None,
            )
