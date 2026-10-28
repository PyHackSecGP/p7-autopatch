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

    def iter_high_findings(
        self,
        limit: int = 200,
        page_size: int = 200,
        product_id: int | None = None,
    ) -> Iterator[Finding]:
        """Yield active, un-mitigated High/Critical findings. Paginates.

        `limit` caps total yielded; `page_size` is per-request page size;
        `product_id` scopes to one DefectDojo product.
        """
        yielded = 0
        offset = 0
        url = f"{self.base}/api/v2/findings/"
        while yielded < limit:
            params: dict = {
                "severity": "High,Critical",
                "active": "true",
                "is_mitigated": "false",
                "duplicate": "false",
                "limit": min(page_size, limit - yielded),
                "offset": offset,
            }
            if product_id is not None:
                params["test__engagement__product"] = product_id
            resp = self._session.get(url, params=params, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results") or []
            if not results:
                return
            for raw in results:
                yielded += 1
                yield Finding(
                    id=raw["id"],
                    title=raw.get("title", ""),
                    severity=raw.get("severity", ""),
                    component_name=raw.get("component_name"),
                    component_version=raw.get("component_version"),
                    fix_available=raw.get("mitigation"),
                    cve=_extract_cve(raw),
                    host=_extract_host(raw),
                )
                if yielded >= limit:
                    return
            if not data.get("next"):
                return
            offset += len(results)

    def mitigate(self, finding_id: int, note: str) -> bool:
        """Mark a finding mitigated and append a note. Return True on success."""
        url = f"{self.base}/api/v2/findings/{finding_id}/"
        payload = {
            "is_mitigated": True,
            "active": False,
            "verified": True,
            "mitigated_by": None,
        }
        try:
            resp = self._session.patch(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as e:
            log.warning("mitigate failed for finding %s: %s", finding_id, e)
            return False
        self.add_note(finding_id, note)
        return True

    def add_note(self, finding_id: int, text: str) -> None:
        """POST a note to a finding. Non-fatal on failure."""
        url = f"{self.base}/api/v2/findings/{finding_id}/notes/"
        try:
            self._session.post(url, json={"entry": text}, timeout=self.timeout).raise_for_status()
        except Exception as e:
            log.debug("add_note failed for finding %s: %s", finding_id, e)

    def list_products(self) -> list[dict]:
        """List all DefectDojo products — id, name."""
        resp = self._session.get(f"{self.base}/api/v2/products/", params={"limit": 100}, timeout=self.timeout)
        resp.raise_for_status()
        return [{"id": p["id"], "name": p["name"]} for p in resp.json().get("results", [])]

    def get_test_product(self, test_id: int) -> str | None:
        """Return product name for a test id, or None. Used to label hosts."""
        try:
            t = self._session.get(f"{self.base}/api/v2/tests/{test_id}/", timeout=self.timeout).json()
            eng_id = t.get("engagement")
            if not eng_id:
                return None
            e = self._session.get(f"{self.base}/api/v2/engagements/{eng_id}/", timeout=self.timeout).json()
            prod_id = e.get("product")
            if not prod_id:
                return e.get("name")
            p = self._session.get(f"{self.base}/api/v2/products/{prod_id}/", timeout=self.timeout).json()
            return p.get("name")
        except Exception:
            return None


def _extract_cve(raw: dict) -> str | None:
    vids = raw.get("vulnerability_ids") or []
    if vids and isinstance(vids, list):
        v = vids[0]
        if isinstance(v, dict):
            return v.get("vulnerability_id")
    return None


def _extract_host(raw: dict) -> str | None:
    """Best-effort host label from finding — tags, file_path, or test id."""
    tags = raw.get("tags") or []
    if tags and isinstance(tags, list):
        return ",".join(str(t) for t in tags[:3])
    fp = raw.get("file_path")
    if fp:
        return fp.split("/", 2)[1] if "/" in fp else fp
    tid = raw.get("test")
    return f"test:{tid}" if tid else None
