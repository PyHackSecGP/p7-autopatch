"""Trivy rescan verifier — confirms a CVE is cleared after patch."""
from __future__ import annotations

import json
import logging

from .pct import Pct, PctResult

log = logging.getLogger(__name__)


class TrivyVerifier:
    """Rescan a container filesystem with trivy inside the CT. CVE still present => fail."""

    def __init__(self, pct: Pct) -> None:
        self.pct = pct

    def rescan_rootfs(self, ctid: int, cve_id: str) -> tuple[bool, PctResult]:
        """Return (cleared, pct_result). `cleared=True` means the CVE is no longer reported.

        Rescans the CT rootfs. Suitable when the CT itself is the vulnerable image.
        """
        res = self.pct.exec(
            ctid,
            "trivy", "rootfs", "--quiet", "--format", "json",
            "--severity", "HIGH,CRITICAL", "/",
        )
        if not res.ok:
            log.warning("ct%s trivy rescan failed rc=%s stderr=%s", ctid, res.returncode, res.stderr[:200])
            return (False, res)
        try:
            data = json.loads(res.stdout) if res.stdout else {}
        except json.JSONDecodeError:
            return (False, res)
        found = _cve_in_results(data, cve_id)
        return (not found, res)


def _cve_in_results(data: dict, cve_id: str) -> bool:
    """Walk trivy JSON report, return True if cve_id appears in any vulnerability."""
    cve_id = cve_id.strip().upper()
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            if str(v.get("VulnerabilityID", "")).upper() == cve_id:
                return True
    return False
