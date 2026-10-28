import json

from p7.pct import Pct, PctResult
from p7.trivy import TrivyVerifier, _cve_in_results


class FakePct(Pct):
    def __init__(self, stdout: str, rc: int = 0):
        super().__init__(dry_run=False)
        self._stdout = stdout
        self._rc = rc

    def _run(self, argv):
        return PctResult(self._rc, self._stdout, "")


def _trivy_json(cves: list[str]) -> str:
    return json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": c} for c in cves]}]})


def test_cve_in_results_true():
    data = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2026-1234"}]}]}
    assert _cve_in_results(data, "CVE-2026-1234")


def test_cve_in_results_case_insensitive():
    data = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "cve-2026-1234"}]}]}
    assert _cve_in_results(data, "CVE-2026-1234")


def test_cve_in_results_absent():
    data = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2000-0001"}]}]}
    assert not _cve_in_results(data, "CVE-2026-9999")


def test_rescan_rootfs_cleared_when_cve_gone():
    pct = FakePct(stdout=_trivy_json(["CVE-2000-0001"]))
    cleared, _ = TrivyVerifier(pct).rescan_rootfs(205, "CVE-2026-9999")
    assert cleared


def test_rescan_rootfs_not_cleared_when_cve_present():
    pct = FakePct(stdout=_trivy_json(["CVE-2026-9999"]))
    cleared, _ = TrivyVerifier(pct).rescan_rootfs(205, "CVE-2026-9999")
    assert not cleared


def test_rescan_rootfs_fail_when_trivy_errors():
    pct = FakePct(stdout="", rc=1)
    cleared, res = TrivyVerifier(pct).rescan_rootfs(205, "CVE-2026-9999")
    assert not cleared and res.returncode == 1
