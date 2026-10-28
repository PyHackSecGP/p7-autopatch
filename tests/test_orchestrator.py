"""End-to-end orchestrator test with mocked pct + dojo. No shell, no network."""
from __future__ import annotations

import json

from p7.classifier import ChangeLevel
from p7.dojo import Finding
from p7.notify import NullNotifier
from p7.orchestrator import Orchestrator
from p7.pct import Pct, PctResult


class FakePct(Pct):
    """pct replacement that records calls and lets tests set per-command returns."""

    def __init__(self, health_ok: bool = True, patch_ok: bool = True, trivy_cves: list[str] | None = None):
        super().__init__(dry_run=False)
        self.calls: list[list[str]] = []
        self.health_ok = health_ok
        self.patch_ok = patch_ok
        self.trivy_cves = trivy_cves or []

    def _run(self, argv):
        self.calls.append(argv)
        if argv and argv[0] == "exec" and "systemctl" in argv:
            return PctResult(0 if self.health_ok else 3, "active" if self.health_ok else "failed", "")
        if argv and argv[0] == "exec" and ("apt-get" in argv or "apk" in argv) and ("install" in argv or "add" in argv):
            return PctResult(0 if self.patch_ok else 100, "", "" if self.patch_ok else "pkg fail")
        if argv and argv[0] == "exec" and "dpkg-query" in argv:
            return PctResult(0, "1.2.3-1ubuntu0.1", "")
        if argv and argv[0] == "exec" and "trivy" in argv:
            payload = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": c} for c in self.trivy_cves]}]}
            return PctResult(0, json.dumps(payload), "")
        return PctResult(0, "", "")


class FakeDojo:
    def __init__(self, findings: list[Finding]):
        self._findings = findings
        self.mitigated: list[int] = []

    def iter_high_findings(self, limit=1000, product_id=None, page_size=200):
        yield from self._findings

    def mitigate(self, finding_id: int, note: str) -> bool:
        self.mitigated.append(finding_id)
        return True


def _mk(fid: int, pkg: str, cur: str, fix: str, host: str = "ct209-scanner", cve: str | None = None) -> Finding:
    return Finding(
        id=fid, title=f"CVE on {pkg}", severity="High",
        component_name=pkg, component_version=cur,
        fix_available=fix, cve=cve, host=host,
    )


def test_patch_applied_when_healthy():
    pct = FakePct()
    dojo = FakeDojo([_mk(1, "curl", "1.2.3", "1.2.4")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]})
    out = orch.run(209)
    assert out[0].applied and not out[0].rolled_back


def test_rollback_on_healthcheck_fail():
    pct = FakePct(health_ok=False)
    dojo = FakeDojo([_mk(2, "curl", "1.2.3", "1.2.4")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]})
    out = orch.run(209)
    assert out[0].rolled_back
    assert any(c[0] == "rollback" for c in pct.calls)
    assert any(c[0] == "reboot" for c in pct.calls)


def test_rollback_on_apt_fail():
    pct = FakePct(patch_ok=False)
    dojo = FakeDojo([_mk(3, "curl", "1.2.3", "1.2.4")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]})
    out = orch.run(209)
    assert out[0].rolled_back
    assert any(c[0] == "rollback" for c in pct.calls)


def test_major_change_skipped_at_default_max():
    pct = FakePct()
    dojo = FakeDojo([_mk(4, "openssl", "1.1.1", "3.0.0")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]})
    out = orch.run(209)
    assert not out[0].applied and not out[0].rolled_back
    assert out[0].level is ChangeLevel.MAJOR


def test_skip_host_short_circuits():
    pct = FakePct()
    dojo = FakeDojo([_mk(5, "curl", "1.2.3", "1.2.4")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={}, skip_hosts={209})
    assert orch.run(209) == []
    assert pct.calls == []


def test_apk_backend_runs_apk_add():
    pct = FakePct()
    dojo = FakeDojo([_mk(6, "libssl3", "3.5.5-r0", "3.5.6-r0", host="ct205-defectdojo")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={205: ["docker"]}, backend="apk")
    out = orch.run(205)
    assert out[0].applied
    assert any("apk" in c and "add" in c for c in pct.calls)


def test_trivy_verify_rollback_when_cve_persists():
    pct = FakePct(trivy_cves=["CVE-2026-9999"])
    dojo = FakeDojo([_mk(7, "curl", "1.2.3", "1.2.4", cve="CVE-2026-9999")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, verify_cves=True)
    out = orch.run(209)
    assert out[0].rolled_back
    assert "trivy" in out[0].note.lower()


def test_trivy_verify_passes_when_cve_cleared():
    pct = FakePct(trivy_cves=[])
    dojo = FakeDojo([_mk(8, "curl", "1.2.3", "1.2.4", cve="CVE-2026-9999")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, verify_cves=True)
    out = orch.run(209)
    assert out[0].applied and not out[0].rolled_back


def test_writeback_marks_mitigated_in_dojo():
    pct = FakePct()
    dojo = FakeDojo([_mk(9, "curl", "1.2.3", "1.2.4")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, writeback=True)
    orch.run(209)
    assert 9 in dojo.mitigated


def test_notifier_called_on_rollback():
    class CapturingNotifier(NullNotifier):
        def __init__(self):
            self.msgs = []
        def send(self, text):
            self.msgs.append(text)
            return True

    n = CapturingNotifier()
    pct = FakePct(health_ok=False)
    dojo = FakeDojo([_mk(10, "curl", "1.2.3", "1.2.4")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, notifier=n)
    orch.run(209)
    assert any("ROLLBACK" in m for m in n.msgs)
