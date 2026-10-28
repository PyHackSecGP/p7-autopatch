"""End-to-end orchestrator test with mocked pct + dojo. No shell, no network."""
from __future__ import annotations

from dataclasses import dataclass

from p7.classifier import ChangeLevel
from p7.dojo import Finding
from p7.orchestrator import Orchestrator
from p7.pct import Pct, PctResult


class FakePct(Pct):
    """pct replacement that records calls and lets tests set per-command returns."""

    def __init__(self, health_ok: bool = True, patch_ok: bool = True):
        super().__init__(dry_run=False)
        self.calls: list[list[str]] = []
        self.health_ok = health_ok
        self.patch_ok = patch_ok

    def _run(self, argv: list[str]) -> PctResult:
        self.calls.append(argv)
        if argv[:2] == ["exec"] and False:
            pass
        if argv and argv[0] == "exec" and "systemctl" in argv:
            return PctResult(0 if self.health_ok else 3, "active" if self.health_ok else "failed", "")
        if argv and argv[0] == "exec" and "apt-get" in argv and "install" in argv:
            return PctResult(0 if self.patch_ok else 100, "", "" if self.patch_ok else "E: Unable to locate package")
        if argv and argv[0] == "exec" and "dpkg-query" in argv:
            return PctResult(0, "1.2.3-1ubuntu0.1", "")
        return PctResult(0, "", "")


class FakeDojo:
    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    def iter_high_findings(self):
        yield from self._findings


def _mk_finding(fid: int, pkg: str, cur: str, fix: str, host: str) -> Finding:
    return Finding(
        id=fid, title=f"CVE on {pkg}", severity="High",
        component_name=pkg, component_version=cur,
        fix_available=fix, cve=f"CVE-2026-{fid:04d}", host=host,
    )


def test_patch_level_applied_when_healthy():
    pct = FakePct(health_ok=True, patch_ok=True)
    dojo = FakeDojo([_mk_finding(1, "curl", "1.2.3", "1.2.4", "ct209-scanner")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, max_change=ChangeLevel.PATCH)
    out = orch.run(209)
    assert len(out) == 1
    assert out[0].applied
    assert not out[0].rolled_back
    assert out[0].level is ChangeLevel.PATCH
    assert any(c[:2] == ["snapshot", "209"] for c in pct.calls)


def test_rollback_fires_on_healthcheck_fail():
    pct = FakePct(health_ok=False, patch_ok=True)
    dojo = FakeDojo([_mk_finding(2, "curl", "1.2.3", "1.2.4", "ct209-scanner")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, max_change=ChangeLevel.PATCH)
    out = orch.run(209)
    assert out[0].rolled_back
    assert not out[0].applied
    assert any(c[0] == "rollback" for c in pct.calls)
    assert any(c[0] == "reboot" for c in pct.calls)


def test_rollback_fires_on_apt_fail():
    pct = FakePct(health_ok=True, patch_ok=False)
    dojo = FakeDojo([_mk_finding(3, "curl", "1.2.3", "1.2.4", "ct209-scanner")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, max_change=ChangeLevel.PATCH)
    out = orch.run(209)
    assert out[0].rolled_back
    assert not out[0].applied
    assert any(c[0] == "rollback" for c in pct.calls)


def test_major_change_skipped_at_default_max():
    pct = FakePct()
    dojo = FakeDojo([_mk_finding(4, "openssl", "1.1.1", "3.0.0", "ct209-scanner")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={209: ["ssh"]}, max_change=ChangeLevel.PATCH)
    out = orch.run(209)
    assert not out[0].applied
    assert not out[0].rolled_back
    assert out[0].level is ChangeLevel.MAJOR
    # ensure no snapshot was taken for a skipped finding
    assert not any(c[0] == "snapshot" for c in pct.calls)


def test_skip_host_short_circuits():
    pct = FakePct()
    dojo = FakeDojo([_mk_finding(5, "curl", "1.2.3", "1.2.4", "ct209-scanner")])
    orch = Orchestrator(dojo=dojo, pct=pct, healthchecks={}, max_change=ChangeLevel.PATCH, skip_hosts={209})
    out = orch.run(209)
    assert out == []
    assert pct.calls == []
