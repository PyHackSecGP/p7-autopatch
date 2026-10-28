from p7.patcher import ApkPatcher, AptPatcher, select_patcher
from p7.pct import Pct, PctResult


class RecordingPct(Pct):
    def __init__(self):
        super().__init__(dry_run=False)
        self.calls: list[list[str]] = []
        self.next: PctResult | None = None

    def _run(self, argv):
        self.calls.append(argv)
        return self.next or PctResult(0, "", "")


def test_select_patcher_apt():
    assert isinstance(select_patcher("apt", RecordingPct()), AptPatcher)


def test_select_patcher_apk():
    assert isinstance(select_patcher("apk", RecordingPct()), ApkPatcher)


def test_select_patcher_unknown_raises():
    import pytest
    with pytest.raises(ValueError):
        select_patcher("yum", RecordingPct())


def test_apt_apply_builds_correct_argv():
    pct = RecordingPct()
    AptPatcher(pct).apply(209, "curl", "7.88.1-10+deb12u5")
    cmd = pct.calls[-1]
    assert cmd[0] == "exec" and cmd[1] == "209"
    assert "apt-get" in cmd and "install" in cmd
    assert "curl=7.88.1-10+deb12u5" in cmd


def test_apk_apply_builds_correct_argv():
    pct = RecordingPct()
    ApkPatcher(pct).apply(205, "libssl3", "3.5.6-r0")
    cmd = pct.calls[-1]
    assert cmd[0] == "exec" and cmd[1] == "205"
    assert "apk" in cmd and "add" in cmd
    assert "libssl3=3.5.6-r0" in cmd


def test_apk_installed_version_parses_apk_info_output():
    pct = RecordingPct()
    pct.next = PctResult(0, "libssl3-3.5.5-r0\ndescription", "")
    assert ApkPatcher(pct).installed_version(205, "libssl3") == "3.5.5-r0"


def test_apk_installed_version_none_when_absent():
    pct = RecordingPct()
    pct.next = PctResult(1, "", "ERROR")
    assert ApkPatcher(pct).installed_version(205, "ghost") is None
