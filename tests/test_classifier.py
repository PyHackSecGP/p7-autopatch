from p7.classifier import ChangeLevel, allowed, classify


def test_patch_level():
    assert classify("1.2.3", "1.2.4") is ChangeLevel.PATCH


def test_minor_level():
    assert classify("1.2.3", "1.3.0") is ChangeLevel.MINOR


def test_major_level():
    assert classify("1.9.9", "2.0.0") is ChangeLevel.MAJOR


def test_debian_versioning_collapses_to_semver():
    assert classify("1.2.3-1ubuntu0.4", "1.2.4-1ubuntu0.1") is ChangeLevel.PATCH


def test_equal_versions_unknown():
    assert classify("1.0.0", "1.0.0") is ChangeLevel.UNKNOWN


def test_empty_version_unknown():
    assert classify("", "1.0.0") is ChangeLevel.UNKNOWN


def test_allowed_patch_only():
    assert allowed(ChangeLevel.PATCH, ChangeLevel.PATCH)
    assert not allowed(ChangeLevel.MINOR, ChangeLevel.PATCH)
    assert not allowed(ChangeLevel.MAJOR, ChangeLevel.PATCH)


def test_allowed_up_to_minor():
    assert allowed(ChangeLevel.PATCH, ChangeLevel.MINOR)
    assert allowed(ChangeLevel.MINOR, ChangeLevel.MINOR)
    assert not allowed(ChangeLevel.MAJOR, ChangeLevel.MINOR)
