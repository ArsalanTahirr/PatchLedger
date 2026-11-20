import pytest

from patchledger.simulation.nvd_versions import (
    compare_versions,
    version_in_range,
)


@pytest.mark.parametrize(
    ("installed", "boundary", "expected"),
    [
        ("1.0", "1.0.0", 0),
        ("1.2.10", "1.2.9", 1),
        ("1.2.3", "1.2.4", -1),
        ("unknown", "1.0", None),
        ("1.0-beta", "1.0", None),
    ],
)
def test_compare_versions(installed, boundary, expected):
    assert compare_versions(installed, boundary) == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("157.0.8103.49", True),
        ("157.0.8103.50", False),
        ("157.0.8103.51", False),
        ("unknown", None),
    ],
)
def test_exclusive_upper_boundary(version, expected):
    rule = {"versionEndExcluding": "157.0.8103.50"}
    assert version_in_range(version, rule) is expected


def test_inclusive_boundaries():
    rule = {
        "versionStartIncluding": "1.0",
        "versionEndIncluding": "2.0",
    }

    assert version_in_range("1.0", rule) is True
    assert version_in_range("1.5", rule) is True
    assert version_in_range("2.0", rule) is True
    assert version_in_range("2.1", rule) is False


def test_exclusive_lower_boundary():
    rule = {"versionStartExcluding": "1.0"}

    assert version_in_range("1.0", rule) is False
    assert version_in_range("1.0.1", rule) is True
