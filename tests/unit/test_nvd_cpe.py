import pytest

from patchledger.simulation.nvd_cpe import (
    match_cpe_criteria,
    parse_cpe,
)

RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "157.0.8103.50",
}


def installed(version, vendor="google", product="chrome"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:-:-:-:-:-:-:-"


@pytest.mark.parametrize(
    ("cpe", "expected"),
    [
        (installed("157.0.8103.49"), True),
        (installed("157.0.8103.50"), False),
        (installed("157.0.8103.51"), False),
        (installed("157.0.8103.49", "mozilla", "firefox"), False),
        (installed("unknown"), None),
        (installed("*"), None),
    ],
)
def test_cpe_matching(cpe, expected):
    assert match_cpe_criteria(cpe, RULE) is expected


def test_invalid_cpe():
    assert parse_cpe("not-a-cpe") is None


def test_architecture_mismatch():
    rule = {"criteria": "cpe:2.3:a:example:software:*:*:*:*:*:*:x64:*"}
    cpe = "cpe:2.3:a:example:software:1.0:-:-:-:-:-:x86:-"

    assert match_cpe_criteria(cpe, rule) is False


def test_escaped_ampersand():
    rule = {"criteria": r"cpe:2.3:a:siemens:opcenter_rd\&l:-:*:*:*:*:*:*:*"}
    installed = r"cpe:2.3:a:siemens:opcenter_rd\&l:-:-:-:-:-:-:-:-"

    assert match_cpe_criteria(installed, rule) is True


def test_escaped_colons():
    rule = {
        "criteria": r"cpe:2.3:a:jmcnamara:spreadsheet\:\:parseexcel:*:*:*:*:*:perl:*:*"
    }
    installed = r"cpe:2.3:a:jmcnamara:spreadsheet\:\:parseexcel:1.0:-:-:-:-:perl:-:-"

    assert parse_cpe(rule["criteria"]) is not None
    assert match_cpe_criteria(installed, rule) is True


def test_escaped_colon_connector():
    rule = {"criteria": r"cpe:2.3:a:cisco:dna_spaces\:_connector:*:*:*:*:*:*:*:*"}
    installed = r"cpe:2.3:a:cisco:dna_spaces\:_connector:1.0:-:-:-:-:-:-:-"

    assert match_cpe_criteria(installed, rule) is True


def test_unsupported_wildcard_expression():
    rule = {"criteria": "cpe:2.3:a:example:product*:1.0:*:*:*:*:*:*:*"}

    assert (
        match_cpe_criteria(
            "cpe:2.3:a:example:productx:1.0:*:*:*:*:*:*:*",
            rule,
        )
        is None
    )


def test_dash_version_against_concrete_version_is_inconclusive():
    installed_cpe = "cpe:2.3:o:linux:linux_kernel:6.8.0:-:-:-:-:-:-:-"
    rule = {"criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}

    assert match_cpe_criteria(installed_cpe, rule) is None


def test_dash_version_still_rejects_wrong_product():
    installed_cpe = "cpe:2.3:o:example:other_os:6.8.0:-:-:-:-:-:-:-"
    rule = {"criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}

    assert match_cpe_criteria(installed_cpe, rule) is False
