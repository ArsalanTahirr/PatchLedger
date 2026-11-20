from patchledger.simulation.nvd_cpe import match_cpe_criteria

BASE = "cpe:2.3:a:adobe:coldfusion:2018:update10:*:*:*:*:*:*"


def test_identical_cpe_with_wildcard_fields_matches():
    assert match_cpe_criteria(BASE, {"criteria": BASE}) is True


def test_unknown_update_does_not_confirm_specific_update():
    installed = BASE.replace(":update10:", ":*:")
    assert match_cpe_criteria(installed, {"criteria": BASE}) is None


def test_different_explicit_update_does_not_match():
    installed = BASE.replace(":update10:", ":update11:")
    assert match_cpe_criteria(installed, {"criteria": BASE}) is False


def test_expected_wildcard_accepts_specific_update():
    expected = BASE.replace(":update10:", ":*:")
    assert match_cpe_criteria(BASE, {"criteria": expected}) is True
