import pytest

from patchledger.simulation.nvd_evidence import evaluate_asset

APP_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "2.0",
    "matchCriteriaId": "app-rule-001",
}

OS_RULE = {
    "vulnerable": False,
    "criteria": "cpe:2.3:o:example:linux:-:*:*:*:*:*:*:*",
    "matchCriteriaId": "platform-rule-001",
}

CONFIG = [
    {
        "nodes": [
            {
                "operator": "AND",
                "cpeMatch": [APP_RULE, OS_RULE],
            }
        ],
    }
]


def installation(asset_id, installation_id, cpe):
    return {
        "asset_id": asset_id,
        "installation_id": installation_id,
        "cpe": cpe,
    }


APP = "cpe:2.3:a:example:app:1.5:-:-:-:-:-:-:-"
LINUX = "cpe:2.3:o:example:linux:-:-:-:-:-:-:-:-"


def test_same_asset_matches_with_evidence():
    result = evaluate_asset(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [
            installation("asset-1", "install-app", APP),
            installation("asset-1", "install-os", LINUX),
        ],
        inventory_complete=True,
    )

    assert result.applicable is True
    assert len(result.rules) == 2
    assert result.rules[0].matched_installations == ("install-app",)
    assert result.rules[1].matched_installations == ("install-os",)
    assert result.rules[0].match_criteria_id == "app-rule-001"
    assert result.rules[1].vulnerable is False


def test_platform_on_other_asset_cannot_satisfy_dependency():
    with pytest.raises(ValueError, match="Cross-asset"):
        evaluate_asset(
            "CVE-TEST-001",
            CONFIG,
            "asset-1",
            [
                installation("asset-1", "install-app", APP),
                installation("asset-2", "install-os", LINUX),
            ],
            inventory_complete=True,
        )


def test_missing_platform_on_complete_asset():
    result = evaluate_asset(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [installation("asset-1", "install-app", APP)],
        inventory_complete=True,
    )

    assert result.applicable is False


def test_missing_platform_on_incomplete_asset():
    result = evaluate_asset(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [installation("asset-1", "install-app", APP)],
        inventory_complete=False,
    )

    assert result.applicable is None


def test_duplicate_installation_id_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_asset(
            "CVE-TEST-001",
            CONFIG,
            "asset-1",
            [
                installation("asset-1", "same-id", APP),
                installation("asset-1", "same-id", LINUX),
            ],
        )


def test_matched_app_does_not_override_missing_platform():
    result = evaluate_asset(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [installation("asset-1", "install-app", APP)],
        inventory_complete=True,
    )

    # The application matches, but the required platform is absent.
    assert result.applicable is False
    assert result.rules[0].matched_installations == ("install-app",)
    assert result.rules[1].matched_installations == ()


def test_matched_app_with_incomplete_inventory():
    result = evaluate_asset(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [installation("asset-1", "install-app", APP)],
        inventory_complete=False,
    )

    # Missing platform information is not proof of absence.
    assert result.applicable is None
    assert result.rules[0].matched_installations == ("install-app",)


def test_uncertain_platform_has_separate_evidence():
    numeric_linux = "cpe:2.3:o:example:linux:6.8.0:-:-:-:-:-:-:-"

    result = evaluate_asset(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [
            installation("asset-1", "install-app", APP),
            installation("asset-1", "install-os", numeric_linux),
        ],
        inventory_complete=True,
    )

    assert result.applicable is None
    assert result.rules[0].matched_installations == ("install-app",)
    assert result.rules[1].matched_installations == ()
    assert result.rules[1].inconclusive_installations == ("install-os",)
