import pytest

from patchledger.simulation.nvd_proof_records import build_proof_report

APP_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "2.0",
}

OTHER_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:example:other_app:*:*:*:*:*:*:*:*",
}

LINUX_RULE = {
    "vulnerable": False,
    "criteria": "cpe:2.3:o:example:linux:-:*:*:*:*:*:*:*",
}

APP_OLD = "cpe:2.3:a:example:app:1.5:-:-:-:-:-:-:-"
APP_FIXED = "cpe:2.3:a:example:app:2.0:-:-:-:-:-:-:-"
LINUX = "cpe:2.3:o:example:linux:-:-:-:-:-:-:-:-"


def install(identifier, cpe):
    return {
        "asset_id": "asset-1",
        "installation_id": identifier,
        "cpe": cpe,
    }


def test_missing_and_requirement_cannot_be_bypassed_by_outer_or():
    config = [
        {
            "operator": "OR",
            "nodes": [
                {
                    "operator": "AND",
                    "cpeMatch": [APP_RULE, LINUX_RULE],
                },
                {
                    "operator": "OR",
                    "cpeMatch": [OTHER_RULE],
                },
            ],
        }
    ]

    report = build_proof_report(
        "CVE-TEST-001",
        config,
        "asset-1",
        [install("app-1", APP_OLD)],
        inventory_complete=True,
    )

    assert report.applicable is False
    assert report.proof_verified is False
    assert report.supporting_records == ()


def test_fixed_application_plus_linux_not_vulnerable():
    config = [
        {
            "operator": "OR",
            "cpeMatch": [APP_RULE, LINUX_RULE],
        }
    ]

    report = build_proof_report(
        "CVE-TEST-002",
        config,
        "asset-1",
        [
            install("app-fixed", APP_FIXED),
            install("linux-1", LINUX),
        ],
        inventory_complete=True,
    )

    assert report.applicable is False
    assert report.proof_verified is False
    assert report.supporting_records == ()


def test_fixed_and_affected_installations_keep_correct_evidence():
    config = [
        {
            "operator": "AND",
            "cpeMatch": [APP_RULE, LINUX_RULE],
        }
    ]

    report = build_proof_report(
        "CVE-TEST-003",
        config,
        "asset-1",
        [
            install("app-affected", APP_OLD),
            install("app-fixed", APP_FIXED),
            install("linux-1", LINUX),
        ],
        inventory_complete=True,
    )

    assert report.applicable is True
    assert report.proof_verified is True

    affected_ids = {
        item.installation_id for item in report.supporting_records if item.vulnerable
    }

    assert affected_ids == {"app-affected"}
    assert "app-fixed" not in {
        item.installation_id for item in report.supporting_records
    }


def test_cross_asset_installation_is_rejected():
    config = [
        {
            "operator": "AND",
            "cpeMatch": [APP_RULE, LINUX_RULE],
        }
    ]

    other_asset_linux = {
        "asset_id": "asset-2",
        "installation_id": "linux-other",
        "cpe": LINUX,
    }

    with pytest.raises(ValueError, match="Cross-asset"):
        build_proof_report(
            "CVE-TEST-004",
            config,
            "asset-1",
            [
                install("app-1", APP_OLD),
                other_asset_linux,
            ],
            inventory_complete=True,
        )
