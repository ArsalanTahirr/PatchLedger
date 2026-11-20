from test_nvd_evidence import APP, CONFIG, LINUX, installation

from patchledger.simulation.nvd_proof_records import (
    build_proof_report,
)


def test_structured_proof_for_complete_match():
    report = build_proof_report(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [
            installation("asset-1", "install-app", APP),
            installation("asset-1", "install-os", LINUX),
        ],
        inventory_complete=True,
    )

    assert report.applicable is True
    assert report.proof_verified is True
    assert len(report.supporting_records) == 2

    affected = [r for r in report.supporting_records if r.vulnerable]
    platform = [r for r in report.supporting_records if not r.vulnerable]

    assert len(affected) == 1
    assert len(platform) == 1
    assert affected[0].installation_id == "install-app"
    assert affected[0].match_criteria_id == "app-rule-001"
    assert affected[0].asset_id == "asset-1"
    assert platform[0].installation_id == "install-os"
    assert platform[0].match_criteria_id == "platform-rule-001"


def test_no_verified_records_when_platform_missing():
    report = build_proof_report(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [installation("asset-1", "install-app", APP)],
        inventory_complete=True,
    )

    assert report.applicable is False
    assert report.proof_verified is False
    assert report.supporting_records == ()


def test_no_verified_records_when_inventory_incomplete():
    report = build_proof_report(
        "CVE-TEST-001",
        CONFIG,
        "asset-1",
        [installation("asset-1", "install-app", APP)],
        inventory_complete=False,
    )

    assert report.applicable is None
    assert report.proof_verified is False
    assert report.supporting_records == ()


def test_nested_and_or_selects_correct_supporting_rules():
    alternative_rule = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:example:other_app:*:*:*:*:*:*:*:*",
    }

    config = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        alternative_rule,
                        CONFIG[0]["nodes"][0]["cpeMatch"][0],
                    ],
                },
                {
                    "operator": "OR",
                    "cpeMatch": [CONFIG[0]["nodes"][0]["cpeMatch"][1]],
                },
            ],
        }
    ]

    report = build_proof_report(
        "CVE-TEST-NESTED",
        config,
        "asset-1",
        [
            installation("asset-1", "app-1", APP),
            installation("asset-1", "linux-1", LINUX),
        ],
        inventory_complete=True,
    )

    assert report.applicable is True
    assert report.proof_verified is True
    assert {r.installation_id for r in report.supporting_records} == {
        "app-1",
        "linux-1",
    }
    assert len(report.supporting_records) == 2


def test_outer_or_prefers_affected_branch_over_platform_only():
    app_rule, os_rule = CONFIG[0]["nodes"][0]["cpeMatch"]

    config = [
        {
            "operator": "OR",
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [os_rule],
                },
                {
                    "operator": "AND",
                    "cpeMatch": [app_rule, os_rule],
                },
            ],
        }
    ]

    report = build_proof_report(
        "CVE-TEST-ALTERNATIVES",
        config,
        "asset-1",
        [
            installation("asset-1", "app-1", APP),
            installation("asset-1", "linux-1", LINUX),
        ],
        inventory_complete=True,
    )

    assert report.applicable is True
    assert report.proof_verified is True
    assert {r.installation_id for r in report.supporting_records} == {
        "app-1",
        "linux-1",
    }
    assert all(".nodes[1]." in r.rule_path for r in report.supporting_records)


def test_multiple_matching_app_installations_preserved():
    report = build_proof_report(
        "CVE-TEST-MULTI",
        CONFIG,
        "asset-1",
        [
            installation("asset-1", "app-1", APP),
            installation("asset-1", "app-2", APP),
            installation("asset-1", "linux-1", LINUX),
        ],
        inventory_complete=True,
    )

    assert report.applicable is True
    assert report.proof_verified is True
    assert len(report.supporting_records) == 3
    assert {r.installation_id for r in report.supporting_records if r.vulnerable} == {
        "app-1",
        "app-2",
    }
