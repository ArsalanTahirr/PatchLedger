from patchledger.simulation.nvd_proof import (
    select_applicability_proof,
)

APP_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "2.0",
}

LINUX_RULE = {
    "vulnerable": False,
    "criteria": "cpe:2.3:o:example:linux:-:*:*:*:*:*:*:*",
}

APP = "cpe:2.3:a:example:app:1.5:-:-:-:-:-:-:-"
FIXED = "cpe:2.3:a:example:app:2.0:-:-:-:-:-:-:-"
LINUX = "cpe:2.3:o:example:linux:-:-:-:-:-:-:-:-"


def install(identifier, cpe, asset="asset-1"):
    return {
        "asset_id": asset,
        "installation_id": identifier,
        "cpe": cpe,
    }


def config(operator):
    return [
        {
            "nodes": [
                {
                    "operator": operator,
                    "cpeMatch": [APP_RULE, LINUX_RULE],
                }
            ],
        }
    ]


def test_and_requires_both_supporting_rules():
    result = select_applicability_proof(
        "CVE-TEST-001",
        config("AND"),
        "asset-1",
        [install("app-1", APP), install("os-1", LINUX)],
        inventory_complete=True,
    )

    assert result.applicable is True
    assert result.proof_verified is True
    assert len(result.supporting_paths) == 2
    assert result.other_matched_paths == ()


def test_or_selects_affected_branch_only():
    result = select_applicability_proof(
        "CVE-TEST-001",
        config("OR"),
        "asset-1",
        [install("app-1", APP), install("os-1", LINUX)],
        inventory_complete=True,
    )

    assert result.applicable is True
    assert result.proof_verified is True
    assert result.supporting_paths == ("configurations[0].nodes[0].cpeMatch[0]",)
    assert result.other_matched_paths == ("configurations[0].nodes[0].cpeMatch[1]",)


def test_platform_only_match_is_not_proof():
    result = select_applicability_proof(
        "CVE-TEST-001",
        config("OR"),
        "asset-1",
        [install("app-1", FIXED), install("os-1", LINUX)],
        inventory_complete=True,
    )

    assert result.applicable is False
    assert result.proof_verified is False
    assert result.supporting_paths == ()
    assert len(result.other_matched_paths) == 1


def test_missing_required_platform_is_not_proof():
    result = select_applicability_proof(
        "CVE-TEST-001",
        config("AND"),
        "asset-1",
        [install("app-1", APP)],
        inventory_complete=True,
    )

    assert result.applicable is False
    assert result.proof_verified is False
    assert result.supporting_paths == ()


def test_inconclusive_platform_is_not_verified():
    numeric_linux = "cpe:2.3:o:example:linux:6.8.0:-:-:-:-:-:-:-"

    result = select_applicability_proof(
        "CVE-TEST-001",
        config("AND"),
        "asset-1",
        [
            install("app-1", APP),
            install("os-1", numeric_linux),
        ],
        inventory_complete=True,
    )

    assert result.applicable is None
    assert result.proof_verified is False
    assert result.supporting_paths == ()
