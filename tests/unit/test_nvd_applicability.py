import pytest

from patchledger.simulation.nvd_applicability import (
    evaluate_nvd_configurations,
)


CHROME_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "157.0.8103.50",
}


def chrome(version):
    return (
        f"cpe:2.3:a:google:chrome:{version}"
        ":-:-:-:-:-:-:-"
    )


def configurations(rule=CHROME_RULE, operator="OR"):
    return [{
        "nodes": [{
            "operator": operator,
            "cpeMatch": [rule],
        }]
    }]


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("157.0.8103.49", True),
        ("157.0.8103.50", False),
        ("unknown", None),
    ],
)
def test_chrome_version(version, expected):
    assert evaluate_nvd_configurations(
        configurations(),
        [chrome(version)],
        inventory_complete=True,
    ) is expected


def test_incomplete_inventory():
    assert evaluate_nvd_configurations(
        configurations(),
        [],
    ) is None


def test_negated_node_is_inconclusive():
    config = [{
        "nodes": [{
            "operator": "OR",
            "negate": True,
            "cpeMatch": [CHROME_RULE],
        }]
    }]

    assert evaluate_nvd_configurations(
        config,
        [chrome("157.0.8103.49")],
        inventory_complete=True,
    ) is None


def test_non_vulnerable_constraint_is_inconclusive():
    rule = {
        **CHROME_RULE,
        "vulnerable": False,
    }

    assert evaluate_nvd_configurations(
        configurations(rule),
        [chrome("157.0.8103.49")],
        inventory_complete=True,
    ) is None


def test_and_combines_rules():
    config = [{
        "nodes": [{
            "operator": "AND",
            "cpeMatch": [
                CHROME_RULE,
                {
                    "vulnerable": True,
                    "criteria":
                        "cpe:2.3:a:example:agent:*:*:*:*:*:*:*:*",
                },
            ],
        }]
    }]

    assert evaluate_nvd_configurations(
        config,
        [chrome("157.0.8103.49")],
        inventory_complete=True,
    ) is False
