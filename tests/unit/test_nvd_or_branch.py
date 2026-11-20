"""OR branches must not confuse platform and affected-product matches."""

import pytest

from patchledger.simulation.nvd_applicability_v2 import (
    evaluate_nvd_configurations,
)


CONFIG = [{
    "nodes": [{
        "operator": "OR",
        "cpeMatch": [
            {
                "vulnerable": False,
                "criteria":
                    "cpe:2.3:o:example:linux:-:*:*:*:*:*:*:*",
            },
            {
                "vulnerable": True,
                "criteria":
                    "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.0",
            },
        ],
    }],
}]

LINUX = "cpe:2.3:o:example:linux:-:-:-:-:-:-:-:-"


def app(version):
    return (
        f"cpe:2.3:a:example:app:{version}"
        ":-:-:-:-:-:-:-"
    )


@pytest.mark.parametrize(
    ("inventory", "complete", "expected"),
    [
        ([LINUX, app("1.5")], True, True),
        ([LINUX, app("2.0")], True, False),
        ([LINUX, app("2.0")], False, None),
        ([LINUX, app("*")], True, None),
    ],
)
def test_or_branch(inventory, complete, expected):
    result = evaluate_nvd_configurations(
        CONFIG,
        inventory,
        inventory_complete=complete,
    )
    assert result is expected


def test_unsupported_operator_remains_inconclusive():
    config = [{
        "nodes": [
            {
                "operator": "OR",
                "cpeMatch": [CONFIG[0]["nodes"][0]["cpeMatch"][0]],
            },
            {
                "operator": "XOR",
                "cpeMatch": [CONFIG[0]["nodes"][0]["cpeMatch"][1]],
            },
        ],
    }]

    result = evaluate_nvd_configurations(
        config,
        [LINUX, app("2.0")],
        inventory_complete=True,
    )

    assert result is None


def test_negated_branch_remains_inconclusive():
    config = [{
        "nodes": [
            {
                "operator": "OR",
                "cpeMatch": [CONFIG[0]["nodes"][0]["cpeMatch"][0]],
            },
            {
                "operator": "OR",
                "negate": True,
                "cpeMatch": [CONFIG[0]["nodes"][0]["cpeMatch"][1]],
            },
        ],
    }]

    result = evaluate_nvd_configurations(
        config,
        [LINUX, app("2.0")],
        inventory_complete=True,
    )

    assert result is None
