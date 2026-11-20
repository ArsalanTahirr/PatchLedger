import pytest

from patchledger.simulation.nvd_applicability_v2 import (
    evaluate_nvd_configurations,
)

APP = "cpe:2.3:a:example:app:1.0:-:-:-:-:-:-:-"
OS = "cpe:2.3:o:example:os:10:-:-:-:-:-:-:-"

APP_RULE = {
    "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
    "vulnerable": True,
}

OS_RULE = {
    "criteria": "cpe:2.3:o:example:os:*:*:*:*:*:*:*:*",
    "vulnerable": False,
}

CONFIG = [
    {
        "nodes": [
            {
                "operator": "AND",
                "children": [
                    {"operator": "OR", "cpeMatch": [APP_RULE]},
                    {"operator": "OR", "cpeMatch": [OS_RULE]},
                ],
            }
        ],
    }
]


@pytest.mark.parametrize(
    ("inventory", "complete", "expected"),
    [
        ([APP, OS], True, True),
        ([APP], True, False),
        ([APP], False, None),
        ([OS], True, False),
        ([], True, False),
    ],
)
def test_platform_dependency(inventory, complete, expected):
    result = evaluate_nvd_configurations(
        CONFIG,
        inventory,
        inventory_complete=complete,
    )
    assert result is expected


def test_platform_alone_is_not_vulnerable():
    config = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [OS_RULE],
                }
            ],
        }
    ]

    assert evaluate_nvd_configurations(config, [OS], inventory_complete=True) is None
