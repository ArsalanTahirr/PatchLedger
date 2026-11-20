import pytest

from patchledger.simulation.nvd_applicability_v3 import (
    evaluate_nvd_configurations,
)

LINUX = "cpe:2.3:o:example:linux:-:-:-:-:-:-:-:-"


def app(version):
    return f"cpe:2.3:a:example:app:{version}:-:-:-:-:-:-:-"


APP_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
    "versionEndExcluding": "2.0",
}

LINUX_RULE = {
    "vulnerable": False,
    "criteria": "cpe:2.3:o:example:linux:-:*:*:*:*:*:*:*",
}


@pytest.mark.parametrize(
    ("operator", "inventory", "complete", "expected"),
    [
        ("AND", [LINUX, app("1.5")], True, True),
        ("AND", [LINUX, app("2.0")], True, False),
        ("AND", [app("1.5")], True, False),
        ("AND", [app("1.5")], False, None),
        ("OR", [LINUX, app("1.5")], True, True),
        ("OR", [LINUX, app("2.0")], True, False),
        ("OR", [LINUX, app("*")], True, None),
        ("OR", [LINUX, app("2.0")], False, None),
    ],
)
def test_branch_aware(operator, inventory, complete, expected):
    config = [
        {
            "nodes": [
                {
                    "operator": operator,
                    "cpeMatch": [APP_RULE, LINUX_RULE],
                }
            ],
        }
    ]

    assert (
        evaluate_nvd_configurations(
            config,
            inventory,
            inventory_complete=complete,
        )
        is expected
    )


@pytest.mark.parametrize(
    "unsupported",
    [
        {"operator": "XOR", "cpeMatch": [APP_RULE]},
        {"operator": "OR", "negate": True, "cpeMatch": [APP_RULE]},
    ],
)
def test_unsupported_branch(unsupported):
    config = [
        {
            "nodes": [
                {"operator": "OR", "cpeMatch": [LINUX_RULE]},
                unsupported,
            ],
        }
    ]

    assert (
        evaluate_nvd_configurations(
            config,
            [LINUX, app("2.0")],
            inventory_complete=True,
        )
        is None
    )


def test_platform_only_is_not_vulnerability():
    config = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [LINUX_RULE],
                }
            ],
        }
    ]

    assert (
        evaluate_nvd_configurations(
            config,
            [LINUX],
            inventory_complete=True,
        )
        is None
    )
