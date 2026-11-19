"""Regression tests based on NVD CVE-2026-123218."""

import pytest

from patchledger.simulation.nvd_applicability_v2 import (
    evaluate_nvd_configurations,
)


FASPEX_RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:ibm:aspera_faspex:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "5.0.0",
    "versionEndExcluding": "5.0.19.1",
}

LINUX_RULE = {
    "vulnerable": False,
    "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
}

CONFIG = [{
    "nodes": [{
        "operator": "AND",
        "nodes": [
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [FASPEX_RULE],
            },
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [LINUX_RULE],
            },
        ],
    }],
}]


def faspex(version):
    return (
        f"cpe:2.3:a:ibm:aspera_faspex:{version}"
        ":-:-:-:-:-:-:-"
    )


LINUX = (
    "cpe:2.3:o:linux:linux_kernel:-"
    ":-:-:-:-:-:-:-"
)


@pytest.mark.parametrize(
    ("inventory", "complete", "expected"),
    [
        ([faspex("5.0.0"), LINUX], True, True),
        ([faspex("5.0.10"), LINUX], True, True),
        ([faspex("5.0.19.1"), LINUX], True, False),
        ([faspex("4.9.9"), LINUX], True, False),
        ([faspex("5.0.10")], True, False),
        ([faspex("5.0.10")], False, None),
        ([LINUX], True, False),
    ],
)
def test_real_faspex_linux_configuration(
    inventory, complete, expected
):
    result = evaluate_nvd_configurations(
        CONFIG,
        inventory,
        inventory_complete=complete,
    )
    assert result is expected
