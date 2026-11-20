import csv
import json

import pytest

from patchledger.simulation.nvd_catalog import (
    extract_cpe_matches,
    load_nvd_catalog,
)


def test_load_nvd_catalog(tmp_path):
    path = tmp_path / "nvd.csv"

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "configurations_json"])
        writer.writeheader()
        writer.writerow(
            {
                "cve_id": "CVE-2026-1000",
                "configurations_json": json.dumps(
                    [{"nodes": [{"operator": "OR", "cpeMatch": []}]}]
                ),
            }
        )

    catalog = load_nvd_catalog(path, limit=10)

    assert len(catalog) == 1
    assert catalog[0]["cve_id"] == "CVE-2026-1000"


def test_extract_nested_cpe():
    catalog = [
        {
            "cve_id": "CVE-2026-1001",
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                            "versionEndExcluding": "157.0.8103.50",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ]

    matches = extract_cpe_matches(catalog)

    assert len(matches) == 1
    assert matches[0]["vendor"] == "google"
    assert matches[0]["product"] == "chrome"
    assert matches[0]["versionEndExcluding"] == "157.0.8103.50"


def test_invalid_cpe_skipped():
    catalog = [
        {
            "cve_id": "CVE-2026-1002",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "invalid-cpe",
                                    "vulnerable": True,
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ]

    assert extract_cpe_matches(catalog) == []


def test_limit_must_be_positive(tmp_path):
    with pytest.raises(ValueError):
        load_nvd_catalog(tmp_path / "missing.csv", limit=0)


def test_extract_escaped_colon_cpe():
    criteria = (
        r"cpe:2.3:a:cisco:dna_spaces\:_connector:"
        "*:*:*:*:*:*:*:*"
    )

    catalog = [
        {
            "cve_id": "CVE-2021-44228",
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "criteria": criteria,
                                    "vulnerable": True,
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ]

    matches = extract_cpe_matches(catalog)

    assert len(matches) == 1
    assert matches[0]["vendor"] == "cisco"
    assert matches[0]["product"] == "dna_spaces:_connector"
    assert matches[0]["criteria"] == criteria
