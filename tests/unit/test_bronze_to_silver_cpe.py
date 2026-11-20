import importlib.util
import json
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def etl():
    path = Path(__file__).resolve().parents[2] / "scripts" / "bronze_to_silver.py"
    spec = importlib.util.spec_from_file_location("bronze_to_silver_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parent_and_with_platform_prerequisite(etl):
    config = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:ibm:aspera_faspex:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "5.0.0",
                            "versionEndExcluding": "5.0.19.1",
                        }
                    ],
                },
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                        }
                    ],
                },
            ],
        }
    ]

    rules = list(etl.cpe_entries(json.dumps(config), "CVE-2026-123218"))

    assert len(rules) == 2
    assert all(r["configuration_operator"] == "AND" for r in rules)
    assert all(r["node_operator"] == "OR" for r in rules)
    assert [r["vulnerable"] for r in rules] == [True, False]
    assert rules[0]["version_start_including"] == "5.0.0"
    assert rules[0]["version_end_excluding"] == "5.0.19.1"


def test_unspecified_parent_with_and_node(etl):
    config = [
        {
            "nodes": [
                {
                    "operator": "AND",
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:whatsapp:whatsapp:*:*:*:*:desktop:*:*:*",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:whatsapp:whatsapp:*:*:*:*:*:iphone_os:*:*",
                        },
                    ],
                }
            ],
        }
    ]

    rules = list(etl.cpe_entries(json.dumps(config), "CVE-2019-18426"))

    assert len(rules) == 2
    assert all(r["configuration_operator"] == "" for r in rules)
    assert all(r["node_operator"] == "AND" for r in rules)
    assert all(r["vulnerable"] is True for r in rules)


def test_export_schema_contains_parent_operator(etl):
    assert "configuration_operator" in etl.CPE_FIELDS
