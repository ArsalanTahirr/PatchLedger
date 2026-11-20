import csv
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "bronze_to_silver.py"
)


def write_csv(path, columns, records):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def test_nvd_epss_kev_alignment(tmp_path):
    ids = [
        "CVE-2026-100001",
        "CVE-2026-100002",
        "CVE-2026-100003",
        "CVE-2026-100004",
    ]

    config = [{
        "operator": "AND",
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": (
                    "cpe:2.3:a:example:application:"
                    "*:*:*:*:*:*:*:*"
                ),
            }],
        }],
    }]

    nvd = [
        {
            "cve_id": cve,
            "published": f"2026-11-{10-i:02d}T12:00:00Z",
            "configurations_json": (
                json.dumps(config) if i == 3 else ""
            ),
        }
        for i, cve in enumerate(ids)
    ]

    write_csv(
        tmp_path / "nvd_cves.csv",
        ["cve_id", "published", "configurations_json"],
        nvd,
    )

    write_csv(
        tmp_path / "epss_scores.csv",
        ["cve", "epss", "percentile"],
        [
            {"cve": ids[3], "epss": "0.9", "percentile": "0.99"},
            {"cve": ids[0], "epss": "0.5", "percentile": "0.80"},
            {"cve": ids[2], "epss": "0.2", "percentile": "0.40"},
        ],
    )

    write_csv(
        tmp_path / "known_exploited_vulnerabilities.csv",
        ["cveID", "vendorProject", "product"],
        [{
            "cveID": ids[3],
            "vendorProject": "Example",
            "product": "Application",
        }],
    )

    output = tmp_path / "alignment_output"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--data-dir", str(tmp_path),
            "--output-dir", str(output),
            "--max-rows", "3",
            "--chunksize", "2",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )

    silver = output / "silver"

    nvd_ids = {
        r["cve_id"]
        for r in read_csv(silver / "nvd_clean.csv")
    }
    epss_ids = {
        r["cve_id"]
        for r in read_csv(silver / "epss_clean.csv")
    }
    kev_ids = {
        r["cve_id"]
        for r in read_csv(silver / "kev_clean.csv")
    }

    assert nvd_ids == {ids[0], ids[1], ids[3]}
    assert epss_ids == {ids[0], ids[3]}
    assert kev_ids == {ids[3]}

    cpe = read_csv(silver / "nvd_affected_cpe.csv")

    assert len(cpe) == 1
    assert cpe[0]["cve_id"] == ids[3]
    assert cpe[0]["configuration_operator"] == "AND"
    assert cpe[0]["node_operator"] == "OR"

    quality = json.loads(
        (
            output / "reports" / "data_quality_details.json"
        ).read_text(encoding="utf-8")
    )

    selection = quality["selection"]

    assert selection["kev_matched_in_nvd_export"] == 1
    assert selection["epss_matched_in_nvd_export"] == 2
    assert selection["all_three_overlap"] == 1
    assert selection["nvd_cpe_export_rows"] == 1

    assert len(read_csv(silver / "nvd_clean.csv")) == 3
    assert len(read_csv(silver / "epss_clean.csv")) == 2
    assert len(read_csv(silver / "kev_clean.csv")) == 1
