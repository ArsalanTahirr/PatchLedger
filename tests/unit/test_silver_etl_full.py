"""Regression tests for full-coverage Bronze-to-Silver ETL."""
import csv
import json
from pathlib import Path
import subprocess
import sys

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bronze_to_silver_full.py"


def write_rows(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_rows(path):
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def fixture(tmp_path):
    ids = ["CVE-2026-100001", "CVE-2026-100002", "CVE-2026-100003", "CVE-2026-100004"]
    config = [{"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:example:tool:*:*:*:*:*:*:*:*"
    }]}]}]
    write_rows(tmp_path / "nvd_cves.csv", ["cve_id", "published", "configurations_json"], [
        {"cve_id": v, "published": f"2026-11-{10-i:02d}T12:00:00Z",
         "configurations_json": json.dumps(config) if i == 3 else ""}
        for i, v in enumerate(ids)
    ])
    write_rows(tmp_path / "epss_scores.csv", ["cve", "epss", "percentile"], [
        {"cve": ids[0], "epss": "0.4", "percentile": "0.8"},
        {"cve": ids[3], "epss": "0.9", "percentile": "0.99"},
        {"cve": "CVE-2026-999999", "epss": "0.3", "percentile": "0.7"},
    ])
    write_rows(tmp_path / "known_exploited_vulnerabilities.csv", ["cveID", "vendorProject", "product"], [
        {"cveID": ids[3], "vendorProject": "Example", "product": "Tool"},
        {"cveID": "CVE-2026-999998", "vendorProject": "Example", "product": "Other"},
    ])
    return ids


def test_full_mode_keeps_all_valid_nvd_and_kev(tmp_path):
    ids = fixture(tmp_path)
    target = tmp_path / "full_export"
    result = subprocess.run([
        sys.executable, str(SCRIPT), "--data-dir", str(tmp_path),
        "--output-dir", str(target), "--chunksize", "2",
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    silver = target / "silver"
    assert {r["cve_id"] for r in read_rows(silver / "nvd_clean.csv")} == set(ids)
    assert {r["cve_id"] for r in read_rows(silver / "epss_clean.csv")} == {ids[0], ids[3]}
    assert len(read_rows(silver / "kev_clean.csv")) == 2
    cpe = read_rows(silver / "nvd_affected_cpe.csv")
    assert len(cpe) == 1
    assert cpe[0]["configuration_operator"] == "AND"
    assert cpe[0]["node_operator"] == "OR"
    assert cpe[0]["cve_id"] == ids[3]
    info = json.loads((target / "reports/data_quality_details.json").read_text())
    assert info["selection"]["mode"] == "full_coverage"
    assert info["selection"]["kev_matched_in_nvd_export"] == 1
    assert info["selection"]["epss_matched_in_nvd_export"] == 2
    assert info["selection"]["all_three_overlap"] == 1
    assert info["selection"]["nvd_cpe_export_rows"] == 1
    assert (target / "rejected/nvd_rejected.csv").is_file()


def test_full_mode_refuses_existing_output(tmp_path):
    fixture(tmp_path)
    target = tmp_path / "existing"
    target.mkdir()
    marker = target / "marker.txt"
    marker.write_text("PROTECTED")
    result = subprocess.run([
        sys.executable, str(SCRIPT), "--data-dir", str(tmp_path),
        "--output-dir", str(target), "--chunksize", "2",
    ], capture_output=True, text=True)
    assert result.returncode != 0
    assert marker.read_text() == "PROTECTED"
