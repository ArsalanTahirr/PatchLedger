import csv
import math
import re
import sys
from collections import Counter
from pathlib import Path

csv.field_size_limit(sys.maxsize)

import argparse

parser = argparse.ArgumentParser(description="Audit PatchLedger Silver datasets")
parser.add_argument(
    "--silver-dir",
    type=Path,
    required=True,
    help="Directory containing the four Silver CSV files",
)
args = parser.parse_args()
folder = args.silver_dir.expanduser().resolve()

if not folder.is_dir():
    parser.error(f"Silver directory does not exist: {folder}")

files = {
    "NVD": folder / "nvd_clean.csv",
    "CPE": folder / "nvd_affected_cpe.csv",
    "EPSS": folder / "epss_clean.csv",
    "KEV": folder / "kev_clean.csv",
}

pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
sets = {}

for name, path in files.items():
    ids = set()
    repeated = 0
    missing = 0
    invalid = 0
    invalid_scores = 0
    statuses = Counter()
    count = 0

    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            count += 1
            cve = (row.get("cve_id") or "").strip()

            if not cve:
                missing += 1
            elif not pattern.fullmatch(cve):
                invalid += 1
            else:
                if cve in ids:
                    repeated += 1
                ids.add(cve)

            if name == "EPSS":
                for col in ("epss", "percentile"):
                    try:
                        score = float(row[col])
                        if not math.isfinite(score) or not 0 <= score <= 1:
                            invalid_scores += 1
                    except (ValueError, KeyError, TypeError):
                        invalid_scores += 1

            if name == "NVD":
                statuses[row.get("vulnerability_status") or "(missing)"] += 1

    sets[name] = ids

    print(f"\n=== {name} ===", flush=True)
    print("Rows:", count)
    print("Distinct CVEs:", len(ids))
    print("Repeated CVE IDs:", repeated)
    print("Missing CVE IDs:", missing)
    print("Invalid CVE IDs:", invalid)
    print("Invalid EPSS values:", invalid_scores)

    if name == "NVD":
        print("Statuses:", dict(statuses))

print("\n=== CROSS-DATASET COVERAGE ===")
for name in ("EPSS", "KEV", "CPE"):
    print(name, "CVEs found in NVD:", len(sets[name] & sets["NVD"]))
    print(name, "CVEs absent from NVD:", len(sets[name] - sets["NVD"]))

print("\nSilver audit completed.")
