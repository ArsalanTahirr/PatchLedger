"""PatchPulse Bronze -> Silver ETL for the three PatchLedgerData CSV feeds.

Run: python3 bronze_to_silver.py
Requires: pandas (python3 -m pip install pandas)

- Input files are not modified.
- EPSS remains cve_id, epss, percentile (NO fabricated score_date).
- Large input files are processed in chunks.
- Rejected records include rejection_reason.
- NVD CPE applicability entries are extracted WITHOUT asserting an asset match.
- Outputs are written safely via temporary files, then published when complete.
- Full source files are scanned for CVE alignment; each Silver CSV has at most 15,000 data rows (configurable).
"""

import argparse
import csv
import heapq
import json
import os
import re
import sqlite3
import sys
import tempfile
from collections import Counter
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    sys.exit("Missing dependency: install with python3 -m pip install pandas")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
INPUTS = {
    "nvd": "nvd_cves.csv",
    "epss": "epss_scores.csv",
    "kev": "known_exploited_vulnerabilities.csv",
}
COLUMN_MAPS = {
    "nvd": {"cve_id": "cve_id"},
    "epss": {"cve": "cve_id"},
    "kev": {
        "cveID": "cve_id",
        "vendorProject": "vendor_project",
        "vulnerabilityName": "vulnerability_name",
        "dateAdded": "date_added",
        "shortDescription": "short_description",
        "requiredAction": "required_action",
        "dueDate": "due_date",
        "knownRansomwareCampaignUse": "known_ransomware_campaign_use",
        "forensicTriage": "forensic_triage",
    },
}
DATE_COLS = {
    "nvd": ("published", "last_modified"),
    "epss": (),
    "kev": ("date_added", "due_date"),
}
JSON_COLS = {
    "nvd": ("configurations_json", "weaknesses_json", "raw_json"),
    "epss": (),
    "kev": ("cwes", "raw_json"),
}
CPE_FIELDS = [
    "cve_id",
    "configuration_index",
    "configuration_operator",
    "node_path",
    "node_operator",
    "node_negate",
    "vulnerable",
    "criteria",
    "match_criteria_id",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
]


def blank(value):
    return value is None or str(value).strip().lower() in ("", "nan", "none", "null")


def normalize_cve(value):
    return "" if blank(value) else str(value).strip().upper()


def normalize_date(value):
    """Return ISO date/time string or None for malformed nonempty text."""
    if blank(value):
        return ""
    try:
        ts = pd.to_datetime(str(value).strip(), errors="coerce", utc=True)
        if pd.isna(ts):
            return None
        return (
            ts.strftime("%Y-%m-%d")
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value).strip())
            else ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    except (ValueError, TypeError, OverflowError):
        return None


def numeric(value, upper):
    if blank(value):
        return "", False
    try:
        val = float(str(value).strip())
        if not (0 <= val <= upper):  # also rejects NaN and infinity
            return "", True
        return format(val, ".15g"), False
    except (ValueError, TypeError, OverflowError):
        return "", True


def cpe_entries(configurations, cve_id):
    """Extract individual match rules, keeping tree path; NOT complete applicability logic."""
    if blank(configurations):
        return
    try:
        payload = json.loads(configurations)
    except (TypeError, ValueError):
        return
    configs = payload if isinstance(payload, list) else [payload]

    def walk(node, cfg_index, path, config_operator):
        if not isinstance(node, dict):
            return
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict):
                continue
            yield {
                "cve_id": cve_id,
                "configuration_index": cfg_index,
                "configuration_operator": config_operator,
                "node_path": path,
                "node_operator": node.get("operator", ""),
                "node_negate": node.get("negate", False),
                "vulnerable": match.get("vulnerable", ""),
                "criteria": match.get("criteria", ""),
                "match_criteria_id": match.get("matchCriteriaId", ""),
                "version_start_including": match.get("versionStartIncluding", ""),
                "version_start_excluding": match.get("versionStartExcluding", ""),
                "version_end_including": match.get("versionEndIncluding", ""),
                "version_end_excluding": match.get("versionEndExcluding", ""),
            }
        for i, child in enumerate(node.get("children") or []):
            yield from walk(child, cfg_index, f"{path}/children[{i}]", config_operator)

    for idx, config in enumerate(configs):
        if isinstance(config, dict):
            for i, node in enumerate(config.get("nodes") or []):
                yield from walk(node, idx, f"nodes[{i}]", config.get("operator", ""))


def process_record(source, rec):
    reasons = []
    output = dict(rec)
    output["cve_id"] = normalize_cve(rec.get("cve_id"))
    if not CVE_PATTERN.fullmatch(output["cve_id"]):
        reasons.append("invalid_cve_id")

    for col in DATE_COLS[source]:
        if col in output:
            converted = normalize_date(output[col])
            if converted is None:
                reasons.append("invalid_" + col)
            else:
                output[col] = converted

    limits = {
        "nvd": {"cvss_score": 10},
        "epss": {"epss": 1, "percentile": 1},
        "kev": {},
    }
    for col, max_val in limits[source].items():
        if col in output:
            converted, invalid = numeric(output[col], max_val)
            if invalid:
                reasons.append("invalid_" + col)
            else:
                output[col] = converted

    for col in JSON_COLS[source]:
        if col in output and not blank(output[col]):
            try:
                json.loads(output[col])
            except (ValueError, TypeError):
                reasons.append("invalid_json_" + col)

    if source == "kev":
        for col in ("vendor_project", "product"):
            if col in output and not blank(output[col]):
                output[col] = str(output[col]).strip()
    if (
        source == "nvd"
        and "cvss_severity" in output
        and not blank(output["cvss_severity"])
    ):
        output["cvss_severity"] = str(output["cvss_severity"]).strip().upper()

    return output, reasons


def schema(source, root):
    src = root / INPUTS[source]
    if not src.is_file():
        raise FileNotFoundError(f"Missing source: {src}")
    cols = pd.read_csv(src, nrows=0, encoding="utf-8-sig").columns.tolist()
    renames = COLUMN_MAPS[source]
    required = {
        "nvd": ["cve_id", "published"],
        "epss": ["cve", "epss", "percentile"],
        "kev": ["cveID"],
    }[source]
    missing = [c for c in required if c not in cols]
    if missing:
        raise ValueError(f"{src.name} missing required columns: {missing}")
    output = [renames.get(c, c) for c in cols]
    if len(output) != len(set(output)):
        raise ValueError(f"Duplicate standardized columns in {src.name}")
    return output


def input_records(source, root, chunksize):
    src = root / INPUTS[source]
    for chunk in pd.read_csv(
        src,
        chunksize=chunksize,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
        on_bad_lines="error",
    ):
        chunk = chunk.rename(columns=COLUMN_MAPS[source])
        for rec in chunk.to_dict(orient="records"):  # noqa: UP028
            yield rec


def scan(source, root, work, chunksize, visitor):
    """Scan whole feed, validate each record, record rejected records & profile."""
    cols = schema(source, root)
    counts = Counter()
    nulls = Counter()
    db = sqlite3.connect(str(work / f"{source}_seen.sqlite"))
    db.execute("CREATE TABLE seen (cve TEXT PRIMARY KEY)")
    with (work / f"{source}_rejected.csv").open(
        "w", newline="", encoding="utf-8"
    ) as rf:
        rejected_writer = csv.DictWriter(
            rf, fieldnames=cols + ["rejection_reason"], extrasaction="ignore"
        )
        rejected_writer.writeheader()
        try:
            for rec in input_records(source, root, chunksize):
                counts["input"] += 1
                for col, value in rec.items():
                    if blank(value):
                        nulls[col] += 1
                row, errors = process_record(source, rec)
                if not errors:
                    try:
                        db.execute("INSERT INTO seen VALUES (?)", (row["cve_id"],))
                    except sqlite3.IntegrityError:
                        errors.append("duplicate_cve_id")
                if errors:
                    rejected_writer.writerow(
                        {**row, "rejection_reason": ";".join(errors)}
                    )
                    counts["rejected"] += 1
                    for reason in errors:
                        counts[reason] += 1
                else:
                    counts["valid"] += 1
                    visitor(row)
                if counts["input"] % 50000 == 0:
                    db.commit()
                    print(
                        f"  {source.upper()}: scanned {counts['input']:,}",
                        end="\r",
                        flush=True,
                    )
        finally:
            db.commit()
            db.close()
    print(
        f"  {source.upper()}: scanned {counts['input']:,}; valid {counts['valid']:,}; rejected {counts['rejected']:,}"
        + " " * 12
    )
    return counts, nulls, cols


def write_clean(path, columns, rows):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="PatchPulse CVE-aligned Bronze to Silver ETL"
    )
    parser.add_argument(
        "--data-dir", type=Path, default=Path(__file__).resolve().parent
    )
    parser.add_argument(
        "--max-rows", type=int, default=15000, help="Maximum records in each Silver CSV"
    )
    parser.add_argument("--chunksize", type=int, default=10000)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New output directory inside --data-dir; must not exist",
    )
    args = parser.parse_args()
    if args.max_rows < 1 or args.chunksize < 1:
        parser.error("max-rows and chunksize must be positive")
    root = args.data_dir.expanduser().resolve()
    if not root.is_dir():
        parser.error("data-dir must be an existing directory")

    output_root = args.output_dir.expanduser().resolve()

    if output_root.parent != root:
        parser.error("output-dir must be a direct child of data-dir")

    if output_root.name in ("silver", "rejected", "reports"):
        parser.error("cannot use an existing standard output name")

    if output_root.exists() or output_root.is_symlink():
        parser.error("output-dir already exists; choose a new name")

    print("Input directory:", root)
    print("New output directory:", output_root)
    print(
        "Strategy: KEV first; select matching NVD plus most recently published NVD; match EPSS on selected NVD IDs."
    )
    print("Scanning entire NVD/EPSS source files (not just first 15,000 rows).")

    # Build everything in temp files; only replace existing outputs after success.
    with tempfile.TemporaryDirectory(prefix="patchpulse_aligned_", dir=root) as temp:
        work = Path(temp)
        results = {}
        kev_rows = []

        def add_kev(rec):
            if len(kev_rows) < args.max_rows:
                kev_rows.append(rec)

        kev_counts, kev_nulls, kev_cols = scan(
            "kev", root, work, args.chunksize, add_kev
        )
        kev_keys = {row["cve_id"] for row in kev_rows}
        write_clean(work / "kev_clean.csv", kev_cols, kev_rows)
        results["kev"] = (kev_counts, kev_nulls)

        # Keep every NVD record corresponding to a KEV ID, then fill remaining
        # slots with the most recently published vulnerabilities from NVD.
        # The heap holds at most max_rows non-KEV candidates in memory.
        nvd_kev = []
        recent_heap = []
        serial = 0

        def add_nvd(rec):
            nonlocal serial
            serial += 1
            if rec["cve_id"] in kev_keys:
                nvd_kev.append(rec)
            else:
                # ISO-8601 date sorting is chronologically equivalent here.
                published = rec.get("published", "")
                rank = (published, rec["cve_id"])
                entry = (rank, serial, rec)
                if len(recent_heap) < args.max_rows:
                    heapq.heappush(recent_heap, entry)
                elif rank > recent_heap[0][0]:
                    heapq.heapreplace(recent_heap, entry)

        nvd_counts, nvd_nulls, nvd_cols = scan(
            "nvd", root, work, args.chunksize, add_nvd
        )
        # If KEV itself exceeds the configured cap, preserve KEV-linked priority.
        nvd_kev.sort(key=lambda x: (x.get("published", ""), x["cve_id"]), reverse=True)
        kev_selected = nvd_kev[: args.max_rows]
        remaining = args.max_rows - len(kev_selected)
        recent = [entry[2] for entry in heapq.nlargest(remaining, recent_heap)]
        selected_nvd = kev_selected + recent
        nvd_ids = {row["cve_id"] for row in selected_nvd}
        write_clean(work / "nvd_clean.csv", nvd_cols, selected_nvd)
        results["nvd"] = (nvd_counts, nvd_nulls)
        nvd_counts["kev_matched_selected"] = len(kev_selected)
        nvd_counts["recent_selected"] = len(recent)
        nvd_counts["selected"] = len(selected_nvd)
        nvd_counts["valid_not_exported"] = nvd_counts["valid"] - len(selected_nvd)

        # EPSS has no score date: retain only the one provided snapshot.
        # Avoid exporting irrelevant early-1999 CVEs that are absent from NVD.
        epss_rows = []

        def add_epss(rec):
            if rec["cve_id"] in nvd_ids and len(epss_rows) < args.max_rows:
                epss_rows.append(rec)

        epss_counts, epss_nulls, epss_cols = scan(
            "epss", root, work, args.chunksize, add_epss
        )
        write_clean(work / "epss_clean.csv", epss_cols, epss_rows)
        results["epss"] = (epss_counts, epss_nulls)

        # Extract CPE match rules in priority order (KEV-linked CVEs first).
        # This is an excerpt, not a complete NVD configuration truth table.
        cpe_count = 0
        cpe_with_rules = set()

        with (work / "nvd_affected_cpe.csv").open(
            "w", newline="", encoding="utf-8"
        ) as cf:
            writer = csv.DictWriter(cf, fieldnames=CPE_FIELDS, extrasaction="ignore")
            writer.writeheader()

            for row in selected_nvd:
                for match in cpe_entries(
                    row.get("configurations_json"),
                    row["cve_id"],
                ):
                    writer.writerow(match)
                    cpe_count += 1
                    cpe_with_rules.add(row["cve_id"])

        overlap_nvd_kev = len(nvd_ids & kev_keys)
        epss_ids = {r["cve_id"] for r in epss_rows}
        overlap_all = len(epss_ids & kev_keys)
        quality = {}
        report = []
        exports = {
            "kev": len(kev_rows),
            "nvd": len(selected_nvd),
            "epss": len(epss_rows),
        }
        for source in ("nvd", "epss", "kev"):
            counts, nulls = results[source]
            counts["exported"] = exports[source]
            counts["valid_not_exported"] = counts["valid"] - counts["exported"]
            quality[source] = {
                "counts": dict(counts),
                "raw_null_counts": dict(nulls),
                "note": "Full CSV scanned. Silver output is a selected subset; dropped-from-export valid rows are NOT rejected.",
            }
            report.append(
                {
                    "dataset": source,
                    "raw_rows_scanned": counts["input"],
                    "valid_rows": counts["valid"],
                    "exported_rows": exports[source],
                    "valid_not_exported": counts["valid_not_exported"],
                    "rejected_rows": counts["rejected"],
                    "duplicate_cve_ids": counts["duplicate_cve_id"],
                }
            )
        quality["selection"] = {
            "max_rows_per_silver_csv": args.max_rows,
            "kevs_in_kev_export": len(kev_keys),
            "kev_matched_in_nvd_export": overlap_nvd_kev,
            "epss_matched_in_nvd_export": len(epss_rows),
            "all_three_overlap": overlap_all,
            "nvd_cpe_export_rows": cpe_count,
            "nvd_cve_ids_with_exported_cpe": len(cpe_with_rules),
            "warning": "All extracted CPE rules for selected NVD CVEs are exported. Original configurations_json remains authoritative for Boolean applicability.",
        }
        with (work / "data_quality_report.csv").open(
            "w", newline="", encoding="utf-8"
        ) as f:
            w = csv.DictWriter(f, fieldnames=list(report[0]))
            w.writeheader()
            w.writerows(report)
        (work / "data_quality_details.json").write_text(
            json.dumps(quality, indent=2), encoding="utf-8"
        )

        # Build the complete output tree in temporary storage.
        publish = work / "publish"

        destinations = {
            "nvd_clean.csv": "silver",
            "epss_clean.csv": "silver",
            "kev_clean.csv": "silver",
            "nvd_affected_cpe.csv": "silver",
            "nvd_rejected.csv": "rejected",
            "epss_rejected.csv": "rejected",
            "kev_rejected.csv": "rejected",
            "data_quality_report.csv": "reports",
            "data_quality_details.json": "reports",
        }

        for folder in ("silver", "rejected", "reports"):
            (publish / folder).mkdir(parents=True)

        for filename, folder in destinations.items():
            src = work / filename
            if not src.is_file():
                raise RuntimeError(f"Missing generated file: {filename}")
            os.replace(src, publish / folder / filename)

        # Exclusive creation prevents an existing run being reused.
        # Publish the complete tree with one filesystem rename.
        output_root.mkdir()
        os.replace(publish, output_root)
        print("Published new dataset:", output_root)

    print("\nCompleted! Silver rows:")
    print(f"  NVD:  {len(selected_nvd):,} (KEV-linked: {overlap_nvd_kev:,})")
    print(f"  EPSS: {len(epss_rows):,} (all matched to selected NVD)")
    print(f"  KEV:  {len(kev_rows):,}")
    print(f"  CPE:  {cpe_count:,} extracted match rules (no independent CPE row cap)")
    print(f"  Three-way overlap: {overlap_all:,}")
    print(
        "Original Bronze CSVs unchanged; results published to a separate output directory."
    )
    print("EPSS has no score_date; historical EPSS trends cannot be inferred.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, pd.errors.ParserError, sqlite3.Error) as exc:
        sys.exit(f"ETL failed: {exc}")
