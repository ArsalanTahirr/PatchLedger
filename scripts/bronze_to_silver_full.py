"""Full-coverage, streaming Bronze-to-Silver export for PatchLedger.

Reuses validation and CPE extraction from scripts/bronze_to_silver.py.
Never edits source CSVs, existing Silver outputs, or PostgreSQL.
"""

import argparse
import csv
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

csv.field_size_limit(sys.maxsize)


def load_existing_etl():
    path = Path(__file__).resolve().with_name("bronze_to_silver.py")
    if not path.is_file():
        raise FileNotFoundError(f"Required existing ETL missing: {path}")
    spec = importlib.util.spec_from_file_location("patchledger_selected_etl", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(
        description="Full-coverage streaming Bronze -> Silver ETL"
    )
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--chunksize", type=int, default=500)
    args = parser.parse_args()

    if args.chunksize < 1:
        parser.error("chunksize must be positive")
    root = args.data_dir.expanduser().resolve(strict=True)
    if not root.is_dir():
        parser.error("data-dir must be a directory")
    target = args.output_dir.expanduser().absolute()
    # Don't resolve the final component: an existing symlink must be rejected.
    target = target.parent.resolve() / target.name
    if target.parent != root:
        parser.error("output-dir must be a direct child of data-dir")
    if target.name in {"silver", "rejected", "reports"}:
        parser.error("output-dir may not use a standard output directory name")
    if target.exists() or target.is_symlink():
        parser.error("output-dir already exists; choose a new name")

    etl = load_existing_etl()
    print("Mode: FULL COVERAGE (no NVD, EPSS, KEV, or CPE export cap)", flush=True)
    print("Input:", root, flush=True)
    print("New output:", target, flush=True)

    with tempfile.TemporaryDirectory(
        prefix="patchledger_full_staging_", dir=root
    ) as temporary:
        work = Path(temporary)
        db = sqlite3.connect(work / "aligned_ids.sqlite")
        claimed = False
        published = False
        try:
            db.execute("CREATE TABLE kev_ids (cve_id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE nvd_ids (cve_id TEXT PRIMARY KEY)")
            stats = {}
            counts = {"kev": 0, "nvd": 0, "epss": 0, "cpe": 0}
            cpe_with_rules = 0

            def stream_source(source, output_name, visit):
                columns = etl.schema(source, root)
                with (work / output_name).open(
                    "w", encoding="utf-8", newline=""
                ) as handle:
                    writer = csv.DictWriter(
                        handle, fieldnames=columns, extrasaction="ignore"
                    )
                    writer.writeheader()

                    def visitor(record):
                        visit(record, writer)

                    source_counts, nulls, _ = etl.scan(
                        source, root, work, args.chunksize, visitor
                    )
                stats[source] = (source_counts, nulls)

            def visit_kev(record, writer):
                writer.writerow(record)
                db.execute(
                    "INSERT INTO kev_ids (cve_id) VALUES (?)", (record["cve_id"],)
                )
                counts["kev"] += 1

            stream_source("kev", "kev_clean.csv", visit_kev)
            db.commit()

            with (work / "nvd_affected_cpe.csv").open(
                "w", encoding="utf-8", newline=""
            ) as cpe_file:
                cpe_writer = csv.DictWriter(
                    cpe_file, fieldnames=etl.CPE_FIELDS, extrasaction="ignore"
                )
                cpe_writer.writeheader()

                def visit_nvd(record, writer):
                    writer.writerow(record)
                    db.execute(
                        "INSERT INTO nvd_ids (cve_id) VALUES (?)", (record["cve_id"],)
                    )
                    counts["nvd"] += 1
                    nonlocal cpe_with_rules
                    found_rule = False
                    for rule in etl.cpe_entries(
                        record.get("configurations_json"), record["cve_id"]
                    ):
                        cpe_writer.writerow(rule)
                        counts["cpe"] += 1
                        found_rule = True
                    if found_rule:
                        cpe_with_rules += 1

                stream_source("nvd", "nvd_clean.csv", visit_nvd)
            db.commit()

            def visit_epss(record, writer):
                present = db.execute(
                    "SELECT 1 FROM nvd_ids WHERE cve_id = ?", (record["cve_id"],)
                ).fetchone()
                if present:
                    writer.writerow(record)
                    counts["epss"] += 1

            stream_source("epss", "epss_clean.csv", visit_epss)
            db.commit()

            overlap_kev = db.execute(
                "SELECT COUNT(*) FROM kev_ids JOIN nvd_ids USING (cve_id)"
            ).fetchone()[0]
            overlap_three = 0
            with (work / "epss_clean.csv").open(
                "r", encoding="utf-8", newline=""
            ) as file:
                for record in csv.DictReader(file):
                    if db.execute(
                        "SELECT 1 FROM kev_ids WHERE cve_id = ?", (record["cve_id"],)
                    ).fetchone():
                        overlap_three += 1

            quality = {}
            report_rows = []
            for source in ("nvd", "epss", "kev"):
                source_counts, nulls = stats[source]
                source_counts["exported"] = counts[source]
                source_counts["valid_not_exported"] = (
                    source_counts["valid"] - counts[source]
                )
                quality[source] = {
                    "counts": dict(source_counts),
                    "raw_null_counts": dict(nulls),
                    "note": (
                        "Full valid source exported."
                        if source != "epss"
                        else "Valid EPSS rows exported only when CVE exists in valid NVD."
                    ),
                }
                report_rows.append(
                    {
                        "dataset": source,
                        "raw_rows_scanned": source_counts["input"],
                        "valid_rows": source_counts["valid"],
                        "exported_rows": counts[source],
                        "valid_not_exported": source_counts["valid_not_exported"],
                        "rejected_rows": source_counts["rejected"],
                        "duplicate_cve_ids": source_counts["duplicate_cve_id"],
                    }
                )
            quality["selection"] = {
                "mode": "full_coverage",
                "max_rows_per_silver_csv": None,
                "kevs_in_kev_export": counts["kev"],
                "kev_matched_in_nvd_export": overlap_kev,
                "epss_matched_in_nvd_export": counts["epss"],
                "all_three_overlap": overlap_three,
                "nvd_cpe_export_rows": counts["cpe"],
                "nvd_cve_ids_with_exported_cpe": cpe_with_rules,
                "warning": "CPE match rows are evidence, not complete Boolean applicability; configurations_json is authoritative.",
            }
            with (work / "data_quality_report.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=list(report_rows[0]))
                writer.writeheader()
                writer.writerows(report_rows)
            (work / "data_quality_details.json").write_text(
                json.dumps(quality, indent=2), encoding="utf-8"
            )

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
            for name, folder in destinations.items():
                src = work / name
                if not src.is_file():
                    raise RuntimeError(f"Missing generated file: {name}")
                os.replace(src, publish / folder / name)

            db.close()
            # An exclusive claim blocks another cooperating run. Only remove our
            # own empty claim on failure; never delete an existing dataset.
            target.mkdir()
            claimed = True
            os.replace(publish, target)
            published = True
            print("Published:", target)
            print("Exported NVD:", counts["nvd"])
            print("Exported KEV:", counts["kev"])
            print("Matched EPSS:", counts["epss"])
            print("CPE rules:", counts["cpe"])
            print("Three-way overlap:", overlap_three)
        finally:
            try:
                db.close()
            except sqlite3.Error as exc:
                print(f"Warning: SQLite cleanup failed: {exc}", file=sys.stderr)
            if claimed and not published:
                try:
                    target.rmdir()  # succeeds only if our claim is still empty
                except OSError:
                    pass


if __name__ == "__main__":
    main()
