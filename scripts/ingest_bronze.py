"""Stream raw CSV records into PostgreSQL Bronze without transforming them."""

import argparse
import csv
import fcntl
import hashlib
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

DATASETS = {
    "nvd": (
        "nvd_cves.csv",
        "bronze.nvd_cves",
        (
            "cve_id",
            "published",
            "last_modified",
            "vulnerability_status",
            "description",
            "cvss_version",
            "cvss_source",
            "cvss_score",
            "cvss_severity",
            "cwe_ids",
            "reference_urls",
            "configurations_json",
            "weaknesses_json",
            "raw_json",
        ),
    ),
    "epss": (
        "epss_scores.csv",
        "bronze.epss_scores",
        ("cve", "epss", "percentile"),
    ),
    "kev": (
        "known_exploited_vulnerabilities.csv",
        "bronze.kev",
        (
            "cveID",
            "vendorProject",
            "product",
            "vulnerabilityName",
            "dateAdded",
            "shortDescription",
            "requiredAction",
            "dueDate",
            "knownRansomwareCampaignUse",
            "notes",
            "cwes",
            "forensicTriage",
            "raw_json",
        ),
    ),
}


def quote(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_header(path, columns):
    csv.field_size_limit(sys.maxsize)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        header = next(csv.reader(handle), None)
    if header != list(columns):
        raise ValueError(
            f"CSV header mismatch in {path.name}\n"
            f"Expected: {list(columns)}\nFound: {header}"
        )


def ingest(name, data_dir, limit):
    """Serialize Bronze imports of each dataset on this host."""
    lock_path = Path(tempfile.gettempdir()) / f"patchledger_bronze_{name}.lock"

    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        return _ingest_unlocked(name, data_dir, limit)


def _ingest_unlocked(name, data_dir, limit):
    filename, table, columns = DATASETS[name]
    path = data_dir / filename

    if not path.is_file():
        raise FileNotFoundError(path)

    validate_header(path, columns)
    fingerprint = checksum(path)
    original_stat = path.stat()
    source_name = name if limit is None else f"{name}:sample:{limit}"
    batch_id = str(uuid.uuid4())

    print(f"Source: {path}", flush=True)
    print(f"SHA256: {fingerprint}", flush=True)
    print(f"Batch: {batch_id}", flush=True)

    quoted_columns = ", ".join(quote(col) for col in columns)
    copy_columns = quoted_columns + ", batch_id, source_row"

    sql_copy = (
        f"COPY {table} ({copy_columns}) FROM STDIN "
        "WITH (FORMAT CSV, NULL '\\N', "
        f"FORCE_NOT_NULL ({quoted_columns}));"
    )

    command = [
        "docker",
        "exec",
        "-i",
        "patchledger-postgres",
        "psql",
        "-X",
        "-q",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "patchledger",
        "-d",
        "patchledger",
    ]

    existing_query = (
        "SELECT b.batch_id, b.row_count, "
        f"(SELECT COUNT(*) FROM {table} r WHERE r.batch_id = b.batch_id) "
        "FROM bronze.ingest_batches b "
        f"WHERE b.source_name = '{source_name}' "
        f"AND b.file_sha256 = '{fingerprint}'"
    )

    existing = subprocess.run(
        [*command, "-A", "-t", "-F", "|", "-c", existing_query],
        capture_output=True,
        text=True,
        check=True,
    )

    if existing.stdout.strip():
        saved_id, recorded_count, actual_count = existing.stdout.strip().split("|")

        if int(recorded_count) != int(actual_count):
            raise RuntimeError(
                f"STOP: Existing batch {saved_id} has inconsistent row counts"
            )

        print(f"ALREADY IMPORTED: {actual_count} rows. Existing batch: {saved_id}")
        return

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as error_log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=error_log,
            text=True,
            encoding="utf-8",
        )
        count = 0
        try:
            stream = process.stdin
            stream.write("BEGIN;\n")
            stream.write(
                "INSERT INTO bronze.ingest_batches "
                "(batch_id, source_name, file_sha256, row_count) "
                f"VALUES ('{batch_id}', '{source_name}', "
                f"'{fingerprint}', 0);\n"
            )
            stream.write(sql_copy + "\n")

            writer = csv.writer(stream, lineterminator="\n")

            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.reader(handle)
                next(reader)

                for row in reader:
                    if limit is not None and count >= limit:
                        break
                    if len(row) != len(columns):
                        raise ValueError(f"Malformed CSV at source row {count + 2}")

                    writer.writerow([*row, batch_id, count + 2])
                    count += 1

                    if count % 100000 == 0:
                        print(f"Streamed {count:,} rows", flush=True)

            new_stat = path.stat()
            if (
                original_stat.st_size != new_stat.st_size
                or original_stat.st_mtime_ns != new_stat.st_mtime_ns
            ):
                raise RuntimeError("Source CSV changed during ingestion")

            stream.write("\\.\n")
            stream.write(
                "UPDATE bronze.ingest_batches "
                f"SET row_count = {count} "
                f"WHERE batch_id = '{batch_id}';\n"
            )
            stream.write("COMMIT;\n")
            stream.close()

        except Exception:
            process.kill()
            process.wait()
            raise

        returncode = process.wait()
        error_log.seek(0)
        errors = error_log.read()

        if returncode != 0:
            raise RuntimeError(f"PostgreSQL import failed:\n{errors.strip()}")

        print(f"SUCCESS: Committed {count:,} raw rows to {table}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=DATASETS)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path.home() / "Desktop/University/PatchLedgerData",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")

    filename, table, columns = DATASETS[args.dataset]
    path = args.data_dir / filename

    validate_header(path, columns)

    if not args.apply:
        print(f"DRY RUN: {path}")
        print(f"Target: {table}")
        print(f"Columns validated: {len(columns)}")
        print("No database connection or writes.")
        return

    ingest(args.dataset, args.data_dir, args.limit)


if __name__ == "__main__":
    main()
