
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

MAX_RETRIES = 5

EXPECTED_FIELDS = ["cve", "epss", "percentile"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def download_file(url: str, path: Path) -> None:
    headers = {
        "User-Agent": "PatchLedger-EPSS-Downloader/1.0",
        "Accept": "application/gzip",
    }

    request = Request(url, headers=headers)

    for attempt in range(MAX_RETRIES):
        try:
            with urlopen(request, timeout=120) as response:
                with path.open("wb") as file:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        file.write(chunk)

            if path.stat().st_size == 0:
                raise RuntimeError("Downloaded EPSS file is empty.")

            return

        except HTTPError as error:
            if error.code == 429 or error.code >= 500:
                wait = 2 ** attempt
                print(f"HTTP {error.code}. Retrying in {wait} seconds...")
                time.sleep(wait)
                continue
            raise

        except (URLError, TimeoutError, OSError):
            if attempt == MAX_RETRIES - 1:
                raise

            wait = 2 ** attempt
            print(f"Network error. Retrying in {wait} seconds...")
            time.sleep(wait)

    raise RuntimeError("EPSS download failed after all retries.")


def convert_to_csv(
    gzip_path: Path,
    csv_path: Path,
) -> tuple[int, str]:
    records_downloaded = 0
    metadata_line = ""

    with gzip.open(gzip_path, "rt", encoding="utf-8-sig", newline="") as source:

        first_line = source.readline()

        if first_line.startswith("#"):
            metadata_line = first_line.strip()
        else:
            source.seek(0)

        reader = csv.reader(source)

        headers = next(reader, None)

        if headers is None:
            raise ValueError("EPSS CSV has no header.")

        if headers != EXPECTED_FIELDS:
            raise ValueError(
                f"Unexpected EPSS columns: {headers}"
            )

        with csv_path.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as output:

            writer = csv.DictWriter(
                output,
                fieldnames=EXPECTED_FIELDS,
            )

            writer.writeheader()

            for row in reader:
                if len(row) != len(EXPECTED_FIELDS):
                    raise ValueError(
                        f"Invalid EPSS row: {row}"
                    )

                writer.writerow(dict(zip(EXPECTED_FIELDS, row)))
                records_downloaded += 1

    return records_downloaded, metadata_line


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download complete EPSS data into PatchLedger Bronze."
    )

    args = parser.parse_args()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")

    run_dir = (
        PROJECT_ROOT
        / "data"
        / "bronze"
        / "epss"
        / f"run_{run_id}"
    )

    run_dir.mkdir(parents=True, exist_ok=True)

    gzip_path = run_dir / "epss_scores-current.csv.gz"
    temp_gzip_path = run_dir / "epss_scores-current.csv.gz.part"

    csv_path = run_dir / "epss_scores.csv"
    temp_csv_path = run_dir / "epss_scores.csv.part"

    manifest_path = run_dir / "manifest.json"

    manifest = {
        "source": "FIRST EPSS",
        "endpoint": EPSS_URL,
        "retrieved_at_utc": utc_now(),
        "run_id": run_id,
        "status": "running",
        "records_downloaded": 0,
        "dataset_complete": False,
    }

    write_manifest(manifest_path, manifest)

    try:
        print("Downloading complete EPSS dataset...")

        download_file(EPSS_URL, temp_gzip_path)

        print("Validating compressed file and generating CSV...")

        records_downloaded, metadata_line = convert_to_csv(
            temp_gzip_path,
            temp_csv_path,
        )

        if records_downloaded == 0:
            raise ValueError("EPSS dataset contains no records.")

        # Publish files only after successful validation.
        temp_gzip_path.replace(gzip_path)
        temp_csv_path.replace(csv_path)

        manifest.update({
            "status": "completed",
            "completed_at_utc": utc_now(),
            "records_downloaded": records_downloaded,
            "dataset_complete": True,
            "source_metadata": metadata_line,
            "original_file": gzip_path.name,
            "original_file_size_bytes": gzip_path.stat().st_size,
            "original_file_sha256": sha256_file(gzip_path),
            "csv_file": csv_path.name,
            "csv_sha256": sha256_file(csv_path),
        })

        write_manifest(manifest_path, manifest)

        print("\nEPSS acquisition completed.")
        print(f"Records downloaded: {records_downloaded}")
        print(f"Output directory: {run_dir}")
        print(f"Original file: {gzip_path}")
        print(f"CSV file: {csv_path}")
        print(f"Manifest: {manifest_path}")

    except Exception as error:
        manifest.update({
            "status": "failed",
            "failed_at_utc": utc_now(),
            "error": str(error),
        })

        write_manifest(manifest_path, manifest)

        for path in [temp_gzip_path, temp_csv_path]:
            if path.exists():
                path.unlink()

        raise


if __name__ == "__main__":
    main()
