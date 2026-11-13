from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

MAX_RETRIES = 5

CSV_FIELDS = [
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
]


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


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
        "User-Agent": "PatchLedger-KEV-Downloader/1.0",
        "Accept": "application/json",
    }

    request = Request(url, headers=headers)

    for attempt in range(MAX_RETRIES):
        try:
            with urlopen(request, timeout=120) as response, path.open("wb") as file:
                while True:
                    chunk = response.read(1024 * 1024)

                    if not chunk:
                        break

                    file.write(chunk)

            if path.stat().st_size == 0:
                raise RuntimeError("Downloaded KEV file is empty.")

            return

        except HTTPError as error:
            if error.code == 429 or error.code >= 500:
                retry_after = error.headers.get("Retry-After")

                try:
                    wait = float(retry_after)
                except (TypeError, ValueError):
                    wait = 2**attempt

                print(f"HTTP {error.code}. Retrying in {wait:.1f} seconds...")

                time.sleep(wait)
                continue

            raise

        except (URLError, TimeoutError, OSError):
            if attempt == MAX_RETRIES - 1:
                raise

            wait = 2**attempt

            print(f"Network error. Retrying in {wait} seconds...")
            time.sleep(wait)

    raise RuntimeError("KEV download failed after all retries.")


def load_and_validate_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        catalog = json.load(file)

    required_fields = [
        "catalogVersion",
        "dateReleased",
        "count",
        "vulnerabilities",
    ]

    for field in required_fields:
        if field not in catalog:
            raise ValueError(f"Missing required catalog field: {field}")

    vulnerabilities = catalog["vulnerabilities"]

    if not isinstance(vulnerabilities, list):
        raise TypeError("KEV vulnerabilities must be a list.")

    if not isinstance(catalog["count"], int):
        raise TypeError("KEV catalog count must be an integer.")

    if catalog["count"] != len(vulnerabilities):
        raise ValueError(
            f"Catalog count mismatch: "
            f"reported {catalog['count']}, "
            f"actual {len(vulnerabilities)}"
        )

    if not vulnerabilities:
        raise ValueError("KEV catalog contains no records.")

    required_record_fields = [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
    ]

    for index, vulnerability in enumerate(vulnerabilities):
        for field in required_record_fields:
            if field not in vulnerability:
                raise ValueError(f"Record {index} is missing field: {field}")

    return catalog


def flatten_vulnerability(vulnerability: dict) -> dict:
    return {
        "cveID": vulnerability.get("cveID", ""),
        "vendorProject": vulnerability.get("vendorProject", ""),
        "product": vulnerability.get("product", ""),
        "vulnerabilityName": vulnerability.get("vulnerabilityName", ""),
        "dateAdded": vulnerability.get("dateAdded", ""),
        "shortDescription": vulnerability.get("shortDescription", ""),
        "requiredAction": vulnerability.get("requiredAction", ""),
        "dueDate": vulnerability.get("dueDate", ""),
        "knownRansomwareCampaignUse": vulnerability.get(
            "knownRansomwareCampaignUse", ""
        ),
        "notes": vulnerability.get("notes", ""),
        "cwes": json_text(vulnerability.get("cwes", [])),
        "forensicTriage": vulnerability.get("forensicTriage", ""),
        "raw_json": json_text(vulnerability),
    }


def convert_to_csv(
    catalog: dict,
    csv_path: Path,
) -> int:
    vulnerabilities = catalog["vulnerabilities"]

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDS,
        )

        writer.writeheader()

        for vulnerability in vulnerabilities:
            writer.writerow(flatten_vulnerability(vulnerability))

    return len(vulnerabilities)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download complete CISA KEV data into PatchLedger Bronze."
    )

    parser.parse_args()

    run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%SZ")

    run_dir = PROJECT_ROOT / "data" / "bronze" / "kev" / f"run_{run_id}"

    run_dir.mkdir(parents=True, exist_ok=True)

    json_path = run_dir / "known_exploited_vulnerabilities.json"
    temp_json_path = run_dir / "known_exploited_vulnerabilities.json.part"

    csv_path = run_dir / "known_exploited_vulnerabilities.csv"
    temp_csv_path = run_dir / "known_exploited_vulnerabilities.csv.part"

    manifest_path = run_dir / "manifest.json"

    manifest = {
        "source": "CISA Known Exploited Vulnerabilities",
        "endpoint": KEV_URL,
        "retrieved_at_utc": utc_now(),
        "run_id": run_id,
        "status": "running",
        "records_downloaded": 0,
        "dataset_complete": False,
    }

    write_manifest(manifest_path, manifest)

    try:
        print("Downloading complete CISA KEV catalog...")

        download_file(KEV_URL, temp_json_path)

        print("Validating original JSON catalog...")

        catalog = load_and_validate_json(temp_json_path)

        records_downloaded = convert_to_csv(
            catalog,
            temp_csv_path,
        )

        # Publish only after successful validation and conversion.
        temp_json_path.replace(json_path)
        temp_csv_path.replace(csv_path)

        manifest.update(
            {
                "status": "completed",
                "completed_at_utc": utc_now(),
                "catalog_version": catalog["catalogVersion"],
                "catalog_date_released": catalog["dateReleased"],
                "catalog_reported_count": catalog["count"],
                "records_downloaded": records_downloaded,
                "dataset_complete": True,
                "original_file": json_path.name,
                "original_file_size_bytes": json_path.stat().st_size,
                "original_file_sha256": sha256_file(json_path),
                "csv_file": csv_path.name,
                "csv_sha256": sha256_file(csv_path),
            }
        )

        write_manifest(manifest_path, manifest)

        print("\nCISA KEV acquisition completed.")
        print(f"Catalog version: {catalog['catalogVersion']}")
        print(f"Records downloaded: {records_downloaded}")
        print(f"Output directory: {run_dir}")
        print(f"Original JSON: {json_path}")
        print(f"CSV file: {csv_path}")
        print(f"Manifest: {manifest_path}")

    except Exception as error:
        manifest.update(
            {
                "status": "failed",
                "failed_at_utc": utc_now(),
                "error": str(error),
            }
        )

        write_manifest(manifest_path, manifest)

        for path in [temp_json_path, temp_csv_path]:
            if path.exists():
                path.unlink()

        raise


if __name__ == "__main__":
    main()
