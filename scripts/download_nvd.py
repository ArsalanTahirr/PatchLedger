from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dotenv import load_dotenv

# Find the project root from this script's location.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Load the API key from the project's .env file.
load_dotenv(PROJECT_ROOT / ".env")

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PAGE_SIZE = 2000
MAX_RETRIES = 5

CSV_FIELDS = [
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
]


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def get_english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")

    if descriptions:
        return descriptions[0].get("value", "")

    return ""


def get_cvss(cve: dict) -> tuple[str, str, str, str]:
    """Return version, source, score, and severity from the best available metric."""

    metrics = cve.get("metrics", {})

    preferred_metric_types = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_type in preferred_metric_types:
        entries = metrics.get(metric_type, [])

        if not entries:
            continue

        metric = entries[0]
        cvss_data = metric.get("cvssData", {})

        version = cvss_data.get("version", "")
        source = metric.get("source", "")
        score = cvss_data.get("baseScore", "")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity") or ""

        return str(version), source, str(score), severity

    return "", "", "", ""


def get_cwe_ids(cve: dict) -> str:
    values = []

    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value and value not in values:
                values.append(value)

    return ";".join(values)


def get_reference_urls(cve: dict) -> str:
    urls = []

    for reference in cve.get("references", []):
        url = reference.get("url", "")
        if url and url not in urls:
            urls.append(url)

    return ";".join(urls)


def flatten_cve(cve: dict) -> dict:
    """Convert one nested NVD CVE object into a CSV-friendly row."""

    cvss_version, cvss_source, cvss_score, cvss_severity = get_cvss(cve)

    return {
        "cve_id": cve.get("id", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vulnerability_status": cve.get("vulnStatus", ""),
        "description": get_english_description(cve),
        "cvss_version": cvss_version,
        "cvss_source": cvss_source,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_ids": get_cwe_ids(cve),
        "reference_urls": get_reference_urls(cve),
        "configurations_json": json_text(cve.get("configurations", [])),
        "weaknesses_json": json_text(cve.get("weaknesses", [])),
        "raw_json": json_text(cve),
    }


def fetch_page(
    start_index: int,
    results_per_page: int,
    api_key: str | None,
) -> dict:
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    url = f"{API_URL}?{urlencode(params)}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "PatchLedger-NVD-Downloader/1.0",
    }

    if api_key:
        headers["apiKey"] = api_key

    request = Request(url, headers=headers)

    for attempt in range(MAX_RETRIES):
        try:
            with urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))

        except HTTPError as error:
            # Retry only rate-limit and server errors.
            if error.code == 429 or error.code >= 500:
                retry_after = error.headers.get("Retry-After")
                try:
                    wait_seconds = float(retry_after)
                except (TypeError, ValueError):
                    wait_seconds = 2**attempt

                print(f"HTTP {error.code}. Retrying in {wait_seconds:.1f} seconds...")
                time.sleep(wait_seconds)
                continue

            raise

        except (URLError, TimeoutError, OSError):
            if attempt == MAX_RETRIES - 1:
                raise

            wait_seconds = 2**attempt
            print(f"Network error. Retrying in {wait_seconds} seconds...")
            time.sleep(wait_seconds)

    raise RuntimeError("NVD request failed after all retry attempts.")


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download NVD CVE data into PatchLedger Bronze."
    )

    parser.add_argument(
        "--max-records",
        type=int,
        default=100,
        help="Maximum CVE records to download. Default: 100.",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Download all CVE records returned by the NVD API.",
    )

    args = parser.parse_args()

    if args.all and "--max-records" in os.sys.argv:
        parser.error("Use either --all or --max-records, not both.")

    if args.max_records < 1:
        parser.error("--max-records must be at least 1.")

    max_records = None if args.all else args.max_records

    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        request_delay = 1.0
        print("NVD API key found.")
    else:
        request_delay = 6.5
        print("No NVD API key found. Using a slower request interval.")

    run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%SZ")

    run_dir = PROJECT_ROOT / "data" / "bronze" / "nvd" / f"run_{run_id}"

    pages_dir = run_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)

    csv_path = run_dir / "nvd_cves.csv"
    temp_csv_path = run_dir / "nvd_cves.csv.part"
    manifest_path = run_dir / "manifest.json"

    manifest = {
        "source": "NVD CVE API 2.0",
        "endpoint": API_URL,
        "retrieved_at_utc": utc_now(),
        "run_id": run_id,
        "status": "running",
        "api_key_used": bool(api_key),
        "requested_max_records": max_records,
        "records_downloaded": 0,
        "pages_downloaded": 0,
        "total_results_reported_by_api": None,
        "dataset_complete": False,
    }

    write_manifest(manifest_path, manifest)

    records_downloaded = 0
    pages_downloaded = 0
    total_results = None
    start_index = 0

    try:
        with temp_csv_path.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=CSV_FIELDS,
            )
            writer.writeheader()

            while True:
                if max_records is not None:
                    remaining = max_records - records_downloaded
                    if remaining <= 0:
                        break
                    page_limit = min(PAGE_SIZE, remaining)
                else:
                    page_limit = PAGE_SIZE

                print(f"Requesting records starting at {start_index}...")

                data = fetch_page(
                    start_index=start_index,
                    results_per_page=page_limit,
                    api_key=api_key,
                )

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    manifest["total_results_reported_by_api"] = total_results

                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                # Preserve the original API response before flattening it.
                page_number = pages_downloaded + 1
                page_path = pages_dir / f"page_{page_number:06d}.json"

                page_path.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    writer.writerow(flatten_cve(cve))
                    records_downloaded += 1

                pages_downloaded += 1
                csv_file.flush()

                print(
                    f"Downloaded {records_downloaded} "
                    f"of {total_results} reported records."
                )

                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break

                if max_records is not None and records_downloaded >= max_records:
                    break

                time.sleep(request_delay)

        # Publish the CSV only after the download finishes successfully.
        temp_csv_path.replace(csv_path)

        dataset_complete = max_records is None and records_downloaded == total_results

        manifest.update(
            {
                "status": "completed",
                "completed_at_utc": utc_now(),
                "records_downloaded": records_downloaded,
                "pages_downloaded": pages_downloaded,
                "dataset_complete": dataset_complete,
                "limited_test": max_records is not None,
                "csv_file": csv_path.name,
                "csv_sha256": sha256_file(csv_path),
            }
        )

        write_manifest(manifest_path, manifest)

        print("\nDownload finished.")
        print(f"Records downloaded: {records_downloaded}")
        print(f"Pages downloaded: {pages_downloaded}")
        print(f"Output directory: {run_dir}")
        print(f"CSV file: {csv_path}")
        print(f"Manifest: {manifest_path}")

        if not dataset_complete:
            print(
                "Note: This is a limited or partial acquisition, "
                "not a complete NVD dataset."
            )

    except Exception as error:
        manifest.update(
            {
                "status": "failed",
                "failed_at_utc": utc_now(),
                "records_downloaded": records_downloaded,
                "pages_downloaded": pages_downloaded,
                "error": str(error),
            }
        )

        write_manifest(manifest_path, manifest)

        if temp_csv_path.exists():
            temp_csv_path.unlink()

        raise


if __name__ == "__main__":
    main()
