"""Create an isolated, deterministic *simulation staging* inventory from a verified NVD manifest.

Does NOT connect to PostgreSQL or claim to have generated operational scan findings.
Outputs assets.csv, products.csv, installations.csv, exposure_candidates.csv,
and validation_report.json. These are inputs for a later OLTP service-based importer.

Run from PatchLedger repo root:
  uv run python scripts/build_nvd_inventory_stage.py \
    --manifest ../PatchLedgerData/nvd_scenario_v1/manifest.json \
    --output-dir ../PatchLedgerData/nvd_scenario_v1/oltp_stage_v1
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

SCENARIO = "nvd-backed-v1"
ASSET_COLUMNS = [
    "asset_key",
    "hostname",
    "department",
    "environment",
    "asset_type",
    "criticality",
    "is_synthetic",
]
PRODUCT_COLUMNS = [
    "product_key",
    "publisher",
    "name",
    "version",
    "update",
    "cpe",
    "cve_id",
    "is_synthetic_inventory",
]
INSTALL_COLUMNS = [
    "installation_key",
    "asset_key",
    "product_key",
    "installed_version",
    "verified_cpe",
    "observed_at",
    "is_synthetic",
]
EXPOSURE_COLUMNS = [
    "candidate_key",
    "installation_key",
    "asset_key",
    "product_key",
    "cve_id",
    "cpe",
    "nvd_config_sha256",
    "kev_present",
    "epss_present",
    "classification",
    "basis",
]


def stable_key(label: str) -> str:
    return hashlib.sha256((SCENARIO + ":" + label).encode("utf-8")).hexdigest()[:24]


def write_csv(path: Path, columns: list[str], rows: list[dict]):
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def validate_manifest(manifest: dict) -> list[dict]:
    if manifest.get("scenario") != SCENARIO or manifest.get("manifest_version") != 1:
        raise ValueError("Unsupported scenario or manifest version")
    if manifest.get("synthetic_inventory") is not True:
        raise ValueError("Expected explicitly synthetic inventory")
    products = manifest.get("products")
    if not isinstance(products, list) or not products:
        raise ValueError("Manifest has no products")
    keys, cves = set(), set()
    for p in products:
        for field in [
            "product_key",
            "publisher",
            "name",
            "version",
            "update",
            "cpe",
            "cve_id",
            "nvd_config_sha256",
        ]:
            if not isinstance(p.get(field), str) or not p[field]:
                raise ValueError(f"Missing required product field: {field}")
        if p["product_key"] in keys or p["cve_id"] in cves:
            raise ValueError("Duplicate product key or CVE")
        keys.add(p["product_key"])
        cves.add(p["cve_id"])
        parts = p["cpe"].split(":")
        if (
            len(parts) != 13
            or parts[:2] != ["cpe", "2.3"]
            or parts[5:7] != [p["version"], p["update"]]
        ):
            raise ValueError(f"Invalid verified CPE identity for {p['product_key']}")
        if p.get("nvd_applicable_for_assumed_complete_inventory") is not True:
            raise ValueError("Unverified NVD applicability")
        if p.get("kev_present") is not True or p.get("epss_present") is not True:
            raise ValueError("Incomplete enrichment coverage")
        if len(p["nvd_config_sha256"]) != 64 or any(
            c not in "0123456789abcdef" for c in p["nvd_config_sha256"]
        ):
            raise ValueError("Invalid NVD configuration hash")
    return sorted(products, key=lambda p: p["product_key"])


def build(products: list[dict], num_assets: int, observed_at: str):
    departments = ("Engineering", "Operations", "Security", "Finance")
    assets, product_rows, installs, candidates = [], [], [], []
    for p in products:
        product_rows.append(
            {
                "product_key": p["product_key"],
                "publisher": p["publisher"],
                "name": p["name"],
                "version": p["version"],
                "update": p["update"],
                "cpe": p["cpe"],
                "cve_id": p["cve_id"],
                "is_synthetic_inventory": "true",
            }
        )
    # Each asset has exactly one product, cycling through every verified product.
    # This deliberately avoids cross-asset evidence inference.
    for i in range(num_assets):
        p = products[i % len(products)]
        asset_key = f"sim:{SCENARIO}:asset:{i:06d}"
        installation_key = f"sim:{SCENARIO}:installation:{stable_key(asset_key + ':' + p['product_key'])}"
        assets.append(
            {
                "asset_key": asset_key,
                "hostname": f"nvd-sim-host-{i + 1:04d}",
                "department": departments[i % len(departments)],
                "environment": "staging" if i % 3 == 0 else "production",
                "asset_type": "server",
                "criticality": (i % 5) + 1,
                "is_synthetic": "true",
            }
        )
        installs.append(
            {
                "installation_key": installation_key,
                "asset_key": asset_key,
                "product_key": p["product_key"],
                "installed_version": p["version"],
                "verified_cpe": p["cpe"],
                "observed_at": observed_at,
                "is_synthetic": "true",
            }
        )
        candidates.append(
            {
                "candidate_key": f"sim:{SCENARIO}:candidate:{stable_key(installation_key + ':' + p['cve_id'])}",
                "installation_key": installation_key,
                "asset_key": asset_key,
                "product_key": p["product_key"],
                "cve_id": p["cve_id"],
                "cpe": p["cpe"],
                "nvd_config_sha256": p["nvd_config_sha256"],
                "kev_present": "true",
                "epss_present": "true",
                "classification": "nvd_applicability_candidate",
                "basis": "verified NVD configuration + assumed complete simulated inventory; NOT a scan result",
            }
        )
    assert len({r["asset_key"] for r in assets}) == num_assets
    assert len({r["installation_key"] for r in installs}) == num_assets
    assert len({r["candidate_key"] for r in candidates}) == num_assets
    return assets, product_rows, installs, candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--assets", type=int, default=12)
    parser.add_argument("--observed-at", default="2026-11-19T00:00:00+00:00")
    args = parser.parse_args()
    if not 4 <= args.assets <= 10000:
        parser.error("--assets must be between 4 and 10000")
    try:
        timestamp = datetime.fromisoformat(args.observed_at)
        if timestamp.utcoffset() is None:
            raise ValueError("Timezone required")
        observed_at = timestamp.astimezone(UTC).isoformat()
    except ValueError as exc:
        parser.error(f"--observed-at invalid: {exc}")
    manifest_path = args.manifest.resolve()
    output = args.output_dir.resolve()
    if not manifest_path.is_file():
        parser.error(f"Manifest not found: {manifest_path}")
    if output.exists():
        parser.error(f"Refusing to overwrite existing output: {output}")
    if output == manifest_path.parent or output in manifest_path.parents:
        parser.error("Output must not replace the manifest or its parents")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    products = validate_manifest(manifest)
    assets, product_rows, installs, candidates = build(
        products, args.assets, observed_at
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".oltp-stage-", dir=output.parent))
    try:
        write_csv(staging / "assets.csv", ASSET_COLUMNS, assets)
        write_csv(staging / "products.csv", PRODUCT_COLUMNS, product_rows)
        write_csv(staging / "installations.csv", INSTALL_COLUMNS, installs)
        write_csv(staging / "exposure_candidates.csv", EXPOSURE_COLUMNS, candidates)
        report = {
            "scenario": SCENARIO,
            "purpose": "simulation staging for future OLTP service ingestion",
            "writes_to_postgresql": False,
            "represents_observed_scans": False,
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "counts": {
                "assets": len(assets),
                "products": len(product_rows),
                "installations": len(installs),
                "nvd_exposure_candidates": len(candidates),
                "observed_scan_findings": 0,
            },
            "unique_cves": sorted({r["cve_id"] for r in candidates}),
            "warning": "Do not ingest exposure_candidates directly as confirmed scan findings.",
        }
        (staging / "validation_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if output.exists():
            raise FileExistsError(f"Refusing to overwrite {output}")
        os.rename(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(
        f"PASS: {len(assets)} simulated assets, {len(installs)} installations, {len(candidates)} NVD exposure candidates"
    )
    print(f"PASS: output created at {output}")
    print(
        "No PostgreSQL, Bronze, Silver, or Git operations; zero observed scan findings asserted."
    )


if __name__ == "__main__":
    main()
