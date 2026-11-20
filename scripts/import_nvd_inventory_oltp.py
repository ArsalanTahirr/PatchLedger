"""Import a VERIFIED PatchLedger NVD scenario inventory using operational services.

DRY RUN by default, with NO PostgreSQL connection. --apply explicitly enables
transactional OLTP writes; never imports exposure candidates as scan findings.

From the PatchLedger repository root:
  uv run python scripts/import_nvd_inventory_oltp.py \
    --stage ../PatchLedgerData/nvd_scenario_v1/oltp_stage_v1 \
    --manifest ../PatchLedgerData/nvd_scenario_v1/manifest.json

Only after reviewing dry run, append --apply to write operational inventory.
Existing assets, installations, products and identifiers are never updated.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime
from pathlib import Path

SCENARIO = "nvd-backed-v1"
PREFIX = f"sim:{SCENARIO}:"
ASSET_COLS = {
    "asset_key",
    "hostname",
    "department",
    "environment",
    "asset_type",
    "criticality",
    "is_synthetic",
}
PRODUCT_COLS = {
    "product_key",
    "publisher",
    "name",
    "version",
    "update",
    "cpe",
    "cve_id",
    "is_synthetic_inventory",
}
INSTALL_COLS = {
    "installation_key",
    "asset_key",
    "product_key",
    "installed_version",
    "verified_cpe",
    "observed_at",
    "is_synthetic",
}
CANDIDATE_COLS = {
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
}


def read_csv(path: Path, required: set[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or set(reader.fieldnames) != required:
            raise ValueError(
                f"Unexpected CSV columns in {path.name}: {reader.fieldnames}"
            )
        rows = list(reader)
    if not rows or any(
        None in row or any(value is None for value in row.values()) for row in rows
    ):
        raise ValueError(f"Missing or malformed rows in {path.name}")
    return rows


def unique(rows: list[dict], field: str):
    keys = [row[field] for row in rows]
    if any(not key for key in keys) or len(set(keys)) != len(keys):
        raise ValueError(f"Duplicate/empty {field}")


def load(stage: Path, manifest_path: Path) -> tuple[dict, list, list, list, list, str]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    report = json.loads((stage / "validation_report.json").read_text())
    if (
        manifest.get("scenario") != SCENARIO
        or manifest.get("synthetic_inventory") is not True
    ):
        raise ValueError("Manifest scenario/synthetic flag mismatch")
    if (
        report.get("scenario") != SCENARIO
        or report.get("writes_to_postgresql") is not False
        or report.get("represents_observed_scans") is not False
    ):
        raise ValueError("Unexpected stage report scenario or provenance")
    if report.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError("Stage was generated from a different manifest")

    assets = read_csv(stage / "assets.csv", ASSET_COLS)
    products = read_csv(stage / "products.csv", PRODUCT_COLS)
    installs = read_csv(stage / "installations.csv", INSTALL_COLS)
    candidates = read_csv(stage / "exposure_candidates.csv", CANDIDATE_COLS)
    for rows, field in (
        (assets, "asset_key"),
        (products, "product_key"),
        (installs, "installation_key"),
        (candidates, "candidate_key"),
    ):
        unique(rows, field)

    expected_counts = {
        "assets": len(assets),
        "products": len(products),
        "installations": len(installs),
        "nvd_exposure_candidates": len(candidates),
        "observed_scan_findings": 0,
    }
    if any(report.get("counts", {}).get(k) != v for k, v in expected_counts.items()):
        raise ValueError("Staging report count mismatch")
    indexed_assets = {a["asset_key"]: a for a in assets}
    indexed_products = {p["product_key"]: p for p in products}
    indexed_installs = {i["installation_key"]: i for i in installs}
    manifest_products = {p["product_key"]: p for p in manifest["products"]}
    if set(indexed_products) != set(manifest_products):
        raise ValueError("Product keys differ from manifest")
    for p in products:
        source = manifest_products[p["product_key"]]
        for key in ("publisher", "name", "version", "update", "cpe", "cve_id"):
            if p[key] != source[key]:
                raise ValueError(
                    f"Product {p['product_key']} differs from verified manifest: {key}"
                )
        if (
            source.get("nvd_applicable_for_assumed_complete_inventory") is not True
            or source.get("epss_present") is not True
            or source.get("kev_present") is not True
            or p["is_synthetic_inventory"] != "true"
        ):
            raise ValueError("Unverified product or enrichment")
        if len(p["cpe"].split(":")) != 13:
            raise ValueError("Invalid CPE")
    for a in assets:
        if (
            not a["asset_key"].startswith(PREFIX + "asset:")
            or a["is_synthetic"] != "true"
        ):
            raise ValueError("Invalid scenario asset")
        if not a["criticality"].isdigit() or not 1 <= int(a["criticality"]) <= 5:
            raise ValueError("Invalid asset criticality")
    for i in installs:
        if (
            i["asset_key"] not in indexed_assets
            or i["product_key"] not in indexed_products
        ):
            raise ValueError("Orphan installation")
        p = indexed_products[i["product_key"]]
        if (
            not i["installation_key"].startswith(PREFIX + "installation:")
            or i["verified_cpe"] != p["cpe"]
            or i["installed_version"] != p["version"]
            or i["is_synthetic"] != "true"
        ):
            raise ValueError("Inconsistent installation")
        when = datetime.fromisoformat(i["observed_at"])
        if when.tzinfo is None or when.utcoffset() is None:
            raise ValueError("Installation timestamp must include time zone")
    if len(installs) != len(candidates) or len(
        {i["asset_key"] for i in installs}
    ) != len(installs):
        raise ValueError("Expected exactly one installation and candidate per asset")
    for c in candidates:
        i = indexed_installs.get(c["installation_key"])
        if i is None:
            raise ValueError("Orphan NVD candidate")
        p = indexed_products[i["product_key"]]
        source = manifest_products[p["product_key"]]
        if (
            c["asset_key"] != i["asset_key"]
            or c["product_key"] != i["product_key"]
            or c["cve_id"] != p["cve_id"]
            or c["cpe"] != i["verified_cpe"]
            or c["nvd_config_sha256"] != source["nvd_config_sha256"]
            or c["kev_present"] != "true"
            or c["epss_present"] != "true"
            or c["classification"] != "nvd_applicability_candidate"
        ):
            raise ValueError("Inconsistent exposure candidate")
    provenance = hashlib.sha256(manifest_bytes).hexdigest()
    return report, assets, products, installs, candidates, provenance


def apply_to_database(assets, products, installs, provenance):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from patchledger.core.config import Settings
    from patchledger.db.session import make_engine
    from patchledger.operational.models import (
        Asset,
        Department,
        SoftwareInstallation,
        SoftwareProduct,
    )
    from patchledger.operational.services.assets import (
        create_department,
        register_asset,
    )
    from patchledger.operational.services.common import EventContext
    from patchledger.operational.services.software import (
        get_or_create_product,
        install_software,
        register_product_identifier,
    )

    source = f"simulator:nvd-backed-v1:manifest-sha256:{provenance}"
    engine = make_engine(Settings().sqlalchemy_url)
    try:
        with Session(engine) as session:  # noqa: SIM117
            with session.begin():
                # Fail CLOSED if any scenario or catalog record already exists. No updates/replays.
                existing_assets = session.scalars(
                    select(Asset).where(
                        Asset.asset_key.in_([x["asset_key"] for x in assets])
                    )
                ).first()
                existing_products = session.scalars(
                    select(SoftwareProduct).where(
                        SoftwareProduct.product_key.in_(
                            [x["product_key"] for x in products]
                        )
                    )
                ).first()
                existing_installations = session.scalars(
                    select(SoftwareInstallation).where(
                        SoftwareInstallation.installation_key.in_(
                            [x["installation_key"] for x in installs]
                        )
                    )
                ).first()
                # Check entire scenario namespace: prevents accidental partial imports.
                other_scenario = session.scalars(
                    select(Asset).where(Asset.asset_key.like(PREFIX + "%"))
                ).first()
                if any(
                    (
                        existing_assets,
                        existing_products,
                        existing_installations,
                        other_scenario,
                    )
                ):
                    raise ValueError(
                        "Scenario/catalog records already exist; refusing to modify or partially replay"
                    )

                departments = {}
                for name in sorted({a["department"] for a in assets}):
                    code = "NVD1-" + hashlib.sha256(name.encode()).hexdigest()[:12]
                    dept = session.scalar(
                        select(Department).where(Department.code == code)
                    )
                    if dept is None:
                        dept = create_department(session, code=code, name=name)
                    elif dept.name != name or dept.retired_at is not None:
                        raise ValueError(
                            "Department code collision or retired department"
                        )
                    departments[name] = dept

                product_ids = {}
                for p in products:
                    product = get_or_create_product(
                        session,
                        product_key=p["product_key"],
                        name=p["name"],
                        publisher_name=p["publisher"],
                        ecosystem="nvd-backed-simulation",
                    )
                    product_ids[p["product_key"]] = product.id
                    # Actual CPE identity stored as product identifier; NVD provenance explicit.
                    register_product_identifier(
                        session,
                        product.id,
                        scheme="cpe23",
                        identifier=p["cpe"],
                        source_ref=source,
                    )

                asset_ids = {}
                for a in assets:
                    observed_at = next(
                        i["observed_at"]
                        for i in installs
                        if i["asset_key"] == a["asset_key"]
                    )
                    when = datetime.fromisoformat(observed_at)
                    ctx = EventContext(when, f"simulator:{SCENARIO}", source, True)
                    asset = register_asset(
                        session,
                        asset_key=a["asset_key"],
                        hostname=a["hostname"],
                        department_id=departments[a["department"]].id,
                        asset_type=a["asset_type"],
                        environment=a["environment"],
                        business_criticality=int(a["criticality"]),
                        exposure="internal",
                        context=ctx,
                    )
                    asset_ids[a["asset_key"]] = asset.id

                for i in installs:
                    p = next(
                        p for p in products if p["product_key"] == i["product_key"]
                    )
                    when = datetime.fromisoformat(i["observed_at"])
                    ctx = EventContext(when, f"simulator:{SCENARIO}", source, True)
                    install_software(
                        session,
                        asset_id=asset_ids[i["asset_key"]],
                        product_id=product_ids[i["product_key"]],
                        installation_key=i["installation_key"],
                        version=i["installed_version"],
                        build=p["update"],
                        context=ctx,
                        start_basis="actual",
                        context_description=f"Simulated NVD-backed installation. Verified CPE: {i['verified_cpe']}",
                    )
                session.flush()
        print(
            f"PASS: Imported {len(assets)} synthetic OLTP assets, {len(products)} products, and {len(installs)} installations"
        )
        print("PASS: Exact CPE product identifiers and manifest provenance recorded")
        print(
            "No scan runs, observations, or vulnerability findings created; existing scenario preserved"
        )
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Explicitly write to PostgreSQL; default is offline dry run",
    )
    args = parser.parse_args()
    _report, assets, products, installs, candidates, sha = load(
        args.stage, args.manifest
    )
    print(f"PASS: verified scenario {SCENARIO}")
    print(
        f"PASS: {len(assets)} assets, {len(products)} products, {len(installs)} installations, {len(candidates)} exposure candidates"
    )
    print(f"Manifest SHA256: {sha}")
    if args.apply:
        apply_to_database(assets, products, installs, sha)
    else:
        print(
            "DRY RUN: no database connection or writes. Add --apply only after reviewing the staged records."
        )
        print("Exposure candidates will NOT be loaded as observations/findings")


if __name__ == "__main__":
    main()
