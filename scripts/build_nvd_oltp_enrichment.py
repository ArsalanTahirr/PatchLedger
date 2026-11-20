"""Create a verified, read-only OLTP↔NVD↔EPSS↔KEV enrichment extract.

Only writes its explicit output directory; never modifies Postgres or Silver.
Uses NVD applicability from the previously validated manifest, not scan observations.
"""

from __future__ import annotations

import argparse
import csv
import sys

# NVD configurations_json fields can exceed Python's default CSV limit.
limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(limit)
        break
    except OverflowError:
        limit //= 10
import hashlib
import json
from collections import Counter
from pathlib import Path

from sqlalchemy import text


def read_stage(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def target_rows(path, targets):
    if not path.is_file():
        raise FileNotFoundError(path)
    result = {}
    with path.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            cve = row.get("cve_id")
            if cve in targets:
                if cve in result:
                    raise ValueError(f"Duplicate CVE in {path.name}: {cve}")
                result[cve] = row
    if set(result) != set(targets):
        raise ValueError(f"Missing CVEs in {path.name}: {set(targets) - set(result)}")
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--silver", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args()
    output = args.output_dir.resolve()
    silver = args.silver.resolve()
    if output.exists():
        ap.error("Output already exists; will not overwrite existing results")
    if silver == output or silver in output.parents:
        ap.error("Output must not be inside Silver")

    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    report = json.loads((args.stage / "validation_report.json").read_text())
    assert (
        manifest["scenario"] == "nvd-backed-v1"
        and manifest["synthetic_inventory"] is True
    )
    assert report["manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    products = {r["product_key"]: r for r in read_stage(args.stage / "products.csv")}
    assets = {r["asset_key"]: r for r in read_stage(args.stage / "assets.csv")}
    installations = {
        r["installation_key"]: r for r in read_stage(args.stage / "installations.csv")
    }
    candidates = read_stage(args.stage / "exposure_candidates.csv")
    if (len(assets), len(products), len(installations), len(candidates)) != (
        12,
        4,
        12,
        12,
    ):
        raise ValueError("Unexpected staging counts for nvd-backed-v1")
    targets = {p["cve_id"] for p in products.values()}
    manifest_products = {p["product_key"]: p for p in manifest["products"]}

    nvd = target_rows(silver / "nvd_clean.csv", targets)
    epss = target_rows(silver / "epss_clean.csv", targets)
    kev = target_rows(silver / "kev_clean.csv", targets)
    for product_key, p in products.items():
        mp = manifest_products[product_key]
        assert p["cpe"] == mp["cpe"] and p["cve_id"] == mp["cve_id"]
        assert (
            hashlib.sha256(nvd[p["cve_id"]]["configurations_json"].encode()).hexdigest()
            == mp["nvd_config_sha256"]
        ), "NVD changed since verification"

    from patchledger.core.config import Settings
    from patchledger.db.session import make_engine

    engine = make_engine(Settings().sqlalchemy_url)
    # Explicit SQL read-only transaction. Only scenario-qualified inventory is read.
    statement = text("""
      SELECT a.asset_key, a.hostname, sp.product_key, si.installation_key,
             h.version AS installed_version, h.build AS installed_build,
             pi.identifier AS verified_cpe
      FROM operational.assets a
      JOIN operational.software_installations si ON si.asset_id = a.id
      JOIN operational.software_products sp ON sp.id = si.product_id
      JOIN operational.installation_history h ON h.installation_id = si.id
      JOIN operational.product_identifiers pi ON pi.product_id = sp.id
      WHERE a.asset_key LIKE 'sim:nvd-backed-v1:asset:%'
        AND si.installation_key LIKE 'sim:nvd-backed-v1:installation:%'
        AND sp.product_key LIKE 'nvd-v1:%' AND pi.scheme = 'cpe23'
    """)
    try:
        with engine.connect() as connection, connection.begin():
            connection.execute(text("SET TRANSACTION READ ONLY"))
            db_rows = [dict(r) for r in connection.execute(statement).mappings()]
    finally:
        engine.dispose()
    if len(db_rows) != 12:
        raise ValueError(
            f"Expected 12 current OLTP installation+identity rows, got {len(db_rows)}. Check installation_history column names/filters."
        )
    db = {r["installation_key"]: r for r in db_rows}
    if len(db) != len(db_rows):
        raise ValueError("Duplicate current installation rows in OLTP")

    enriched = []
    for c in candidates:
        i = installations[c["installation_key"]]
        p = products[i["product_key"]]
        a = assets[i["asset_key"]]
        stored = db.get(c["installation_key"])
        if stored is None:
            raise ValueError(f"Missing persisted installation {c['installation_key']}")
        for label, actual, expected in (
            ("asset_key", stored["asset_key"], i["asset_key"]),
            ("hostname", stored["hostname"], a["hostname"]),
            ("product_key", stored["product_key"], i["product_key"]),
            ("version", stored["installed_version"], i["installed_version"]),
            ("build", stored["installed_build"], p["update"]),
            ("cpe", stored["verified_cpe"], i["verified_cpe"]),
            ("candidate cpe", c["cpe"], p["cpe"]),
            ("candidate cve", c["cve_id"], p["cve_id"]),
        ):
            if actual != expected:
                raise ValueError(
                    f"Persisted relationship mismatch {label}: {actual!r} != {expected!r}"
                )
        cve = c["cve_id"]
        e = epss[cve]
        k = kev[cve]
        n = nvd[cve]
        row = {
            "scenario": "nvd-backed-v1",
            "asset_key": a["asset_key"],
            "hostname": a["hostname"],
            "department": a["department"],
            "environment": a["environment"],
            "business_criticality": a["criticality"],
            "installation_key": i["installation_key"],
            "product_key": p["product_key"],
            "publisher": p["publisher"],
            "product_name": p["name"],
            "installed_version": p["version"],
            "installed_update": p["update"],
            "verified_cpe": p["cpe"],
            "cve_id": cve,
            "nvd_configuration_sha256": c["nvd_config_sha256"],
            "nvd_applicability": "true_assuming_complete_simulated_inventory",
            "nvd_source": "silver_full_v1/nvd_clean.csv",
            "epss_source": "silver_full_v1/epss_clean.csv",
            "kev_source": "silver_full_v1/kev_clean.csv",
            "kev_present": "true",
            "epss_present": "true",
            "classification": "nvd_applicability_candidate",
            "is_simulated_inventory": "true",
            "observed_scan_finding": "false",
        }
        # Preserve all real source fields, without inventing metrics or scores.
        for prefix, source in (("nvd", n), ("epss", e), ("kev", k)):
            for field, value in source.items():
                if field not in ("cve_id", "configurations_json"):
                    row[f"{prefix}_{field}"] = value
        enriched.append(row)

    if len(enriched) != 12 or {r["cve_id"] for r in enriched} != targets:
        raise ValueError("Enrichment cardinality or coverage failed")
    output.mkdir(parents=True, exist_ok=False)
    fields = list(dict.fromkeys(k for row in enriched for k in row))
    with (output / "nvd_oltp_enriched_candidates.csv").open(
        "x", newline="", encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(enriched)
    validation = {
        "scenario": "nvd-backed-v1",
        "assets": len(assets),
        "persisted_installations_matched": len(enriched),
        "distinct_real_cves": len(targets),
        "all_nvd_epss_kev_sources_matched": True,
        "source": "OLTP read-only and Silver read-only",
        "semantics": "NVD applicability candidate, NOT an observed scanner finding",
        "counts_by_cve": dict(sorted(Counter(r["cve_id"] for r in enriched).items())),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    (output / "validation_report.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n"
    )
    print(
        f"PASS: {len(enriched)} persisted OLTP installations joined to real NVD, EPSS, KEV"
    )
    print(f"PASS: {len(targets)} distinct CVEs; exact CPE, version and update verified")
    print(f"PASS: {output}")
    print(
        "READ ONLY on PostgreSQL and Silver; no scan findings created. No Git operations."
    )


if __name__ == "__main__":
    main()
