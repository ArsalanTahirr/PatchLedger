"""Build a versioned, read-only-source manifest for a simulated NVD-backed OLTP scenario.

Run from the PatchLedger repository root:
  uv run python scripts/build_nvd_scenario_manifest.py \
    --silver ../PatchLedgerData/silver_full_v1/silver \
    --output ../PatchLedgerData/nvd_scenario_v1/manifest.json

The script NEVER connects to PostgreSQL, runs the legacy simulator, or modifies
Bronze/Silver. It creates only its explicit manifest output after validations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from patchledger.simulation.nvd_applicability_v3 import evaluate_nvd_configurations

# Explicit product identities and full CPE identifiers validated against actual
# NVD rules in the preceding discovery phase. Assets will be simulated later.
PRODUCTS = (
    {
        "product_key": "nvd-v1:zimbra",
        "publisher": "Synacor",
        "name": "Zimbra Collaboration Suite",
        "version": "8.8.15",
        "update": "p10",
        "cpe": "cpe:2.3:a:synacor:zimbra_collaboration_suite:8.8.15:p10:*:*:*:*:*:*",
        "cve_id": "CVE-2022-27925",
    },
    {
        "product_key": "nvd-v1:vcenter",
        "publisher": "VMware",
        "name": "vCenter Server",
        "version": "7.0",
        "update": "update1",
        "cpe": "cpe:2.3:a:vmware:vcenter_server:7.0:update1:*:*:*:*:*:*",
        "cve_id": "CVE-2021-21972",
    },
    {
        "product_key": "nvd-v1:exchange",
        "publisher": "Microsoft",
        "name": "Exchange Server",
        "version": "2016",
        "update": "cumulative_update_10",
        "cpe": "cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_10:*:*:*:*:*:*",
        "cve_id": "CVE-2021-26855",
    },
    {
        "product_key": "nvd-v1:coldfusion",
        "publisher": "Adobe",
        "name": "ColdFusion",
        "version": "2018",
        "update": "update10",
        "cpe": "cpe:2.3:a:adobe:coldfusion:2018:update10:*:*:*:*:*:*",
        "cve_id": "CVE-2023-26360",
    },
)


def rules_in(node):
    if not isinstance(node, dict):
        return
    for rule in node.get("cpeMatch", []):
        if isinstance(rule, dict):
            yield rule
    for key in ("nodes", "children"):
        for child in node.get(key, []):
            yield from rules_in(child)


def read_target_rows(path: Path, usecols: list[str], wanted: set[str]):
    if not path.is_file():
        raise FileNotFoundError(f"Missing Silver input: {path}")
    found = {}
    for chunk in pd.read_csv(
        path,
        usecols=usecols,
        dtype=str,
        keep_default_na=False,
        chunksize=10000,
    ):
        for record in chunk.loc[chunk["cve_id"].isin(wanted)].to_dict("records"):
            key = record["cve_id"]
            if key in found:
                raise ValueError(f"Duplicate Silver CVE {key} in {path}")
            found[key] = record
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    silver = args.silver.resolve()
    output = args.output.resolve()
    if silver == output.parent or silver in output.parents:
        parser.error("Output must be OUTSIDE the immutable Silver directory")
    if output.exists():
        parser.error(f"Output already exists, refusing overwrite: {output}")

    wanted = {item["cve_id"] for item in PRODUCTS}
    nvd = read_target_rows(
        silver / "nvd_clean.csv", ["cve_id", "configurations_json"], wanted
    )
    epss = read_target_rows(silver / "epss_clean.csv", ["cve_id"], wanted)
    kev = read_target_rows(silver / "kev_clean.csv", ["cve_id"], wanted)

    records = []
    for item in PRODUCTS:
        cve = item["cve_id"]
        if cve not in nvd:
            raise ValueError(f"CVE absent from NVD Silver: {cve}")
        raw = nvd[cve]["configurations_json"]
        configs = json.loads(raw)
        if isinstance(configs, dict):
            configs = [configs]
        if not isinstance(configs, list):
            raise ValueError(f"Invalid NVD configurations for {cve}")  # noqa: TRY004
        matches = [
            rule
            for node in configs
            for rule in rules_in(node)
            if rule.get("vulnerable") is True and rule.get("criteria") == item["cpe"]
        ]
        if not matches:
            raise ValueError(
                f"Exact CPE not a vulnerable NVD criterion: {cve}, {item['cpe']}"
            )
        actual = evaluate_nvd_configurations(
            configs, [item["cpe"]], inventory_complete=True
        )
        if actual is not True:
            raise ValueError(f"NVD applicability not TRUE (was {actual!r}): {cve}")
        if cve not in kev:
            raise ValueError(f"Candidate missing from KEV Silver: {cve}")
        if cve not in epss:
            raise ValueError(f"Candidate missing from EPSS Silver: {cve}")
        records.append(
            {
                **item,
                "nvd_applicable_for_assumed_complete_inventory": True,
                "kev_present": True,
                "epss_present": True,
                "nvd_config_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "evidence_type": "NVD CPE configuration applicability; simulated inventory, not an observed scan",
            }
        )

    manifest = {
        "scenario": "nvd-backed-v1",
        "manifest_version": 1,
        "synthetic_inventory": True,
        "source_dataset": "silver_full_v1",
        "inventory_assumption": "Exact selected product CPEs installed; inventory complete for evaluated configuration",
        "warning": "No OLTP data generated. NVD applicability is not proof of exploitation or an observed scan.",
        "products": records,
    }
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    # x mode prevents silently replacing a previously generated manifest.
    with output.open("x", encoding="utf-8") as handle:
        handle.write(payload)
    print(
        f"PASS: {len(records)} real-CVE/CPE mappings validated against NVD, EPSS and KEV Silver"
    )
    print(f"PASS: manifest created at {output}")
    print(
        "No OLTP/database, Bronze or Silver content modified; no Git operations performed"
    )


if __name__ == "__main__":
    main()
