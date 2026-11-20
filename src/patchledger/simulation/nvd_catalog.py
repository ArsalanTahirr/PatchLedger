"""Load NVD CVEs while preserving their configuration rules."""

import csv

csv.field_size_limit(64 * 1024 * 1024)
import json
from pathlib import Path

from patchledger.simulation.nvd_cpe import parse_cpe


def load_nvd_catalog(csv_path: str | Path, limit: int = 100):
    if limit < 1:
        raise ValueError("limit must be positive")

    catalog = []

    with Path(csv_path).open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required = {"cve_id", "configurations_json"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Missing required NVD columns")

        for row in reader:
            raw = row["configurations_json"]

            if not raw or not raw.strip():
                continue

            try:
                configurations = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if not isinstance(configurations, list) or not configurations:
                continue

            catalog.append(
                {
                    "cve_id": row["cve_id"],
                    "configurations": configurations,
                }
            )

            if len(catalog) >= limit:
                break

    return catalog


def extract_cpe_matches(catalog):
    """Extract candidate CPE rules, retaining source metadata."""
    matches = []

    def visit(node, cve_id, path):
        if isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, cve_id, f"{path}[{index}]")
            return

        if not isinstance(node, dict):
            return

        for match in node.get("cpeMatch", []):
            if not isinstance(match, dict):
                continue

            criteria = match.get("criteria", "")
            parts = parse_cpe(criteria)

            if parts is None:
                continue

            matches.append(
                {
                    "cve_id": cve_id,
                    "part": parts[0],
                    "vendor": parts[1],
                    "product": parts[2],
                    "cpe_version": parts[3],
                    "criteria": criteria,
                    "vulnerable": match.get("vulnerable"),
                    "versionStartIncluding": match.get("versionStartIncluding"),
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding": match.get("versionEndIncluding"),
                    "versionEndExcluding": match.get("versionEndExcluding"),
                    "matchCriteriaId": match.get("matchCriteriaId"),
                    "configuration_path": path,
                }
            )

        for key in ("nodes", "children", "configurations"):
            if key in node:
                visit(node[key], cve_id, f"{path}.{key}")

    for record in catalog:
        visit(record["configurations"], record["cve_id"], "configurations")

    return matches
