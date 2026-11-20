"""Read-only, asset-scoped NVD matching evidence."""

from dataclasses import dataclass

from patchledger.simulation.nvd_applicability_v3 import (
    evaluate_nvd_configurations,
)
from patchledger.simulation.nvd_cpe import match_cpe_criteria


@dataclass(frozen=True)
class RuleEvidence:
    path: str
    criteria: str
    match_criteria_id: str | None
    vulnerable: bool
    matched_installations: tuple[str, ...]
    inconclusive_installations: tuple[str, ...]


@dataclass(frozen=True)
class AssetEvaluation:
    asset_id: str
    cve_id: str
    applicable: bool | None
    rules: tuple[RuleEvidence, ...]


def evaluate_asset(
    cve_id,
    configurations,
    asset_id,
    installations,
    *,
    inventory_complete=False,
):
    """Evaluate one asset without mixing installations across assets."""

    if not isinstance(installations, (list, tuple)):
        raise ValueError("Installations must be a list or tuple.")  # noqa: TRY004

    if not isinstance(asset_id, str) or not asset_id:
        raise ValueError("A valid asset_id is required.")

    seen = set()

    for installation in installations:
        if not isinstance(installation, dict):
            raise ValueError("Invalid installation record.")  # noqa: TRY004

        if installation.get("asset_id") != asset_id:
            raise ValueError("Cross-asset installation detected.")

        installation_id = installation.get("installation_id")
        cpe = installation.get("cpe")

        if (
            not isinstance(installation_id, str)
            or not installation_id
            or installation_id in seen
            or not isinstance(cpe, str)
            or not cpe
        ):
            raise ValueError("Invalid or duplicate installation data.")

        seen.add(installation_id)

    cpes = [item["cpe"] for item in installations]

    applicable = evaluate_nvd_configurations(
        configurations,
        cpes,
        inventory_complete=inventory_complete,
    )

    evidence = []

    def visit(value, path):
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")
            return

        if not isinstance(value, dict):
            return

        rules = value.get("cpeMatch", [])

        if isinstance(rules, list):
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    continue

                criteria = rule.get("criteria")
                vulnerable = rule.get("vulnerable")

                if not isinstance(criteria, str):
                    continue
                if type(vulnerable) is not bool:
                    continue

                matched = []
                inconclusive = []

                for installation in installations:
                    result = match_cpe_criteria(installation["cpe"], rule)

                    if result is True:
                        matched.append(installation["installation_id"])
                    elif result is None:
                        inconclusive.append(installation["installation_id"])

                evidence.append(
                    RuleEvidence(
                        path=f"{path}.cpeMatch[{index}]",
                        criteria=criteria,
                        match_criteria_id=rule.get("matchCriteriaId"),
                        vulnerable=vulnerable,
                        matched_installations=tuple(matched),
                        inconclusive_installations=tuple(inconclusive),
                    )
                )

        for key in ("nodes", "children"):
            if key in value:
                visit(value[key], f"{path}.{key}")

    visit(configurations, "configurations")

    return AssetEvaluation(
        asset_id=asset_id,
        cve_id=cve_id,
        applicable=applicable,
        rules=tuple(evidence),
    )
