"""Select branch-aware evidence for an NVD applicability result."""

from dataclasses import dataclass

from patchledger.simulation.nvd_evidence import evaluate_asset


@dataclass(frozen=True)
class BranchResult:
    condition: bool | None
    affected: bool
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApplicabilityProof:
    asset_id: str
    cve_id: str
    applicable: bool | None
    proof_verified: bool
    supporting_paths: tuple[str, ...]
    other_matched_paths: tuple[str, ...]


def combine(results, operator):
    if not results or operator not in ("AND", "OR"):
        return BranchResult(None, False)

    if operator == "AND":
        if any(r.condition is False for r in results):
            return BranchResult(False, False)

        if any(r.condition is None for r in results):
            return BranchResult(None, False)

        paths = tuple(path for result in results for path in result.paths)

        return BranchResult(
            True,
            any(r.affected for r in results),
            paths,
        )

    matched = [r for r in results if r.condition is True]

    if matched:
        # Prefer a branch containing a matched affected-product rule.
        chosen = next(
            (r for r in matched if r.affected),
            matched[0],
        )
        return chosen

    if any(r.condition is None for r in results):
        return BranchResult(None, False)

    return BranchResult(False, False)


def select_applicability_proof(
    cve_id,
    configurations,
    asset_id,
    installations,
    *,
    inventory_complete=False,
):
    asset_result = evaluate_asset(
        cve_id,
        configurations,
        asset_id,
        installations,
        inventory_complete=inventory_complete,
    )

    evidence = {rule.path: rule for rule in asset_result.rules}

    def evaluate_rule(rule, path):
        if not isinstance(rule, dict):
            return BranchResult(None, False)

        if type(rule.get("vulnerable")) is not bool:
            return BranchResult(None, False)

        item = evidence.get(path)
        if item is None:
            return BranchResult(None, False)

        if item.matched_installations:
            return BranchResult(
                True,
                rule["vulnerable"],
                (path,),
            )

        if item.inconclusive_installations or not inventory_complete:
            return BranchResult(None, False)

        return BranchResult(False, False)

    def evaluate_node(node, path):
        if not isinstance(node, dict):
            return BranchResult(None, False)

        if node.get("negate", False) is not False:
            return BranchResult(None, False)

        operator = node.get("operator", "OR")
        if operator not in ("AND", "OR"):
            return BranchResult(None, False)

        values = []

        rules = node.get("cpeMatch", [])
        if not isinstance(rules, list):
            return BranchResult(None, False)

        for index, rule in enumerate(rules):
            rule_path = f"{path}.cpeMatch[{index}]"
            values.append(evaluate_rule(rule, rule_path))

        for key in ("nodes", "children"):
            children = node.get(key, [])
            if not isinstance(children, list):
                return BranchResult(None, False)

            for index, child in enumerate(children):
                child_path = f"{path}.{key}[{index}]"
                values.append(evaluate_node(child, child_path))

        return combine(values, operator)

    if not isinstance(configurations, list):
        branch = BranchResult(None, False)
    else:
        branch = combine(
            [
                evaluate_node(
                    node,
                    f"configurations[{index}]",
                )
                for index, node in enumerate(configurations)
            ],
            "OR",
        )

    verified = (
        asset_result.applicable is True and branch.condition is True and branch.affected
    )

    supporting = branch.paths if verified else ()

    all_matched = [
        rule.path for rule in asset_result.rules if rule.matched_installations
    ]

    others = tuple(path for path in all_matched if path not in supporting)

    return ApplicabilityProof(
        asset_id=asset_id,
        cve_id=cve_id,
        applicable=asset_result.applicable,
        proof_verified=verified,
        supporting_paths=supporting,
        other_matched_paths=others,
    )
