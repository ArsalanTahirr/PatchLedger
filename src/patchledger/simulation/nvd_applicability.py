"""Conservative NVD configuration evaluation.

Returns True, False, or None.
A True result is a configuration match, not a verified scan finding.
"""

from patchledger.simulation.nvd_cpe import match_cpe_criteria


def combine(values, operator):
    """Three-valued AND/OR logic."""
    if not values:
        return None

    if operator == "OR":
        if True in values:
            return True
        if None in values:
            return None
        return False

    if operator == "AND":
        if False in values:
            return False
        if None in values:
            return None
        return True

    return None


def evaluate_rule(rule, installed_cpes, inventory_complete):
    if not isinstance(rule, dict):
        return None

    # Non-vulnerable matches may represent platform dependencies.
    # Their semantics need separate handling.
    if rule.get("vulnerable") is not True:
        return None

    results = [
        match_cpe_criteria(cpe, rule)
        for cpe in installed_cpes
    ]

    if True in results:
        return True

    if None in results:
        return None

    return False if inventory_complete else None


def evaluate_node(node, installed_cpes, inventory_complete):
    if not isinstance(node, dict):
        return None

    if node.get("negate", False) is not False:
        return None

    operator = node.get("operator", "OR")
    if operator not in ("AND", "OR"):
        return None

    results = []

    for rule in node.get("cpeMatch", []):
        results.append(
            evaluate_rule(rule, installed_cpes, inventory_complete)
        )

    for key in ("children", "nodes"):
        for child in node.get(key, []):
            results.append(
                evaluate_node(child, installed_cpes, inventory_complete)
            )

    return combine(results, operator)


def evaluate_nvd_configurations(
    configurations,
    installed_cpes,
    *,
    inventory_complete=False,
):
    """Evaluate the OR of top-level NVD configurations."""
    if not isinstance(configurations, list):
        return None

    if not isinstance(installed_cpes, (list, tuple)):
        return None

    return combine(
        [
            evaluate_node(
                configuration,
                installed_cpes,
                inventory_complete,
            )
            for configuration in configurations
        ],
        "OR",
    )
