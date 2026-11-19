"""Experimental NVD evaluator with platform prerequisites.

Each result is (condition_matched, affected_product_matched).
True as the public result requires both.
"""

from patchledger.simulation.nvd_cpe import match_cpe_criteria


def combine_conditions(results, operator):
    if not results or operator not in ("AND", "OR"):
        return None, False

    conditions = [condition for condition, _ in results]

    if operator == "AND":
        if False in conditions:
            return False, False
        if None in conditions:
            return None, False
        return True, any(affected for _, affected in results)

    if True in conditions:
        return (
            True,
            any(
                condition is True and affected
                for condition, affected in results
            ),
        )

    if None in conditions:
        return None, False

    return False, False


def evaluate_rule(rule, installed_cpes, inventory_complete):
    if not isinstance(rule, dict):
        return None, False

    if rule.get("vulnerable") not in (True, False):
        return None, False

    results = [
        match_cpe_criteria(cpe, rule)
        for cpe in installed_cpes
    ]

    if True in results:
        return True, rule["vulnerable"] is True

    if None in results:
        return None, False

    if inventory_complete:
        return False, False

    return None, False


def evaluate_node(node, installed_cpes, inventory_complete):
    if not isinstance(node, dict):
        return None, False

    if node.get("negate", False) is not False:
        return None, False

    operator = node.get("operator", "OR")

    if operator not in ("AND", "OR"):
        return None, False

    results = []

    rules = node.get("cpeMatch", [])
    if not isinstance(rules, list):
        return None, False

    for rule in rules:
        results.append(
            evaluate_rule(rule, installed_cpes, inventory_complete)
        )

    for key in ("children", "nodes"):
        children = node.get(key, [])
        if not isinstance(children, list):
            return None, False

        for child in children:
            results.append(
                evaluate_node(child, installed_cpes, inventory_complete)
            )

    return combine_conditions(results, operator)


def evaluate_nvd_configurations(
    configurations,
    installed_cpes,
    *,
    inventory_complete=False,
):
    if not isinstance(configurations, list):
        return None

    if not isinstance(installed_cpes, (list, tuple)):
        return None

    condition, affected = combine_conditions(
        [
            evaluate_node(node, installed_cpes, inventory_complete)
            for node in configurations
        ],
        "OR",
    )

    if condition is True:
        return True if affected else None

    return condition
