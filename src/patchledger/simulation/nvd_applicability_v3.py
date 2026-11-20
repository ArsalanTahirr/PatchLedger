"""Experimental branch-aware NVD applicability evaluator."""

from dataclasses import dataclass

from patchledger.simulation.nvd_cpe import match_cpe_criteria


@dataclass(frozen=True)
class Evaluation:
    condition: bool | None
    exposure: bool | None
    has_vulnerable_rule: bool


def combine(values, operator):
    if not values or operator not in ("AND", "OR"):
        return Evaluation(None, None, True)

    conditions = [v.condition for v in values]
    exposures = [v.exposure for v in values]

    if operator == "AND":
        condition = (
            False if False in conditions else None if None in conditions else True
        )

        affected = True if True in exposures else None if None in exposures else False

        exposure = (
            False
            if condition is False or affected is False
            else None
            if condition is None or affected is None
            else True
        )

    else:
        condition = (
            True if True in conditions else None if None in conditions else False
        )

        exposure = True if True in exposures else None if None in exposures else False

    return Evaluation(
        condition,
        exposure,
        any(v.has_vulnerable_rule for v in values),
    )


def evaluate_rule(rule, installed_cpes, inventory_complete):
    if not isinstance(rule, dict):
        return Evaluation(None, None, True)

    if type(rule.get("vulnerable")) is not bool:
        return Evaluation(None, None, True)

    results = [match_cpe_criteria(cpe, rule) for cpe in installed_cpes]

    condition = (
        True
        if True in results
        else None
        if None in results or not inventory_complete
        else False
    )

    vulnerable = rule["vulnerable"]

    return Evaluation(
        condition=condition,
        exposure=condition if vulnerable else False,
        has_vulnerable_rule=vulnerable,
    )


def evaluate_node(node, installed_cpes, inventory_complete):
    if not isinstance(node, dict):
        return Evaluation(None, None, True)

    if node.get("negate", False) is not False:
        return Evaluation(None, None, True)

    operator = node.get("operator", "OR")

    if operator not in ("AND", "OR"):
        return Evaluation(None, None, True)

    values = []

    rules = node.get("cpeMatch", [])
    if not isinstance(rules, list):
        return Evaluation(None, None, True)

    for rule in rules:
        values.append(evaluate_rule(rule, installed_cpes, inventory_complete))

    for key in ("nodes", "children"):
        children = node.get(key, [])
        if not isinstance(children, list):
            return Evaluation(None, None, True)

        for child in children:
            values.append(evaluate_node(child, installed_cpes, inventory_complete))

    return combine(values, operator)


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

    result = combine(
        [
            evaluate_node(item, installed_cpes, inventory_complete)
            for item in configurations
        ],
        "OR",
    )

    if not result.has_vulnerable_rule:
        return None

    return result.exposure
