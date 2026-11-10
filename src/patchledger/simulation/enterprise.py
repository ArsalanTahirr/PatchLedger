"""Pure enterprise and installation plans with stable scenario business keys."""

from dataclasses import dataclass

from patchledger.simulation.config import SimulationConfig
from patchledger.simulation.fixtures import CATALOG
from patchledger.simulation.random_state import random_stream


@dataclass(frozen=True)
class AssetPlan:
    index: int
    asset_key: str
    hostname: str
    department: str
    asset_type: str
    environment: str
    criticality: int
    exposure: str
    products: tuple[str, ...]
    versions: tuple[str, ...]
    final_status: str


def enterprise_plan(config: SimulationConfig) -> tuple[AssetPlan, ...]:
    result = []
    names, weights = zip(*sorted(config.departments.items()), strict=True)
    levels, criticality_weights = zip(*sorted(config.criticality.items()), strict=True)
    for index in range(config.assets):
        rng = random_stream(config, f"asset:{index}")
        department = rng.choices(names, weights=weights, k=1)[0]
        catalog = list(CATALOG)
        rng.shuffle(catalog)
        draw = rng.random()
        final = (
            "retired"
            if draw < config.retirement_probability
            else (
                "suspended"
                if draw < config.retirement_probability + config.suspension_probability
                else "active"
            )
        )
        result.append(
            AssetPlan(
                index=index,
                asset_key=f"{config.prefix}asset:{index:06d}",
                hostname=f"pl-{config.scenario.lower().replace('_', '-')[:40]}-host-{index:06d}",
                department=department,
                asset_type=rng.choices(
                    ("server", "workstation", "laptop"), weights=(45, 40, 15), k=1
                )[0],
                environment=rng.choices(
                    ("production", "staging", "development"), weights=(75, 10, 15), k=1
                )[0],
                criticality=rng.choices(levels, weights=criticality_weights, k=1)[0],
                exposure="internet_facing"
                if rng.random() < config.internet_facing_probability
                else "internal",
                products=tuple(
                    catalog[slot % len(catalog)].key
                    for slot in range(config.installations_per_asset)
                ),
                versions=tuple(
                    "2.0-fixture"
                    if slot > 0 and rng.random() < config.initial_safe_probability
                    else "1.0-fixture"
                    for slot in range(config.installations_per_asset)
                ),
                final_status=final,
            )
        )
    return tuple(result)
