"""Pure chronological schedule. Expected failures are data, never caught SQL errors."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from patchledger.simulation.config import SimulationConfig
from patchledger.simulation.enterprise import AssetPlan
from patchledger.simulation.random_state import random_stream


@dataclass(frozen=True, order=True)
class ScheduledEvent:
    at: datetime
    order: int
    key: str
    asset: int
    kind: str
    detail: str = ""


def event_schedule(config: SimulationConfig, assets: tuple[AssetPlan, ...]):
    events = []

    def add(day, hour, asset, kind, detail="", order=0):
        when = config.start + timedelta(days=day, hours=hour)
        if when < config.end:
            key = f"asset:{asset}:{kind}:{day}:{detail}"
            events.append(ScheduledEvent(when, order, key, asset, kind, detail))

    for asset in assets:
        index = asset.index
        for day in range(0, config.days, config.scan_interval_days):
            add(day, 9, index, "scan", "periodic")
        rng = random_stream(config, f"remediation:{index}")
        if rng.random() < config.remediation_probability:
            add(0, 10, index, "task")
            late = rng.random() < config.sla_breach_probability
            delay = config.sla_days + 1 if late else config.sla_days // 2
            for attempt in range(config.max_attempts):
                day = delay + attempt * config.remediation_interval_days
                success = rng.random() < config.patch_success_probability
                effective = (
                    success and rng.random() >= config.ineffective_patch_probability
                )
                result = (
                    "effective"
                    if effective
                    else ("ineffective" if success else "failed")
                )
                add(day, 10, index, "scan", f"precheck-{attempt}")
                add(day, 11, index, "attempt", f"{attempt}:{result}")
                add(day, 12, index, "verify", f"{attempt}:{result}")
                if effective:
                    if rng.random() < config.recurrence_probability:
                        add(day + 2, 15, index, "regression")
                        add(day + 2, 16, index, "scan", "recurrence")
                        add(day + 2, 17, index, "recurrence_task")
                    break
                if rng.random() >= config.retry_probability:
                    break
        churn = random_stream(config, f"inventory:{index}")
        if (
            config.installations_per_asset > 1
            and churn.random() < config.inventory_churn_probability
        ):
            day = max(1, config.days // 3)
            add(day, 14, index, "remove")
            add(day + 1, 14, index, "reinstall")
        add(config.days // 2, 18, index, "attributes")
        if asset.final_status != "active":
            add(config.days - 1, 23, index, asset.final_status)
    return tuple(sorted(events))
