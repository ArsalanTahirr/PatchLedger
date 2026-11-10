"""Run reproducible scenarios using bounded caller-owned service transactions."""

import argparse
import hashlib
import json
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from patchledger.core.config import Settings
from patchledger.db.session import make_engine, make_session_factory
from patchledger.simulation import execution
from patchledger.simulation.config import SimulationConfig
from patchledger.simulation.enterprise import enterprise_plan
from patchledger.simulation.errors import ScenarioConflictError, SimulationError
from patchledger.simulation.inventory import initialize
from patchledger.simulation.quality import check_quality
from patchledger.simulation.reporting import load_records, summarize
from patchledger.simulation.scheduler import event_schedule


def plan_simulation(config):
    assets = enterprise_plan(config)
    events = event_schedule(config, assets)
    return assets, events


def run_simulation(engine, config: SimulationConfig):
    # Defensive copy: frozen Pydantic models do not deep-freeze nested dictionaries.
    config = SimulationConfig.model_validate(config.model_dump())
    assets, events = plan_simulation(config)
    sessions = make_session_factory(engine)
    lock_key = int.from_bytes(
        hashlib.sha256(config.prefix.encode()).digest()[:8], "big", signed=True
    )
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as guard:
        if not guard.scalar(
            text("SELECT pg_try_advisory_lock(:key)"), {"key": lock_key}
        ):
            raise ScenarioConflictError(
                "This scenario is already running in this database"
            )
        try:
            if (
                guard.scalar(text("SELECT version_num FROM public.alembic_version"))
                != "0004"
            ):
                raise SimulationError(
                    "Apply the existing operational migrations through 0004 before simulation"
                )
            initialize(sessions, config, assets)
            for event in events:
                try:
                    with sessions.begin() as session:
                        execution.execute_event(
                            session, config, assets[event.asset], event
                        )
                except Exception as exc:
                    raise SimulationError(
                        f"Workflow {event.key} failed and rolled back; replay the unchanged scenario to recover"
                    ) from exc
            with sessions.begin() as session:
                session.connection(
                    execution_options={"isolation_level": "REPEATABLE READ"}
                )
                session.execute(text("SET TRANSACTION READ ONLY"))
                records = load_records(session, config)
                quality = check_quality(config, records)
                report = summarize(config, records)
                report["data_quality"] = quality
            return report
        finally:
            try:
                guard.execute(
                    text("SELECT pg_advisory_unlock(:key)"), {"key": lock_key}
                )
            except DBAPIError:
                guard.invalidate()
                raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate synthetic PatchLedger operational data through existing services"
    )
    parser.add_argument("--scenario")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--assets", type=int)
    parser.add_argument("--installations-per-asset", type=int)
    parser.add_argument(
        "--start",
        help="Timezone-aware ISO-8601 start; default 2024-01-01T00:00:00+00:00",
    )
    parser.add_argument("--days", type=int)
    parser.add_argument(
        "--config",
        type=Path,
        help="Optional JSON configuration; CLI arguments override it",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print planned counts without loading credentials or connecting",
    )
    args = parser.parse_args(argv)
    try:
        values = json.loads(args.config.read_text()) if args.config else {}
        if not isinstance(values, dict):
            raise TypeError("Configuration file must be a JSON object")
        for key in (
            "scenario",
            "seed",
            "assets",
            "installations_per_asset",
            "start",
            "days",
        ):
            value = getattr(args, key)
            if value is not None:
                values[key] = value
        config = SimulationConfig.model_validate(values)
        if args.plan:
            assets, events = plan_simulation(config)
            print(
                json.dumps(
                    {
                        "mode": "plan-only; no persisted data",
                        "scenario": config.scenario,
                        "fingerprint": config.fingerprint,
                        "planned_assets": len(assets),
                        "planned_installations": len(assets)
                        * config.installations_per_asset,
                        "planned_workflows": len(events),
                        "applicability": "synthetic-fixture-only",
                    },
                    indent=2,
                )
            )
            return 0
        engine = make_engine(Settings().sqlalchemy_url)
        try:
            print(json.dumps(run_simulation(engine, config), indent=2, sort_keys=True))
        finally:
            engine.dispose()
        return 0
    except ValidationError as exc:
        parser.exit(2, f"Invalid configuration: {exc.errors(include_input=False)}\n")
    except (OSError, TypeError, ValueError) as exc:
        parser.exit(2, f"Invalid configuration: {exc}\n")
    except SimulationError as exc:
        parser.exit(1, f"Simulation failed: {exc}\n")
    except DBAPIError:
        parser.exit(
            1,
            "Database operation failed; check server access, configuration and operational migrations.\n",
        )


if __name__ == "__main__":
    raise SystemExit(main())
