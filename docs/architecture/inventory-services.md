# Inventory services (Milestone 2)

Apply `uv run alembic upgrade head` to a development database first. The following
example is runnable from the repository root with `uv run python`, or saved to a
local script and run with `uv run python path/to/script.py`. It inserts a small
explicit example, not a simulator or seed dataset. The example keys must be unused;
department/asset creation intentionally rejects duplicate keys.

```python
from datetime import UTC, datetime

from patchledger.core.config import Settings
from patchledger.db.session import make_engine, make_session_factory
from patchledger.operational.services.assets import create_department, register_asset
from patchledger.operational.services.common import EventContext
from patchledger.operational.services.software import (
    change_software_version,
    get_or_create_product,
    get_version_at,
    install_software,
    register_product_identifier,
)


def event(day):
    return EventContext(
        occurred_at=datetime(2024, 1, day, tzinfo=UTC),
        actor_ref="example:operator",
        source_key="example:manual-inventory",
        is_synthetic=True,
    )


engine = make_engine(Settings().sqlalchemy_url)
sessions = make_session_factory(engine)
try:
    with sessions.begin() as session:
        department = create_department(
            session, code="EXAMPLE", name="Example department"
        )
        asset = register_asset(
            session,
            asset_key="example:server-01",
            hostname="example-server",
            department_id=department.id,
            asset_type="server",
            environment="test",
            business_criticality=3,
            exposure="internal",
            context=event(1),
        )
        product = get_or_create_product(
            session,
            product_key="example:agent",
            name="Example agent",
            publisher_name="Example publisher",
            ecosystem="generic",
        )
        register_product_identifier(
            session, product.id, scheme="vendor", identifier="example:agent"
        )
        first = install_software(
            session,
            asset_id=asset.id,
            product_id=product.id,
            installation_key="system/example-agent",
            version="1.0",
            context=event(2),
        )
        installation_id = first.installation_id
        second = change_software_version(
            session,
            installation_id,
            version="2.0",
            change_kind="upgrade",
            expected_history_id=first.id,
            context=event(5),
        )
        assert second.installation_id == installation_id

    with sessions.begin() as session:
        earlier = get_version_at(
            session, installation_id, at=datetime(2024, 1, 3, tzinfo=UTC)
        )
        assert earlier.version == "1.0"
        print(earlier.version)
finally:
    engine.dispose()
```

No example data is inserted by migrations or normal imports. These product
identifiers assert no software-to-CVE applicability.

## Available operations

| Module | Functions |
| --- | --- |
| `services.assets` | `create_department`, `get_department`, `retire_department`, `register_asset`, `get_asset`, `update_asset`, `retire_asset` |
| `services.software` | `get_or_create_product`, `register_product_identifier`, `install_software`, `change_software_version`, `remove_software`, `get_current_version`, `get_installation_history`, `get_version_at` |

`install_software` and `change_software_version` return an `InstallationHistory`
row containing both its own ID and the stable installation ID. Use
`change_kind="downgrade"` for an explicit downgrade; version strings are never
compared as semantic versions. Optional build/platform/architecture arguments
describe the full new version state, so pass known qualifiers on each change.

To update an asset, pass only approved attributes, for example:
`update_asset(session, asset_id, changes={"business_criticality": 5,
"department_id": department_id}, context=event_context)`.
`owner_ref=None` explicitly clears an owner. No-op changes do not append events.
Retired assets cannot be revived or modified by these services.

To remove software, call `remove_software(session, installation_id,
expected_history_id=current.id, context=event_context)`. It closes the current
period once. A later `install_software` with the same asset/product/key reuses the
logical installation. A different product requires a new installation key/ID.
An asset can host multiple instances by using different installation keys.

## Transactions, time and errors

- The caller owns `sessions.begin()`. Services flush but never commit. Let failures
  escape this context so **all** changes roll back; do not catch a domain error and
  commit a partially completed multi-operation workflow.
- Supply timezone-aware business times through `EventContext`. They normalize to
  UTC. `created_at`, `updated_at`, `recorded_at` and `ended_recorded_at` use the
  actual database clock, not the simulated date. End provenance is stored separately.
- Periods are half-open `[started_at, ended_at)`. At an upgrade timestamp the new
  version applies; at removal there is no installed version. Lookup returns `None`
  for gaps and raises `NotFoundError` for an unknown installation.
- Asset then installation row locks serialize lifecycle changes. Expected history
  IDs reject stale callers. All period writes must use these services.
- Milestone 2 rejects changes before the current version start, earlier-gap
  insertions and any rewrite of established periods. A reinstallation can occur
  at or after the latest removal. Asset updates reject times before the latest
  snapshot; equal times are ordered by event number.
- `ConflictError` covers duplicate identity or conflicting catalog content;
  `InvalidOperationError` covers invalid input/state; `HistoricalConflictError`
  covers unsupported backdating; `StaleVersionError` covers stale version IDs.
  `ImmutableRecordError` guards ORM identity/history rewrites.
- Repeating product creation with identical attributes or identifier registration
  with identical provenance returns the existing row. Other inventory mutations
  are not general exactly-once commands; duplicate creates or stale retries fail
  explicitly. The simulator's broader idempotency contract remains future work.

Remove software before retiring its asset. Department retirement requires all
current assets to be reassigned or retired and rejects times before the recorded
timelines of assets previously assigned to it. Historical department assignments
and asset criticality are preserved; historical department names are not tracked.

PostgreSQL enforces FKs, nonempty required keys, classification checks, positive
period duration and one open period. ORM guards protect IDs and immutable history.
Without an exclusion constraint, arbitrary SQL can still insert overlapping
closed periods or bypass history guards. This implementation relies on one
documented service write path, not database triggers or a permissions framework.
