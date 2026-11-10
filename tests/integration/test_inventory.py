"""Explicit inventory fixtures only; no company generator or CVE associations."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from time import monotonic, sleep
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError

from patchledger.db.session import make_session_factory
from patchledger.operational.exceptions import (
    ConflictError,
    HistoricalConflictError,
    ImmutableRecordError,
    InvalidOperationError,
    NotFoundError,
    StaleVersionError,
)
from patchledger.operational.models import (
    Asset,
    AssetEvent,
    Department,
    InstallationHistory,
    ProductIdentifier,
    SoftwareInstallation,
    SoftwareProduct,
)
from patchledger.operational.services.assets import (
    create_department,
    get_asset,
    get_department,
    register_asset,
    retire_asset,
    retire_department,
    update_asset,
)
from patchledger.operational.services.common import EventContext
from patchledger.operational.services.software import (
    change_software_version,
    get_current_version,
    get_installation_history,
    get_or_create_product,
    get_version_at,
    install_software,
    register_product_identifier,
    remove_software,
)

pytestmark = pytest.mark.integration
START = datetime(2024, 1, 1, tzinfo=UTC)


def ctx(day=0):
    return EventContext(
        START + timedelta(days=day), "test:operator", "fixture:inventory", True
    )


@pytest.fixture
def sessions(postgres_engine):
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    with postgres_engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    return make_session_factory(postgres_engine)


def new_asset(session, department_id, key="asset-1", **kwargs):
    return register_asset(
        session,
        asset_key=key,
        hostname=key,
        department_id=department_id,
        asset_type="server",
        environment="production",
        business_criticality=4,
        exposure="internal",
        context=ctx(),
        **kwargs,
    )


@pytest.fixture
def inventory(sessions):
    with sessions.begin() as session:
        department = create_department(session, code="ENG", name="Engineering")
        asset = new_asset(session, department.id)
        product = get_or_create_product(
            session,
            product_key="fixture:agent",
            name="Test agent",
            publisher_name="Fixture publisher",
            ecosystem="generic",
        )
        return department.id, asset.id, product.id


def install(session, inventory, day=1, **kwargs):
    return install_software(
        session,
        asset_id=inventory[1],
        product_id=inventory[2],
        installation_key="system/agent",
        version="1.0",
        context=ctx(day),
        **kwargs,
    )


def test_departments_uniqueness_and_retirement(sessions):
    with sessions.begin() as session:
        dep = create_department(session, code="ENG", name="Engineering")
        dep_id = dep.id
        assert get_department(session, dep_id).name == "Engineering"
    with pytest.raises(ConflictError), sessions.begin() as session:
        create_department(session, code="ENG", name="Duplicate")
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(Department(code="ENG", name="Direct duplicate"))
    with sessions.begin() as session:
        retire_department(session, dep_id, context=ctx(1))
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        new_asset(session, dep_id)
    with pytest.raises(NotFoundError), sessions.begin() as session:
        get_department(session, uuid4())


def test_asset_snapshots_preserve_assignments_and_criticality(sessions, inventory):
    with sessions.begin() as session:
        asset = get_asset(session, inventory[1])
        assert asset.registered_at == START
        assert asset.created_at > START
        dep2 = create_department(session, code="OPS", name="Operations")
        dep2_id = dep2.id
        update_asset(
            session,
            asset.id,
            changes={
                "department_id": dep2.id,
                "business_criticality": 5,
                "hostname": "renamed",
                "exposure": "internet_facing",
                "owner_ref": "test:owner",
            },
            context=ctx(2),
        )
        update_asset(session, asset.id, changes={"owner_ref": None}, context=ctx(3))
        update_asset(session, asset.id, changes={"hostname": "renamed"}, context=ctx(4))
    with sessions.begin() as session:
        events = list(
            session.scalars(select(AssetEvent).order_by(AssetEvent.event_number))
        )
        assert len(events) == 3  # No event for a no-op.
        assert [(e.department_id, e.business_criticality) for e in events] == [
            (inventory[0], 4),
            (dep2_id, 5),
            (dep2_id, 5),
        ]
        assert events[1].occurred_at == ctx(2).occurred_at
        assert events[1].recorded_at > events[1].occurred_at
        assert events[2].owner_ref is None
        assert all(e.is_synthetic for e in events)


@pytest.mark.parametrize(
    "changes",
    [
        {"business_criticality": 0},
        {"business_criticality": 6},
        {"lifecycle_status": "broken"},
        {"exposure": "public-ish"},
        {"hostname": " "},
    ],
)
def test_asset_constraints_in_postgresql(sessions, inventory, changes):
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(update(Asset).where(Asset.id == inventory[1]).values(**changes))


def test_asset_update_and_snapshot_roll_back_together(sessions, inventory):
    with pytest.raises(RuntimeError), sessions.begin() as session:
        update_asset(
            session, inventory[1], changes={"business_criticality": 5}, context=ctx(2)
        )
        raise RuntimeError("failure after state and history flush")
    with sessions.begin() as session:
        assert get_asset(session, inventory[1]).business_criticality == 4
        assert session.scalar(select(func.count()).select_from(AssetEvent)) == 1
    with pytest.raises(RuntimeError), sessions.begin() as session:
        new_asset(session, inventory[0], "rolled-back")
        raise RuntimeError("registration failure")
    with sessions.begin() as session:
        assert session.scalar(select(func.count()).select_from(Asset)) == 1
        assert session.scalar(select(func.count()).select_from(AssetEvent)) == 1


def test_retirement_preserves_history_and_checks_current_inventory(sessions, inventory):
    with sessions.begin() as session:
        period = install(session, inventory)
        installation_id, period_id = period.installation_id, period.id
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        retire_asset(session, inventory[1], context=ctx(2), reason="Decommission")
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        retire_department(session, inventory[0], context=ctx(2))
    with sessions.begin() as session:
        remove_software(
            session, installation_id, expected_history_id=period_id, context=ctx(3)
        )
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        retire_asset(session, inventory[1], context=ctx(2), reason="Too early")
    with sessions.begin() as session:
        retire_asset(session, inventory[1], context=ctx(4), reason="Decommission")
        retire_department(session, inventory[0], context=ctx(4))
    with sessions.begin() as session:
        assert get_asset(session, inventory[1]).retired_at == ctx(4).occurred_at
        assert session.scalar(
            select(AssetEvent).where(AssetEvent.event_type == "retired")
        )
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        update_asset(
            session, inventory[1], changes={"hostname": "revive"}, context=ctx(5)
        )
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        install(session, inventory, day=5)


def test_product_and_identifier_reuse_and_conflicts(sessions, inventory):
    with sessions.begin() as session:
        product = get_or_create_product(
            session,
            product_key="fixture:agent",
            name="Test agent",
            publisher_name="Fixture publisher",
            ecosystem="generic",
        )
        assert product.id == inventory[2]
        one = register_product_identifier(
            session, product.id, scheme="vendor", identifier="fixture:agent"
        )
        two = register_product_identifier(
            session, product.id, scheme="vendor", identifier="fixture:agent"
        )
        assert one.id == two.id
    with pytest.raises(ConflictError), sessions.begin() as session:
        get_or_create_product(
            session,
            product_key="fixture:agent",
            name="Different",
            publisher_name="Fixture publisher",
            ecosystem="generic",
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            SoftwareProduct(
                product_key="fixture:agent",
                name="Duplicate",
                publisher_name="Fixture",
                ecosystem="generic",
            )
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            ProductIdentifier(
                product_id=inventory[2], scheme="vendor", identifier="fixture:agent"
            )
        )


def test_install_upgrade_downgrade_remove_reinstall_and_historical_lookup(
    sessions, inventory
):
    with sessions.begin() as session:
        p1 = install(session, inventory)
        installation_id = p1.installation_id
        p2 = change_software_version(
            session,
            installation_id,
            version="2.0",
            change_kind="upgrade",
            expected_history_id=p1.id,
            context=ctx(2),
        )
        p3 = change_software_version(
            session,
            installation_id,
            version="1.5",
            change_kind="downgrade",
            expected_history_id=p2.id,
            context=ctx(3),
        )
        remove_software(
            session, installation_id, expected_history_id=p3.id, context=ctx(4)
        )
        assert get_current_version(session, installation_id) is None
        p4 = install(session, inventory, day=6)
        assert p4.installation_id == installation_id
        assert get_current_version(session, installation_id).id == p4.id
        assert get_version_at(session, installation_id, at=START) is None
        assert (
            get_version_at(session, installation_id, at=ctx(1.5).occurred_at).version
            == "1.0"
        )
        assert (
            get_version_at(session, installation_id, at=ctx(2).occurred_at).id == p2.id
        )
        assert (
            get_version_at(session, installation_id, at=ctx(3).occurred_at).id == p3.id
        )
        assert get_version_at(session, installation_id, at=ctx(4).occurred_at) is None
        assert get_version_at(session, installation_id, at=ctx(5).occurred_at) is None
        assert (
            get_version_at(session, installation_id, at=ctx(6).occurred_at).id == p4.id
        )
        periods = get_installation_history(session, installation_id)
        assert [p.end_reason for p in periods] == [
            "upgrade",
            "downgrade",
            "removal",
            None,
        ]
        assert all(p.ended_recorded_at > p.ended_at for p in periods[:-1])


def test_multiple_installations_and_product_replacement_identity(sessions, inventory):
    with sessions.begin() as session:
        first = install(session, inventory)
        second = install_software(
            session,
            asset_id=inventory[1],
            product_id=inventory[2],
            installation_key="container/agent",
            version="3",
            context=ctx(1),
        )
        assert first.installation_id != second.installation_id
        remove_software(
            session, first.installation_id, expected_history_id=first.id, context=ctx(2)
        )
        other = get_or_create_product(
            session,
            product_key="fixture:other",
            name="Other",
            publisher_name="Fixture",
            ecosystem="generic",
        )
        other_id = other.id
    with pytest.raises(ConflictError), sessions.begin() as session:
        install_software(
            session,
            asset_id=inventory[1],
            product_id=other_id,
            installation_key="system/agent",
            version="1",
            context=ctx(3),
        )


def test_duplicate_active_period_rejected_by_database(sessions, inventory):
    with sessions.begin() as session:
        p = install(session, inventory)
        installation_id = p.installation_id
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            InstallationHistory(
                installation_id=installation_id,
                version="bad",
                started_at=ctx(2).occurred_at,
                start_basis="actual",
                actor_ref="test:operator",
                source_key="fixture:inventory",
                is_synthetic=True,
            )
        )


def test_invalid_period_bounds_and_incomplete_closure_rejected(sessions, inventory):
    with sessions.begin() as session:
        p = install(session, inventory)
        pid = p.id
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            update(InstallationHistory)
            .where(InstallationHistory.id == pid)
            .values(
                ended_at=START,
                end_basis="actual",
                end_reason="removal",
                ended_recorded_at=func.clock_timestamp(),
                end_actor_ref="test:operator",
                end_source_key="fixture",
                end_is_synthetic=True,
            )
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            update(InstallationHistory)
            .where(InstallationHistory.id == pid)
            .values(ended_at=ctx(2).occurred_at)
        )


def test_backdated_changes_overlap_and_gap_insertion_are_rejected(sessions, inventory):
    with sessions.begin() as session:
        p1 = install(session, inventory)
        p2 = change_software_version(
            session,
            p1.installation_id,
            version="2",
            change_kind="upgrade",
            expected_history_id=p1.id,
            context=ctx(3),
        )
        iid, pid = p2.installation_id, p2.id
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        change_software_version(
            session,
            iid,
            version="3",
            change_kind="upgrade",
            expected_history_id=pid,
            context=ctx(2),
        )
    with pytest.raises(StaleVersionError), sessions.begin() as session:
        change_software_version(
            session,
            iid,
            version="3",
            change_kind="upgrade",
            expected_history_id=uuid4(),
            context=ctx(4),
        )
    with sessions.begin() as session:
        remove_software(session, iid, expected_history_id=pid, context=ctx(4))
        p3 = install(session, inventory, day=6)
        remove_software(session, iid, expected_history_id=p3.id, context=ctx(7))
    for day in (2, 5):
        with pytest.raises(HistoricalConflictError), sessions.begin() as session:
            install(session, inventory, day=day)
    with sessions.begin() as session:
        assert len(get_installation_history(session, iid)) == 3


def test_failed_upgrade_workflow_rolls_back_both_periods(sessions, inventory):
    with sessions.begin() as session:
        p = install(session, inventory)
        iid, pid = p.installation_id, p.id
    with pytest.raises(RuntimeError), sessions.begin() as session:
        change_software_version(
            session,
            iid,
            version="2",
            change_kind="upgrade",
            expected_history_id=pid,
            context=ctx(2),
        )
        raise RuntimeError("patch workflow failed after flushing history")
    with sessions.begin() as session:
        assert get_current_version(session, iid).id == pid
        assert len(get_installation_history(session, iid)) == 1


def test_referential_integrity_and_restrict_deletion(sessions, inventory):
    with sessions.begin() as session:
        p = install(session, inventory)
        iid = p.installation_id
    for table, identity in (
        ("departments", inventory[0]),
        ("assets", inventory[1]),
        ("software_products", inventory[2]),
        ("software_installations", iid),
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                text(f"DELETE FROM operational.{table} WHERE id = :id"),
                {"id": identity},
            )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            SoftwareInstallation(
                asset_id=uuid4(), product_id=inventory[2], installation_key="missing"
            )
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            SoftwareInstallation(
                asset_id=inventory[1], product_id=uuid4(), installation_key="missing"
            )
        )


def test_orm_stable_identities_and_append_only_history(sessions, inventory):
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.get(Asset, inventory[1]).asset_key = "changed"
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.scalar(select(AssetEvent)).business_criticality = 1
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.delete(session.scalar(select(AssetEvent)))
    with sessions.begin() as session:
        p = install(session, inventory)
        pid = p.id
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.get(InstallationHistory, pid).version = "overwritten"


def test_backdated_asset_update_rejected(sessions, inventory):
    with sessions.begin() as session:
        update_asset(session, inventory[1], changes={"hostname": "new"}, context=ctx(3))
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        update_asset(
            session, inventory[1], changes={"hostname": "older"}, context=ctx(2)
        )


def test_department_retirement_cannot_predate_asset_reassignment(sessions, inventory):
    with sessions.begin() as session:
        target = create_department(session, code="OPS", name="Operations")
        update_asset(
            session, inventory[1], changes={"department_id": target.id}, context=ctx(4)
        )
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        retire_department(session, inventory[0], context=ctx(2))
    with sessions.begin() as session:
        retire_department(session, inventory[0], context=ctx(4))


def test_duplicate_asset_key_and_invalid_service_attributes(sessions, inventory):
    with pytest.raises(ConflictError), sessions.begin() as session:
        new_asset(session, inventory[0])
    for changes in (
        {"business_criticality": 0},
        {"asset_key": "replace"},
        {"lifecycle_status": "registered"},
        {"department_id": uuid4()},
    ):
        with (
            pytest.raises((InvalidOperationError, NotFoundError)),
            sessions.begin() as session,
        ):
            update_asset(session, inventory[1], changes=changes, context=ctx(1))


def test_asset_snapshot_failure_rolls_back_current_state(
    sessions, inventory, monkeypatch
):
    from patchledger.operational.services import assets

    def fail_snapshot(*args, **kwargs):
        raise RuntimeError("snapshot insert failed")

    monkeypatch.setattr(assets, "_snapshot", fail_snapshot)
    with pytest.raises(RuntimeError), sessions.begin() as session:
        update_asset(
            session, inventory[1], changes={"hostname": "unrecorded"}, context=ctx(1)
        )
    with sessions.begin() as session:
        assert get_asset(session, inventory[1]).hostname == "asset-1"
        assert session.scalar(select(func.count()).select_from(AssetEvent)) == 1


def test_concurrent_upgrades_block_then_reject_stale_version(
    sessions, inventory, postgres_engine
):
    with sessions.begin() as session:
        p = install(session, inventory)
        iid, pid = p.installation_id, p.id
    backend_ids = Queue()

    def competing_upgrade():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backend_ids.put(session.scalar(text("SELECT pg_backend_pid()")))
            with pytest.raises(StaleVersionError):
                change_software_version(
                    session,
                    iid,
                    version="3",
                    change_kind="upgrade",
                    expected_history_id=pid,
                    context=ctx(3),
                )

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            winner = change_software_version(
                session,
                iid,
                version="2",
                change_kind="upgrade",
                expected_history_id=pid,
                context=ctx(2),
            )
            winner_id = winner.id
            future = executor.submit(competing_upgrade)
            backend_id = backend_ids.get(timeout=3)
            deadline = monotonic() + 3
            with postgres_engine.connect() as observer:
                while not observer.scalar(
                    text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                    {"pid": backend_id},
                ):
                    assert monotonic() < deadline, (
                        "Competing upgrade did not wait for the row lock"
                    )
                    sleep(0.01)
        future.result(timeout=5)
    with sessions.begin() as session:
        assert get_current_version(session, iid).id == winner_id
        assert len(get_installation_history(session, iid)) == 2
