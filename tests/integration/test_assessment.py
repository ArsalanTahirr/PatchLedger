"""Synthetic applicability fixtures only; CVE syntax is not an NVD match."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from time import monotonic, sleep
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, insert, inspect, select, text, update
from sqlalchemy.exc import IntegrityError

from patchledger.db.session import make_session_factory
from patchledger.operational.exceptions import (
    HistoricalConflictError,
    IdempotencyConflictError,
    ImmutableRecordError,
    InvalidEvidenceError,
    InvalidOperationError,
)
from patchledger.operational.models import (
    FindingEvent,
    InstallationHistory,
    ScanObservation,
    ScanRun,
    VulnerabilityFinding,
)
from patchledger.operational.services import assessment
from patchledger.operational.services.assessment import (
    SLAPolicy,
    create_scan_run,
    record_observation,
    set_scan_status,
)
from patchledger.operational.services.assets import (
    create_department,
    register_asset,
    retire_asset,
)
from patchledger.operational.services.common import EventContext
from patchledger.operational.services.software import (
    change_software_version,
    get_or_create_product,
    install_software,
    remove_software,
)

pytestmark = pytest.mark.integration
START = datetime(2024, 1, 1, tzinfo=UTC)
CVE = "CVE-2024-10001"
POLICY = SLAPolicy("fixture:standard:v1", 7 * 86400)
NEW_TABLES = {
    "scan_runs",
    "scan_observations",
    "vulnerability_findings",
    "finding_events",
}


def at(day):
    return START + timedelta(days=day)


def ctx(day):
    return EventContext(at(day), "test:assessor", "fixture:assessment", True)


def migrate(engine, operation, *args):
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        operation(config, *args)


@pytest.fixture
def sessions(postgres_engine):
    migrate(postgres_engine, command.upgrade, "head")
    return make_session_factory(postgres_engine)


def asset(session, department, key):
    return register_asset(
        session,
        asset_key=key,
        hostname=key,
        department_id=department,
        asset_type="server",
        environment="test",
        business_criticality=3,
        exposure="internal",
        context=ctx(0),
    )


@pytest.fixture
def target(sessions):
    with sessions.begin() as session:
        department = create_department(session, code="SEC", name="Fixture Security")
        machine = asset(session, department.id, "fixture:host")
        product = get_or_create_product(
            session,
            product_key="fixture:package",
            name="Fixture only",
            publisher_name="Fixture",
            ecosystem="generic",
        )
        period = install_software(
            session,
            asset_id=machine.id,
            product_id=product.id,
            installation_key="system/package",
            version="fixture-1",
            context=ctx(1),
        )
        return {
            "asset": machine.id,
            "department": department.id,
            "product": product.id,
            "installation": period.installation_id,
            "history": period.id,
        }


def scan(session, target, day=2, *, key=None, **changes):
    values = {
        "asset_id": target["asset"],
        "source_key": "fixture:assessment",
        "external_run_key": key or str(uuid4()),
        "producer_version": "fixture-1",
        "is_synthetic": True,
        "scope": {"kind": "explicit-fixture", "coverage": "selected-tests"},
        "status": "completed",
        "started_at": at(day),
        "completed_at": at(day) + timedelta(hours=1),
    }
    values.update(changes)
    return create_scan_run(session, **values)


def observation(session, target, day=2, *, run=None, **changes):
    run = run or scan(session, target, day)
    values = {
        "scan_run_id": run.id,
        "external_observation_key": "test-1",
        "cve_id": CVE,
        "outcome": "affected",
        "context": ctx(day),
        "test_ref": "fixture:rule:v1",
        "installation_id": target["installation"],
        "installation_history_id": target["history"],
        "evidence": {"fixture": True},
        "sla_policy": POLICY,
    }
    values.update(changes)
    return record_observation(session, **values)


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def resolved_fixture(session, finding_id, day=4):
    """Test-only verified-state fixture; no production resolution service exists yet."""
    finding = session.get(VulnerabilityFinding, finding_id)
    finding.status, finding.resolved_at = "resolved", at(day)
    number = (
        session.scalar(
            select(func.max(FindingEvent.event_number)).where(
                FindingEvent.finding_id == finding_id
            )
        )
        + 1
    )
    session.add(
        FindingEvent(
            finding_id=finding_id,
            event_number=number,
            operation_id=uuid4(),
            event_type="resolved",
            status_after="resolved",
            occurred_at=at(day),
            actor_ref="test:verifier",
            source_key="fixture:verification",
            is_synthetic=True,
            reason="Test-only verified-state fixture",
            sla_policy_ref=finding.sla_policy_ref,
            sla_target_seconds=finding.sla_target_seconds,
            sla_deadline=finding.sla_deadline,
        )
    )
    session.flush()


def test_scan_creation_idempotency_and_conflicting_retry(sessions, target):
    with sessions.begin() as session:
        first = scan(session, target, key="one", batch_key="batch-1")
        retry = scan(session, target, key="one", batch_key="batch-1")
        assert first.id == retry.id
        assert first.is_synthetic and first.producer_version == "fixture-1"
        assert first.started_at == at(2) and first.completed_at > first.started_at
        assert first.created_at > first.completed_at
        assert count(session, ScanRun) == 1
    with pytest.raises(IdempotencyConflictError), sessions.begin() as session:
        scan(session, target, key="one", batch_key="batch-1", scope={"different": True})
    with sessions.begin() as session:
        other_source = scan(session, target, key="one", source_key="fixture:other")
        assert other_source.id != first.id


def test_scan_state_transitions_do_not_change_creation_retry(sessions, target):
    with sessions.begin() as session:
        run = scan(
            session,
            target,
            key="queued",
            status="queued",
            started_at=None,
            completed_at=None,
        )
        set_scan_status(session, run.id, status="running", started_at=at(2))
        observation(session, target, run=run)
        set_scan_status(session, run.id, status="partial", completed_at=at(3))
        retry = scan(
            session,
            target,
            key="queued",
            status="queued",
            started_at=None,
            completed_at=None,
        )
        assert retry.id == run.id and retry.status == "partial"
        set_scan_status(session, run.id, status="partial", completed_at=at(3))
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        set_scan_status(session, run.id, status="running", started_at=at(2))
    with sessions.begin() as session:
        cancelled = scan(
            session, target, status="queued", started_at=None, completed_at=None
        )
        set_scan_status(session, cancelled.id, status="cancelled", completed_at=at(2))


def test_scan_completion_cannot_predate_evidence(sessions, target):
    with sessions.begin() as session:
        run = scan(session, target, status="running", completed_at=None)
        observation(session, target, day=3, run=run)
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        set_scan_status(session, run.id, status="completed", completed_at=at(2.5))


def test_observation_retry_and_initial_finding_snapshot(sessions, target):
    with sessions.begin() as session:
        run = scan(session, target)
        first = observation(session, target, run=run)
        retry = observation(session, target, run=run)
        assert first.id == retry.id and len(first.payload_digest) == 64
        finding = session.get(VulnerabilityFinding, first.finding_id)
        event = session.scalar(select(FindingEvent))
        assert finding.first_detected_at == finding.last_observed_at == at(2)
        assert finding.current_opened_at == at(2) and finding.status == "open"
        assert finding.sla_deadline == at(9)
        assert event.event_type == "opened" and event.event_number == 1
        assert (
            event.operation_id == first.id and event.sla_policy_ref == POLICY.policy_ref
        )
        assert first.recorded_at > first.occurred_at
        assert count(session, ScanObservation) == count(session, FindingEvent) == 1
    for changes in (
        {"evidence": {"different": True}},
        {"outcome": "inconclusive"},
        {"context": ctx(2.01)},
        {"test_ref": "fixture:different"},
        {"sla_policy": SLAPolicy("fixture:other", 60)},
    ):
        with pytest.raises(IdempotencyConflictError), sessions.begin() as session:
            observation(session, target, run=session.get(ScanRun, run.id), **changes)


def test_repeated_positives_and_out_of_order_open_evidence(sessions, target):
    with sessions.begin() as session:
        first = observation(session, target, day=2)
        second = observation(session, target, day=4)
        third = observation(session, target, day=3)
        assert first.finding_id == second.finding_id == third.finding_id
        finding = session.get(VulnerabilityFinding, first.finding_id)
        assert finding.last_observed_at == at(4) and finding.first_detected_at == at(2)
        assert finding.sla_deadline == at(9)
        assert count(session, VulnerabilityFinding) == count(session, FindingEvent) == 1
        assert count(session, ScanObservation) == 3


def test_separate_cves_and_installations(sessions, target):
    with sessions.begin() as session:
        first = observation(session, target)
        second = observation(session, target, cve_id="CVE-2024-10002")
        period = install_software(
            session,
            asset_id=target["asset"],
            product_id=target["product"],
            installation_key="container/package",
            version="fixture-1",
            context=ctx(1),
        )
        third = observation(
            session,
            target,
            installation_id=period.installation_id,
            installation_history_id=period.id,
        )
        assert len({first.finding_id, second.finding_id, third.finding_id}) == 3
        assert count(session, VulnerabilityFinding) == 3


def test_asset_scoped_findings_reuse_identity_and_database_null_uniqueness(
    sessions, target
):
    with sessions.begin() as session:
        first = observation(
            session, target, installation_id=None, installation_history_id=None
        )
        second = observation(
            session, target, day=3, installation_id=None, installation_history_id=None
        )
        assert first.finding_id == second.finding_id
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            VulnerabilityFinding(
                asset_id=target["asset"],
                installation_id=None,
                cve_id=CVE,
                status="open",
                first_detected_at=at(2),
                current_opened_at=at(2),
                last_observed_at=at(2),
            )
        )


@pytest.mark.parametrize(
    "cve",
    [
        "cve-2024-10001",
        "CVE-24-10001",
        "CVE-2024-123",
        "CVE-2024-1234\n",
        "",
        "CVE-2024-ABCD",
    ],
)
def test_invalid_cve_service_and_database(sessions, target, cve):
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        observation(session, target, cve_id=cve)
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            VulnerabilityFinding(
                asset_id=target["asset"],
                cve_id=cve,
                status="open",
                first_detected_at=at(2),
                current_opened_at=at(2),
                last_observed_at=at(2),
            )
        )


def test_cross_asset_and_historical_target_validation(sessions, target):
    with sessions.begin() as session:
        other = asset(session, target["department"], "fixture:other")
        period = install_software(
            session,
            asset_id=other.id,
            product_id=target["product"],
            installation_key="system/package",
            version="fixture-1",
            context=ctx(1),
        )
        other_target = {**target, "asset": other.id}
    for changes in (
        {"installation_history_id": None},
        {"installation_history_id": uuid4()},
        {"installation_history_id": period.id},
        {
            "installation_id": period.installation_id,
            "installation_history_id": period.id,
        },
        {"installation_id": None},
    ):
        with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
            observation(session, target, **changes)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        observation(session, other_target)


def test_historical_version_and_half_open_boundary(sessions, target):
    with sessions.begin() as session:
        newer = change_software_version(
            session,
            target["installation"],
            version="fixture-2",
            change_kind="upgrade",
            expected_history_id=target["history"],
            context=ctx(3),
        )
        new_history_id = newer.id
        old = observation(session, target, day=2)
        new = observation(session, target, day=3, installation_history_id=newer.id)
        assert old.finding_id == new.finding_id
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        observation(session, target, day=3)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        observation(session, target, day=2, installation_history_id=new_history_id)


@pytest.mark.parametrize("outcome", ["not_affected", "target_absent", "inconclusive"])
def test_negative_observations_never_resolve(sessions, target, outcome):
    with sessions.begin() as session:
        first = observation(session, target)
        negative = observation(
            session, target, day=3, outcome=outcome, installation_history_id=None
        )
        assert negative.finding_id == first.finding_id
        assert session.get(VulnerabilityFinding, first.finding_id).status == "open"
        assert count(session, FindingEvent) == 1
        # Evidence without any previous finding is preserved independently.
        standalone = observation(
            session,
            target,
            day=4,
            outcome=outcome,
            cve_id="CVE-2024-19999",
            installation_history_id=None,
        )
        assert standalone.finding_id is None
        assert count(session, VulnerabilityFinding) == 1


@pytest.mark.parametrize("status", ["partial", "failed", "cancelled"])
def test_incomplete_scans_positives_and_missing_observations(sessions, target, status):
    with sessions.begin() as session:
        run = scan(session, target, status=status)
        first = observation(session, target, run=run)
        scan(session, target, day=3, status=status)  # No observation is not an absence.
        finding = session.get(VulnerabilityFinding, first.finding_id)
        assert finding.status == "open" and finding.last_observed_at == at(2)
        assert count(session, FindingEvent) == 1


def test_recurrence_preserves_history_and_establishes_new_sla(sessions, target):
    with sessions.begin() as session:
        first = observation(session, target)
        resolved_fixture(session, first.finding_id)
        recurrence = observation(
            session, target, day=5, sla_policy=SLAPolicy("fixture:urgent:v2", 86400)
        )
        finding = session.get(VulnerabilityFinding, first.finding_id)
        assert recurrence.finding_id == first.finding_id
        assert finding.status == "open" and finding.resolved_at is None
        assert finding.first_detected_at == at(2) and finding.current_opened_at == at(5)
        assert finding.sla_deadline == at(6)
        events = list(
            session.scalars(select(FindingEvent).order_by(FindingEvent.event_number))
        )
        assert [event.event_type for event in events] == [
            "opened",
            "resolved",
            "reopened",
        ]
        assert events[0].sla_deadline == events[1].sla_deadline == at(9)
        assert events[2].sla_deadline == at(6)
        # Late evidence in the old occurrence must not alter the new opening.
        observation(session, target, day=3)
        assert finding.current_opened_at == at(5) and finding.last_observed_at == at(5)


def test_late_positive_in_resolved_occurrence_does_not_reopen(sessions, target):
    with sessions.begin() as session:
        first = observation(session, target)
        resolved_fixture(session, first.finding_id)
        late = observation(session, target, day=3)
        finding = session.get(VulnerabilityFinding, first.finding_id)
        assert late.finding_id == finding.id and finding.status == "resolved"
        assert finding.last_observed_at == at(3) and finding.resolved_at == at(4)
        assert count(session, FindingEvent) == 2
        observation(session, target, day=5, outcome="not_affected")
        assert finding.status == "resolved"


@pytest.mark.parametrize("day", [1.5, 4, 4.5])
def test_contradictory_lifecycle_times_require_manual_reconciliation(
    sessions, target, day
):
    with sessions.begin() as session:
        first = observation(session, target)
        resolved_fixture(session, first.finding_id)
        observation(session, target, day=5)
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        observation(session, target, day=day)
    with sessions.begin() as session:
        assert count(session, ScanObservation) == 2
        assert count(session, FindingEvent) == 3


def test_invalid_scan_and_evidence_times_provenance_and_bounds(sessions, target):
    for changes in (
        {"started_at": at(3)},
        {"started_at": START - timedelta(days=1)},
        {"status": "unknown"},
        {"started_at": datetime(2024, 1, 2)},
        {"scope": {"oversized": "x" * 17000}},
        {"is_synthetic": "yes"},
    ):
        with pytest.raises(InvalidOperationError), sessions.begin() as session:
            scan(session, target, **changes)
    with sessions.begin() as session:
        run = scan(session, target)
        queued = scan(
            session, target, status="queued", started_at=None, completed_at=None
        )
    for changes in (
        {"context": ctx(1)},
        {"context": ctx(3)},
        {"context": EventContext(at(2), "test:actor", "other:source", True)},
        {"context": EventContext(at(2), "test:actor", "fixture:assessment", False)},
        {"evidence": {"oversized": "x" * 17000}},
        {"evidence": {"bad": float("nan")}},
    ):
        with pytest.raises(InvalidOperationError), sessions.begin() as session:
            observation(session, target, run=session.get(ScanRun, run.id), **changes)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        observation(session, target, run=session.get(ScanRun, queued.id))


def test_reconciliation_and_observation_roll_back_atomically(
    sessions, target, monkeypatch
):
    with sessions.begin() as session:
        run = scan(session, target)
    original = assessment._opening_event

    def fail_after_event(*args, **kwargs):
        original(*args, **kwargs)
        args[0].flush()
        raise RuntimeError("failure after finding and event insertion")

    monkeypatch.setattr(assessment, "_opening_event", fail_after_event)
    with pytest.raises(RuntimeError), sessions.begin() as session:
        observation(session, target, run=session.get(ScanRun, run.id))
    with sessions.begin() as session:
        assert (
            count(session, VulnerabilityFinding)
            == count(session, FindingEvent)
            == count(session, ScanObservation)
            == 0
        )
    monkeypatch.setattr(assessment, "_opening_event", original)
    with pytest.raises(RuntimeError), sessions.begin() as session:
        observation(session, target, run=session.get(ScanRun, run.id))
        raise RuntimeError("caller failed after successful service flush")
    with sessions.begin() as session:
        assert (
            count(session, VulnerabilityFinding)
            == count(session, FindingEvent)
            == count(session, ScanObservation)
            == 0
        )


def test_orm_observations_events_and_finding_identity_are_immutable(sessions, target):
    with sessions.begin() as session:
        obs = observation(session, target)
        event = session.scalar(select(FindingEvent))
        obs_id, event_id, finding_id = obs.id, event.id, obs.finding_id
    for model, identity, field, value in (
        (ScanObservation, obs_id, "evidence_ref", "changed"),
        (FindingEvent, event_id, "reason", "changed"),
        (VulnerabilityFinding, finding_id, "cve_id", "CVE-2024-99999"),
    ):
        with pytest.raises(ImmutableRecordError), sessions.begin() as session:
            setattr(session.get(model, identity), field, value)
    for model, identity in ((ScanObservation, obs_id), (FindingEvent, event_id)):
        with pytest.raises(ImmutableRecordError), sessions.begin() as session:
            session.delete(session.get(model, identity))


def test_database_scoped_foreign_keys_and_checks(sessions, target):
    with sessions.begin() as session:
        obs = observation(session, target)
        other_asset = asset(session, target["department"], "fixture:other")
        other_period = install_software(
            session,
            asset_id=other_asset.id,
            product_id=target["product"],
            installation_key="other",
            version="1",
            context=ctx(1),
        )
        raw = {
            column.name: getattr(obs, column.name)
            for column in ScanObservation.__table__.columns
        }
    for changes in (
        {"asset_id": other_asset.id},
        {"installation_id": other_period.installation_id},
        {"installation_history_id": other_period.id},
        {"cve_id": "CVE-2024-10002"},
        {"installation_id": None},
        {"installation_history_id": None},
        {"payload_digest": "bad"},
        {"evidence": {"large": "x" * 17000}},
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                insert(ScanObservation).values(
                    **{
                        **raw,
                        "id": uuid4(),
                        "external_observation_key": str(uuid4()),
                        **changes,
                    }
                )
            )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(insert(ScanObservation).values(**{**raw, "id": uuid4()}))
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            update(ScanRun)
            .where(ScanRun.id == raw["scan_run_id"])
            .values(completed_at=at(1))
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            update(VulnerabilityFinding)
            .where(VulnerabilityFinding.id == obs.finding_id)
            .values(installation_id=other_period.installation_id)
        )
    for table, identity in (
        (ScanRun, raw["scan_run_id"]),
        (InstallationHistory, target["history"]),
        (VulnerabilityFinding, obs.finding_id),
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(table.__table__.delete().where(table.id == identity))


@pytest.mark.parametrize("asset_scoped", [False, True])
def test_concurrent_first_detections_serialize_on_finding_uniqueness(
    sessions, target, postgres_engine, asset_scoped
):
    with sessions.begin() as session:
        run1, run2 = scan(session, target), scan(session, target, day=3)
    backend_ids = Queue()
    changes = (
        {"installation_id": None, "installation_history_id": None}
        if asset_scoped
        else {}
    )

    def competing_detection():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backend_ids.put(session.scalar(text("SELECT pg_backend_pid()")))
            return observation(
                session, target, day=3, run=session.get(ScanRun, run2.id), **changes
            ).finding_id

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            winner = observation(
                session, target, run=session.get(ScanRun, run1.id), **changes
            )
            finding_id = winner.finding_id
            future = executor.submit(competing_detection)
            backend_id = backend_ids.get(timeout=3)
            deadline = monotonic() + 3
            with postgres_engine.connect() as observer:
                while not observer.scalar(
                    text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                    {"pid": backend_id},
                ):
                    assert monotonic() < deadline, (
                        "Competing detection did not wait for unique finding insertion"
                    )
                    sleep(0.01)
        assert future.result(timeout=5) == finding_id
    with sessions.begin() as session:
        assert count(session, VulnerabilityFinding) == count(session, FindingEvent) == 1
        assert count(session, ScanObservation) == 2
        assert session.get(VulnerabilityFinding, finding_id).last_observed_at == at(3)


def test_0003_roundtrip_preserves_inventory_data(postgres_engine):
    migrate(postgres_engine, command.upgrade, "0002")
    sessions = make_session_factory(postgres_engine)
    with sessions.begin() as session:
        department = create_department(session, code="KEEP", name="Keep")
        preserved = department.id
        machine = asset(session, department.id, "fixture:preserved")
        product = get_or_create_product(
            session,
            product_key="fixture:preserved",
            name="Fixture",
            publisher_name="Fixture",
            ecosystem="generic",
        )
        period = install_software(
            session,
            asset_id=machine.id,
            product_id=product.id,
            installation_key="fixture:preserved",
            version="1",
            context=ctx(1),
        )
        target = {
            "asset": machine.id,
            "installation": period.installation_id,
            "history": period.id,
        }
    migrate(postgres_engine, command.upgrade, "0003")
    migrate(postgres_engine, command.check)
    with sessions.begin() as session:
        observation(session, target)
    with postgres_engine.connect() as connection:
        assert NEW_TABLES <= set(
            inspect(connection).get_table_names(schema="operational")
        )
    migrate(postgres_engine, command.downgrade, "0002")
    with postgres_engine.connect() as connection:
        assert len(inspect(connection).get_table_names(schema="operational")) == 7
        assert (
            connection.scalar(
                text("SELECT id FROM operational.departments WHERE code = 'KEEP'")
            )
            == preserved
        )
        assert (
            connection.scalar(text("SELECT version_num FROM public.alembic_version"))
            == "0002"
        )
        assert (
            connection.scalar(
                text(
                    "SELECT version FROM operational.installation_history WHERE id = :id"
                ),
                {"id": period.id},
            )
            == "1"
        )
    migrate(postgres_engine, command.upgrade, "0003")
    migrate(postgres_engine, command.check)
    with postgres_engine.connect() as connection:
        assert len(inspect(connection).get_table_names(schema="operational")) == 11


def test_retry_after_resolution_preserves_original_observation(sessions, target):
    with sessions.begin() as session:
        run = scan(session, target)
        original = observation(session, target, run=run)
        resolved_fixture(session, original.finding_id)
    with sessions.begin() as session:
        retried = observation(session, target, run=session.get(ScanRun, run.id))
        assert retried.id == original.id
        assert (
            session.get(VulnerabilityFinding, original.finding_id).status == "resolved"
        )
        assert (
            count(session, ScanObservation) == 1 and count(session, FindingEvent) == 2
        )


def test_database_finding_and_event_lifecycle_invariants(sessions, target):
    with sessions.begin() as session:
        obs = observation(session, target)
        event = session.scalar(select(FindingEvent))
        raw = {
            column.name: getattr(event, column.name)
            for column in FindingEvent.__table__.columns
        }
    for changes in (
        {"status": "fixed"},
        {"status": "resolved"},
        {"resolved_at": at(3)},
        {"current_opened_at": at(1)},
        {"last_observed_at": at(1)},
        {"sla_target_seconds": 0},
        {"sla_policy_ref": None},
        {"sla_deadline": at(1)},
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                update(VulnerabilityFinding)
                .where(VulnerabilityFinding.id == obs.finding_id)
                .values(**changes)
            )
    for changes in (
        {"event_number": 0},
        {"event_type": "deleted"},
        {"status_after": "resolved"},
        {"event_type": "resolved", "status_after": "resolved", "reason": None},
        {"sla_target_seconds": None},
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                insert(FindingEvent).values(
                    **{
                        **raw,
                        "id": uuid4(),
                        "event_number": 2,
                        "operation_id": uuid4(),
                        **changes,
                    }
                )
            )
    for changes in ({"event_number": 2}, {"operation_id": uuid4()}):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                insert(FindingEvent).values(**{**raw, "id": uuid4(), **changes})
            )


def test_recurrence_failure_rolls_back_status_and_opening_history(
    sessions, target, monkeypatch
):
    with sessions.begin() as session:
        first = observation(session, target)
        resolved_fixture(session, first.finding_id)
    original = assessment._opening_event

    def fail_after_event(*args, **kwargs):
        original(*args, **kwargs)
        args[0].flush()
        raise RuntimeError("recurrence failure")

    monkeypatch.setattr(assessment, "_opening_event", fail_after_event)
    with pytest.raises(RuntimeError), sessions.begin() as session:
        observation(session, target, day=5)
    with sessions.begin() as session:
        finding = session.get(VulnerabilityFinding, first.finding_id)
        assert finding.status == "resolved" and finding.resolved_at == at(4)
        assert finding.current_opened_at == at(2) and finding.sla_deadline == at(9)
        assert (
            count(session, FindingEvent) == 2 and count(session, ScanObservation) == 1
        )


def test_backdated_inventory_closure_cannot_invalidate_assessed_version(
    sessions, target
):
    with sessions.begin() as session:
        observation(session, target, day=5)
    for day in (3, 5):
        with pytest.raises(HistoricalConflictError), sessions.begin() as session:
            change_software_version(
                session,
                target["installation"],
                version="fixture-2",
                change_kind="upgrade",
                expected_history_id=target["history"],
                context=ctx(day),
            )
        with pytest.raises(HistoricalConflictError), sessions.begin() as session:
            remove_software(
                session,
                target["installation"],
                expected_history_id=target["history"],
                context=ctx(day),
            )
    with sessions.begin() as session:
        change_software_version(
            session,
            target["installation"],
            version="fixture-2",
            change_kind="upgrade",
            expected_history_id=target["history"],
            context=ctx(6),
        )
        assert session.get(InstallationHistory, target["history"]).ended_at == at(6)


def test_backdated_retirement_cannot_invalidate_asset_scoped_evidence(sessions, target):
    with sessions.begin() as session:
        remove_software(
            session,
            target["installation"],
            expected_history_id=target["history"],
            context=ctx(3),
        )
        obs = observation(
            session, target, day=5, installation_id=None, installation_history_id=None
        )
    for day in (4, 5):
        with pytest.raises(HistoricalConflictError), sessions.begin() as session:
            retire_asset(
                session, target["asset"], context=ctx(day), reason="Fixture retirement"
            )
    with sessions.begin() as session:
        retire_asset(
            session, target["asset"], context=ctx(6), reason="Fixture retirement"
        )
        assert session.get(VulnerabilityFinding, obs.finding_id).status == "open"


def test_inventory_writer_waits_for_assessment_then_rejects_backdated_closure(
    sessions, target, postgres_engine
):
    backend_ids = Queue()

    def backdated_upgrade():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backend_ids.put(session.scalar(text("SELECT pg_backend_pid()")))
            with pytest.raises(HistoricalConflictError):
                change_software_version(
                    session,
                    target["installation"],
                    version="fixture-2",
                    change_kind="upgrade",
                    expected_history_id=target["history"],
                    context=ctx(3),
                )

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            observation(session, target, day=5)
            future = executor.submit(backdated_upgrade)
            backend_id = backend_ids.get(timeout=3)
            deadline = monotonic() + 3
            with postgres_engine.connect() as observer:
                while not observer.scalar(
                    text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                    {"pid": backend_id},
                ):
                    assert monotonic() < deadline, (
                        "Inventory writer did not wait for assessment's asset share lock"
                    )
                    sleep(0.01)
        future.result(timeout=5)
    with sessions.begin() as session:
        assert session.get(InstallationHistory, target["history"]).ended_at is None
        assert count(session, ScanObservation) == 1
