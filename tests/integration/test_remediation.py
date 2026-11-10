"""Synthetic OLTP workflows; no fixture applicability is a validated NVD match."""

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
    ConflictError,
    HistoricalConflictError,
    IdempotencyConflictError,
    ImmutableRecordError,
    InvalidEvidenceError,
    InvalidOperationError,
)
from patchledger.operational.models import (
    FindingEvent,
    InstallationHistory,
    RemediationEvent,
    RemediationTask,
    TaskFinding,
    VerificationResult,
    VulnerabilityFinding,
)
from patchledger.operational.services import verification
from patchledger.operational.services.assessment import (
    create_scan_run,
    record_observation,
)
from patchledger.operational.services.assets import create_department, register_asset
from patchledger.operational.services.common import EventContext
from patchledger.operational.services.remediation import (
    add_task_finding,
    create_task,
    current_opening,
    transition_task,
    update_task,
    withdraw_task_finding,
)
from patchledger.operational.services.remediation_actions import (
    apply_software_change,
    record_action,
)
from patchledger.operational.services.software import (
    change_software_version,
    get_or_create_product,
    install_software,
    remove_software,
)
from patchledger.operational.services.verification import verify_finding

pytestmark = pytest.mark.integration
START = datetime(2024, 1, 1, tzinfo=UTC)
CVES = ("CVE-2099-90001", "CVE-2099-90002")
NEW_TABLES = {
    "remediation_tasks",
    "task_findings",
    "remediation_events",
    "verification_results",
}


def at(day):
    return START + timedelta(days=day)


def ctx(day, source="fixture:operations"):
    return EventContext(at(day), "fixture:operator", source, True)


def migrate(engine, operation, *args):
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        operation(config, *args)


@pytest.fixture
def sessions(postgres_engine):
    migrate(postgres_engine, command.upgrade, "head")
    return make_session_factory(postgres_engine)


def assess(
    session,
    case,
    day,
    *,
    outcome="affected",
    cve=CVES[0],
    history=None,
    status="completed",
    scope=None,
    evidence=None,
):
    run = create_scan_run(
        session,
        asset_id=case["asset"],
        source_key="fixture:scanner",
        external_run_key=str(uuid4()),
        producer_version="fixture-v1",
        is_synthetic=True,
        scope=scope or {"tests": ["fixture:rule"]},
        status=status,
        started_at=at(day),
        completed_at=at(day) + timedelta(minutes=1),
    )
    return record_observation(
        session,
        scan_run_id=run.id,
        external_observation_key=cve,
        cve_id=cve,
        outcome=outcome,
        context=ctx(day, "fixture:scanner"),
        test_ref="fixture:rule",
        installation_id=case["installation"],
        installation_history_id=history if history is not None else case["history"],
        evidence=evidence or {"fixture": True},
        evidence_ref="fixture:scan-evidence",
    )


@pytest.fixture
def case(sessions):
    with sessions.begin() as session:
        department = create_department(session, code="SEC", name="Fixture Security")
        asset = register_asset(
            session,
            asset_key="fixture:server",
            hostname="fixture-server",
            department_id=department.id,
            asset_type="server",
            environment="test",
            business_criticality=3,
            exposure="internal",
            context=ctx(0),
        )
        product = get_or_create_product(
            session,
            product_key="fixture:package",
            name="Fixture Package",
            publisher_name="Fixture",
            ecosystem="generic",
        )
        history = install_software(
            session,
            asset_id=asset.id,
            product_id=product.id,
            installation_key="fixture:package",
            version="fixture-1",
            context=ctx(1),
        )
        values = {
            "department": department.id,
            "asset": asset.id,
            "product": product.id,
            "installation": history.installation_id,
            "history": history.id,
        }
        findings, openings = [], []
        for cve in CVES:
            obs = assess(session, values, 2, cve=cve)
            finding = session.get(VulnerabilityFinding, obs.finding_id)
            findings.append(finding.id)
            openings.append(current_opening(session, finding).id)
        return {**values, "findings": findings, "openings": openings}


def task(session, case, *, goal="eliminate", targets=(0,), key=None):
    work = create_task(
        session,
        task_key=key or str(uuid4()),
        title="Fixture remediation",
        owner_department_id=case["department"],
        priority=2,
        goal=goal,
        due_at=at(20),
        context=ctx(3),
        operation_id=uuid4(),
        estimated_effort_minutes=30,
    )
    links = [
        add_task_finding(
            session,
            work.id,
            finding_id=case["findings"][i],
            opening_event_id=case["openings"][i],
            context=ctx(3),
            operation_id=uuid4(),
        )
        for i in targets
    ]
    return work, links


def transition(session, task_id, status, day, **changes):
    return transition_task(
        session,
        task_id,
        status=status,
        context=ctx(day),
        operation_id=changes.pop("operation_id", uuid4()),
        reason=changes.pop("reason", "Fixture state change"),
        **changes,
    )


def patch(session, case, work, day=5, **changes):
    values = {
        "action_kind": "patch",
        "target_asset_id": case["asset"],
        "installation_id": case["installation"],
        "expected_history_id": case["history"],
        "version": "fixture-2",
        "context": ctx(day),
        "operation_id": uuid4(),
        "evidence_ref": "fixture:patch-report",
        "actual_effort_minutes": 15,
    }
    values.update(changes)
    return apply_software_change(session, work.id, **values)


def verify(session, case, obs=None, *, index=0, day=8, **changes):
    values = {
        "opening_event_id": case["openings"][index],
        "operation_id": uuid4(),
        "method": "scan",
        "verdict": "absence_confirmed",
        "context": ctx(day),
        "verifier_ref": "fixture:verifier",
        "rationale": "Explicit synthetic assessment result",
        "observation_id": obs.id if obs else None,
    }
    values.update(changes)
    return verify_finding(session, case["findings"][index], **values)


def manual(
    session,
    case,
    *,
    index=0,
    verdict="mitigation_effective",
    day=6,
    evidence_day=5,
    **changes,
):
    values = {
        "method": "manual",
        "verdict": verdict,
        "evidence_at": at(evidence_day),
        "assessed_history_id": case["history"],
        "manual_evidence_kind": "control_validation",
        "evidence_ref": "fixture:independent-control-test",
        "valid_until": at(10) if verdict == "mitigation_effective" else None,
    }
    values.update(changes)
    return verify(session, case, index=index, day=day, **values)


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_task_creation_assignment_planning_and_retry(sessions, case):
    op = uuid4()
    params = {
        "task_key": "fixture:work",
        "title": "Patch fixtures",
        "owner_department_id": case["department"],
        "priority": 2,
        "goal": "eliminate",
        "due_at": at(20),
        "context": ctx(3),
        "operation_id": op,
    }
    with sessions.begin() as session:
        work = create_task(session, **params)
        assert create_task(session, **params).id == work.id
        event = update_task(
            session,
            work.id,
            changes={"assignee_ref": "fixture:engineer"},
            context=ctx(4),
            operation_id=uuid4(),
            reason="Assign work",
        )
        assert (
            event.event_type == "assigned" and event.assignee_ref == "fixture:engineer"
        )
        update_task(
            session,
            work.id,
            changes={"priority": 1, "due_at": at(12)},
            context=ctx(5),
            operation_id=uuid4(),
            reason="Expedite",
        )
        assert work.priority == 1 and work.due_at == at(12)
        assert (
            count(session, RemediationTask) == 1
            and count(session, RemediationEvent) == 3
        )
    with pytest.raises(IdempotencyConflictError), sessions.begin() as session:
        create_task(session, **{**params, "title": "Conflicting retry"})
    with pytest.raises(ConflictError), sessions.begin() as session:
        create_task(session, **{**params, "operation_id": uuid4()})


def test_target_occurrence_links_retries_and_withdrawal(sessions, case):
    with sessions.begin() as session:
        work, links = task(session, case, targets=(0, 1))
        op = uuid4()
        old = withdraw_task_finding(
            session,
            work.id,
            task_finding_id=links[1].id,
            reason="Split work",
            context=ctx(4),
            operation_id=op,
        )
        retry = withdraw_task_finding(
            session,
            work.id,
            task_finding_id=links[1].id,
            reason="Split work",
            context=ctx(4),
            operation_id=op,
        )
        assert old.id == retry.id and old.withdrawn_recorded_at > old.withdrawn_at
        assert count(session, TaskFinding) == 2
    with pytest.raises(ConflictError), sessions.begin() as session:
        add_task_finding(
            session,
            work.id,
            finding_id=case["findings"][0],
            opening_event_id=case["openings"][0],
            context=ctx(5),
            operation_id=uuid4(),
        )
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        withdraw_task_finding(
            session,
            work.id,
            task_finding_id=links[0].id,
            reason=" ",
            context=ctx(5),
            operation_id=uuid4(),
        )
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        add_task_finding(
            session,
            work.id,
            finding_id=case["findings"][0],
            opening_event_id=case["openings"][1],
            context=ctx(5),
            operation_id=uuid4(),
        )


def test_valid_transitions_block_completion_reopening_and_cancellation(sessions, case):
    with sessions.begin() as session:
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
        transition(session, work.id, "blocked", 5)
        transition(session, work.id, "in_progress", 6)
        transition(session, work.id, "completed", 7)
        assert work.started_at == at(4) and work.work_completed_at == at(7)
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
        transition(session, work.id, "in_progress", 8)
        assert work.work_completed_at is None
        transition(session, work.id, "cancelled", 9)
        transition(session, work.id, "open", 10)
        assert work.closed_at is None
        assert session.scalar(
            select(RemediationEvent).where(RemediationEvent.event_type == "reopened")
        )


@pytest.mark.parametrize("status", ["completed", "closed", "blocked", "open"])
def test_invalid_open_task_transitions(sessions, case, status):
    with sessions.begin() as session:
        work, _ = task(session, case)
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        transition(session, work.id, status, 4)


def test_empty_task_cannot_start_or_close(sessions, case):
    with sessions.begin() as session:
        work, _ = task(session, case, targets=())
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        transition(session, work.id, "in_progress", 4)
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        transition(session, work.id, "closed", 4)


def test_successful_patch_is_atomic_idempotent_and_not_resolution(sessions, case):
    op = uuid4()
    with sessions.begin() as session:
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
        action = patch(session, case, work, operation_id=op)
        retry = patch(session, case, work, operation_id=op)
        assert action.id == retry.id and action.before_history_id == case["history"]
        assert action.after_history_id != action.before_history_id
        assert (
            session.get(InstallationHistory, action.after_history_id).version
            == "fixture-2"
        )
        assert count(session, InstallationHistory) == 2
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
    with pytest.raises(IdempotencyConflictError), sessions.begin() as session:
        patch(
            session,
            case,
            session.get(RemediationTask, work.id),
            operation_id=op,
            version="different",
        )


def test_failed_patch_and_configuration_outcomes_are_preserved(sessions, case):
    with sessions.begin() as session:
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
        op = uuid4()
        params = {
            "action_kind": "patch",
            "action_outcome": "failed",
            "target_asset_id": case["asset"],
            "installation_id": case["installation"],
            "before_history_id": case["history"],
            "evidence_ref": "fixture:failure-log",
            "context": ctx(5),
            "operation_id": op,
        }
        event = record_action(session, work.id, **params)
        assert record_action(session, work.id, **params).id == event.id
        record_action(
            session,
            work.id,
            **{
                **params,
                "action_kind": "configuration",
                "action_outcome": "inconclusive",
                "operation_id": uuid4(),
                "context": ctx(6),
            },
        )
        assert count(session, InstallationHistory) == 1
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"


def test_full_workflow_completed_is_distinct_from_verified_closure(sessions, case):
    with sessions.begin() as session:
        work, links = task(session, case)
        transition(session, work.id, "in_progress", 4)
        action = patch(session, case, work)
        transition(session, work.id, "completed", 6)
        assert work.status == "completed" and work.closed_at is None
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        transition(session, work.id, "closed", 6.5)
    with sessions.begin() as session:
        negative = assess(
            session, case, 7, outcome="not_affected", history=action.after_history_id
        )
        result = verify(
            session,
            case,
            negative,
            task_finding_id=links[0].id,
            action_event_id=action.id,
        )
        finding = session.get(VulnerabilityFinding, case["findings"][0])
        event = session.scalar(
            select(FindingEvent).where(FindingEvent.operation_id == result.operation_id)
        )
        assert finding.status == "resolved" and finding.resolved_at == at(7)
        assert result.verified_at == at(8) and result.recorded_at > result.verified_at
        assert (
            event.event_type == "resolved" and event.occurred_at == result.evidence_at
        )
        transition(session, work.id, "closed", 9)
        persisted = session.get(RemediationTask, work.id)
        assert persisted.status == "closed" and persisted.closed_at == at(9)
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        withdraw_task_finding(
            session,
            work.id,
            task_finding_id=links[0].id,
            context=ctx(10),
            operation_id=uuid4(),
            reason="Silent scope change",
        )


def test_verification_retry_and_conflicting_operation(sessions, case):
    op = uuid4()
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
        first = verify(session, case, negative, day=4, operation_id=op)
        assert verify(session, case, negative, day=4, operation_id=op).id == first.id
        assert count(session, VerificationResult) == 1
        assert count(session, FindingEvent) == 3  # two openings and one resolution
    with pytest.raises(IdempotencyConflictError), sessions.begin() as session:
        verify(
            session,
            case,
            negative,
            day=4,
            operation_id=op,
            rationale="Different content",
        )


@pytest.mark.parametrize("status", ["partial", "failed", "cancelled"])
def test_unsuccessful_scans_cannot_prove_absence(sessions, case, status):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected", status=status)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, negative, day=4)


def test_positive_and_inconclusive_verification_preserve_open_findings(sessions, case):
    with sessions.begin() as session:
        positive = assess(session, case, 3)
        result = verify(session, case, positive, day=4, verdict="still_affected")
        assert not result.accepted
        neutral = assess(session, case, 5, outcome="inconclusive")
        result = verify(session, case, neutral, day=6, verdict="inconclusive")
        assert not result.accepted and result.verdict == "inconclusive"
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, positive, day=7)


def test_newer_positive_blocks_stale_absence(sessions, case):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
        assess(session, case, 4)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, negative, day=5)


def test_inventory_change_invalidates_earlier_absence(sessions, case):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
        change_software_version(
            session,
            case["installation"],
            version="fixture-2",
            change_kind="upgrade",
            expected_history_id=case["history"],
            context=ctx(4),
        )
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, negative, day=5)


def test_incorrect_cve_and_asset_evidence_rejected(sessions, case):
    with sessions.begin() as session:
        wrong_cve = assess(
            session, case, 3, cve="CVE-2099-99999", outcome="not_affected"
        )
        other = register_asset(
            session,
            asset_key="fixture:other",
            hostname="other",
            department_id=case["department"],
            asset_type="server",
            environment="test",
            business_criticality=3,
            exposure="internal",
            context=ctx(0),
        )
        other_period = install_software(
            session,
            asset_id=other.id,
            product_id=case["product"],
            installation_key="other",
            version="fixture-1",
            context=ctx(1),
        )
        other_case = {
            **case,
            "asset": other.id,
            "installation": other_period.installation_id,
            "history": other_period.id,
        }
        wrong_asset = assess(session, other_case, 3, outcome="not_affected")
    for obs in (wrong_cve, wrong_asset):
        with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
            verify(session, case, obs, day=4)


def test_target_absent_requires_inventory_coverage_and_actual_absence(sessions, case):
    with sessions.begin() as session:
        remove_software(
            session,
            case["installation"],
            expected_history_id=case["history"],
            context=ctx(3),
        )
        without_coverage = assess(session, case, 4, outcome="target_absent")
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, without_coverage, day=5)
    with sessions.begin() as session:
        covered = assess(
            session,
            case,
            5,
            outcome="target_absent",
            scope={
                "inventory_coverage": {
                    "complete": True,
                    "installation_ids": [str(case["installation"])],
                }
            },
        )
        result = verify(session, case, covered, day=6)
        assert result.accepted and result.verdict == "absence_confirmed"


def test_obsolete_occurrence_cannot_be_verified_or_close_old_task(sessions, case):
    with sessions.begin() as session:
        work, links = task(session, case)
        transition(session, work.id, "in_progress", 4)
        transition(session, work.id, "completed", 5)
        negative = assess(session, case, 6, outcome="not_affected")
        verify(session, case, negative, day=7)
        assess(session, case, 8)
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        verify(session, case, negative, day=9, task_finding_id=links[0].id)
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        transition(session, work.id, "closed", 9)


def test_multi_target_elimination_closes_only_after_every_occurrence_resolves(
    sessions, case
):
    with sessions.begin() as session:
        work, links = task(session, case, targets=(0, 1))
        transition(session, work.id, "in_progress", 4)
        transition(session, work.id, "completed", 5)
        negative = assess(session, case, 6, outcome="not_affected")
        verify(session, case, negative, day=7, task_finding_id=links[0].id)
        assert session.get(VulnerabilityFinding, case["findings"][1]).status == "open"
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        transition(session, work.id, "closed", 8)
    with sessions.begin() as session:
        second = assess(session, case, 8, outcome="not_affected", cve=CVES[1])
        verify(session, case, second, index=1, day=9, task_finding_id=links[1].id)
        transition(session, work.id, "closed", 10)
        assert work.id == session.get(RemediationTask, work.id).id


def test_mitigation_keeps_finding_open_and_can_close_mitigate_task(sessions, case):
    with sessions.begin() as session:
        work, links = task(session, case, goal="mitigate", targets=(0, 1))
        transition(session, work.id, "in_progress", 4)
        first = manual(session, case, task_finding_id=links[0].id)
        assert (
            first.accepted
            and session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
        )
        manual(
            session,
            case,
            index=1,
            verdict="absence_confirmed",
            day=6,
            task_finding_id=links[1].id,
            manual_evidence_kind="independent_assessment",
        )
        transition(session, work.id, "completed", 7)
        transition(session, work.id, "closed", 8)
        assert work.status == "closed"


@pytest.mark.parametrize("goal,close_day", [("eliminate", 8), ("mitigate", 10)])
def test_mitigation_cannot_eliminate_or_outlive_expiry(sessions, case, goal, close_day):
    with sessions.begin() as session:
        work, _ = task(session, case, goal=goal)
        transition(session, work.id, "in_progress", 4)
        manual(session, case)
        transition(session, work.id, "completed", 7)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        transition(session, work.id, "closed", close_day)


def test_failed_mitigation_invalidates_success_for_closure(sessions, case):
    with sessions.begin() as session:
        work, _ = task(session, case, goal="mitigate")
        transition(session, work.id, "in_progress", 4)
        manual(session, case)
        failure = manual(
            session, case, verdict="mitigation_failed", day=7, evidence_day=6
        )
        assert not failure.accepted
        transition(session, work.id, "completed", 8)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        transition(session, work.id, "closed", 9)


@pytest.mark.parametrize(
    "changes",
    [
        {"evidence_ref": None},
        {"verifier_ref": " "},
        {"rationale": " "},
        {"manual_evidence_kind": "patch_report"},
        {"evidence_at": at(7)},
        {"valid_until": at(6)},
        {"assessed_history_id": None},
        {"assessed_history_id": uuid4()},
    ],
)
def test_manual_verification_requires_independent_evidence_and_valid_times(
    sessions, case, changes
):
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        manual(session, case, **changes)


def test_verification_resolution_and_task_patch_rollback(sessions, case, monkeypatch):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
    original = verification._resolve

    def fail_after_resolution(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("failure after resolution flush")

    monkeypatch.setattr(verification, "_resolve", fail_after_resolution)
    with pytest.raises(RuntimeError), sessions.begin() as session:
        verify(session, case, negative, day=4)
    with sessions.begin() as session:
        assert count(session, VerificationResult) == 0
        assert count(session, FindingEvent) == 2
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
    with pytest.raises(RuntimeError), sessions.begin() as session:
        patch(session, case, session.get(RemediationTask, work.id))
        raise RuntimeError("caller rolls back inventory and patch event")
    with sessions.begin() as session:
        assert count(session, InstallationHistory) == 1
        assert count(session, RemediationEvent) == 3


def test_database_constraints_and_history_guards(sessions, case):
    with sessions.begin() as session:
        work, links = task(session, case)
        first_event = session.scalar(
            select(RemediationEvent).where(RemediationEvent.event_type == "created")
        )
        raw_event = {
            c.name: getattr(first_event, c.name)
            for c in RemediationEvent.__table__.columns
        }
    for changes in (
        {"priority": 0},
        {"goal": "ignore"},
        {"status": "closed"},
        {"estimated_effort_minutes": -1},
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                update(RemediationTask)
                .where(RemediationTask.id == work.id)
                .values(**changes)
            )
    for changes in (
        {"event_number": 0},
        {"payload_digest": "bad"},
        {"action_kind": "patch"},
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                insert(RemediationEvent).values(
                    **{
                        **raw_event,
                        "id": uuid4(),
                        "event_number": 9,
                        "operation_id": uuid4(),
                        **changes,
                    }
                )
            )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            TaskFinding(
                task_id=work.id,
                finding_id=case["findings"][0],
                opening_event_id=case["openings"][1],
                added_at=at(3),
                added_by_ref="fixture:actor",
            )
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            update(TaskFinding)
            .where(TaskFinding.id == links[0].id)
            .values(withdrawn_at=at(4))
        )
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.get(RemediationEvent, first_event.id).reason = "Rewrite"
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.delete(session.get(TaskFinding, links[0].id))


def test_concurrent_positive_blocks_stale_verification(sessions, case, postgres_engine):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
    backends = Queue()

    def competing_verification():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backends.put(session.scalar(text("SELECT pg_backend_pid()")))
            with pytest.raises(InvalidEvidenceError):
                verify(session, case, negative, day=5)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            assess(session, case, 4)
            future = executor.submit(competing_verification)
            backend = backends.get(timeout=3)
            deadline = monotonic() + 3
            with postgres_engine.connect() as connection:
                while not connection.scalar(
                    text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                    {"pid": backend},
                ):
                    assert monotonic() < deadline, (
                        "Verification did not wait for finding lock"
                    )
                    sleep(0.01)
        future.result(timeout=5)
    with sessions.begin() as session:
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
        assert count(session, VerificationResult) == 0


def test_0004_roundtrip_preserves_first_eleven_tables_and_data(postgres_engine):
    migrate(postgres_engine, command.upgrade, "0003")
    sessions = make_session_factory(postgres_engine)
    with sessions.begin() as session:
        department = create_department(session, code="KEEP", name="Preserved")
        preserved_id = department.id
    migrate(postgres_engine, command.upgrade, "0004")
    migrate(postgres_engine, command.check)
    with sessions.begin() as session:
        create_task(
            session,
            task_key="fixture:downgrade",
            title="Disposable work",
            owner_department_id=preserved_id,
            priority=3,
            goal="eliminate",
            due_at=at(20),
            context=ctx(3),
            operation_id=uuid4(),
        )
    with postgres_engine.connect() as connection:
        assert len(inspect(connection).get_table_names(schema="operational")) == 15
        assert NEW_TABLES <= set(
            inspect(connection).get_table_names(schema="operational")
        )
    migrate(postgres_engine, command.downgrade, "0003")
    with postgres_engine.connect() as connection:
        assert len(inspect(connection).get_table_names(schema="operational")) == 11
        assert (
            connection.scalar(
                text("SELECT id FROM operational.departments WHERE code = 'KEEP'")
            )
            == preserved_id
        )
    migrate(postgres_engine, command.upgrade, "0004")
    migrate(postgres_engine, command.check)


@pytest.mark.parametrize("action_kind", ["upgrade", "downgrade", "removal"])
def test_inventory_action_kinds_preserve_history(sessions, case, action_kind):
    with sessions.begin() as session:
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
        event = patch(
            session,
            case,
            work,
            action_kind=action_kind,
            version=None if action_kind == "removal" else "fixture-2",
        )
        previous = session.get(InstallationHistory, event.before_history_id)
        assert previous.end_reason == action_kind and previous.ended_at == at(5)
        if action_kind == "removal":
            assert event.after_history_id is None
        else:
            assert session.get(
                InstallationHistory, event.after_history_id
            ).started_at == at(5)


def test_reopened_closed_task_can_address_a_new_occurrence(sessions, case):
    with sessions.begin() as session:
        work, old_links = task(session, case)
        transition(session, work.id, "in_progress", 4)
        transition(session, work.id, "completed", 5)
        obs = assess(session, case, 6, outcome="not_affected")
        verify(session, case, obs, day=7)
        transition(session, work.id, "closed", 8)
        assess(session, case, 9)
        transition(session, work.id, "open", 10)
        withdraw_task_finding(
            session,
            work.id,
            task_finding_id=old_links[0].id,
            reason="Old occurrence",
            context=ctx(10),
            operation_id=uuid4(),
        )
        finding = session.get(VulnerabilityFinding, case["findings"][0])
        link = add_task_finding(
            session,
            work.id,
            finding_id=finding.id,
            opening_event_id=current_opening(session, finding).id,
            context=ctx(10),
            operation_id=uuid4(),
        )
        transition(session, work.id, "in_progress", 11)
        assert (
            link.id != old_links[0].id
            and link.opening_event_id != old_links[0].opening_event_id
        )
        assert work.status == "in_progress" and count(session, TaskFinding) == 2


def test_removing_every_target_blocks_successful_closure(sessions, case):
    with sessions.begin() as session:
        work, links = task(session, case)
        transition(session, work.id, "in_progress", 4)
        transition(session, work.id, "completed", 5)
        withdraw_task_finding(
            session,
            work.id,
            task_finding_id=links[0].id,
            context=ctx(6),
            operation_id=uuid4(),
            reason="Split work",
        )
    with pytest.raises(InvalidOperationError), sessions.begin() as session:
        transition(session, work.id, "closed", 7)


def test_task_times_and_unsupported_edits_are_rejected(sessions, case):
    with sessions.begin() as session:
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        transition(session, work.id, "blocked", 3)
    for changes in (
        {"priority": 6},
        {"goal": "mitigate"},
        {"due_at": at(1)},
        {"estimated_effort_minutes": -1},
    ):
        with pytest.raises(InvalidOperationError), sessions.begin() as session:
            update_task(
                session,
                work.id,
                changes=changes,
                context=ctx(5),
                operation_id=uuid4(),
                reason="Bad input",
            )


def test_verification_requires_evidence_after_specific_action(sessions, case):
    with sessions.begin() as session:
        work, _ = task(session, case)
        transition(session, work.id, "in_progress", 4)
        negative = assess(session, case, 5, outcome="not_affected")
        action = record_action(
            session,
            work.id,
            action_kind="configuration",
            action_outcome="succeeded",
            target_asset_id=case["asset"],
            installation_id=case["installation"],
            context=ctx(6),
            operation_id=uuid4(),
            evidence_ref="fixture:config",
        )
    with pytest.raises(HistoricalConflictError), sessions.begin() as session:
        verify(session, case, negative, action_event_id=action.id, day=7)
    # Omitting the action reference must not permit accepting the older evidence.
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, negative, day=7)


def test_scan_based_control_verification_does_not_claim_elimination(sessions, case):
    with sessions.begin() as session:
        control = assess(
            session,
            case,
            5,
            outcome="affected",
            evidence={"fixture": True, "control_verdict": "effective"},
        )
        result = verify(
            session,
            case,
            control,
            verdict="mitigation_effective",
            valid_until=at(10),
            day=6,
        )
        assert result.accepted and result.method == "scan"
        assert session.get(VulnerabilityFinding, case["findings"][0]).status == "open"
        assert count(session, FindingEvent) == 2


def test_manual_positive_blocks_older_absence(sessions, case):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
        manual(session, case, verdict="still_affected", day=5, evidence_day=4)
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, negative, day=6)


def test_manual_verification_protects_historical_inventory_from_backdating(
    sessions, case
):
    with sessions.begin() as session:
        manual(session, case, day=6, evidence_day=5)
    for day in (4, 5):
        with pytest.raises(HistoricalConflictError), sessions.begin() as session:
            remove_software(
                session,
                case["installation"],
                expected_history_id=case["history"],
                context=ctx(day),
            )


def test_verification_results_immutable_and_database_occurrence_constraints(
    sessions, case
):
    with sessions.begin() as session:
        work, links = task(session, case)
        obs = assess(session, case, 4, outcome="not_affected")
        result = verify(session, case, obs, day=5, task_finding_id=links[0].id)
        raw = {
            c.name: getattr(result, c.name)
            for c in VerificationResult.__table__.columns
        }
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.get(VerificationResult, result.id).rationale = "Rewrite"
    with pytest.raises(ImmutableRecordError), sessions.begin() as session:
        session.delete(session.get(VerificationResult, result.id))
    for changes in (
        {"accepted": False},
        {"verified_at": at(3)},
        {"verifier_ref": " "},
        {"opening_event_id": case["openings"][0]},
        {"payload_digest": "bad"},
        {"method": "manual"},
        {"evidence_ref": None, "evidence": None},
        {"valid_until": at(9)},
    ):
        with pytest.raises(IntegrityError), sessions.begin() as session:
            session.execute(
                insert(VerificationResult).values(
                    **{
                        **raw,
                        "id": uuid4(),
                        "operation_id": uuid4(),
                        "finding_id": case["findings"][1],
                        "opening_event_id": case["openings"][1],
                        "task_finding_id": None,
                        **changes,
                    }
                )
            )
    # The accepted-absence partial index forbids another decision for this occurrence.
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            insert(VerificationResult).values(
                **{**raw, "id": uuid4(), "operation_id": uuid4()}
            )
        )
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.execute(
            RemediationTask.__table__.delete().where(RemediationTask.id == work.id)
        )


def wait_for_lock(engine, backend):
    deadline = monotonic() + 3
    with engine.connect() as connection:
        while not connection.scalar(
            text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"), {"pid": backend}
        ):
            assert monotonic() < deadline, (
                "Competing transaction did not wait for a row lock"
            )
            sleep(0.01)


@pytest.mark.parametrize(
    "positive_day,expected_status", [(2.5, "resolved"), (5, "open")]
)
def test_concurrent_resolution_then_positive_uses_occurrence_time(
    sessions, case, postgres_engine, positive_day, expected_status
):
    with sessions.begin() as session:
        negative = assess(session, case, 3, outcome="not_affected")
    backends = Queue()

    def positive_detection():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backends.put(session.scalar(text("SELECT pg_backend_pid()")))
            assess(session, case, positive_day)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            verify(session, case, negative, day=4)
            future = executor.submit(positive_detection)
            wait_for_lock(postgres_engine, backends.get(timeout=3))
        future.result(timeout=5)
    with sessions.begin() as session:
        finding = session.get(VulnerabilityFinding, case["findings"][0])
        assert finding.status == expected_status
        assert count(session, VerificationResult) == 1
        assert count(session, FindingEvent) == (4 if expected_status == "open" else 3)


def test_concurrent_task_changes_preserve_event_order(sessions, case, postgres_engine):
    with sessions.begin() as session:
        work, _ = task(session, case)
    backends = Queue()

    def competing_change():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backends.put(session.scalar(text("SELECT pg_backend_pid()")))
            update_task(
                session,
                work.id,
                changes={"assignee_ref": "fixture:second"},
                context=ctx(5),
                operation_id=uuid4(),
                reason="Assign",
            )

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            update_task(
                session,
                work.id,
                changes={"priority": 1},
                context=ctx(4),
                operation_id=uuid4(),
                reason="Prioritize",
            )
            future = executor.submit(competing_change)
            wait_for_lock(postgres_engine, backends.get(timeout=3))
        future.result(timeout=5)
    with sessions.begin() as session:
        events = list(
            session.scalars(
                select(RemediationEvent)
                .where(RemediationEvent.task_id == work.id)
                .order_by(RemediationEvent.event_number)
            )
        )
        assert [e.event_number for e in events] == [1, 2, 3, 4]
        assert events[-1].priority == 1 and events[-1].assignee_ref == "fixture:second"


def test_task_closure_serializes_scope_change(sessions, case, postgres_engine):
    with sessions.begin() as session:
        work, links = task(session, case)
        transition(session, work.id, "in_progress", 4)
        transition(session, work.id, "completed", 5)
        negative = assess(session, case, 6, outcome="not_affected")
        verify(session, case, negative, day=7)
    backends = Queue()

    def withdraw_after_close():
        with sessions.begin() as session:
            session.execute(text("SET LOCAL lock_timeout = '5s'"))
            backends.put(session.scalar(text("SELECT pg_backend_pid()")))
            with pytest.raises(InvalidOperationError):
                withdraw_task_finding(
                    session,
                    work.id,
                    task_finding_id=links[0].id,
                    context=ctx(9),
                    operation_id=uuid4(),
                    reason="Competing change",
                )

    with ThreadPoolExecutor(max_workers=1) as executor:
        with sessions.begin() as session:
            transition(session, work.id, "closed", 8)
            future = executor.submit(withdraw_after_close)
            wait_for_lock(postgres_engine, backends.get(timeout=3))
        future.result(timeout=5)
    with sessions.begin() as session:
        assert session.get(RemediationTask, work.id).status == "closed"
        assert session.get(TaskFinding, links[0].id).withdrawn_at is None


def test_runnable_fixture_example_and_replay(sessions, case):
    from runpy import run_path

    example = run_path(
        str(Path(__file__).resolve().parents[2] / "examples/remediation_workflow.py")
    )
    with sessions.begin() as session:
        params = {
            "finding_id": case["findings"][0],
            "history_id": case["history"],
            "first_at": at(3),
            "namespace": "integration",
            "patched_version": "fixture-2",
        }
        result = example["run_fixture_workflow"](session, **params)
        replay = example["run_fixture_workflow"](session, **params)
        assert result == replay
        assert session.get(RemediationTask, result["task_id"]).status == "closed"
        assert (
            session.get(VulnerabilityFinding, result["finding_id"]).status == "resolved"
        )
        assert (
            count(session, VerificationResult) == 1
            and count(session, InstallationHistory) == 2
        )


def test_verified_target_absence_cannot_be_invalidated_by_backdated_reinstallation(
    sessions, case
):
    with sessions.begin() as session:
        remove_software(
            session,
            case["installation"],
            expected_history_id=case["history"],
            context=ctx(3),
        )
        manual(
            session,
            case,
            verdict="absence_confirmed",
            day=6,
            evidence_day=5,
            manual_evidence_kind="inventory_review",
            assessed_history_id=None,
        )
    for day in (4, 5):
        with pytest.raises(HistoricalConflictError), sessions.begin() as session:
            install_software(
                session,
                asset_id=case["asset"],
                product_id=case["product"],
                installation_key="fixture:package",
                version="fixture-reinstalled",
                context=ctx(day),
            )
    with sessions.begin() as session:
        install_software(
            session,
            asset_id=case["asset"],
            product_id=case["product"],
            installation_key="fixture:package",
            version="fixture-reinstalled",
            context=ctx(7),
        )


def test_asset_scoped_finding_accepts_explicit_scoped_absence(sessions, case):
    with sessions.begin() as session:
        asset_case = {**case, "installation": None, "history": None}
        first = assess(session, asset_case, 2, cve="CVE-2099-90003")
        finding = session.get(VulnerabilityFinding, first.finding_id)
        target = {
            **asset_case,
            "findings": [finding.id],
            "openings": [current_opening(session, finding).id],
        }
        negative = assess(
            session, target, 3, cve="CVE-2099-90003", outcome="not_affected"
        )
        result = verify(session, target, negative, day=4)
        assert (
            result.accepted
            and finding.status == "resolved"
            and result.assessed_history_id is None
        )


def test_malformed_target_absence_coverage_is_not_accepted(sessions, case):
    with sessions.begin() as session:
        remove_software(
            session,
            case["installation"],
            expected_history_id=case["history"],
            context=ctx(3),
        )
        obs = assess(
            session,
            case,
            4,
            outcome="target_absent",
            scope={
                "inventory_coverage": {
                    "complete": True,
                    "installation_ids": str(case["installation"]),
                }
            },
        )
    with pytest.raises(InvalidEvidenceError), sessions.begin() as session:
        verify(session, case, obs, day=5)
