"""Bounded business workflows using the operational remediation/verification services."""

from datetime import timedelta

from sqlalchemy import select

from patchledger.operational.models import (
    Asset,
    FindingEvent,
    RemediationEvent,
    RemediationTask,
    TaskFinding,
)
from patchledger.operational.services.remediation import (
    add_task_finding,
    create_task,
    transition_task,
)
from patchledger.operational.services.remediation_actions import (
    apply_software_change,
    record_action,
)
from patchledger.operational.services.software import get_version_at
from patchledger.operational.services.verification import verify_finding
from patchledger.simulation.errors import ScenarioConflictError
from patchledger.simulation.inventory import context, get_installation
from patchledger.simulation.random_state import operation_id
from patchledger.simulation.scenarios import findings_at, observation_for, scan_asset


def opening_at(session, finding, when):
    opening = session.scalar(
        select(FindingEvent)
        .where(
            FindingEvent.finding_id == finding.id,
            FindingEvent.event_type.in_(("opened", "reopened")),
            FindingEvent.occurred_at <= when,
        )
        .order_by(FindingEvent.event_number.desc())
        .limit(1)
    )
    if opening is None:
        raise ScenarioConflictError(
            "Finding has no historical opening at the planned operation time"
        )
    return opening


def task_key(config, plan, cycle="primary"):
    return f"{config.prefix}task:{plan.index}:{cycle}"


def create_work(session, config, plan, event):
    findings = findings_at(session, config, plan, event.at)
    if not findings:
        raise ScenarioConflictError(
            "Baseline fixture scan did not establish planned findings"
        )
    cycle = "recurrence" if event.kind == "recurrence_task" else "primary"
    openings = [opening_at(session, finding, event.at) for finding in findings]
    work = create_task(
        session,
        task_key=task_key(config, plan, cycle),
        title=f"Synthetic {cycle} patch for {plan.hostname}",
        description="Controlled fixture applicability only; no validated NVD matching",
        owner_department_id=session.get(Asset, findings[0].asset_id).department_id,
        assignee_ref=f"simulator:{config.scenario}:engineer-{plan.index % 12}",
        priority=6 - plan.criticality,
        goal="eliminate",
        due_at=min(o.occurred_at for o in openings) + timedelta(days=config.sla_days),
        estimated_effort_minutes=30 + 10 * len(findings),
        context=context(config, event.at),
        operation_id=operation_id(config, f"{event.key}:create"),
    )
    for finding, opening in zip(findings, openings, strict=True):
        add_task_finding(
            session,
            work.id,
            finding_id=finding.id,
            opening_event_id=opening.id,
            context=context(config, event.at),
            operation_id=operation_id(config, f"{event.key}:link:{finding.cve_id}"),
        )
    if cycle == "primary":
        transition_task(
            session,
            work.id,
            status="in_progress",
            context=context(config, event.at + timedelta(seconds=1)),
            operation_id=operation_id(config, f"{event.key}:start"),
            reason="Synthetic scheduled work begins",
        )


def attempt_work(session, config, plan, event):
    work = session.scalar(
        select(RemediationTask).where(
            RemediationTask.task_key == task_key(config, plan)
        )
    )
    attempt, result = event.detail.split(":")
    if int(attempt) > 0:
        transition_task(
            session,
            work.id,
            status="in_progress",
            context=context(config, event.at),
            operation_id=operation_id(config, f"{event.key}:retry"),
            reason="Synthetic retry after failed verification/attempt",
        )
    installation = get_installation(session, plan, 0)
    before = get_version_at(
        session, installation.id, at=event.at - timedelta(microseconds=1)
    )
    if before is None:
        raise ScenarioConflictError("Patch attempt has no historical before-version")
    kwargs = {
        "target_asset_id": installation.asset_id,
        "installation_id": installation.id,
        "context": context(config, event.at),
        "operation_id": operation_id(config, f"{event.key}:action"),
        "evidence_ref": f"synthetic:{config.scenario}:{event.key}",
        "actual_effort_minutes": 15 + 5 * int(attempt),
    }
    if result == "failed":
        record_action(
            session,
            work.id,
            action_kind="patch",
            action_outcome="failed",
            before_history_id=before.id,
            evidence={"fixture": "catalog-v1", "attempt": "expected synthetic failure"},
            **kwargs,
        )
    else:
        version = (
            "2.0-fixture" if result == "effective" else f"1.{int(attempt) + 1}-fixture"
        )
        apply_software_change(
            session,
            work.id,
            action_kind="patch",
            expected_history_id=before.id,
            version=version,
            evidence={
                "fixture": "catalog-v1",
                "applicability": "synthetic-fixture-only",
            },
            **kwargs,
        )
    transition_task(
        session,
        work.id,
        status="blocked" if result == "failed" else "completed",
        context=context(config, event.at + timedelta(seconds=1)),
        operation_id=operation_id(config, f"{event.key}:outcome"),
        reason="Synthetic patch outcome; successful work still needs independent assessment",
    )


def verify_work(session, config, plan, event):
    work = session.scalar(
        select(RemediationTask).where(
            RemediationTask.task_key == task_key(config, plan)
        )
    )
    attempt_key = event.key.replace(":verify:", ":attempt:")
    action = session.scalar(
        select(RemediationEvent).where(
            RemediationEvent.task_id == work.id,
            RemediationEvent.operation_id
            == operation_id(config, f"{attempt_key}:action"),
        )
    )
    if action is None:
        raise ScenarioConflictError(
            "Verification has no committed patch attempt receipt"
        )
    run = scan_asset(
        session, config, plan, event.at, f"{event.key}:assessment", definitive=True
    )
    installation = get_installation(session, plan, 0)
    links = list(
        session.scalars(
            select(TaskFinding)
            .where(TaskFinding.task_id == work.id)
            .order_by(TaskFinding.finding_id)
        )
    )
    from patchledger.operational.models import VulnerabilityFinding

    accepted = []
    for link in links:
        finding = session.get(VulnerabilityFinding, link.finding_id)
        observation = observation_for(session, run, installation, finding.cve_id)
        verdict = (
            "absence_confirmed"
            if observation.outcome in {"not_affected", "target_absent"}
            else (
                "still_affected"
                if observation.outcome == "affected"
                else "inconclusive"
            )
        )
        result = verify_finding(
            session,
            finding.id,
            opening_event_id=link.opening_event_id,
            operation_id=operation_id(config, f"{event.key}:decision:{finding.cve_id}"),
            method="scan",
            verdict=verdict,
            context=context(config, event.at + timedelta(seconds=30)),
            verifier_ref=f"simulator:{config.scenario}:verifier",
            rationale="Explicit controlled synthetic fixture assessment",
            observation_id=observation.id,
            task_finding_id=link.id,
            action_event_id=action.id,
        )
        accepted.append(result.accepted and result.verdict == "absence_confirmed")
    if accepted and all(accepted):
        transition_task(
            session,
            work.id,
            status="closed",
            context=context(config, event.at + timedelta(seconds=31)),
            operation_id=operation_id(config, f"{event.key}:close"),
            reason="All synthetic target occurrences have explicit verified absence",
        )
