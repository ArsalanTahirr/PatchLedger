"""Task state and typed event history; transactions belong to the caller."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from patchledger.operational.exceptions import (
    ConflictError,
    HistoricalConflictError,
    IdempotencyConflictError,
    InvalidOperationError,
    NotFoundError,
)
from patchledger.operational.models import (
    Asset,
    Department,
    FindingEvent,
    RemediationEvent,
    RemediationTask,
    TaskFinding,
    VulnerabilityFinding,
)
from patchledger.operational.models.remediation import GOALS
from patchledger.operational.services.common import (
    EventContext,
    effective_time,
    nonempty,
    payload_digest,
)

SNAPSHOT = (
    "title",
    "description",
    "owner_department_id",
    "assignee_ref",
    "priority",
    "goal",
    "due_at",
    "estimated_effort_minutes",
    "status",
    "started_at",
    "work_completed_at",
    "closed_at",
)
TRANSITIONS = {
    "open": {"in_progress", "cancelled"},
    "in_progress": {"blocked", "completed", "cancelled"},
    "blocked": {"in_progress", "cancelled"},
    "completed": {"in_progress", "closed", "cancelled"},
    "closed": {"open"},
    "cancelled": {"open"},
}


def request_digest(command, context, **values):
    return payload_digest(
        {
            "command": command,
            "occurred_at": context.occurred_at,
            "actor_ref": context.actor_ref,
            "source_key": context.source_key,
            "is_synthetic": context.is_synthetic,
            **values,
        }
    )


def lock_task(session, task_id):
    task = session.scalar(
        select(RemediationTask)
        .where(RemediationTask.id == task_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if task is None:
        raise NotFoundError("Remediation task does not exist")
    return task


def replay_event(session, task_id, operation_id, digest):
    if not isinstance(operation_id, UUID):
        raise InvalidOperationError("operation_id must be a stable UUID")
    old = session.scalar(
        select(RemediationEvent).where(
            RemediationEvent.task_id == task_id,
            RemediationEvent.operation_id == operation_id,
        )
    )
    if old is not None and old.payload_digest != digest:
        raise IdempotencyConflictError(
            "Task operation key was reused with different content"
        )
    return old


def latest_event(session, task_id):
    return session.scalar(
        select(RemediationEvent)
        .where(RemediationEvent.task_id == task_id)
        .order_by(RemediationEvent.event_number.desc())
        .limit(1)
    )


def check_time(session, task, context):
    latest = latest_event(session, task.id)
    if latest is not None and context.occurred_at < latest.occurred_at:
        raise HistoricalConflictError("Task changes cannot predate established history")
    return latest


def require_editable(task):
    if task.status in {"closed", "cancelled"}:
        raise InvalidOperationError(
            "Reopen the task before changing its scope or attributes"
        )


def append_event(
    session, task, context, operation_id, digest, event_type, *, reason=None, **details
):
    latest = check_time(session, task, context)
    event = RemediationEvent(
        task_id=task.id,
        event_number=latest.event_number + 1 if latest else 1,
        operation_id=operation_id,
        payload_digest=digest,
        event_type=event_type,
        occurred_at=context.occurred_at,
        actor_ref=context.actor_ref,
        source_key=context.source_key,
        is_synthetic=context.is_synthetic,
        reason=reason,
        **{key: getattr(task, key) for key in SNAPSHOT},
        **details,
    )
    session.add(event)
    session.flush()
    return event


def _department(session, department_id):
    department = session.scalar(
        select(Department)
        .where(Department.id == department_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if department is None:
        raise NotFoundError("Owner department does not exist")
    if department.retired_at is not None:
        raise InvalidOperationError(
            "A retired department cannot own new remediation work"
        )


def nonnegative_minutes(value, name):
    if value is not None and (type(value) is not int or not 0 <= value <= 2147483647):
        raise InvalidOperationError(f"{name} must be nonnegative integer minutes")
    return value


def _priority(value):
    if type(value) is not int or not 1 <= value <= 5:
        raise InvalidOperationError("priority must be an integer from 1 to 5")
    return value


def create_task(
    session: Session,
    *,
    task_key: str,
    title: str,
    owner_department_id: UUID,
    priority: int,
    goal: str,
    due_at: datetime,
    context: EventContext,
    operation_id: UUID,
    description: str | None = None,
    assignee_ref: str | None = None,
    estimated_effort_minutes: int | None = None,
) -> RemediationTask:
    if goal not in GOALS:
        raise InvalidOperationError("Task goal must be eliminate or mitigate")
    values = {
        "task_key": nonempty(task_key, "task_key"),
        "title": nonempty(title, "title"),
        "owner_department_id": owner_department_id,
        "priority": _priority(priority),
        "goal": goal,
        "due_at": effective_time(due_at),
        "description": description,
        "assignee_ref": nonempty(assignee_ref, "assignee_ref")
        if assignee_ref is not None
        else None,
        "estimated_effort_minutes": nonnegative_minutes(
            estimated_effort_minutes, "estimated effort"
        ),
    }
    if values["due_at"] < context.occurred_at:
        raise HistoricalConflictError(
            "A new planning deadline cannot precede task creation"
        )
    if not isinstance(operation_id, UUID):
        raise InvalidOperationError("operation_id must be a stable UUID")
    digest = request_digest("create_task", context, **values)
    existing = session.scalar(
        select(RemediationTask).where(RemediationTask.task_key == values["task_key"])
    )
    if existing is not None:
        existing = lock_task(session, existing.id)
        if replay_event(session, existing.id, operation_id, digest) is None:
            raise ConflictError("Task business key already exists")
        return existing
    _department(session, owner_department_id)
    task = session.scalar(
        insert(RemediationTask)
        .values(**values, status="open")
        .on_conflict_do_nothing(index_elements=["task_key"])
        .returning(RemediationTask)
    )
    if task is None:
        task = session.scalar(
            select(RemediationTask).where(
                RemediationTask.task_key == values["task_key"]
            )
        )
        task = lock_task(session, task.id)
        if replay_event(session, task.id, operation_id, digest) is None:
            raise ConflictError("Task business key already exists")
        return task
    append_event(session, task, context, operation_id, digest, "created")
    return task


def update_task(
    session: Session,
    task_id: UUID,
    *,
    changes: dict,
    context: EventContext,
    operation_id: UUID,
    reason: str,
) -> RemediationEvent:
    allowed = {
        "title",
        "description",
        "owner_department_id",
        "assignee_ref",
        "priority",
        "due_at",
        "estimated_effort_minutes",
    }
    if not changes or set(changes) - allowed:
        raise InvalidOperationError(
            "Only task planning and assignment fields may change"
        )
    values = dict(changes)
    if "priority" in values:
        values["priority"] = _priority(values["priority"])
    if "title" in values:
        values["title"] = nonempty(values["title"], "title")
    if values.get("assignee_ref") is not None:
        values["assignee_ref"] = nonempty(values["assignee_ref"], "assignee_ref")
    if "due_at" in values:
        values["due_at"] = effective_time(values["due_at"])
        if values["due_at"] < context.occurred_at:
            raise HistoricalConflictError(
                "A new deadline cannot predate the planning change"
            )
    if "estimated_effort_minutes" in values:
        values["estimated_effort_minutes"] = nonnegative_minutes(
            values["estimated_effort_minutes"], "estimated effort"
        )
    reason = nonempty(reason, "reason")
    digest = request_digest("update_task", context, changes=values, reason=reason)
    task = lock_task(session, task_id)
    old = replay_event(session, task.id, operation_id, digest)
    if old is not None:
        return old
    require_editable(task)
    check_time(session, task, context)
    if "owner_department_id" in values:
        _department(session, values["owner_department_id"])
    for key, value in values.items():
        setattr(task, key, value)
    kind = (
        "assigned"
        if set(values) <= {"owner_department_id", "assignee_ref"}
        else "planning_changed"
    )
    return append_event(
        session, task, context, operation_id, digest, kind, reason=reason
    )


def current_opening(session, finding):
    opening = session.scalar(
        select(FindingEvent)
        .where(
            FindingEvent.finding_id == finding.id,
            FindingEvent.event_type.in_(("opened", "reopened")),
        )
        .order_by(FindingEvent.event_number.desc())
        .limit(1)
    )
    if opening is None or opening.occurred_at != finding.current_opened_at:
        raise HistoricalConflictError("Finding opening history is inconsistent")
    return opening


def lock_finding(session, finding_id):
    finding = session.scalar(
        select(VulnerabilityFinding)
        .where(VulnerabilityFinding.id == finding_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if finding is None:
        raise NotFoundError("Finding does not exist")
    return finding


def active_targets(session, task_id):
    return list(
        session.scalars(
            select(TaskFinding)
            .where(TaskFinding.task_id == task_id, TaskFinding.withdrawn_at.is_(None))
            .order_by(TaskFinding.finding_id)
        )
    )


def lock_target_findings(session, links):
    ids = sorted({link.finding_id for link in links})
    findings = list(
        session.scalars(
            select(VulnerabilityFinding).where(VulnerabilityFinding.id.in_(ids))
        )
    )
    for asset_id in sorted({f.asset_id for f in findings}):
        session.scalar(
            select(Asset)
            .where(Asset.id == asset_id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        )
    return {identity: lock_finding(session, identity) for identity in ids}


def add_task_finding(
    session: Session,
    task_id: UUID,
    *,
    finding_id: UUID,
    opening_event_id: UUID,
    context: EventContext,
    operation_id: UUID,
) -> TaskFinding:
    digest = request_digest(
        "add_target", context, finding_id=finding_id, opening_event_id=opening_event_id
    )
    task = lock_task(session, task_id)
    old = replay_event(session, task.id, operation_id, digest)
    if old is not None:
        return session.get(TaskFinding, old.task_finding_id)
    require_editable(task)
    check_time(session, task, context)
    finding = lock_finding(session, finding_id)
    opening = current_opening(session, finding)
    if finding.status != "open" or opening.id != opening_event_id:
        raise InvalidOperationError(
            "Target must be the finding's currently open occurrence"
        )
    if context.occurred_at < opening.occurred_at:
        raise HistoricalConflictError("Task scope cannot predate finding occurrence")
    link = session.scalar(
        insert(TaskFinding)
        .values(
            task_id=task.id,
            finding_id=finding.id,
            opening_event_id=opening.id,
            added_at=context.occurred_at,
            added_by_ref=context.actor_ref,
        )
        .on_conflict_do_nothing(
            index_elements=["task_id", "finding_id", "opening_event_id"]
        )
        .returning(TaskFinding)
    )
    if link is None:
        raise ConflictError(
            "This finding occurrence is already linked, including any withdrawn historical link"
        )
    append_event(
        session,
        task,
        context,
        operation_id,
        digest,
        "target_added",
        task_finding_id=link.id,
    )
    return link


def withdraw_task_finding(
    session: Session,
    task_id: UUID,
    *,
    task_finding_id: UUID,
    reason: str,
    context: EventContext,
    operation_id: UUID,
) -> TaskFinding:
    reason = nonempty(reason, "reason")
    digest = request_digest(
        "withdraw_target", context, task_finding_id=task_finding_id, reason=reason
    )
    task = lock_task(session, task_id)
    old = replay_event(session, task.id, operation_id, digest)
    if old is not None:
        return session.get(TaskFinding, task_finding_id)
    require_editable(task)
    check_time(session, task, context)
    link = session.get(TaskFinding, task_finding_id)
    if link is None or link.task_id != task.id:
        raise NotFoundError("Task target does not exist")
    if link.withdrawn_at is not None:
        raise InvalidOperationError("Target has already been withdrawn")
    if context.occurred_at < link.added_at:
        raise HistoricalConflictError("Withdrawal precedes target addition")
    link.withdrawn_at, link.withdrawal_reason = context.occurred_at, reason
    link.withdrawn_by_ref, link.withdrawn_recorded_at = (
        context.actor_ref,
        func.clock_timestamp(),
    )
    append_event(
        session,
        task,
        context,
        operation_id,
        digest,
        "target_withdrawn",
        reason=reason,
        task_finding_id=link.id,
    )
    return link


def transition_task(
    session: Session,
    task_id: UUID,
    *,
    status: str,
    context: EventContext,
    operation_id: UUID,
    reason: str,
) -> RemediationEvent:
    reason = nonempty(reason, "reason")
    digest = request_digest("transition_task", context, status=status, reason=reason)
    task = lock_task(session, task_id)
    old = replay_event(session, task.id, operation_id, digest)
    if old is not None:
        return old
    check_time(session, task, context)
    if status not in TRANSITIONS.get(task.status, set()):
        raise InvalidOperationError("Unsupported task state transition")
    if status in {"in_progress", "completed", "closed"}:
        links = active_targets(session, task.id)
        if not links:
            raise InvalidOperationError(
                "Work and successful closure require active targets"
            )
        findings = lock_target_findings(session, links)
        for link in links:
            if (
                current_opening(session, findings[link.finding_id]).id
                != link.opening_event_id
            ):
                raise InvalidOperationError(
                    "Task target refers to an obsolete finding occurrence"
                )
        if status == "closed":
            from patchledger.operational.services.verification import (
                validate_task_closure,
            )

            validate_task_closure(session, task, links, findings, context.occurred_at)
        elif status == "in_progress" and any(
            f.status != "open" for f in findings.values()
        ):
            raise InvalidOperationError(
                "Starting work requires open finding occurrences"
            )
    if status == "in_progress":
        task.started_at = task.started_at or context.occurred_at
    task.work_completed_at = (
        context.occurred_at
        if status == "completed"
        else (task.work_completed_at if status == "closed" else None)
    )
    task.closed_at = context.occurred_at if status == "closed" else None
    previous = task.status
    task.status = status
    kind = (
        "reopened"
        if previous in {"closed", "cancelled"}
        else ("cancelled" if status == "cancelled" else "status_changed")
    )
    return append_event(
        session, task, context, operation_id, digest, kind, reason=reason
    )
