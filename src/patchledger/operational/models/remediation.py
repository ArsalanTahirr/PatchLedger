"""The final four operational tables: accountable work and immutable decisions."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Text,
    UniqueConstraint,
    event,
    func,
    inspect,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, Session, mapped_column

from patchledger.db.base import Base
from patchledger.operational.exceptions import ImmutableRecordError
from patchledger.operational.models.inventory import Identity, RecordedState

TASK_STATES = ("open", "in_progress", "blocked", "completed", "closed", "cancelled")
GOALS = ("eliminate", "mitigate")
ACTION_KINDS = (
    "patch",
    "upgrade",
    "downgrade",
    "removal",
    "configuration",
    "mitigation",
)
VERDICTS = (
    "absence_confirmed",
    "still_affected",
    "mitigation_effective",
    "mitigation_failed",
    "inconclusive",
)
MANUAL_KINDS = ("independent_assessment", "inventory_review", "control_validation")


def task_checks():
    return (
        CheckConstraint("btrim(title) <> ''", name="title_nonempty"),
        CheckConstraint("priority BETWEEN 1 AND 5", name="priority_range"),
        CheckConstraint(f"goal IN {GOALS}", name="goal_valid"),
        CheckConstraint(f"status IN {TASK_STATES}", name="status_valid"),
        CheckConstraint(
            "estimated_effort_minutes IS NULL OR estimated_effort_minutes >= 0",
            name="estimate_nonnegative",
        ),
        CheckConstraint(
            "status NOT IN ('in_progress', 'blocked', 'completed', 'closed') OR started_at IS NOT NULL",
            name="started_required",
        ),
        CheckConstraint(
            "(status IN ('completed', 'closed') AND work_completed_at IS NOT NULL) OR (status NOT IN ('completed', 'closed') AND work_completed_at IS NULL)",
            name="completion_consistent",
        ),
        CheckConstraint(
            "(status = 'closed' AND closed_at IS NOT NULL) OR (status <> 'closed' AND closed_at IS NULL)",
            name="closure_consistent",
        ),
        CheckConstraint(
            "work_completed_at IS NULL OR work_completed_at >= started_at",
            name="completion_order",
        ),
        CheckConstraint(
            "closed_at IS NULL OR closed_at >= work_completed_at", name="closure_order"
        ),
        CheckConstraint(
            "assignee_ref IS NULL OR btrim(assignee_ref) <> ''",
            name="assignee_nonempty",
        ),
    )


class TaskAttributes:
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    owner_department_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.departments.id", ondelete="RESTRICT")
    )
    assignee_ref: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[int]
    goal: Mapped[str] = mapped_column(Text)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    estimated_effort_minutes: Mapped[int | None]
    status: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    work_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RemediationTask(RecordedState, TaskAttributes, Base):
    __tablename__ = "remediation_tasks"
    __table_args__ = (
        UniqueConstraint("task_key"),
        CheckConstraint("btrim(task_key) <> ''", name="key_nonempty"),
        *task_checks(),
        Index("ix_tasks_owner_status", "owner_department_id", "status"),
        Index("ix_tasks_status_due", "status", "due_at"),
        Index("ix_tasks_assignee", "assignee_ref"),
    )
    immutable_fields = ("id", "task_key", "goal", "created_at")
    task_key: Mapped[str] = mapped_column(Text)


class TaskFinding(Identity, Base):
    __tablename__ = "task_findings"
    __table_args__ = (
        UniqueConstraint("task_id", "finding_id", "opening_event_id"),
        UniqueConstraint("id", "task_id", name="uq_task_findings_id_task"),
        UniqueConstraint(
            "id", "finding_id", "opening_event_id", name="uq_task_findings_occurrence"
        ),
        ForeignKeyConstraint(
            ["opening_event_id", "finding_id"],
            ["operational.finding_events.id", "operational.finding_events.finding_id"],
            name="fk_task_findings_opening",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(withdrawn_at IS NULL AND withdrawal_reason IS NULL AND withdrawn_by_ref IS NULL AND withdrawn_recorded_at IS NULL) OR (withdrawn_at IS NOT NULL AND withdrawn_at >= added_at AND withdrawal_reason IS NOT NULL AND btrim(withdrawal_reason) <> '' AND withdrawn_by_ref IS NOT NULL AND btrim(withdrawn_by_ref) <> '' AND withdrawn_recorded_at IS NOT NULL)",
            name="withdrawal_consistent",
        ),
        CheckConstraint("btrim(added_by_ref) <> ''", name="actor_nonempty"),
        Index("ix_task_findings_finding", "finding_id", "opening_event_id"),
    )
    task_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.remediation_tasks.id", ondelete="RESTRICT")
    )
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.vulnerability_findings.id", ondelete="RESTRICT")
    )
    opening_event_id: Mapped[UUID]
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    added_by_ref: Mapped[str] = mapped_column(Text)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_recorded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    withdrawal_reason: Mapped[str | None] = mapped_column(Text)
    withdrawn_by_ref: Mapped[str | None] = mapped_column(Text)


class RemediationEvent(Identity, TaskAttributes, Base):
    __tablename__ = "remediation_events"
    __table_args__ = (
        UniqueConstraint("task_id", "event_number"),
        UniqueConstraint(
            "task_id", "operation_id", name="uq_remediation_events_operation"
        ),
        ForeignKeyConstraint(
            ["task_finding_id", "task_id"],
            ["operational.task_findings.id", "operational.task_findings.task_id"],
            name="fk_remediation_events_target_link",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["installation_id", "target_asset_id"],
            [
                "operational.software_installations.id",
                "operational.software_installations.asset_id",
            ],
            name="fk_remediation_events_installation_asset",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["before_history_id", "installation_id"],
            [
                "operational.installation_history.id",
                "operational.installation_history.installation_id",
            ],
            name="fk_remediation_events_before",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["after_history_id", "installation_id"],
            [
                "operational.installation_history.id",
                "operational.installation_history.installation_id",
            ],
            name="fk_remediation_events_after",
            ondelete="RESTRICT",
        ),
        *task_checks(),
        CheckConstraint("event_number > 0", name="number_positive"),
        CheckConstraint(
            "event_type IN ('created', 'status_changed', 'assigned', 'planning_changed', 'target_added', 'target_withdrawn', 'action_recorded', 'reopened', 'cancelled')",
            name="type_valid",
        ),
        CheckConstraint(
            "btrim(actor_ref) <> '' AND btrim(source_key) <> ''",
            name="provenance_nonempty",
        ),
        CheckConstraint("payload_digest ~ '^[0-9a-f]{64}$'", name="digest_valid"),
        CheckConstraint(
            "event_type NOT IN ('target_added', 'target_withdrawn') OR task_finding_id IS NOT NULL",
            name="scope_has_link",
        ),
        CheckConstraint(
            f"(event_type = 'action_recorded' AND target_asset_id IS NOT NULL AND action_kind IS NOT NULL AND action_kind IN {ACTION_KINDS} AND action_outcome IS NOT NULL AND action_outcome IN ('succeeded', 'failed', 'inconclusive') AND evidence_ref IS NOT NULL AND btrim(evidence_ref) <> '') OR (event_type <> 'action_recorded' AND action_kind IS NULL AND action_outcome IS NULL AND target_asset_id IS NULL AND installation_id IS NULL AND before_history_id IS NULL AND after_history_id IS NULL AND actual_effort_minutes IS NULL)",
            name="action_consistent",
        ),
        CheckConstraint(
            "(before_history_id IS NULL AND after_history_id IS NULL) OR installation_id IS NOT NULL",
            name="history_has_installation",
        ),
        CheckConstraint(
            "actual_effort_minutes IS NULL OR actual_effort_minutes >= 0",
            name="effort_nonnegative",
        ),
        CheckConstraint(
            "evidence IS NULL OR (jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 16384)",
            name="evidence_bounded",
        ),
        Index(
            "ix_remediation_events_timeline", "task_id", "occurred_at", "event_number"
        ),
        Index(
            "ix_remediation_events_target_time",
            "target_asset_id",
            "installation_id",
            "occurred_at",
        ),
        Index("ix_remediation_events_recorded", "recorded_at"),
        Index("ix_remediation_events_before", "before_history_id"),
        Index("ix_remediation_events_after", "after_history_id"),
    )
    task_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.remediation_tasks.id", ondelete="RESTRICT")
    )
    event_number: Mapped[int]
    operation_id: Mapped[UUID]
    payload_digest: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(Text)
    task_finding_id: Mapped[UUID | None]
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    actor_ref: Mapped[str] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(Text)
    is_synthetic: Mapped[bool]
    reason: Mapped[str | None] = mapped_column(Text)
    target_asset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operational.assets.id", ondelete="RESTRICT")
    )
    installation_id: Mapped[UUID | None]
    action_kind: Mapped[str | None] = mapped_column(Text)
    action_outcome: Mapped[str | None] = mapped_column(Text)
    actual_effort_minutes: Mapped[int | None]
    before_history_id: Mapped[UUID | None]
    after_history_id: Mapped[UUID | None]
    evidence_ref: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))


class VerificationResult(Identity, Base):
    __tablename__ = "verification_results"
    __table_args__ = (
        UniqueConstraint(
            "finding_id", "operation_id", name="uq_verification_results_operation"
        ),
        ForeignKeyConstraint(
            ["opening_event_id", "finding_id"],
            ["operational.finding_events.id", "operational.finding_events.finding_id"],
            name="fk_verification_results_opening",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["task_finding_id", "finding_id", "opening_event_id"],
            [
                "operational.task_findings.id",
                "operational.task_findings.finding_id",
                "operational.task_findings.opening_event_id",
            ],
            name="fk_verification_results_task_occurrence",
            ondelete="RESTRICT",
        ),
        CheckConstraint(f"verdict IN {VERDICTS}", name="verdict_valid"),
        CheckConstraint(
            "accepted = (verdict IN ('absence_confirmed', 'mitigation_effective'))",
            name="acceptance_consistent",
        ),
        CheckConstraint(
            "(method = 'scan' AND observation_id IS NOT NULL AND manual_evidence_kind IS NULL) OR (method = 'manual' AND observation_id IS NULL AND manual_evidence_kind IS NOT NULL)",
            name="method_consistent",
        ),
        CheckConstraint(
            f"manual_evidence_kind IS NULL OR manual_evidence_kind IN {MANUAL_KINDS}",
            name="manual_kind_valid",
        ),
        CheckConstraint(
            "btrim(verifier_ref) <> '' AND btrim(rationale) <> '' AND btrim(actor_ref) <> '' AND btrim(source_key) <> ''",
            name="provenance_nonempty",
        ),
        CheckConstraint(
            "evidence_ref IS NOT NULL OR evidence IS NOT NULL", name="evidence_required"
        ),
        CheckConstraint(
            "evidence_ref IS NULL OR btrim(evidence_ref) <> ''",
            name="reference_nonempty",
        ),
        CheckConstraint(
            "evidence IS NULL OR (jsonb_typeof(evidence) = 'object' AND evidence <> '{}'::jsonb AND octet_length(evidence::text) <= 16384)",
            name="evidence_bounded",
        ),
        CheckConstraint("verified_at >= evidence_at", name="decision_order"),
        CheckConstraint(
            "(verdict = 'mitigation_effective' AND valid_until IS NOT NULL AND valid_until > verified_at) OR (verdict <> 'mitigation_effective' AND valid_until IS NULL)",
            name="validity_consistent",
        ),
        CheckConstraint("payload_digest ~ '^[0-9a-f]{64}$'", name="digest_valid"),
        Index(
            "uq_verification_absence_occurrence",
            "opening_event_id",
            unique=True,
            postgresql_where=text("accepted AND verdict = 'absence_confirmed'"),
        ),
        Index(
            "ix_verification_occurrence_time",
            "finding_id",
            "opening_event_id",
            "verified_at",
        ),
        Index("ix_verification_history", "assessed_history_id", "evidence_at"),
        Index("ix_verification_recorded", "recorded_at"),
        Index("ix_verification_observation", "observation_id"),
        Index("ix_verification_action", "action_event_id"),
        Index("ix_verification_task_link", "task_finding_id"),
    )
    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.vulnerability_findings.id", ondelete="RESTRICT")
    )
    opening_event_id: Mapped[UUID]
    task_finding_id: Mapped[UUID | None]
    observation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operational.scan_observations.id", ondelete="RESTRICT")
    )
    action_event_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operational.remediation_events.id", ondelete="RESTRICT")
    )
    assessed_history_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("operational.installation_history.id", ondelete="RESTRICT")
    )
    operation_id: Mapped[UUID]
    payload_digest: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(Text)
    manual_evidence_kind: Mapped[str | None] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(Text)
    accepted: Mapped[bool]
    evidence_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    verifier_ref: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    actor_ref: Mapped[str] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(Text)
    is_synthetic: Mapped[bool]


@event.listens_for(Session, "before_flush")
def protect_remediation_records(session, flush_context, instances):
    for obj in session.deleted:
        if isinstance(obj, (RemediationEvent, VerificationResult, TaskFinding)):
            raise ImmutableRecordError("Remediation history cannot be deleted")
    for obj in session.dirty:
        if isinstance(obj, (RemediationEvent, VerificationResult)):
            if any(a.history.has_changes() for a in inspect(obj).attrs):
                raise ImmutableRecordError(
                    "Remediation events and verification results are immutable"
                )
        elif isinstance(obj, TaskFinding):
            state = inspect(obj)
            changed = {a.key for a in state.attrs if a.history.has_changes()}
            allowed = {
                "withdrawn_at",
                "withdrawn_recorded_at",
                "withdrawal_reason",
                "withdrawn_by_ref",
            }
            if changed and (
                changed - allowed
                or "withdrawn_at" not in changed
                or state.attrs.withdrawn_at.history.deleted != [None]
            ):
                raise ImmutableRecordError("A target can only be withdrawn once")
