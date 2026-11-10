"""Create remediation management and evidence-backed verification.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Frozen DDL: no imports of mutable application metadata.
    op.create_table(
        "remediation_tasks",
        sa.Column("task_key", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_department_id", sa.Uuid(), nullable=False),
        sa.Column("assignee_ref", sa.Text(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("estimated_effort_minutes", sa.Integer(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("work_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status = 'closed' AND closed_at IS NOT NULL) OR (status <> 'closed' AND closed_at IS NULL)",
            name=op.f("ck_remediation_tasks_closure_consistent"),
        ),
        sa.CheckConstraint(
            "(status IN ('completed', 'closed') AND work_completed_at IS NOT NULL) OR (status NOT IN ('completed', 'closed') AND work_completed_at IS NULL)",
            name=op.f("ck_remediation_tasks_completion_consistent"),
        ),
        sa.CheckConstraint(
            "assignee_ref IS NULL OR btrim(assignee_ref) <> ''",
            name=op.f("ck_remediation_tasks_assignee_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(task_key) <> ''", name=op.f("ck_remediation_tasks_key_nonempty")
        ),
        sa.CheckConstraint(
            "btrim(title) <> ''", name=op.f("ck_remediation_tasks_title_nonempty")
        ),
        sa.CheckConstraint(
            "goal IN ('eliminate', 'mitigate')",
            name=op.f("ck_remediation_tasks_goal_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_progress', 'blocked', 'completed', 'closed', 'cancelled')",
            name=op.f("ck_remediation_tasks_status_valid"),
        ),
        sa.CheckConstraint(
            "status NOT IN ('in_progress', 'blocked', 'completed', 'closed') OR started_at IS NOT NULL",
            name=op.f("ck_remediation_tasks_started_required"),
        ),
        sa.CheckConstraint(
            "closed_at IS NULL OR closed_at >= work_completed_at",
            name=op.f("ck_remediation_tasks_closure_order"),
        ),
        sa.CheckConstraint(
            "estimated_effort_minutes IS NULL OR estimated_effort_minutes >= 0",
            name=op.f("ck_remediation_tasks_estimate_nonnegative"),
        ),
        sa.CheckConstraint(
            "priority BETWEEN 1 AND 5", name=op.f("ck_remediation_tasks_priority_range")
        ),
        sa.CheckConstraint(
            "work_completed_at IS NULL OR work_completed_at >= started_at",
            name=op.f("ck_remediation_tasks_completion_order"),
        ),
        sa.ForeignKeyConstraint(
            ["owner_department_id"],
            ["operational.departments.id"],
            name=op.f("fk_remediation_tasks_owner_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_remediation_tasks")),
        sa.UniqueConstraint("task_key", name=op.f("uq_remediation_tasks_task_key")),
        schema="operational",
    )
    op.create_index(
        "ix_tasks_assignee",
        "remediation_tasks",
        ["assignee_ref"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_tasks_owner_status",
        "remediation_tasks",
        ["owner_department_id", "status"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_tasks_status_due",
        "remediation_tasks",
        ["status", "due_at"],
        unique=False,
        schema="operational",
    )
    op.create_table(
        "task_findings",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("opening_event_id", sa.Uuid(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("added_by_ref", sa.Text(), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_recorded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawal_reason", sa.Text(), nullable=True),
        sa.Column("withdrawn_by_ref", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "(withdrawn_at IS NULL AND withdrawal_reason IS NULL AND withdrawn_by_ref IS NULL AND withdrawn_recorded_at IS NULL) OR (withdrawn_at IS NOT NULL AND withdrawn_at >= added_at AND withdrawal_reason IS NOT NULL AND btrim(withdrawal_reason) <> '' AND withdrawn_by_ref IS NOT NULL AND btrim(withdrawn_by_ref) <> '' AND withdrawn_recorded_at IS NOT NULL)",
            name=op.f("ck_task_findings_withdrawal_consistent"),
        ),
        sa.CheckConstraint(
            "btrim(added_by_ref) <> ''", name=op.f("ck_task_findings_actor_nonempty")
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["operational.vulnerability_findings.id"],
            name=op.f("fk_task_findings_finding_id_vulnerability_findings"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["opening_event_id", "finding_id"],
            ["operational.finding_events.id", "operational.finding_events.finding_id"],
            name="fk_task_findings_opening",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["operational.remediation_tasks.id"],
            name=op.f("fk_task_findings_task_id_remediation_tasks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_findings")),
        sa.UniqueConstraint(
            "id", "finding_id", "opening_event_id", name="uq_task_findings_occurrence"
        ),
        sa.UniqueConstraint("id", "task_id", name="uq_task_findings_id_task"),
        sa.UniqueConstraint(
            "task_id",
            "finding_id",
            "opening_event_id",
            name=op.f("uq_task_findings_task_id"),
        ),
        schema="operational",
    )
    op.create_index(
        "ix_task_findings_finding",
        "task_findings",
        ["finding_id", "opening_event_id"],
        unique=False,
        schema="operational",
    )
    op.create_table(
        "remediation_events",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("event_number", sa.Integer(), nullable=False),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("payload_digest", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("task_finding_id", sa.Uuid(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("actor_ref", sa.Text(), nullable=False),
        sa.Column("source_key", sa.Text(), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("target_asset_id", sa.Uuid(), nullable=True),
        sa.Column("installation_id", sa.Uuid(), nullable=True),
        sa.Column("action_kind", sa.Text(), nullable=True),
        sa.Column("action_outcome", sa.Text(), nullable=True),
        sa.Column("actual_effort_minutes", sa.Integer(), nullable=True),
        sa.Column("before_history_id", sa.Uuid(), nullable=True),
        sa.Column("after_history_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_ref", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_department_id", sa.Uuid(), nullable=False),
        sa.Column("assignee_ref", sa.Text(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("estimated_effort_minutes", sa.Integer(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("work_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(event_type = 'action_recorded' AND target_asset_id IS NOT NULL AND action_kind IS NOT NULL AND action_kind IN ('patch', 'upgrade', 'downgrade', 'removal', 'configuration', 'mitigation') AND action_outcome IS NOT NULL AND action_outcome IN ('succeeded', 'failed', 'inconclusive') AND evidence_ref IS NOT NULL AND btrim(evidence_ref) <> '') OR (event_type <> 'action_recorded' AND action_kind IS NULL AND action_outcome IS NULL AND target_asset_id IS NULL AND installation_id IS NULL AND before_history_id IS NULL AND after_history_id IS NULL AND actual_effort_minutes IS NULL)",
            name=op.f("ck_remediation_events_action_consistent"),
        ),
        sa.CheckConstraint(
            "(status = 'closed' AND closed_at IS NOT NULL) OR (status <> 'closed' AND closed_at IS NULL)",
            name=op.f("ck_remediation_events_closure_consistent"),
        ),
        sa.CheckConstraint(
            "(status IN ('completed', 'closed') AND work_completed_at IS NOT NULL) OR (status NOT IN ('completed', 'closed') AND work_completed_at IS NULL)",
            name=op.f("ck_remediation_events_completion_consistent"),
        ),
        sa.CheckConstraint(
            "assignee_ref IS NULL OR btrim(assignee_ref) <> ''",
            name=op.f("ck_remediation_events_assignee_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(actor_ref) <> '' AND btrim(source_key) <> ''",
            name=op.f("ck_remediation_events_provenance_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(title) <> ''", name=op.f("ck_remediation_events_title_nonempty")
        ),
        sa.CheckConstraint(
            "event_type IN ('created', 'status_changed', 'assigned', 'planning_changed', 'target_added', 'target_withdrawn', 'action_recorded', 'reopened', 'cancelled')",
            name=op.f("ck_remediation_events_type_valid"),
        ),
        sa.CheckConstraint(
            "event_type NOT IN ('target_added', 'target_withdrawn') OR task_finding_id IS NOT NULL",
            name=op.f("ck_remediation_events_scope_has_link"),
        ),
        sa.CheckConstraint(
            "evidence IS NULL OR (jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 16384)",
            name=op.f("ck_remediation_events_evidence_bounded"),
        ),
        sa.CheckConstraint(
            "goal IN ('eliminate', 'mitigate')",
            name=op.f("ck_remediation_events_goal_valid"),
        ),
        sa.CheckConstraint(
            "payload_digest ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_remediation_events_digest_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_progress', 'blocked', 'completed', 'closed', 'cancelled')",
            name=op.f("ck_remediation_events_status_valid"),
        ),
        sa.CheckConstraint(
            "status NOT IN ('in_progress', 'blocked', 'completed', 'closed') OR started_at IS NOT NULL",
            name=op.f("ck_remediation_events_started_required"),
        ),
        sa.CheckConstraint(
            "(before_history_id IS NULL AND after_history_id IS NULL) OR installation_id IS NOT NULL",
            name=op.f("ck_remediation_events_history_has_installation"),
        ),
        sa.CheckConstraint(
            "actual_effort_minutes IS NULL OR actual_effort_minutes >= 0",
            name=op.f("ck_remediation_events_effort_nonnegative"),
        ),
        sa.CheckConstraint(
            "closed_at IS NULL OR closed_at >= work_completed_at",
            name=op.f("ck_remediation_events_closure_order"),
        ),
        sa.CheckConstraint(
            "estimated_effort_minutes IS NULL OR estimated_effort_minutes >= 0",
            name=op.f("ck_remediation_events_estimate_nonnegative"),
        ),
        sa.CheckConstraint(
            "event_number > 0", name=op.f("ck_remediation_events_number_positive")
        ),
        sa.CheckConstraint(
            "priority BETWEEN 1 AND 5",
            name=op.f("ck_remediation_events_priority_range"),
        ),
        sa.CheckConstraint(
            "work_completed_at IS NULL OR work_completed_at >= started_at",
            name=op.f("ck_remediation_events_completion_order"),
        ),
        sa.ForeignKeyConstraint(
            ["after_history_id", "installation_id"],
            [
                "operational.installation_history.id",
                "operational.installation_history.installation_id",
            ],
            name="fk_remediation_events_after",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["before_history_id", "installation_id"],
            [
                "operational.installation_history.id",
                "operational.installation_history.installation_id",
            ],
            name="fk_remediation_events_before",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id", "target_asset_id"],
            [
                "operational.software_installations.id",
                "operational.software_installations.asset_id",
            ],
            name="fk_remediation_events_installation_asset",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_department_id"],
            ["operational.departments.id"],
            name=op.f("fk_remediation_events_owner_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_asset_id"],
            ["operational.assets.id"],
            name=op.f("fk_remediation_events_target_asset_id_assets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_finding_id", "task_id"],
            ["operational.task_findings.id", "operational.task_findings.task_id"],
            name="fk_remediation_events_target_link",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["operational.remediation_tasks.id"],
            name=op.f("fk_remediation_events_task_id_remediation_tasks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_remediation_events")),
        sa.UniqueConstraint(
            "task_id", "event_number", name=op.f("uq_remediation_events_task_id")
        ),
        sa.UniqueConstraint(
            "task_id", "operation_id", name="uq_remediation_events_operation"
        ),
        schema="operational",
    )
    op.create_index(
        "ix_remediation_events_after",
        "remediation_events",
        ["after_history_id"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_remediation_events_before",
        "remediation_events",
        ["before_history_id"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_remediation_events_recorded",
        "remediation_events",
        ["recorded_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_remediation_events_target_time",
        "remediation_events",
        ["target_asset_id", "installation_id", "occurred_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_remediation_events_timeline",
        "remediation_events",
        ["task_id", "occurred_at", "event_number"],
        unique=False,
        schema="operational",
    )
    op.create_table(
        "verification_results",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("opening_event_id", sa.Uuid(), nullable=False),
        sa.Column("task_finding_id", sa.Uuid(), nullable=True),
        sa.Column("observation_id", sa.Uuid(), nullable=True),
        sa.Column("action_event_id", sa.Uuid(), nullable=True),
        sa.Column("assessed_history_id", sa.Uuid(), nullable=True),
        sa.Column("operation_id", sa.Uuid(), nullable=False),
        sa.Column("payload_digest", sa.Text(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("manual_evidence_kind", sa.Text(), nullable=True),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column("evidence_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("verifier_ref", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("actor_ref", sa.Text(), nullable=False),
        sa.Column("source_key", sa.Text(), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "(method = 'scan' AND observation_id IS NOT NULL AND manual_evidence_kind IS NULL) OR (method = 'manual' AND observation_id IS NULL AND manual_evidence_kind IS NOT NULL)",
            name=op.f("ck_verification_results_method_consistent"),
        ),
        sa.CheckConstraint(
            "(verdict = 'mitigation_effective' AND valid_until IS NOT NULL AND valid_until > verified_at) OR (verdict <> 'mitigation_effective' AND valid_until IS NULL)",
            name=op.f("ck_verification_results_validity_consistent"),
        ),
        sa.CheckConstraint(
            "accepted = (verdict IN ('absence_confirmed', 'mitigation_effective'))",
            name=op.f("ck_verification_results_acceptance_consistent"),
        ),
        sa.CheckConstraint(
            "btrim(verifier_ref) <> '' AND btrim(rationale) <> '' AND btrim(actor_ref) <> '' AND btrim(source_key) <> ''",
            name=op.f("ck_verification_results_provenance_nonempty"),
        ),
        sa.CheckConstraint(
            "evidence IS NULL OR (jsonb_typeof(evidence) = 'object' AND evidence <> '{}'::jsonb AND octet_length(evidence::text) <= 16384)",
            name=op.f("ck_verification_results_evidence_bounded"),
        ),
        sa.CheckConstraint(
            "evidence_ref IS NULL OR btrim(evidence_ref) <> ''",
            name=op.f("ck_verification_results_reference_nonempty"),
        ),
        sa.CheckConstraint(
            "manual_evidence_kind IS NULL OR manual_evidence_kind IN ('independent_assessment', 'inventory_review', 'control_validation')",
            name=op.f("ck_verification_results_manual_kind_valid"),
        ),
        sa.CheckConstraint(
            "payload_digest ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_verification_results_digest_valid"),
        ),
        sa.CheckConstraint(
            "verdict IN ('absence_confirmed', 'still_affected', 'mitigation_effective', 'mitigation_failed', 'inconclusive')",
            name=op.f("ck_verification_results_verdict_valid"),
        ),
        sa.CheckConstraint(
            "evidence_ref IS NOT NULL OR evidence IS NOT NULL",
            name=op.f("ck_verification_results_evidence_required"),
        ),
        sa.CheckConstraint(
            "verified_at >= evidence_at",
            name=op.f("ck_verification_results_decision_order"),
        ),
        sa.ForeignKeyConstraint(
            ["action_event_id"],
            ["operational.remediation_events.id"],
            name=op.f("fk_verification_results_action_event_id_remediation_events"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["assessed_history_id"],
            ["operational.installation_history.id"],
            name=op.f(
                "fk_verification_results_assessed_history_id_installation_history"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["operational.vulnerability_findings.id"],
            name=op.f("fk_verification_results_finding_id_vulnerability_findings"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"],
            ["operational.scan_observations.id"],
            name=op.f("fk_verification_results_observation_id_scan_observations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["opening_event_id", "finding_id"],
            ["operational.finding_events.id", "operational.finding_events.finding_id"],
            name="fk_verification_results_opening",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_finding_id", "finding_id", "opening_event_id"],
            [
                "operational.task_findings.id",
                "operational.task_findings.finding_id",
                "operational.task_findings.opening_event_id",
            ],
            name="fk_verification_results_task_occurrence",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verification_results")),
        sa.UniqueConstraint(
            "finding_id", "operation_id", name="uq_verification_results_operation"
        ),
        schema="operational",
    )
    op.create_index(
        "ix_verification_action",
        "verification_results",
        ["action_event_id"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_verification_history",
        "verification_results",
        ["assessed_history_id", "evidence_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_verification_observation",
        "verification_results",
        ["observation_id"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_verification_occurrence_time",
        "verification_results",
        ["finding_id", "opening_event_id", "verified_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_verification_recorded",
        "verification_results",
        ["recorded_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_verification_task_link",
        "verification_results",
        ["task_finding_id"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "uq_verification_absence_occurrence",
        "verification_results",
        ["opening_event_id"],
        unique=True,
        schema="operational",
        postgresql_where=sa.text("accepted AND verdict = 'absence_confirmed'"),
    )


def downgrade() -> None:
    op.drop_table("verification_results", schema="operational")
    op.drop_table("remediation_events", schema="operational")
    op.drop_table("task_findings", schema="operational")
    op.drop_table("remediation_tasks", schema="operational")
