"""Assessment evidence and persistent finding identities; no intelligence catalog."""

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
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, Session, mapped_column

from patchledger.db.base import Base
from patchledger.operational.exceptions import ImmutableRecordError
from patchledger.operational.models.inventory import Identity, RecordedState

SCAN_STATUSES = ("queued", "running", "completed", "partial", "failed", "cancelled")
OUTCOMES = ("affected", "not_affected", "target_absent", "inconclusive")
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
EVIDENCE_LIMIT = 16384


def sla_check():
    return CheckConstraint(
        "(sla_policy_ref IS NULL AND sla_target_seconds IS NULL AND sla_deadline IS NULL) "
        "OR (sla_policy_ref IS NOT NULL AND btrim(sla_policy_ref) <> '' "
        "AND sla_target_seconds IS NOT NULL AND sla_target_seconds > 0 "
        "AND sla_deadline IS NOT NULL)",
        name="sla_complete",
    )


class SLASnapshot:
    sla_policy_ref: Mapped[str | None] = mapped_column(Text)
    sla_target_seconds: Mapped[int | None]
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanRun(RecordedState, Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        UniqueConstraint("source_key", "external_run_key", "asset_id"),
        UniqueConstraint("id", "asset_id", name="uq_scan_runs_id_asset"),
        CheckConstraint("btrim(source_key) <> ''", name="source_nonempty"),
        CheckConstraint("btrim(external_run_key) <> ''", name="external_key_nonempty"),
        CheckConstraint("btrim(producer_version) <> ''", name="producer_nonempty"),
        CheckConstraint(f"status IN {SCAN_STATUSES}", name="status_valid"),
        CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL) OR "
            "(status IN ('completed', 'partial', 'failed') AND started_at IS NOT NULL "
            "AND completed_at IS NOT NULL) OR "
            "(status = 'cancelled' AND completed_at IS NOT NULL)",
            name="status_times",
        ),
        CheckConstraint(
            "completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at",
            name="time_order",
        ),
        CheckConstraint(
            f"jsonb_typeof(scope) = 'object' AND octet_length(scope::text) <= {EVIDENCE_LIMIT}",
            name="scope_bounded_object",
        ),
        CheckConstraint("request_digest ~ '^[0-9a-f]{64}$'", name="digest_valid"),
        Index("ix_scan_runs_asset_started", "asset_id", "started_at"),
        Index("ix_scan_runs_status", "status"),
        Index("ix_scan_runs_batch", "source_key", "batch_key"),
    )
    immutable_fields = (
        "id",
        "asset_id",
        "source_key",
        "external_run_key",
        "batch_key",
        "producer_version",
        "is_synthetic",
        "scope",
        "request_digest",
        "created_at",
    )

    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.assets.id", ondelete="RESTRICT")
    )
    source_key: Mapped[str] = mapped_column(Text)
    external_run_key: Mapped[str] = mapped_column(Text)
    batch_key: Mapped[str | None] = mapped_column(Text)
    producer_version: Mapped[str] = mapped_column(Text)
    is_synthetic: Mapped[bool]
    scope: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    request_digest: Mapped[str] = mapped_column(Text)


class VulnerabilityFinding(RecordedState, SLASnapshot, Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "installation_id",
            "cve_id",
            name="uq_findings_scope_cve",
            postgresql_nulls_not_distinct=True,
        ),
        UniqueConstraint("id", "asset_id", "cve_id", name="uq_findings_id_asset_cve"),
        UniqueConstraint("id", "installation_id", name="uq_findings_id_installation"),
        ForeignKeyConstraint(
            ["installation_id", "asset_id"],
            [
                "operational.software_installations.id",
                "operational.software_installations.asset_id",
            ],
            name="fk_findings_installation_asset",
            ondelete="RESTRICT",
        ),
        CheckConstraint(f"cve_id ~ '{CVE_PATTERN}'", name="cve_valid"),
        CheckConstraint("status IN ('open', 'resolved')", name="status_valid"),
        CheckConstraint(
            "first_detected_at <= current_opened_at AND current_opened_at <= last_observed_at",
            name="detection_order",
        ),
        CheckConstraint(
            "(status = 'open' AND resolved_at IS NULL) OR "
            "(status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at > last_observed_at)",
            name="resolution_consistent",
        ),
        sla_check(),
        CheckConstraint(
            "sla_deadline IS NULL OR sla_deadline > current_opened_at",
            name="sla_after_opening",
        ),
        Index("ix_findings_status_deadline", "status", "sla_deadline"),
        Index("ix_findings_cve", "cve_id"),
        Index("ix_findings_installation", "installation_id"),
    )
    immutable_fields = (
        "id",
        "asset_id",
        "installation_id",
        "cve_id",
        "first_detected_at",
        "created_at",
    )

    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.assets.id", ondelete="RESTRICT")
    )
    installation_id: Mapped[UUID | None]
    cve_id: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    current_opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanObservation(Identity, Base):
    __tablename__ = "scan_observations"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "external_observation_key"),
        ForeignKeyConstraint(
            ["scan_run_id", "asset_id"],
            ["operational.scan_runs.id", "operational.scan_runs.asset_id"],
            name="fk_observations_scan_asset",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["installation_id", "asset_id"],
            [
                "operational.software_installations.id",
                "operational.software_installations.asset_id",
            ],
            name="fk_observations_installation_asset",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["installation_history_id", "installation_id"],
            [
                "operational.installation_history.id",
                "operational.installation_history.installation_id",
            ],
            name="fk_observations_history_installation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["finding_id", "asset_id", "cve_id"],
            [
                "operational.vulnerability_findings.id",
                "operational.vulnerability_findings.asset_id",
                "operational.vulnerability_findings.cve_id",
            ],
            name="fk_observations_finding_asset_cve",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["finding_id", "installation_id"],
            [
                "operational.vulnerability_findings.id",
                "operational.vulnerability_findings.installation_id",
            ],
            name="fk_observations_finding_installation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "btrim(external_observation_key) <> ''", name="external_key_nonempty"
        ),
        CheckConstraint("btrim(test_ref) <> ''", name="test_nonempty"),
        CheckConstraint(f"cve_id ~ '{CVE_PATTERN}'", name="cve_valid"),
        CheckConstraint(f"outcome IN {OUTCOMES}", name="outcome_valid"),
        CheckConstraint(
            "installation_history_id IS NULL OR installation_id IS NOT NULL",
            name="history_has_installation",
        ),
        CheckConstraint(
            "outcome <> 'affected' OR (finding_id IS NOT NULL AND "
            "(installation_id IS NULL OR installation_history_id IS NOT NULL))",
            name="positive_has_target",
        ),
        CheckConstraint(
            f"evidence IS NULL OR (jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= {EVIDENCE_LIMIT})",
            name="evidence_bounded_object",
        ),
        CheckConstraint("payload_digest ~ '^[0-9a-f]{64}$'", name="digest_valid"),
        Index("ix_observations_finding_time", "finding_id", "occurred_at"),
        Index("ix_observations_asset_time", "asset_id", "occurred_at"),
        Index("ix_observations_installation", "installation_id"),
        Index("ix_observations_history", "installation_history_id", "occurred_at"),
        Index("ix_observations_recorded", "recorded_at"),
    )

    scan_run_id: Mapped[UUID]
    # Controlled redundancy for database-enforced cross-asset scope integrity.
    asset_id: Mapped[UUID]
    external_observation_key: Mapped[str] = mapped_column(Text)
    installation_id: Mapped[UUID | None]
    installation_history_id: Mapped[UUID | None]
    finding_id: Mapped[UUID | None]
    cve_id: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    test_ref: Mapped[str] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    payload_digest: Mapped[str] = mapped_column(Text)


class FindingEvent(Identity, SLASnapshot, Base):
    __tablename__ = "finding_events"
    __table_args__ = (
        UniqueConstraint("finding_id", "event_number"),
        UniqueConstraint(
            "finding_id", "operation_id", name="uq_finding_events_operation"
        ),
        UniqueConstraint("id", "finding_id", name="uq_finding_events_id_finding"),
        CheckConstraint("event_number > 0", name="number_positive"),
        CheckConstraint(
            "event_type IN ('opened', 'resolved', 'reopened', 'sla_changed')",
            name="type_valid",
        ),
        CheckConstraint("status_after IN ('open', 'resolved')", name="status_valid"),
        CheckConstraint(
            "(event_type IN ('opened', 'reopened') AND status_after = 'open') OR "
            "(event_type = 'resolved' AND status_after = 'resolved') OR event_type = 'sla_changed'",
            name="transition_status",
        ),
        CheckConstraint("btrim(actor_ref) <> ''", name="actor_nonempty"),
        CheckConstraint("btrim(source_key) <> ''", name="source_nonempty"),
        CheckConstraint(
            "event_type = 'opened' OR (reason IS NOT NULL AND btrim(reason) <> '')",
            name="reason_required",
        ),
        sla_check(),
        Index(
            "ix_finding_events_timeline", "finding_id", "occurred_at", "event_number"
        ),
        Index("ix_finding_events_recorded", "recorded_at"),
    )

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.vulnerability_findings.id", ondelete="RESTRICT")
    )
    event_number: Mapped[int]
    operation_id: Mapped[UUID]
    event_type: Mapped[str] = mapped_column(Text)
    status_after: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    actor_ref: Mapped[str] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(Text)
    is_synthetic: Mapped[bool]
    reason: Mapped[str | None] = mapped_column(Text)


@event.listens_for(Session, "before_flush")
def protect_assessment_evidence(session, flush_context, instances):
    """ORM guardrails follow inventory's documented service-only writer contract."""
    for obj in session.deleted:
        if isinstance(obj, (ScanObservation, FindingEvent)):
            raise ImmutableRecordError(
                "Assessment evidence and finding events cannot be deleted"
            )
    for obj in session.dirty:
        if isinstance(obj, (ScanObservation, FindingEvent)) and any(
            attr.history.has_changes() for attr in inspect(obj).attrs
        ):
            raise ImmutableRecordError(
                "Assessment evidence and finding events are append-only"
            )
