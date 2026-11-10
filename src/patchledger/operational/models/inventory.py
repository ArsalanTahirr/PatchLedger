"""Seven normalized inventory tables. Alembic owns their physical DDL."""

from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    event,
    func,
    inspect,
    text,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from patchledger.db.base import Base
from patchledger.operational.exceptions import ImmutableRecordError

ASSET_TYPES = ("server", "workstation", "laptop", "network_device", "other")
ENVIRONMENTS = ("production", "staging", "development", "test", "other")
EXPOSURES = ("internal", "internet_facing", "unknown")
LIFECYCLE_STATUSES = ("registered", "active", "suspended", "retired")


class Identity:
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    immutable_fields: ClassVar[tuple[str, ...]] = ("id",)


class RecordedState(Identity):
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.clock_timestamp(),
        onupdate=func.clock_timestamp(),
    )


class Department(RecordedState, Base):
    __tablename__ = "departments"
    __table_args__ = (
        UniqueConstraint("code"),
        CheckConstraint("btrim(code) <> ''", name="code_nonempty"),
        CheckConstraint("btrim(name) <> ''", name="name_nonempty"),
    )
    immutable_fields = ("id", "code", "created_at")

    code: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


def asset_checks():
    """Fresh constraints for the current asset and each historical snapshot."""
    return (
        CheckConstraint("btrim(hostname) <> ''", name="hostname_nonempty"),
        CheckConstraint(
            "business_criticality BETWEEN 1 AND 5", name="criticality_range"
        ),
        CheckConstraint(f"asset_type IN {ASSET_TYPES}", name="asset_type_valid"),
        CheckConstraint(f"environment IN {ENVIRONMENTS}", name="environment_valid"),
        CheckConstraint(f"exposure IN {EXPOSURES}", name="exposure_valid"),
        CheckConstraint(
            f"lifecycle_status IN {LIFECYCLE_STATUSES}", name="lifecycle_valid"
        ),
        CheckConstraint(
            "(lifecycle_status = 'retired' AND retired_at IS NOT NULL "
            "AND retired_at >= registered_at) OR "
            "(lifecycle_status <> 'retired' AND retired_at IS NULL)",
            name="retirement_consistent",
        ),
    )


class AssetAttributes:
    hostname: Mapped[str] = mapped_column(Text)
    department_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.departments.id", ondelete="RESTRICT")
    )
    owner_ref: Mapped[str | None] = mapped_column(Text)
    asset_type: Mapped[str] = mapped_column(Text)
    environment: Mapped[str] = mapped_column(Text)
    business_criticality: Mapped[int]
    exposure: Mapped[str] = mapped_column(Text)
    lifecycle_status: Mapped[str] = mapped_column(Text)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Asset(RecordedState, AssetAttributes, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("asset_key"),
        CheckConstraint("btrim(asset_key) <> ''", name="asset_key_nonempty"),
        *asset_checks(),
        Index("ix_assets_department_status", "department_id", "lifecycle_status"),
        Index("ix_assets_hostname", "hostname"),
    )
    immutable_fields = ("id", "asset_key", "registered_at", "created_at")

    asset_key: Mapped[str] = mapped_column(Text)


class AssetEvent(Identity, AssetAttributes, Base):
    __tablename__ = "asset_events"
    __table_args__ = (
        UniqueConstraint("asset_id", "event_number"),
        CheckConstraint("event_number > 0", name="event_number_positive"),
        CheckConstraint(
            "event_type IN ('registered', 'attributes_changed', 'retired')",
            name="event_type_valid",
        ),
        CheckConstraint(
            "occurred_at >= registered_at", name="event_after_registration"
        ),
        CheckConstraint("btrim(actor_ref) <> ''", name="actor_nonempty"),
        CheckConstraint("btrim(source_key) <> ''", name="source_nonempty"),
        *asset_checks(),
        Index("ix_asset_events_timeline", "asset_id", "occurred_at", "event_number"),
        Index("ix_asset_events_department_id", "department_id"),
        Index("ix_asset_events_recorded_at", "recorded_at"),
    )

    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.assets.id", ondelete="RESTRICT")
    )
    event_number: Mapped[int]
    event_type: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    actor_ref: Mapped[str] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(Text)
    is_synthetic: Mapped[bool]
    reason: Mapped[str | None] = mapped_column(Text)


class SoftwareProduct(RecordedState, Base):
    __tablename__ = "software_products"
    __table_args__ = (
        UniqueConstraint("product_key"),
        CheckConstraint("btrim(product_key) <> ''", name="product_key_nonempty"),
        CheckConstraint("btrim(name) <> ''", name="name_nonempty"),
        CheckConstraint("btrim(publisher_name) <> ''", name="publisher_nonempty"),
        CheckConstraint("btrim(ecosystem) <> ''", name="ecosystem_nonempty"),
    )
    immutable_fields = ("id", "product_key", "created_at")

    product_key: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    publisher_name: Mapped[str] = mapped_column(Text)
    ecosystem: Mapped[str] = mapped_column(Text)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProductIdentifier(RecordedState, Base):
    __tablename__ = "product_identifiers"
    __table_args__ = (
        UniqueConstraint("product_id", "scheme", "identifier"),
        CheckConstraint("scheme IN ('cpe23', 'purl', 'vendor')", name="scheme_valid"),
        CheckConstraint("btrim(identifier) <> ''", name="identifier_nonempty"),
        Index("ix_product_identifiers_lookup", "scheme", "identifier"),
    )
    immutable_fields = ("id", "product_id", "scheme", "identifier", "created_at")

    product_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.software_products.id", ondelete="RESTRICT")
    )
    scheme: Mapped[str] = mapped_column(Text)
    identifier: Mapped[str] = mapped_column(Text)
    source_ref: Mapped[str | None] = mapped_column(Text)


class SoftwareInstallation(RecordedState, Base):
    __tablename__ = "software_installations"
    __table_args__ = (
        UniqueConstraint("asset_id", "installation_key"),
        UniqueConstraint("id", "asset_id", name="uq_installations_id_asset"),
        CheckConstraint("btrim(installation_key) <> ''", name="key_nonempty"),
        Index("ix_software_installations_product_id", "product_id"),
    )
    immutable_fields = (
        "id",
        "asset_id",
        "product_id",
        "installation_key",
        "created_at",
    )

    asset_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.assets.id", ondelete="RESTRICT")
    )
    product_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.software_products.id", ondelete="RESTRICT")
    )
    installation_key: Mapped[str] = mapped_column(Text)
    context_description: Mapped[str | None] = mapped_column(Text)


class InstallationHistory(Identity, Base):
    __tablename__ = "installation_history"
    __table_args__ = (
        UniqueConstraint("id", "installation_id", name="uq_history_id_installation"),
        CheckConstraint("btrim(version) <> ''", name="version_nonempty"),
        CheckConstraint(
            "ended_at IS NULL OR ended_at > started_at", name="period_positive"
        ),
        CheckConstraint(
            "start_basis IN ('actual', 'first_observed')", name="start_basis_valid"
        ),
        CheckConstraint("btrim(actor_ref) <> ''", name="actor_nonempty"),
        CheckConstraint("btrim(source_key) <> ''", name="source_nonempty"),
        CheckConstraint(
            "(ended_at IS NULL AND end_basis IS NULL AND end_reason IS NULL "
            "AND ended_recorded_at IS NULL AND end_actor_ref IS NULL "
            "AND end_source_key IS NULL AND end_is_synthetic IS NULL) OR "
            "(ended_at IS NOT NULL AND end_basis IS NOT NULL AND end_reason IS NOT NULL "
            "AND ended_recorded_at IS NOT NULL AND end_actor_ref IS NOT NULL "
            "AND end_source_key IS NOT NULL AND end_is_synthetic IS NOT NULL "
            "AND end_basis IN ('actual', 'first_observed_absent') "
            "AND end_reason IN ('upgrade', 'downgrade', 'removal') "
            "AND btrim(end_actor_ref) <> '' AND btrim(end_source_key) <> '')",
            name="ending_consistent",
        ),
        Index(
            "uq_installation_history_open",
            "installation_id",
            unique=True,
            postgresql_where=text("ended_at IS NULL"),
        ),
        Index("ix_installation_history_timeline", "installation_id", "started_at"),
    )

    installation_id: Mapped[UUID] = mapped_column(
        ForeignKey("operational.software_installations.id", ondelete="RESTRICT")
    )
    version: Mapped[str] = mapped_column(Text)
    build: Mapped[str | None] = mapped_column(Text)
    platform: Mapped[str | None] = mapped_column(Text)
    architecture: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    start_basis: Mapped[str] = mapped_column(Text)
    end_basis: Mapped[str | None] = mapped_column(Text)
    end_reason: Mapped[str | None] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    ended_recorded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    actor_ref: Mapped[str] = mapped_column(Text)
    source_key: Mapped[str] = mapped_column(Text)
    is_synthetic: Mapped[bool]
    end_actor_ref: Mapped[str | None] = mapped_column(Text)
    end_source_key: Mapped[str | None] = mapped_column(Text)
    end_is_synthetic: Mapped[bool | None]


@event.listens_for(Session, "before_flush")
def protect_inventory_records(session, flush_context, instances):
    """ORM guardrails; direct SQL still requires the documented writer contract."""
    for obj in session.deleted:
        if isinstance(obj, (AssetEvent, InstallationHistory)):
            raise ImmutableRecordError("Historical records cannot be deleted")
    for obj in session.dirty:
        if not isinstance(obj, Identity):
            continue
        state = inspect(obj)
        changed = {a.key for a in state.attrs if a.history.has_changes()}
        if not changed:
            continue
        if isinstance(obj, AssetEvent):
            raise ImmutableRecordError("Asset snapshots are append-only")
        if isinstance(obj, InstallationHistory):
            allowed = {
                "ended_at",
                "end_basis",
                "end_reason",
                "ended_recorded_at",
                "end_actor_ref",
                "end_source_key",
                "end_is_synthetic",
            }
            previous = state.attrs.ended_at.history.deleted
            if changed - allowed or "ended_at" not in changed or previous != [None]:
                raise ImmutableRecordError("Version periods may only be closed once")
        elif changed.intersection(obj.immutable_fields):
            raise ImmutableRecordError("Stable identifiers cannot be modified")
