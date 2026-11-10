"""Create the seven enterprise inventory tables.

Revision ID: 0002
Revises: 0001_operational_schema
Create Date: 2026-11-10 07:49:53.911567

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001_operational_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Explicit, reviewed DDL: do not import mutable application metadata here.
    op.create_table(
        "departments",
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "btrim(code) <> ''", name=op.f("ck_departments_code_nonempty")
        ),
        sa.CheckConstraint(
            "btrim(name) <> ''", name=op.f("ck_departments_name_nonempty")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_departments")),
        sa.UniqueConstraint("code", name=op.f("uq_departments_code")),
        schema="operational",
    )
    op.create_table(
        "software_products",
        sa.Column("product_key", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("publisher_name", sa.Text(), nullable=False),
        sa.Column("ecosystem", sa.Text(), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "btrim(ecosystem) <> ''",
            name=op.f("ck_software_products_ecosystem_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(name) <> ''", name=op.f("ck_software_products_name_nonempty")
        ),
        sa.CheckConstraint(
            "btrim(product_key) <> ''",
            name=op.f("ck_software_products_product_key_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(publisher_name) <> ''",
            name=op.f("ck_software_products_publisher_nonempty"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_software_products")),
        sa.UniqueConstraint(
            "product_key", name=op.f("uq_software_products_product_key")
        ),
        schema="operational",
    )
    op.create_table(
        "assets",
        sa.Column("asset_key", sa.Text(), nullable=False),
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
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=False),
        sa.Column("owner_ref", sa.Text(), nullable=True),
        sa.Column("asset_type", sa.Text(), nullable=False),
        sa.Column("environment", sa.Text(), nullable=False),
        sa.Column("business_criticality", sa.Integer(), nullable=False),
        sa.Column("exposure", sa.Text(), nullable=False),
        sa.Column("lifecycle_status", sa.Text(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(lifecycle_status = 'retired' AND retired_at IS NOT NULL AND retired_at >= registered_at) OR (lifecycle_status <> 'retired' AND retired_at IS NULL)",
            name=op.f("ck_assets_retirement_consistent"),
        ),
        sa.CheckConstraint(
            "asset_type IN ('server', 'workstation', 'laptop', 'network_device', 'other')",
            name=op.f("ck_assets_asset_type_valid"),
        ),
        sa.CheckConstraint(
            "btrim(asset_key) <> ''", name=op.f("ck_assets_asset_key_nonempty")
        ),
        sa.CheckConstraint(
            "btrim(hostname) <> ''", name=op.f("ck_assets_hostname_nonempty")
        ),
        sa.CheckConstraint(
            "environment IN ('production', 'staging', 'development', 'test', 'other')",
            name=op.f("ck_assets_environment_valid"),
        ),
        sa.CheckConstraint(
            "exposure IN ('internal', 'internet_facing', 'unknown')",
            name=op.f("ck_assets_exposure_valid"),
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('registered', 'active', 'suspended', 'retired')",
            name=op.f("ck_assets_lifecycle_valid"),
        ),
        sa.CheckConstraint(
            "business_criticality BETWEEN 1 AND 5",
            name=op.f("ck_assets_criticality_range"),
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["operational.departments.id"],
            name=op.f("fk_assets_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("asset_key", name=op.f("uq_assets_asset_key")),
        schema="operational",
    )
    op.create_index(
        "ix_assets_department_status",
        "assets",
        ["department_id", "lifecycle_status"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_assets_hostname", "assets", ["hostname"], unique=False, schema="operational"
    )
    op.create_table(
        "product_identifiers",
        sa.Column("product_id", sa.Uuid(), nullable=False),
        sa.Column("scheme", sa.Text(), nullable=False),
        sa.Column("identifier", sa.Text(), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=True),
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
        sa.CheckConstraint(
            "btrim(identifier) <> ''",
            name=op.f("ck_product_identifiers_identifier_nonempty"),
        ),
        sa.CheckConstraint(
            "scheme IN ('cpe23', 'purl', 'vendor')",
            name=op.f("ck_product_identifiers_scheme_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["operational.software_products.id"],
            name=op.f("fk_product_identifiers_product_id_software_products"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_product_identifiers")),
        sa.UniqueConstraint(
            "product_id",
            "scheme",
            "identifier",
            name=op.f("uq_product_identifiers_product_id"),
        ),
        schema="operational",
    )
    op.create_index(
        "ix_product_identifiers_lookup",
        "product_identifiers",
        ["scheme", "identifier"],
        unique=False,
        schema="operational",
    )
    op.create_table(
        "asset_events",
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("event_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
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
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=False),
        sa.Column("owner_ref", sa.Text(), nullable=True),
        sa.Column("asset_type", sa.Text(), nullable=False),
        sa.Column("environment", sa.Text(), nullable=False),
        sa.Column("business_criticality", sa.Integer(), nullable=False),
        sa.Column("exposure", sa.Text(), nullable=False),
        sa.Column("lifecycle_status", sa.Text(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(lifecycle_status = 'retired' AND retired_at IS NOT NULL AND retired_at >= registered_at) OR (lifecycle_status <> 'retired' AND retired_at IS NULL)",
            name=op.f("ck_asset_events_retirement_consistent"),
        ),
        sa.CheckConstraint(
            "asset_type IN ('server', 'workstation', 'laptop', 'network_device', 'other')",
            name=op.f("ck_asset_events_asset_type_valid"),
        ),
        sa.CheckConstraint(
            "btrim(actor_ref) <> ''", name=op.f("ck_asset_events_actor_nonempty")
        ),
        sa.CheckConstraint(
            "btrim(hostname) <> ''", name=op.f("ck_asset_events_hostname_nonempty")
        ),
        sa.CheckConstraint(
            "btrim(source_key) <> ''", name=op.f("ck_asset_events_source_nonempty")
        ),
        sa.CheckConstraint(
            "environment IN ('production', 'staging', 'development', 'test', 'other')",
            name=op.f("ck_asset_events_environment_valid"),
        ),
        sa.CheckConstraint(
            "event_type IN ('registered', 'attributes_changed', 'retired')",
            name=op.f("ck_asset_events_event_type_valid"),
        ),
        sa.CheckConstraint(
            "exposure IN ('internal', 'internet_facing', 'unknown')",
            name=op.f("ck_asset_events_exposure_valid"),
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('registered', 'active', 'suspended', 'retired')",
            name=op.f("ck_asset_events_lifecycle_valid"),
        ),
        sa.CheckConstraint(
            "business_criticality BETWEEN 1 AND 5",
            name=op.f("ck_asset_events_criticality_range"),
        ),
        sa.CheckConstraint(
            "event_number > 0", name=op.f("ck_asset_events_event_number_positive")
        ),
        sa.CheckConstraint(
            "occurred_at >= registered_at",
            name=op.f("ck_asset_events_event_after_registration"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["operational.assets.id"],
            name=op.f("fk_asset_events_asset_id_assets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["operational.departments.id"],
            name=op.f("fk_asset_events_department_id_departments"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_events")),
        sa.UniqueConstraint(
            "asset_id", "event_number", name=op.f("uq_asset_events_asset_id")
        ),
        schema="operational",
    )
    op.create_index(
        "ix_asset_events_department_id",
        "asset_events",
        ["department_id"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_asset_events_recorded_at",
        "asset_events",
        ["recorded_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "ix_asset_events_timeline",
        "asset_events",
        ["asset_id", "occurred_at", "event_number"],
        unique=False,
        schema="operational",
    )
    op.create_table(
        "software_installations",
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("product_id", sa.Uuid(), nullable=False),
        sa.Column("installation_key", sa.Text(), nullable=False),
        sa.Column("context_description", sa.Text(), nullable=True),
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
        sa.CheckConstraint(
            "btrim(installation_key) <> ''",
            name=op.f("ck_software_installations_key_nonempty"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["operational.assets.id"],
            name=op.f("fk_software_installations_asset_id_assets"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["operational.software_products.id"],
            name=op.f("fk_software_installations_product_id_software_products"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_software_installations")),
        sa.UniqueConstraint(
            "asset_id",
            "installation_key",
            name=op.f("uq_software_installations_asset_id"),
        ),
        sa.UniqueConstraint("id", "asset_id", name="uq_installations_id_asset"),
        schema="operational",
    )
    op.create_index(
        "ix_software_installations_product_id",
        "software_installations",
        ["product_id"],
        unique=False,
        schema="operational",
    )
    op.create_table(
        "installation_history",
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("build", sa.Text(), nullable=True),
        sa.Column("platform", sa.Text(), nullable=True),
        sa.Column("architecture", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("start_basis", sa.Text(), nullable=False),
        sa.Column("end_basis", sa.Text(), nullable=True),
        sa.Column("end_reason", sa.Text(), nullable=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("ended_recorded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("actor_ref", sa.Text(), nullable=False),
        sa.Column("source_key", sa.Text(), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.Column("end_actor_ref", sa.Text(), nullable=True),
        sa.Column("end_source_key", sa.Text(), nullable=True),
        sa.Column("end_is_synthetic", sa.Boolean(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "(ended_at IS NULL AND end_basis IS NULL AND end_reason IS NULL AND ended_recorded_at IS NULL AND end_actor_ref IS NULL AND end_source_key IS NULL AND end_is_synthetic IS NULL) OR (ended_at IS NOT NULL AND end_basis IS NOT NULL AND end_reason IS NOT NULL AND ended_recorded_at IS NOT NULL AND end_actor_ref IS NOT NULL AND end_source_key IS NOT NULL AND end_is_synthetic IS NOT NULL AND end_basis IN ('actual', 'first_observed_absent') AND end_reason IN ('upgrade', 'downgrade', 'removal') AND btrim(end_actor_ref) <> '' AND btrim(end_source_key) <> '')",
            name=op.f("ck_installation_history_ending_consistent"),
        ),
        sa.CheckConstraint(
            "btrim(actor_ref) <> ''",
            name=op.f("ck_installation_history_actor_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(source_key) <> ''",
            name=op.f("ck_installation_history_source_nonempty"),
        ),
        sa.CheckConstraint(
            "btrim(version) <> ''",
            name=op.f("ck_installation_history_version_nonempty"),
        ),
        sa.CheckConstraint(
            "start_basis IN ('actual', 'first_observed')",
            name=op.f("ck_installation_history_start_basis_valid"),
        ),
        sa.CheckConstraint(
            "ended_at IS NULL OR ended_at > started_at",
            name=op.f("ck_installation_history_period_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["operational.software_installations.id"],
            name=op.f("fk_installation_history_installation_id_software_installations"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_installation_history")),
        sa.UniqueConstraint("id", "installation_id", name="uq_history_id_installation"),
        schema="operational",
    )
    op.create_index(
        "ix_installation_history_timeline",
        "installation_history",
        ["installation_id", "started_at"],
        unique=False,
        schema="operational",
    )
    op.create_index(
        "uq_installation_history_open",
        "installation_history",
        ["installation_id"],
        unique=True,
        schema="operational",
        postgresql_where=sa.text("ended_at IS NULL"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Reverse dependency order; only this revision's tables are removed.
    op.drop_index(
        "uq_installation_history_open",
        table_name="installation_history",
        schema="operational",
        postgresql_where=sa.text("ended_at IS NULL"),
    )
    op.drop_index(
        "ix_installation_history_timeline",
        table_name="installation_history",
        schema="operational",
    )
    op.drop_table("installation_history", schema="operational")
    op.drop_index(
        "ix_software_installations_product_id",
        table_name="software_installations",
        schema="operational",
    )
    op.drop_table("software_installations", schema="operational")
    op.drop_index(
        "ix_asset_events_timeline", table_name="asset_events", schema="operational"
    )
    op.drop_index(
        "ix_asset_events_recorded_at", table_name="asset_events", schema="operational"
    )
    op.drop_index(
        "ix_asset_events_department_id", table_name="asset_events", schema="operational"
    )
    op.drop_table("asset_events", schema="operational")
    op.drop_index(
        "ix_product_identifiers_lookup",
        table_name="product_identifiers",
        schema="operational",
    )
    op.drop_table("product_identifiers", schema="operational")
    op.drop_index("ix_assets_hostname", table_name="assets", schema="operational")
    op.drop_index(
        "ix_assets_department_status", table_name="assets", schema="operational"
    )
    op.drop_table("assets", schema="operational")
    op.drop_table("software_products", schema="operational")
    op.drop_table("departments", schema="operational")
