"""Department and asset workflows with atomic typed history snapshots."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from patchledger.operational.exceptions import (
    ConflictError,
    HistoricalConflictError,
    InvalidOperationError,
    NotFoundError,
)
from patchledger.operational.models import (
    Asset,
    AssetEvent,
    Department,
    InstallationHistory,
    ScanObservation,
    SoftwareInstallation,
)
from patchledger.operational.models.inventory import (
    ASSET_TYPES,
    ENVIRONMENTS,
    EXPOSURES,
    LIFECYCLE_STATUSES,
)
from patchledger.operational.services.common import EventContext, nonempty

SNAPSHOT_FIELDS = (
    "hostname",
    "department_id",
    "owner_ref",
    "asset_type",
    "environment",
    "business_criticality",
    "exposure",
    "lifecycle_status",
    "registered_at",
    "retired_at",
)
MUTABLE_FIELDS = set(SNAPSHOT_FIELDS) - {"registered_at", "retired_at"}


def create_department(session: Session, *, code: str, name: str) -> Department:
    department = session.scalar(
        insert(Department)
        .values(code=nonempty(code, "code"), name=nonempty(name, "name"))
        .on_conflict_do_nothing(index_elements=["code"])
        .returning(Department)
    )
    if department is None:
        raise ConflictError("Department code already exists")
    return department


def get_department(session: Session, department_id: UUID) -> Department:
    department = session.get(Department, department_id)
    if department is None:
        raise NotFoundError("Department does not exist")
    return department


def _lock_department(session: Session, department_id: UUID) -> Department:
    department = session.scalar(
        select(Department)
        .where(Department.id == department_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if department is None:
        raise NotFoundError("Department does not exist")
    if department.retired_at is not None:
        raise InvalidOperationError("Department is retired")
    return department


def retire_department(
    session: Session, department_id: UUID, *, context: EventContext
) -> Department:
    department = _lock_department(session, department_id)
    if session.scalar(
        select(Asset.id)
        .where(
            Asset.department_id == department_id, Asset.lifecycle_status != "retired"
        )
        .limit(1)
    ):
        raise InvalidOperationError("Reassign or retire the department's assets first")
    latest = session.scalar(
        select(func.max(AssetEvent.occurred_at)).where(
            AssetEvent.asset_id.in_(
                select(AssetEvent.asset_id).where(
                    AssetEvent.department_id == department_id
                )
            )
        )
    )
    if latest is not None and context.occurred_at < latest:
        raise HistoricalConflictError(
            "Department retirement predates recorded asset history"
        )
    department.retired_at = context.occurred_at
    session.flush()
    return department


def get_asset(session: Session, asset_id: UUID) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset does not exist")
    return asset


def lock_asset(session: Session, asset_id: UUID) -> Asset:
    asset = session.scalar(
        select(Asset)
        .where(Asset.id == asset_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if asset is None:
        raise NotFoundError("Asset does not exist")
    return asset


def _validate_attributes(values: dict) -> None:
    for key, allowed in (
        ("asset_type", ASSET_TYPES),
        ("environment", ENVIRONMENTS),
        ("exposure", EXPOSURES),
        ("lifecycle_status", LIFECYCLE_STATUSES),
    ):
        if key in values and values[key] not in allowed:
            raise InvalidOperationError(f"Invalid {key}")
    if "business_criticality" in values:
        value = values["business_criticality"]
        if type(value) is not int or not 1 <= value <= 5:
            raise InvalidOperationError(
                "business_criticality must be an integer from 1 to 5"
            )
    if "hostname" in values:
        values["hostname"] = nonempty(values["hostname"], "hostname")
    if values.get("owner_ref") is not None:
        values["owner_ref"] = nonempty(values["owner_ref"], "owner_ref")


def _latest_event(
    session: Session, asset: Asset, context: EventContext
) -> AssetEvent | None:
    latest = session.scalar(
        select(AssetEvent)
        .where(AssetEvent.asset_id == asset.id)
        .order_by(AssetEvent.event_number.desc())
        .limit(1)
    )
    if latest is not None and context.occurred_at < latest.occurred_at:
        raise HistoricalConflictError("Backdated asset changes would rewrite history")
    return latest


def _snapshot(session, asset, context, event_type, number, reason):
    session.add(
        AssetEvent(
            asset_id=asset.id,
            event_number=number,
            event_type=event_type,
            occurred_at=context.occurred_at,
            actor_ref=context.actor_ref,
            source_key=context.source_key,
            is_synthetic=context.is_synthetic,
            reason=reason,
            **{field: getattr(asset, field) for field in SNAPSHOT_FIELDS},
        )
    )
    session.flush()


def register_asset(
    session: Session,
    *,
    asset_key: str,
    hostname: str,
    department_id: UUID,
    asset_type: str,
    environment: str,
    business_criticality: int,
    exposure: str,
    context: EventContext,
    owner_ref: str | None = None,
    lifecycle_status: str = "active",
) -> Asset:
    values = {
        "hostname": hostname,
        "department_id": department_id,
        "owner_ref": owner_ref,
        "asset_type": asset_type,
        "environment": environment,
        "business_criticality": business_criticality,
        "exposure": exposure,
        "lifecycle_status": lifecycle_status,
    }
    _validate_attributes(values)
    if lifecycle_status == "retired":
        raise InvalidOperationError("Register an asset before retiring it")
    _lock_department(session, department_id)
    asset = session.scalar(
        insert(Asset)
        .values(
            asset_key=nonempty(asset_key, "asset_key"),
            registered_at=context.occurred_at,
            **values,
        )
        .on_conflict_do_nothing(index_elements=["asset_key"])
        .returning(Asset)
    )
    if asset is None:
        raise ConflictError("Asset key already exists")
    _snapshot(session, asset, context, "registered", 1, None)
    return asset


def update_asset(
    session: Session,
    asset_id: UUID,
    *,
    changes: dict,
    context: EventContext,
    reason: str | None = None,
) -> Asset:
    values = dict(changes)
    if set(values) - MUTABLE_FIELDS:
        raise InvalidOperationError(
            "Only approved mutable asset attributes may be changed"
        )
    _validate_attributes(values)
    if values.get("lifecycle_status") == "retired":
        raise InvalidOperationError("Use retire_asset to retire an asset")
    # Department first; retirement holds this same row while checking assignments.
    if "department_id" in values:
        _lock_department(session, values["department_id"])
    asset = lock_asset(session, asset_id)
    if asset.lifecycle_status == "retired":
        raise InvalidOperationError("Retired assets cannot be modified")
    if (
        values.get("lifecycle_status") == "registered"
        and asset.lifecycle_status != "registered"
    ):
        raise InvalidOperationError(
            "An existing active/suspended asset cannot be registered again"
        )
    latest = _latest_event(session, asset, context)
    if all(getattr(asset, k) == v for k, v in values.items()):
        return asset
    for key, value in values.items():
        setattr(asset, key, value)
    _snapshot(
        session, asset, context, "attributes_changed", latest.event_number + 1, reason
    )
    return asset


def retire_asset(
    session: Session, asset_id: UUID, *, context: EventContext, reason: str
) -> Asset:
    reason = nonempty(reason, "reason")
    asset = lock_asset(session, asset_id)
    if asset.lifecycle_status == "retired":
        raise InvalidOperationError("Asset is already retired")
    latest = _latest_event(session, asset, context)
    if session.scalar(
        select(ScanObservation.id)
        .where(
            ScanObservation.asset_id == asset.id,
            ScanObservation.occurred_at >= context.occurred_at,
        )
        .limit(1)
    ):
        raise HistoricalConflictError(
            "Asset retirement would invalidate already-recorded assessment evidence"
        )
    history = (
        select(InstallationHistory)
        .join(SoftwareInstallation)
        .where(SoftwareInstallation.asset_id == asset_id)
    )
    if session.scalar(history.where(InstallationHistory.ended_at.is_(None)).limit(1)):
        raise InvalidOperationError(
            "Remove installed software explicitly before retiring the asset"
        )
    if session.scalar(
        history.where(InstallationHistory.ended_at > context.occurred_at).limit(1)
    ):
        raise HistoricalConflictError(
            "Asset retirement predates its software removal history"
        )
    asset.lifecycle_status = "retired"
    asset.retired_at = context.occurred_at
    _snapshot(session, asset, context, "retired", latest.event_number + 1, reason)
    return asset
