"""Catalog and installation lifecycle operations; no version ordering is inferred."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from patchledger.operational.exceptions import (
    ConflictError,
    HistoricalConflictError,
    InvalidOperationError,
    NotFoundError,
    StaleVersionError,
)
from patchledger.operational.models import (
    InstallationHistory,
    ProductIdentifier,
    ScanObservation,
    SoftwareInstallation,
    SoftwareProduct,
    VerificationResult,
    VulnerabilityFinding,
)
from patchledger.operational.services.assets import lock_asset
from patchledger.operational.services.common import (
    EventContext,
    effective_time,
    nonempty,
)


def get_or_create_product(
    session: Session,
    *,
    product_key: str,
    name: str,
    publisher_name: str,
    ecosystem: str,
) -> SoftwareProduct:
    values = {
        k: nonempty(v, k)
        for k, v in {
            "product_key": product_key,
            "name": name,
            "publisher_name": publisher_name,
            "ecosystem": ecosystem,
        }.items()
    }
    product = session.scalar(
        insert(SoftwareProduct)
        .values(**values)
        .on_conflict_do_nothing(index_elements=["product_key"])
        .returning(SoftwareProduct)
    )
    if product is None:
        product = session.scalar(
            select(SoftwareProduct)
            .where(SoftwareProduct.product_key == values["product_key"])
            .execution_options(populate_existing=True)
        )
        if any(getattr(product, k) != v for k, v in values.items()):
            raise ConflictError("Product key exists with different catalog attributes")
    return product


def register_product_identifier(
    session: Session,
    product_id: UUID,
    *,
    scheme: str,
    identifier: str,
    source_ref: str | None = None,
) -> ProductIdentifier:
    if session.get(SoftwareProduct, product_id) is None:
        raise NotFoundError("Product does not exist")
    if scheme not in ("cpe23", "purl", "vendor"):
        raise InvalidOperationError("Unsupported product identifier scheme")
    identifier = nonempty(identifier, "identifier")
    record = session.scalar(
        insert(ProductIdentifier)
        .values(
            product_id=product_id,
            scheme=scheme,
            identifier=identifier,
            source_ref=source_ref,
        )
        .on_conflict_do_nothing(index_elements=["product_id", "scheme", "identifier"])
        .returning(ProductIdentifier)
    )
    if record is None:
        record = session.scalar(
            select(ProductIdentifier).where(
                ProductIdentifier.product_id == product_id,
                ProductIdentifier.scheme == scheme,
                ProductIdentifier.identifier == identifier,
            )
        )
        if record.source_ref != source_ref:
            raise ConflictError(
                "Identifier is already registered with different provenance"
            )
    return record


def _get_installation(session, installation_id):
    installation = session.get(SoftwareInstallation, installation_id)
    if installation is None:
        raise NotFoundError("Installation does not exist")
    return installation


def _lock_installation(session, installation_id, context, *, removing=False):
    installation = _get_installation(session, installation_id)
    # All lifecycle writers lock asset before installation, including asset retirement.
    asset = lock_asset(session, installation.asset_id)
    if asset.lifecycle_status == "retired" or (
        not removing and asset.lifecycle_status == "suspended"
    ):
        raise InvalidOperationError(
            "Asset lifecycle does not permit this software change"
        )
    if context.occurred_at < asset.registered_at:
        raise HistoricalConflictError("Installation cannot predate asset registration")
    installation = session.scalar(
        select(SoftwareInstallation)
        .where(SoftwareInstallation.id == installation_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return installation


def get_current_version(
    session: Session, installation_id: UUID
) -> InstallationHistory | None:
    _get_installation(session, installation_id)
    return session.scalar(
        select(InstallationHistory)
        .where(
            InstallationHistory.installation_id == installation_id,
            InstallationHistory.ended_at.is_(None),
        )
        .execution_options(populate_existing=True)
    )


def get_installation_history(
    session: Session, installation_id: UUID
) -> list[InstallationHistory]:
    _get_installation(session, installation_id)
    return list(
        session.scalars(
            select(InstallationHistory)
            .where(InstallationHistory.installation_id == installation_id)
            .order_by(InstallationHistory.started_at)
            .execution_options(populate_existing=True)
        )
    )


def get_version_at(
    session: Session, installation_id: UUID, *, at: datetime
) -> InstallationHistory | None:
    at = effective_time(at)
    _get_installation(session, installation_id)
    return session.execute(
        select(InstallationHistory)
        .where(
            InstallationHistory.installation_id == installation_id,
            InstallationHistory.started_at <= at,
            or_(
                InstallationHistory.ended_at.is_(None),
                InstallationHistory.ended_at > at,
            ),
        )
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()


def _new_period(session, installation_id, version, context, start_basis, **qualifiers):
    if start_basis not in ("actual", "first_observed"):
        raise InvalidOperationError("Invalid installation start basis")
    period = InstallationHistory(
        installation_id=installation_id,
        version=nonempty(version, "version"),
        started_at=context.occurred_at,
        start_basis=start_basis,
        actor_ref=context.actor_ref,
        source_key=context.source_key,
        is_synthetic=context.is_synthetic,
        **qualifiers,
    )
    session.add(period)
    session.flush()
    return period


def install_software(
    session: Session,
    *,
    asset_id: UUID,
    product_id: UUID,
    installation_key: str,
    version: str,
    context: EventContext,
    context_description: str | None = None,
    start_basis: str = "actual",
    build: str | None = None,
    platform: str | None = None,
    architecture: str | None = None,
) -> InstallationHistory:
    version = nonempty(version, "version")
    installation_key = nonempty(installation_key, "installation_key")
    asset = lock_asset(session, asset_id)
    if asset.lifecycle_status not in ("registered", "active"):
        raise InvalidOperationError("Asset is not eligible for software installation")
    if context.occurred_at < asset.registered_at:
        raise HistoricalConflictError("Installation cannot predate asset registration")
    product = session.get(SoftwareProduct, product_id)
    if product is None:
        raise NotFoundError("Product does not exist")
    if product.retired_at is not None:
        raise InvalidOperationError("Product is retired")
    installation = session.scalar(
        select(SoftwareInstallation)
        .where(
            SoftwareInstallation.asset_id == asset_id,
            SoftwareInstallation.installation_key == installation_key,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if installation is None:
        installation = SoftwareInstallation(
            asset_id=asset_id,
            product_id=product_id,
            installation_key=installation_key,
            context_description=context_description,
        )
        session.add(installation)
        session.flush()
    elif installation.product_id != product_id:
        raise ConflictError(
            "A different product requires a new installation identity/key"
        )
    else:
        if get_current_version(session, installation.id) is not None:
            raise ConflictError("Installation already has a current version")
        last_end = session.scalar(
            select(func.max(InstallationHistory.ended_at)).where(
                InstallationHistory.installation_id == installation.id
            )
        )
        if last_end is not None and context.occurred_at < last_end:
            raise HistoricalConflictError(
                "Backdated reinstallation would rewrite established history"
            )
        if session.scalar(
            select(VerificationResult.id)
            .join(
                VulnerabilityFinding,
                VulnerabilityFinding.id == VerificationResult.finding_id,
            )
            .where(
                VulnerabilityFinding.installation_id == installation.id,
                VerificationResult.verdict == "absence_confirmed",
                VerificationResult.accepted,
                VerificationResult.evidence_at >= context.occurred_at,
            )
            .limit(1)
        ):
            raise HistoricalConflictError(
                "Backdated reinstallation would contradict accepted absence evidence"
            )
    return _new_period(
        session,
        installation.id,
        version,
        context,
        start_basis,
        build=build,
        platform=platform,
        architecture=architecture,
    )


def _close_period(session, period, context, reason, end_basis):
    if end_basis not in ("actual", "first_observed_absent"):
        raise InvalidOperationError("Invalid installation end basis")
    period.ended_at = context.occurred_at
    period.end_basis = end_basis
    period.end_reason = reason
    period.ended_recorded_at = func.clock_timestamp()
    period.end_actor_ref = context.actor_ref
    period.end_source_key = context.source_key
    period.end_is_synthetic = context.is_synthetic
    session.flush()


def _expected_period(session, installation_id, expected_history_id, context):
    current = get_current_version(session, installation_id)
    if current is None or current.id != expected_history_id:
        raise StaleVersionError(
            "Current installation history differs from the expected ID"
        )
    if context.occurred_at <= current.started_at:
        raise HistoricalConflictError(
            "Change must follow the current version's start time"
        )
    if session.scalar(
        select(ScanObservation.id)
        .where(
            ScanObservation.installation_history_id == current.id,
            ScanObservation.outcome != "target_absent",
            ScanObservation.occurred_at >= context.occurred_at,
        )
        .limit(1)
    ):
        raise HistoricalConflictError(
            "Version closure would invalidate already-recorded assessment evidence"
        )
    # Reject a conflicting closed/future period even if it was inserted outside services.
    if session.scalar(
        select(VerificationResult.id)
        .where(
            VerificationResult.assessed_history_id == current.id,
            VerificationResult.evidence_at >= context.occurred_at,
        )
        .limit(1)
    ):
        raise HistoricalConflictError(
            "Version closure would invalidate recorded verification evidence"
        )
    if session.scalar(
        select(InstallationHistory.id)
        .where(
            InstallationHistory.installation_id == installation_id,
            InstallationHistory.id != current.id,
            or_(
                InstallationHistory.ended_at.is_(None),
                InstallationHistory.ended_at > current.started_at,
            ),
        )
        .limit(1)
    ):
        raise HistoricalConflictError(
            "Existing installation history contains conflicting periods"
        )
    return current


def change_software_version(
    session: Session,
    installation_id: UUID,
    *,
    version: str,
    change_kind: str,
    expected_history_id: UUID,
    context: EventContext,
    build: str | None = None,
    platform: str | None = None,
    architecture: str | None = None,
) -> InstallationHistory:
    """Caller declares upgrade/downgrade; versions are opaque strings, not semver."""
    if change_kind not in ("upgrade", "downgrade"):
        raise InvalidOperationError("change_kind must be upgrade or downgrade")
    version = nonempty(version, "version")
    _lock_installation(session, installation_id, context)
    current = _expected_period(session, installation_id, expected_history_id, context)
    if (current.version, current.build, current.platform, current.architecture) == (
        version,
        build,
        platform,
        architecture,
    ):
        raise InvalidOperationError("Version and qualifiers are unchanged")
    _close_period(session, current, context, change_kind, "actual")
    return _new_period(
        session,
        installation_id,
        version,
        context,
        "actual",
        build=build,
        platform=platform,
        architecture=architecture,
    )


def remove_software(
    session: Session,
    installation_id: UUID,
    *,
    expected_history_id: UUID,
    context: EventContext,
    end_basis: str = "actual",
) -> InstallationHistory:
    _lock_installation(session, installation_id, context, removing=True)
    current = _expected_period(session, installation_id, expected_history_id, context)
    _close_period(session, current, context, "removal", end_basis)
    return current
