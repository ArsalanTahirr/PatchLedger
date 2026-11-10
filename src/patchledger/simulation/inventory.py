"""Service-only inventory writes with immutable historical receipts for replay."""

from datetime import timedelta
from itertools import batched

from sqlalchemy import select

from patchledger.operational.models import (
    Asset,
    AssetEvent,
    Department,
    InstallationHistory,
    SoftwareInstallation,
)
from patchledger.operational.services.assets import (
    create_department,
    register_asset,
    retire_asset,
    update_asset,
)
from patchledger.operational.services.common import EventContext
from patchledger.operational.services.software import (
    change_software_version,
    get_or_create_product,
    get_version_at,
    install_software,
    register_product_identifier,
    remove_software,
)
from patchledger.simulation.errors import ScenarioConflictError
from patchledger.simulation.fixtures import CATALOG


def context(config, when):
    return EventContext(when, f"simulator:{config.scenario}", config.source, True)


def get_asset(session, plan):
    return session.scalar(select(Asset).where(Asset.asset_key == plan.asset_key))


def get_installation(session, plan, slot):
    asset = get_asset(session, plan)
    installation = session.scalar(
        select(SoftwareInstallation).where(
            SoftwareInstallation.asset_id == asset.id,
            SoftwareInstallation.installation_key
            == f"slot:{slot}:{plan.products[slot]}",
        )
    )
    if installation is None:
        raise ScenarioConflictError("Expected scenario installation is missing")
    return installation


def check_scenario(session, config):
    first = session.scalar(
        select(Asset).where(Asset.asset_key == f"{config.prefix}asset:000000")
    )
    if first is None:
        if session.scalar(
            select(Asset.id)
            .where(Asset.asset_key.startswith(config.prefix, autoescape=True))
            .limit(1)
        ):
            raise ScenarioConflictError(
                "Scenario anchor is missing while other scenario assets exist"
            )
        return
    registration = session.scalar(
        select(AssetEvent).where(
            AssetEvent.asset_id == first.id, AssetEvent.event_number == 1
        )
    )
    if (
        registration is None
        or registration.source_key != config.source
        or not registration.is_synthetic
    ):
        raise ScenarioConflictError(
            "Scenario identifier already belongs to a different configuration or generator version"
        )


def _department_code(config, name):
    return f"{config.prefix}department:{name}"


def _register(session, config, plan, departments):
    values = {
        "hostname": plan.hostname,
        "department_id": departments[plan.department].id,
        "owner_ref": f"simulator:{config.scenario}:{plan.department}",
        "asset_type": plan.asset_type,
        "environment": plan.environment,
        "business_criticality": plan.criticality,
        "exposure": plan.exposure,
        "lifecycle_status": "active",
    }
    existing = get_asset(session, plan)
    if existing is not None:
        registration = session.scalar(
            select(AssetEvent).where(
                AssetEvent.asset_id == existing.id, AssetEvent.event_number == 1
            )
        )
        if (
            registration is None
            or registration.source_key != config.source
            or registration.occurred_at != config.start
            or any(getattr(registration, k) != v for k, v in values.items())
        ):
            raise ScenarioConflictError(
                "Asset registration does not match its immutable scenario plan"
            )
        return
    register_asset(
        session,
        asset_key=plan.asset_key,
        context=context(config, config.start),
        **values,
    )


def initialize(sessions, config, plans):
    # The first batch atomically establishes catalog, departments and registration
    # provenance. Its first asset is the natural configuration anchor, not a fake task.
    for batch in batched(plans, 25):
        with sessions.begin() as session:
            check_scenario(session, config)
            departments = {}
            for name in sorted(config.departments):
                code = _department_code(config, name)
                department = session.scalar(
                    select(Department).where(Department.code == code)
                )
                if department is None:
                    department = create_department(session, code=code, name=name)
                elif department.name != name or department.retired_at is not None:
                    raise ScenarioConflictError(
                        "Scenario department has been changed externally"
                    )
                departments[name] = department
            for fixture in CATALOG:
                product = get_or_create_product(
                    session,
                    product_key=f"{config.prefix}product:{fixture.key}",
                    name=fixture.name,
                    publisher_name=fixture.publisher,
                    ecosystem="synthetic-fixture",
                )
                register_product_identifier(
                    session,
                    product.id,
                    scheme="vendor",
                    identifier=f"synthetic:catalog-v1:{fixture.key}",
                    source_ref=config.source,
                )
            for plan in batch:
                _register(session, config, plan, departments)
    for batch in batched(plans, 25):
        with sessions.begin() as session:
            for plan in batch:
                machine = get_asset(session, plan)
                for slot, product_key in enumerate(plan.products):
                    from patchledger.operational.models import SoftwareProduct

                    product = session.scalar(
                        select(SoftwareProduct).where(
                            SoftwareProduct.product_key
                            == f"{config.prefix}product:{product_key}"
                        )
                    )
                    key = f"slot:{slot}:{product_key}"
                    installation = session.scalar(
                        select(SoftwareInstallation).where(
                            SoftwareInstallation.asset_id == machine.id,
                            SoftwareInstallation.installation_key == key,
                        )
                    )
                    when = config.start + timedelta(seconds=1)
                    if installation is not None:
                        period = session.scalar(
                            select(InstallationHistory).where(
                                InstallationHistory.installation_id == installation.id,
                                InstallationHistory.started_at == when,
                            )
                        )
                        if (
                            period is None
                            or period.version != plan.versions[slot]
                            or period.source_key != config.source
                            or installation.product_id != product.id
                        ):
                            raise ScenarioConflictError(
                                "Initial installation receipt differs from the scenario"
                            )
                        continue
                    install_software(
                        session,
                        asset_id=machine.id,
                        product_id=product.id,
                        installation_key=key,
                        version=plan.versions[slot],
                        context=context(config, when),
                        context_description="Synthetic fixture installation; no validated CPE identity",
                    )


def mutate_inventory(session, config, plan, event, kind, version=None):
    slot = 0 if kind == "downgrade" else len(plan.products) - 1
    installation = get_installation(session, plan, slot)
    ctx = context(config, event.at)
    if kind == "reinstall":
        existing = session.scalar(
            select(InstallationHistory).where(
                InstallationHistory.installation_id == installation.id,
                InstallationHistory.started_at == event.at,
            )
        )
        if existing is not None:
            if (
                existing.version != plan.versions[slot]
                or existing.source_key != config.source
            ):
                raise ScenarioConflictError("Reinstallation receipt conflicts")
            return
        install_software(
            session,
            asset_id=installation.asset_id,
            product_id=installation.product_id,
            installation_key=installation.installation_key,
            version=plan.versions[slot],
            context=ctx,
        )
        return
    before = get_version_at(
        session, installation.id, at=event.at - timedelta(microseconds=1)
    )
    if before is None:
        raise ScenarioConflictError(
            "Inventory operation has no historical before-version"
        )
    reason = "removal" if kind == "remove" else "downgrade"
    if before.ended_at == event.at:
        if before.end_reason != reason or before.end_source_key != config.source:
            raise ScenarioConflictError("Inventory closure receipt conflicts")
        if kind == "downgrade":
            after = get_version_at(session, installation.id, at=event.at)
            if (
                after is None
                or after.version != version
                or after.source_key != config.source
            ):
                raise ScenarioConflictError("Downgrade receipt conflicts")
        return
    if kind == "remove":
        remove_software(
            session, installation.id, expected_history_id=before.id, context=ctx
        )
    else:
        change_software_version(
            session,
            installation.id,
            version=version,
            change_kind="downgrade",
            expected_history_id=before.id,
            context=ctx,
        )


def update_lifecycle(session, config, plan, event):
    machine = get_asset(session, plan)
    when = event.at + timedelta(seconds=1) if event.kind == "retired" else event.at
    existing = session.scalar(
        select(AssetEvent).where(
            AssetEvent.asset_id == machine.id, AssetEvent.occurred_at == when
        )
    )
    if existing is not None:
        matches = (
            existing.lifecycle_status == "retired"
            if event.kind == "retired"
            else existing.lifecycle_status == "suspended"
            if event.kind == "suspended"
            else existing.business_criticality == plan.criticality % 5 + 1
        )
        if (
            existing.source_key != config.source
            or not existing.is_synthetic
            or not matches
        ):
            raise ScenarioConflictError("Asset event receipt has unexpected provenance")
        return
    if event.kind == "retired":
        installations = list(
            session.scalars(
                select(SoftwareInstallation)
                .where(SoftwareInstallation.asset_id == machine.id)
                .order_by(SoftwareInstallation.installation_key)
            )
        )
        for installation in installations:
            period = get_version_at(session, installation.id, at=event.at)
            if period is not None:
                remove_software(
                    session,
                    installation.id,
                    expected_history_id=period.id,
                    context=context(config, event.at),
                )
        retire_asset(
            session,
            machine.id,
            context=context(config, when),
            reason="Synthetic end-of-scenario retirement",
        )
    else:
        changes = (
            {"lifecycle_status": "suspended"}
            if event.kind == "suspended"
            else {"business_criticality": plan.criticality % 5 + 1}
        )
        update_asset(
            session,
            machine.id,
            changes=changes,
            context=context(config, when),
            reason="Synthetic organizational lifecycle",
        )
