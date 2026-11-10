"""Fixture-backed assessments; no applicability inference from names or missing tests."""

from datetime import timedelta

from sqlalchemy import select

from patchledger.operational.models import (
    ScanObservation,
    VulnerabilityFinding,
)
from patchledger.operational.services.assessment import (
    SLAPolicy,
    create_scan_run,
    record_observation,
)
from patchledger.operational.services.software import get_version_at
from patchledger.simulation.fixtures import CATALOG
from patchledger.simulation.inventory import context, get_asset, get_installation
from patchledger.simulation.random_state import random_stream

FIXTURES = {fixture.key: fixture for fixture in CATALOG}


def scan_asset(session, config, plan, when, key, *, definitive=False):
    rng = random_stream(config, f"scan:{key}")
    draw = rng.random()
    status = (
        "completed"
        if definitive
        else (
            "failed"
            if draw < config.failed_scan_probability
            else "partial"
            if draw < config.failed_scan_probability + config.partial_scan_probability
            else "completed"
        )
    )
    machine = get_asset(session, plan)
    installations = [
        get_installation(session, plan, slot) for slot in range(len(plan.products))
    ]
    run = create_scan_run(
        session,
        asset_id=machine.id,
        source_key=config.source,
        external_run_key=key,
        batch_key=f"{config.scenario}:{when.date().isoformat()}",
        producer_version="synthetic-catalog-v1",
        is_synthetic=True,
        scope={
            "applicability": "synthetic-fixture-only",
            "fixture": "catalog-v1",
            "inventory_coverage": {
                "complete": status == "completed",
                "installation_ids": [str(i.id) for i in installations],
            },
        },
        status=status,
        started_at=when,
        completed_at=when + timedelta(seconds=20),
    )
    for slot, installation in enumerate(installations):
        period = get_version_at(session, installation.id, at=when)
        fixture = FIXTURES[plan.products[slot]]
        for cve in fixture.cves:
            outcome = fixture.outcome(cve, period.version if period else None)
            if not definitive and (
                rng.random() < config.inconclusive_probability
                or status == "failed"
                and rng.random() < 0.6
            ):
                outcome = "inconclusive"
            record_observation(
                session,
                scan_run_id=run.id,
                external_observation_key=f"slot:{slot}:{cve}",
                cve_id=cve,
                outcome=outcome,
                context=context(config, when),
                test_ref=f"synthetic:catalog-v1:{fixture.key}:{cve}",
                installation_id=installation.id,
                installation_history_id=period.id if period else None,
                evidence={
                    "applicability": "synthetic-fixture-only",
                    "fixture": "catalog-v1",
                    "version": period.version if period else None,
                },
                sla_policy=SLAPolicy(
                    f"synthetic:{config.scenario}:sla-{config.sla_days}d",
                    config.sla_days * 86400,
                ),
            )
    return run


def findings_at(session, config, plan, when):
    installation = get_installation(session, plan, 0)
    return list(
        session.scalars(
            select(VulnerabilityFinding)
            .where(
                VulnerabilityFinding.asset_id == installation.asset_id,
                VulnerabilityFinding.installation_id == installation.id,
                VulnerabilityFinding.first_detected_at <= when,
            )
            .order_by(VulnerabilityFinding.cve_id)
        )
    )


def observation_for(session, run, installation, cve):
    return session.scalar(
        select(ScanObservation).where(
            ScanObservation.scan_run_id == run.id,
            ScanObservation.installation_id == installation.id,
            ScanObservation.cve_id == cve,
        )
    )
