"""Scenario-scoped persisted counts. Attempts/plans are never passed off as data."""

from collections import defaultdict
from itertools import pairwise

from sqlalchemy import select

from patchledger.operational.models import (
    Asset,
    AssetEvent,
    Department,
    FindingEvent,
    InstallationHistory,
    ProductIdentifier,
    RemediationEvent,
    RemediationTask,
    ScanObservation,
    ScanRun,
    SoftwareInstallation,
    SoftwareProduct,
    TaskFinding,
    VerificationResult,
    VulnerabilityFinding,
)


def load_records(session, config):
    assets = select(Asset.id).where(
        Asset.asset_key.startswith(config.prefix, autoescape=True)
    )
    products = select(SoftwareProduct.id).where(
        SoftwareProduct.product_key.startswith(config.prefix, autoescape=True)
    )
    installations = select(SoftwareInstallation.id).where(
        SoftwareInstallation.asset_id.in_(assets)
    )
    scans = select(ScanRun.id).where(ScanRun.asset_id.in_(assets))
    findings = select(VulnerabilityFinding.id).where(
        VulnerabilityFinding.asset_id.in_(assets)
    )
    tasks = select(RemediationTask.id).where(
        RemediationTask.task_key.startswith(config.prefix, autoescape=True)
    )
    queries = {
        Department: Department.code.startswith(config.prefix, autoescape=True),
        Asset: Asset.id.in_(assets),
        AssetEvent: AssetEvent.asset_id.in_(assets),
        SoftwareProduct: SoftwareProduct.id.in_(products),
        ProductIdentifier: ProductIdentifier.product_id.in_(products),
        SoftwareInstallation: SoftwareInstallation.id.in_(installations),
        InstallationHistory: InstallationHistory.installation_id.in_(installations),
        ScanRun: ScanRun.id.in_(scans),
        ScanObservation: ScanObservation.scan_run_id.in_(scans),
        VulnerabilityFinding: VulnerabilityFinding.id.in_(findings),
        FindingEvent: FindingEvent.finding_id.in_(findings),
        RemediationTask: RemediationTask.id.in_(tasks),
        TaskFinding: TaskFinding.task_id.in_(tasks),
        RemediationEvent: RemediationEvent.task_id.in_(tasks),
        VerificationResult: VerificationResult.finding_id.in_(findings),
    }
    return {
        model.__tablename__: list(session.scalars(select(model).where(condition)))
        for model, condition in queries.items()
    }


def sla_breaches(events, as_of):
    timelines = defaultdict(list)
    for event in events:
        timelines[event.finding_id].append(event)
    breaches = 0
    for timeline in timelines.values():
        opening = None
        for event in sorted(timeline, key=lambda row: row.event_number):
            if event.event_type in {"opened", "reopened"}:
                opening = event
            elif event.event_type == "resolved" and opening is not None:
                if opening.sla_deadline is not None and opening.sla_deadline < min(
                    event.occurred_at, as_of
                ):
                    breaches += 1
                opening = None
        if (
            opening is not None
            and opening.sla_deadline is not None
            and opening.sla_deadline < as_of
        ):
            breaches += 1
    return breaches


def summarize(config, records):
    history = records["installation_history"]
    actions = [
        event
        for event in records["remediation_events"]
        if event.event_type == "action_recorded"
    ]
    periods = defaultdict(list)
    for row in history:
        periods[row.installation_id].append(row)
    reinstalls = sum(
        sum(
            1
            for previous, _ in pairwise(sorted(rows, key=lambda p: p.started_at))
            if previous.end_reason == "removal"
        )
        for rows in periods.values()
    )
    counts = {table: len(rows) for table, rows in records.items()}
    counts.update(
        {
            "upgrades": sum(p.end_reason == "upgrade" for p in history),
            "downgrades": sum(p.end_reason == "downgrade" for p in history),
            "removals": sum(p.end_reason == "removal" for p in history),
            "current_installations": sum(p.ended_at is None for p in history),
            "reinstallations": reinstalls,
            "finding_reopenings": sum(
                e.event_type == "reopened" for e in records["finding_events"]
            ),
            "successful_actions": sum(e.action_outcome == "succeeded" for e in actions),
            "failed_actions": sum(e.action_outcome == "failed" for e in actions),
            "verified_resolutions": sum(
                v.accepted and v.verdict == "absence_confirmed"
                for v in records["verification_results"]
            ),
            "unsuccessful_verifications": sum(
                not v.accepted for v in records["verification_results"]
            ),
            "unresolved_findings": sum(
                f.status == "open" for f in records["vulnerability_findings"]
            ),
            "closed_tasks": sum(
                t.status == "closed" for t in records["remediation_tasks"]
            ),
            "retired_assets": sum(
                a.lifecycle_status == "retired" for a in records["assets"]
            ),
            "sla_breached_occurrences": sla_breaches(
                records["finding_events"], config.end
            ),
        }
    )
    return {
        "scenario": config.scenario,
        "seed": config.seed,
        "start": config.start.isoformat(),
        "end_exclusive": config.end.isoformat(),
        "fingerprint": config.fingerprint,
        "applicability": "synthetic-fixture-only; not validated NVD matching",
        "counts": counts,
    }
