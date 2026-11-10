"""Idempotent assessment ingestion and finding reconciliation; caller owns commit."""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from patchledger.operational.exceptions import (
    HistoricalConflictError,
    IdempotencyConflictError,
    InvalidEvidenceError,
    InvalidOperationError,
    NotFoundError,
)
from patchledger.operational.models import (
    Asset,
    FindingEvent,
    InstallationHistory,
    ScanObservation,
    ScanRun,
    SoftwareInstallation,
    VulnerabilityFinding,
)
from patchledger.operational.models.assessment import (
    CVE_PATTERN,
    EVIDENCE_LIMIT,
    OUTCOMES,
    SCAN_STATUSES,
)
from patchledger.operational.services.common import (
    EventContext,
    effective_time,
    nonempty,
)

TERMINAL_STATUSES = {"completed", "partial", "failed", "cancelled"}


@dataclass(frozen=True)
class SLAPolicy:
    """Caller-selected, versioned policy reference; no prioritization engine."""

    policy_ref: str
    target_seconds: int

    def __post_init__(self):
        object.__setattr__(self, "policy_ref", nonempty(self.policy_ref, "policy_ref"))
        if (
            type(self.target_seconds) is not int
            or not 0 < self.target_seconds <= 2147483647
        ):
            raise InvalidOperationError(
                "SLA target must be positive integer seconds within PostgreSQL integer range"
            )


def _json_object(value, field):
    if not isinstance(value, dict):
        raise InvalidOperationError(f"{field} must be a JSON object")
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode()) > EVIDENCE_LIMIT:
            raise InvalidOperationError(f"{field} exceeds {EVIDENCE_LIMIT} bytes")
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidOperationError(f"{field} must contain valid JSON values") from exc


def _digest(values):
    def encode(value):
        if isinstance(value, datetime):
            return effective_time(value).isoformat()
        if isinstance(value, UUID):
            return str(value)
        raise TypeError("Unsupported assessment payload value")

    return hashlib.sha256(
        json.dumps(
            values,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            default=encode,
        ).encode()
    ).hexdigest()


def _scan_times(status, started_at, completed_at):
    if status not in SCAN_STATUSES:
        raise InvalidOperationError("Invalid scan status")
    start = effective_time(started_at) if started_at is not None else None
    end = effective_time(completed_at) if completed_at is not None else None
    if status == "queued" and (start is not None or end is not None):
        raise InvalidOperationError("Queued scans have no execution timestamps")
    if status == "running" and (start is None or end is not None):
        raise InvalidOperationError("Running scans require only a start timestamp")
    if status in {"completed", "partial", "failed"} and (start is None or end is None):
        raise InvalidOperationError(
            "Finished scans require start and completion timestamps"
        )
    if status == "cancelled" and end is None:
        raise InvalidOperationError("Cancellation requires a completion timestamp")
    if start is not None and end is not None and end < start:
        raise HistoricalConflictError("Scan completion cannot precede its start")
    return start, end


def create_scan_run(
    session: Session,
    *,
    asset_id: UUID,
    source_key: str,
    external_run_key: str,
    producer_version: str,
    is_synthetic: bool,
    scope: dict,
    status: str = "queued",
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    batch_key: str | None = None,
) -> ScanRun:
    """The source/run/asset key identifies one execution; retries compare creation inputs."""
    start, end = _scan_times(status, started_at, completed_at)
    if type(is_synthetic) is not bool:
        raise InvalidOperationError("is_synthetic must be explicit boolean provenance")
    values = {
        "asset_id": asset_id,
        "source_key": nonempty(source_key, "source_key"),
        "external_run_key": nonempty(external_run_key, "external_run_key"),
        "producer_version": nonempty(producer_version, "producer_version"),
        "is_synthetic": is_synthetic,
        "scope": _json_object(scope, "scope"),
        "status": status,
        "started_at": start,
        "completed_at": end,
        "batch_key": nonempty(batch_key, "batch_key")
        if batch_key is not None
        else None,
    }
    digest = _digest(values)
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Scan asset does not exist")
    if any(t is not None and t < asset.registered_at for t in (start, end)):
        raise HistoricalConflictError("Scan cannot start before asset registration")
    scan = session.scalar(
        insert(ScanRun)
        .values(**values, request_digest=digest)
        .on_conflict_do_nothing(
            index_elements=["source_key", "external_run_key", "asset_id"]
        )
        .returning(ScanRun)
    )
    if scan is None:
        scan = session.scalar(
            select(ScanRun)
            .where(
                ScanRun.source_key == values["source_key"],
                ScanRun.external_run_key == values["external_run_key"],
                ScanRun.asset_id == asset_id,
            )
            .execution_options(populate_existing=True)
        )
        if scan.request_digest != digest:
            raise IdempotencyConflictError(
                "Scan key already exists with different creation content"
            )
    return scan


def _lock_scan(session, scan_run_id):
    scan = session.scalar(
        select(ScanRun)
        .where(ScanRun.id == scan_run_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scan is None:
        raise NotFoundError("Scan run does not exist")
    return scan


def set_scan_status(
    session: Session,
    scan_run_id: UUID,
    *,
    status: str,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> ScanRun:
    """Queued -> running/cancelled; running -> terminal. Terminal runs are final."""
    scan = _lock_scan(session, scan_run_id)
    start, end = _scan_times(
        status, started_at if started_at is not None else scan.started_at, completed_at
    )
    if (scan.status, scan.started_at, scan.completed_at) == (status, start, end):
        return scan
    allowed = {"queued": {"running", "cancelled"}, "running": TERMINAL_STATUSES}
    if status not in allowed.get(scan.status, set()):
        raise InvalidOperationError("Unsupported scan status transition")
    if scan.started_at is not None and start != scan.started_at:
        raise HistoricalConflictError("A scan's established start time cannot change")
    asset = session.get(Asset, scan.asset_id)
    if any(t is not None and t < asset.registered_at for t in (start, end)):
        raise HistoricalConflictError("Scan cannot start before asset registration")
    latest = session.scalar(
        select(func.max(ScanObservation.occurred_at)).where(
            ScanObservation.scan_run_id == scan.id
        )
    )
    if end is not None and latest is not None and latest > end:
        raise HistoricalConflictError("Scan completion predates recorded evidence")
    scan.status, scan.started_at, scan.completed_at = status, start, end
    session.flush()
    return scan


def _validate_target(session, scan, installation_id, history_id, outcome, at):
    if scan.started_at is None or scan.status == "queued":
        raise InvalidEvidenceError("An unstarted scan cannot produce observations")
    if at < scan.started_at or (
        scan.completed_at is not None and at > scan.completed_at
    ):
        raise InvalidEvidenceError("Evidence timestamp is outside scan execution")
    # Inventory changes/retirement lock this parent exclusively. Shared readers
    # remain concurrent while protecting the assessed lifetime/version snapshot.
    asset = session.scalar(
        select(Asset)
        .where(Asset.id == scan.asset_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    if at < asset.registered_at or (
        asset.retired_at is not None and at >= asset.retired_at
    ):
        raise InvalidEvidenceError(
            "Evidence is outside the asset's registered lifetime"
        )
    if installation_id is None:
        if history_id is not None:
            raise InvalidEvidenceError("Historical version requires an installation")
        return
    installation = session.get(
        SoftwareInstallation, installation_id, populate_existing=True
    )
    if installation is None or installation.asset_id != scan.asset_id:
        raise InvalidEvidenceError("Installation does not belong to scan asset")
    if outcome == "affected" and history_id is None:
        raise InvalidEvidenceError(
            "Affected installation evidence requires the exact historical version"
        )
    if history_id is not None:
        period = session.get(InstallationHistory, history_id, populate_existing=True)
        if period is None or period.installation_id != installation_id:
            raise InvalidEvidenceError(
                "Historical version does not belong to installation"
            )
        if outcome == "target_absent":
            if period.ended_at is None or at < period.ended_at:
                raise InvalidEvidenceError(
                    "Target absence contradicts the referenced version period"
                )
        elif at < period.started_at or (
            period.ended_at is not None and at >= period.ended_at
        ):
            raise InvalidEvidenceError(
                "Historical version was not present at evidence time"
            )


def _sla_values(policy, opening):
    if policy is None:
        return {
            "sla_policy_ref": None,
            "sla_target_seconds": None,
            "sla_deadline": None,
        }
    if not isinstance(policy, SLAPolicy):
        raise InvalidOperationError("sla_policy must be an SLAPolicy or None")
    try:
        deadline = opening + timedelta(seconds=policy.target_seconds)
    except OverflowError as exc:
        raise InvalidOperationError("SLA deadline exceeds timestamp range") from exc
    return {
        "sla_policy_ref": policy.policy_ref,
        "sla_target_seconds": policy.target_seconds,
        "sla_deadline": deadline,
    }


def _opening_event(session, finding, context, operation_id, event_type, number):
    session.add(
        FindingEvent(
            finding_id=finding.id,
            event_number=number,
            operation_id=operation_id,
            event_type=event_type,
            status_after="open",
            occurred_at=context.occurred_at,
            actor_ref=context.actor_ref,
            source_key=context.source_key,
            is_synthetic=context.is_synthetic,
            reason="Positive assessment evidence"
            if event_type == "opened"
            else "Positive evidence after verified resolution",
            sla_policy_ref=finding.sla_policy_ref,
            sla_target_seconds=finding.sla_target_seconds,
            sla_deadline=finding.sla_deadline,
        )
    )


def _reconcile_positive(
    session, scan, installation_id, cve_id, context, operation_id, policy
):
    at = context.occurred_at
    finding = session.scalar(
        insert(VulnerabilityFinding)
        .values(
            asset_id=scan.asset_id,
            installation_id=installation_id,
            cve_id=cve_id,
            status="open",
            first_detected_at=at,
            last_observed_at=at,
            current_opened_at=at,
            **_sla_values(policy, at),
        )
        .on_conflict_do_nothing(constraint="uq_findings_scope_cve")
        .returning(VulnerabilityFinding)
    )
    if finding is not None:
        _opening_event(session, finding, context, operation_id, "opened", 1)
        return finding
    # Unique insertion serializes concurrent first detections, including null installation.
    finding = session.scalar(
        select(VulnerabilityFinding)
        .where(
            VulnerabilityFinding.asset_id == scan.asset_id,
            VulnerabilityFinding.installation_id.is_not_distinct_from(installation_id),
            VulnerabilityFinding.cve_id == cve_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    events = list(
        session.scalars(
            select(FindingEvent)
            .where(FindingEvent.finding_id == finding.id)
            .order_by(FindingEvent.event_number)
        )
    )
    if not events or at < finding.first_detected_at:
        raise HistoricalConflictError(
            "Evidence predates established opening history; manual reconciliation required"
        )
    # Previously open periods accept late evidence without changing lifecycle events.
    opening = None
    historical = False
    for event in events:
        if event.event_type in {"opened", "reopened"}:
            opening = event.occurred_at
        elif event.event_type == "resolved":
            if opening is not None and opening <= at < event.occurred_at:
                historical = True
            opening = None
    if historical or (finding.status == "open" and at >= finding.current_opened_at):
        finding.last_observed_at = max(finding.last_observed_at, at)
        return finding
    if finding.status == "resolved" and at > finding.resolved_at:
        latest = events[-1]
        if latest.status_after != "resolved" or at <= latest.occurred_at:
            raise HistoricalConflictError(
                "Recurrence conflicts with established lifecycle history"
            )
        finding.status = "open"
        finding.current_opened_at = at
        finding.resolved_at = None
        finding.last_observed_at = max(finding.last_observed_at, at)
        for key, value in _sla_values(policy, at).items():
            setattr(finding, key, value)
        _opening_event(
            session, finding, context, operation_id, "reopened", latest.event_number + 1
        )
        return finding
    raise HistoricalConflictError(
        "Positive evidence contradicts a resolution boundary or closed gap; manual reconciliation required"
    )


def record_observation(
    session: Session,
    *,
    scan_run_id: UUID,
    external_observation_key: str,
    cve_id: str,
    outcome: str,
    context: EventContext,
    test_ref: str,
    installation_id: UUID | None = None,
    installation_history_id: UUID | None = None,
    evidence_ref: str | None = None,
    evidence: dict | None = None,
    sla_policy: SLAPolicy | None = None,
) -> ScanObservation:
    """Insert immutable evidence and atomically reconcile positive detections only.

    SLA input applies only to a new opening/recurrence. Repeats never reset SLA.
    The caller must roll back the transaction after any rejected command.
    """
    if not isinstance(cve_id, str) or re.fullmatch(CVE_PATTERN, cve_id) is None:
        raise InvalidEvidenceError(
            "CVE identifier must match CVE-YYYY-NNNN (four or more digits)"
        )
    if outcome not in OUTCOMES:
        raise InvalidEvidenceError("Unsupported observation outcome")
    scan = _lock_scan(session, scan_run_id)
    if (context.source_key, context.is_synthetic) != (
        scan.source_key,
        scan.is_synthetic,
    ):
        raise InvalidEvidenceError("Observation provenance must agree with its scan")
    values = {
        "scan_run_id": scan.id,
        "asset_id": scan.asset_id,
        "external_observation_key": nonempty(
            external_observation_key, "external_observation_key"
        ),
        "cve_id": cve_id,
        "outcome": outcome,
        "occurred_at": context.occurred_at,
        "test_ref": nonempty(test_ref, "test_ref"),
        "installation_id": installation_id,
        "installation_history_id": installation_history_id,
        "evidence_ref": nonempty(evidence_ref, "evidence_ref")
        if evidence_ref is not None
        else None,
        "evidence": _json_object(evidence, "evidence")
        if evidence is not None
        else None,
    }
    sla = _sla_values(sla_policy, context.occurred_at)
    digest = _digest({**values, **sla, "actor_ref": context.actor_ref})
    previous = session.scalar(
        select(ScanObservation).where(
            ScanObservation.scan_run_id == scan.id,
            ScanObservation.external_observation_key
            == values["external_observation_key"],
        )
    )
    if previous is not None:
        if previous.payload_digest != digest:
            raise IdempotencyConflictError(
                "Observation key already exists with different content"
            )
        return previous
    _validate_target(
        session,
        scan,
        installation_id,
        installation_history_id,
        outcome,
        context.occurred_at,
    )
    observation_id = uuid4()
    if outcome == "affected":
        finding = _reconcile_positive(
            session, scan, installation_id, cve_id, context, observation_id, sla_policy
        )
    else:
        finding = session.scalar(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.asset_id == scan.asset_id,
                VulnerabilityFinding.installation_id.is_not_distinct_from(
                    installation_id
                ),
                VulnerabilityFinding.cve_id == cve_id,
            )
        )
    observation = ScanObservation(
        id=observation_id,
        finding_id=finding.id if finding else None,
        payload_digest=digest,
        **values,
    )
    session.add(observation)
    session.flush()
    return observation
