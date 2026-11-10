"""Explicit evidence decisions, atomic resolution and occurrence-aware task closure."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import or_, select
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
    RemediationEvent,
    ScanObservation,
    ScanRun,
    TaskFinding,
    VerificationResult,
    VulnerabilityFinding,
)
from patchledger.operational.models.remediation import MANUAL_KINDS, VERDICTS
from patchledger.operational.services.common import (
    EventContext,
    bounded_json_object,
    effective_time,
    nonempty,
)
from patchledger.operational.services.remediation import (
    current_opening,
    lock_finding,
    lock_task,
    request_digest,
)


def _period_at(session, installation_id, when):
    periods = list(
        session.scalars(
            select(InstallationHistory)
            .where(
                InstallationHistory.installation_id == installation_id,
                InstallationHistory.started_at <= when,
                or_(
                    InstallationHistory.ended_at.is_(None),
                    InstallationHistory.ended_at > when,
                ),
            )
            .execution_options(populate_existing=True)
        )
    )
    if len(periods) > 1:
        raise InvalidEvidenceError("Inventory contains overlapping version periods")
    return periods[0] if periods else None


def _inventory_snapshot(
    session, finding, evidence_at, as_of, assessed_history_id, *, target_absent=False
):
    if finding.installation_id is None:
        if assessed_history_id is not None or target_absent:
            raise InvalidEvidenceError(
                "Asset-scoped absence cannot claim an absent software installation"
            )
        return
    period = _period_at(session, finding.installation_id, evidence_at)
    if target_absent:
        if period is not None:
            raise InvalidEvidenceError(
                "Inventory still contains the allegedly absent installation"
            )
    elif period is None or assessed_history_id != period.id:
        raise InvalidEvidenceError(
            "Verification needs the exact version assessed at evidence time"
        )
    changed = session.scalar(
        select(InstallationHistory.id)
        .where(
            InstallationHistory.installation_id == finding.installation_id,
            or_(
                (InstallationHistory.started_at > evidence_at)
                & (InstallationHistory.started_at <= as_of),
                (InstallationHistory.ended_at > evidence_at)
                & (InstallationHistory.ended_at <= as_of),
            ),
        )
        .limit(1)
    )
    if changed is not None:
        raise InvalidEvidenceError(
            "Inventory changed after evidence; reassessment is required"
        )


def _later_action(session, finding, evidence_at, as_of):
    return session.scalar(
        select(RemediationEvent.id)
        .where(
            RemediationEvent.event_type == "action_recorded",
            RemediationEvent.target_asset_id == finding.asset_id,
            RemediationEvent.installation_id.is_not_distinct_from(
                finding.installation_id
            ),
            RemediationEvent.occurred_at > evidence_at,
            RemediationEvent.occurred_at <= as_of,
        )
        .limit(1)
    )


def _validate_scan(session, finding, observation, scan, verdict):
    if scan.status != "completed":
        raise InvalidEvidenceError(
            "Only a successfully completed scan supports verification"
        )
    if (observation.asset_id, observation.installation_id, observation.cve_id) != (
        finding.asset_id,
        finding.installation_id,
        finding.cve_id,
    ) or observation.finding_id not in (None, finding.id):
        raise InvalidEvidenceError(
            "Observation asset, installation or CVE does not match finding"
        )
    if verdict == "absence_confirmed" and observation.outcome not in {
        "not_affected",
        "target_absent",
    }:
        raise InvalidEvidenceError("Absence needs an explicit negative observation")
    if verdict == "still_affected" and observation.outcome != "affected":
        raise InvalidEvidenceError(
            "Still-affected verification needs positive evidence"
        )
    if verdict in {"mitigation_effective", "mitigation_failed"}:
        expected = "effective" if verdict == "mitigation_effective" else "failed"
        if (
            not observation.evidence
            or observation.evidence.get("control_verdict") != expected
        ):
            raise InvalidEvidenceError(
                "Mitigation requires an explicit control-test result"
            )
    if observation.outcome == "target_absent" and verdict == "absence_confirmed":
        coverage = scan.scope.get("inventory_coverage", {})
        if (
            finding.installation_id is None
            or not isinstance(coverage, dict)
            or coverage.get("complete") is not True
            or not isinstance(coverage.get("installation_ids"), list)
            or str(finding.installation_id) not in coverage.get("installation_ids", [])
        ):
            raise InvalidEvidenceError(
                "Target absence requires explicit complete inventory coverage for this installation"
            )


def _resolve(session, finding, opening, result, context):
    latest = session.scalar(
        select(FindingEvent)
        .where(FindingEvent.finding_id == finding.id)
        .order_by(FindingEvent.event_number.desc())
        .limit(1)
    )
    if result.evidence_at < latest.occurred_at:
        raise HistoricalConflictError(
            "Resolution would backdate an established finding event"
        )
    finding.status, finding.resolved_at = "resolved", result.evidence_at
    session.add(
        FindingEvent(
            finding_id=finding.id,
            event_number=latest.event_number + 1,
            operation_id=result.operation_id,
            event_type="resolved",
            status_after="resolved",
            occurred_at=result.evidence_at,
            actor_ref=context.actor_ref,
            source_key=context.source_key,
            is_synthetic=context.is_synthetic,
            reason=result.rationale,
            sla_policy_ref=finding.sla_policy_ref,
            sla_target_seconds=finding.sla_target_seconds,
            sla_deadline=finding.sla_deadline,
        )
    )
    session.flush()


def verify_finding(
    session: Session,
    finding_id: UUID,
    *,
    opening_event_id: UUID,
    operation_id: UUID,
    method: str,
    verdict: str,
    context: EventContext,
    verifier_ref: str,
    rationale: str,
    observation_id: UUID | None = None,
    task_finding_id: UUID | None = None,
    action_event_id: UUID | None = None,
    evidence_at: datetime | None = None,
    assessed_history_id: UUID | None = None,
    evidence_ref: str | None = None,
    evidence: dict | None = None,
    valid_until: datetime | None = None,
    manual_evidence_kind: str | None = None,
) -> VerificationResult:
    """Only accepted absence resolves; all writes including the decision roll back together."""
    if verdict not in VERDICTS or method not in {"scan", "manual"}:
        raise InvalidOperationError("Unsupported verification method or verdict")
    if not isinstance(operation_id, UUID):
        raise InvalidOperationError("operation_id must be a stable UUID")
    manual_at = effective_time(evidence_at) if evidence_at is not None else None
    until = effective_time(valid_until) if valid_until is not None else None
    rationale, verifier_ref = (
        nonempty(rationale, "rationale"),
        nonempty(verifier_ref, "verifier_ref"),
    )
    normalized = (
        bounded_json_object(evidence, "evidence") if evidence is not None else None
    )
    ref = nonempty(evidence_ref, "evidence_ref") if evidence_ref is not None else None
    digest = request_digest(
        "verify_finding",
        context,
        finding_id=finding_id,
        opening_event_id=opening_event_id,
        method=method,
        verdict=verdict,
        verifier_ref=verifier_ref,
        rationale=rationale,
        observation_id=observation_id,
        task_finding_id=task_finding_id,
        action_event_id=action_event_id,
        evidence_at=manual_at,
        assessed_history_id=assessed_history_id,
        evidence_ref=ref,
        evidence=normalized,
        valid_until=until,
        manual_evidence_kind=manual_evidence_kind,
    )
    # Read immutable references first, then acquire locks in task -> scan -> asset -> finding order.
    link = (
        session.get(TaskFinding, task_finding_id)
        if task_finding_id is not None
        else None
    )
    action = (
        session.get(RemediationEvent, action_event_id)
        if action_event_id is not None
        else None
    )
    if (
        task_finding_id is not None
        and link is None
        or action_event_id is not None
        and action is None
    ):
        raise NotFoundError("Verification task target or action does not exist")
    task_ids = {obj.task_id for obj in (link, action) if obj is not None}
    if len(task_ids) > 1:
        raise InvalidEvidenceError(
            "Verification action and task target belong to different tasks"
        )
    for task_id in sorted(task_ids):
        lock_task(session, task_id)
    observation = (
        session.get(ScanObservation, observation_id)
        if observation_id is not None
        else None
    )
    scan = None
    if observation is not None:
        scan = session.scalar(
            select(ScanRun)
            .where(ScanRun.id == observation.scan_run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    original = session.get(VulnerabilityFinding, finding_id)
    if original is None:
        raise NotFoundError("Finding does not exist")
    machine = session.scalar(
        select(Asset)
        .where(Asset.id == original.asset_id)
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    finding = lock_finding(session, finding_id)
    previous = session.scalar(
        select(VerificationResult).where(
            VerificationResult.finding_id == finding_id,
            VerificationResult.operation_id == operation_id,
        )
    )
    if previous is not None:
        if previous.payload_digest != digest:
            raise IdempotencyConflictError(
                "Verification operation key was reused with different content"
            )
        return previous
    opening = current_opening(session, finding)
    if finding.status != "open" or opening.id != opening_event_id:
        raise InvalidOperationError(
            "Verification must address the currently open finding occurrence"
        )
    if link is not None:
        session.refresh(link)
        if (link.finding_id, link.opening_event_id) != (
            finding.id,
            opening.id,
        ) or link.withdrawn_at is not None:
            raise InvalidEvidenceError(
                "Verification targets an obsolete or withdrawn task occurrence"
            )
        if context.occurred_at < link.added_at:
            raise HistoricalConflictError("Verification precedes task target addition")
    if method == "scan":
        if (
            observation is None
            or manual_evidence_kind is not None
            or evidence_at is not None
        ):
            raise InvalidEvidenceError(
                "Scan verification requires an observation and derives its evidence time"
            )
        _validate_scan(session, finding, observation, scan, verdict)
        if scan.is_synthetic != context.is_synthetic:
            raise InvalidEvidenceError(
                "Verification provenance conflicts with scanner provenance"
            )
        when = observation.occurred_at
        history_id = observation.installation_history_id
        if assessed_history_id is not None and assessed_history_id != history_id:
            raise InvalidEvidenceError("Assessed version differs from scan evidence")
        ref = ref or observation.evidence_ref
        normalized = normalized or observation.evidence
        absent = observation.outcome == "target_absent"
    else:
        if (
            observation_id is not None
            or manual_at is None
            or manual_evidence_kind not in MANUAL_KINDS
        ):
            raise InvalidEvidenceError(
                "Manual verification requires explicit evidence time and an independent assessment/inventory/control review"
            )
        when, history_id = manual_at, assessed_history_id
        absent = (
            finding.installation_id is not None
            and _period_at(session, finding.installation_id, when) is None
        )
    if history_id is not None:
        assessed = session.get(InstallationHistory, history_id)
        if assessed is None or assessed.installation_id != finding.installation_id:
            raise InvalidEvidenceError(
                "Assessed history does not belong to the finding installation"
            )
        if absent and (assessed.ended_at is None or assessed.ended_at > when):
            raise InvalidEvidenceError(
                "Referenced version contradicts asserted target absence"
            )
    if not ref and not normalized:
        raise InvalidEvidenceError(
            "A verification decision requires reviewable evidence"
        )
    if (
        context.occurred_at < when
        or when < opening.occurred_at
        or when < machine.registered_at
    ):
        raise HistoricalConflictError(
            "Verification evidence or decision has invalid temporal ordering"
        )
    if machine.retired_at is not None and when >= machine.retired_at:
        raise InvalidEvidenceError(
            "Evidence is outside the asset's registered lifetime"
        )
    latest_event = session.scalar(
        select(FindingEvent)
        .where(FindingEvent.finding_id == finding.id)
        .order_by(FindingEvent.event_number.desc())
        .limit(1)
    )
    latest_decision = session.scalar(
        select(VerificationResult)
        .where(VerificationResult.finding_id == finding.id)
        .order_by(VerificationResult.verified_at.desc())
        .limit(1)
    )
    if context.occurred_at < max(
        finding.last_observed_at, latest_event.occurred_at
    ) or (
        latest_decision is not None
        and context.occurred_at < latest_decision.verified_at
    ):
        raise HistoricalConflictError(
            "Verification decision predates established finding/decision history"
        )
    if action is not None:
        if action.event_type != "action_recorded" or (
            action.target_asset_id,
            action.installation_id,
        ) != (finding.asset_id, finding.installation_id):
            raise InvalidEvidenceError(
                "Verification action is outside the finding scope"
            )
        if when <= action.occurred_at:
            raise HistoricalConflictError(
                "Verification evidence must follow the action"
            )
    accepted = verdict in {"absence_confirmed", "mitigation_effective"}
    if verdict == "mitigation_effective":
        if until is None or until <= context.occurred_at:
            raise InvalidEvidenceError(
                "Effective mitigation requires an unexpired validity deadline"
            )
    elif until is not None:
        raise InvalidEvidenceError("Only effective mitigation has a validity deadline")
    if accepted:
        if when < finding.last_observed_at or (
            verdict == "absence_confirmed" and when <= finding.last_observed_at
        ):
            raise InvalidEvidenceError(
                "Evidence is stale relative to positive observations"
            )
        contradiction = session.scalar(
            select(VerificationResult.id)
            .where(
                VerificationResult.finding_id == finding.id,
                VerificationResult.opening_event_id == opening.id,
                VerificationResult.verdict.in_(
                    ("still_affected",)
                    if verdict == "absence_confirmed"
                    else ("mitigation_failed",)
                ),
                VerificationResult.evidence_at >= when,
            )
            .limit(1)
        )
        if contradiction is not None:
            raise InvalidEvidenceError(
                "A newer contradictory verification result exists"
            )
        _inventory_snapshot(
            session,
            finding,
            when,
            context.occurred_at,
            history_id,
            target_absent=absent,
        )
        if _later_action(session, finding, when, context.occurred_at):
            raise InvalidEvidenceError(
                "An intervening action invalidates verification evidence"
            )
    result = VerificationResult(
        finding_id=finding.id,
        opening_event_id=opening.id,
        operation_id=operation_id,
        payload_digest=digest,
        method=method,
        manual_evidence_kind=manual_evidence_kind,
        verdict=verdict,
        accepted=accepted,
        evidence_at=when,
        verified_at=context.occurred_at,
        valid_until=until,
        verifier_ref=verifier_ref,
        rationale=rationale,
        observation_id=observation_id,
        task_finding_id=task_finding_id,
        action_event_id=action_event_id,
        assessed_history_id=history_id,
        evidence_ref=ref,
        evidence=normalized,
        actor_ref=context.actor_ref,
        source_key=context.source_key,
        is_synthetic=context.is_synthetic,
    )
    session.add(result)
    session.flush()  # Decision first; the matching event/state must remain in this transaction.
    if verdict == "absence_confirmed":
        _resolve(session, finding, opening, result, context)
    return result


def validate_task_closure(session, task, links, findings, when):
    """Caller holds task, shared asset locks and every finding lock in sorted order."""
    for link in links:
        finding = findings[link.finding_id]
        result = session.scalar(
            select(VerificationResult)
            .where(
                VerificationResult.finding_id == finding.id,
                VerificationResult.opening_event_id == link.opening_event_id,
            )
            .order_by(
                VerificationResult.verified_at.desc(),
                VerificationResult.recorded_at.desc(),
            )
            .limit(1)
        )
        if result is None or not result.accepted:
            raise InvalidEvidenceError(
                "Every active target requires accepted verification"
            )
        if result.verified_at > when:
            raise HistoricalConflictError("Task closure predates verification")
        if result.verdict == "absence_confirmed":
            if (
                finding.status != "resolved"
                or finding.resolved_at != result.evidence_at
            ):
                raise InvalidEvidenceError(
                    "Absence verification does not match current finding resolution"
                )
        elif (
            task.goal != "mitigate"
            or result.verdict != "mitigation_effective"
            or result.valid_until <= when
        ):
            raise InvalidEvidenceError(
                "Task goal requires absence or unexpired mitigation evidence"
            )
        elif finding.last_observed_at > result.evidence_at:
            raise InvalidEvidenceError(
                "New positive evidence requires reassessment of mitigation"
            )
        absent = (
            finding.installation_id is not None
            and _period_at(session, finding.installation_id, result.evidence_at) is None
        )
        _inventory_snapshot(
            session,
            finding,
            result.evidence_at,
            when,
            result.assessed_history_id,
            target_absent=absent,
        )
        if _later_action(session, finding, result.evidence_at, when):
            raise InvalidEvidenceError(
                "A later action requires fresh verification before closure"
            )
