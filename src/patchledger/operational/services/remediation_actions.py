"""Record outcomes after external work, or atomically apply a logical inventory change."""

from uuid import UUID

from sqlalchemy.orm import Session

from patchledger.operational.exceptions import (
    HistoricalConflictError,
    InvalidEvidenceError,
    InvalidOperationError,
)
from patchledger.operational.models import (
    InstallationHistory,
    SoftwareInstallation,
    VulnerabilityFinding,
)
from patchledger.operational.models.remediation import ACTION_KINDS
from patchledger.operational.services.assets import lock_asset
from patchledger.operational.services.common import (
    EventContext,
    bounded_json_object,
    nonempty,
)
from patchledger.operational.services.remediation import (
    active_targets,
    append_event,
    check_time,
    current_opening,
    lock_finding,
    lock_task,
    nonnegative_minutes,
    replay_event,
    request_digest,
)
from patchledger.operational.services.software import (
    change_software_version,
    remove_software,
)


def _action_values(
    action_kind,
    action_outcome,
    target_asset_id,
    installation_id,
    before_history_id,
    after_history_id,
    evidence_ref,
    evidence,
    actual_effort_minutes,
):
    if action_kind not in ACTION_KINDS or action_outcome not in {
        "succeeded",
        "failed",
        "inconclusive",
    }:
        raise InvalidOperationError("Unsupported remediation action or outcome")
    return {
        "action_kind": action_kind,
        "action_outcome": action_outcome,
        "target_asset_id": target_asset_id,
        "installation_id": installation_id,
        "before_history_id": before_history_id,
        "after_history_id": after_history_id,
        "evidence_ref": nonempty(evidence_ref, "evidence_ref"),
        "evidence": bounded_json_object(evidence, "evidence")
        if evidence is not None
        else None,
        "actual_effort_minutes": nonnegative_minutes(
            actual_effort_minutes, "actual effort"
        ),
    }


def _validate_action(session, task, context, values):
    check_time(session, task, context)
    if task.status not in {"in_progress", "blocked"}:
        raise InvalidOperationError("Actions require an in-progress or blocked task")
    machine = lock_asset(session, values["target_asset_id"])
    if machine.retired_at is not None or context.occurred_at < machine.registered_at:
        raise HistoricalConflictError("Action lies outside the managed asset lifetime")
    iid = values["installation_id"]
    if iid is not None:
        installation = session.get(SoftwareInstallation, iid)
        if installation is None or installation.asset_id != machine.id:
            raise InvalidEvidenceError(
                "Action installation does not belong to its asset"
            )
    elif values["action_kind"] in {"patch", "upgrade", "downgrade", "removal"}:
        raise InvalidEvidenceError("Software actions require an installation")
    targets = []
    for link in active_targets(session, task.id):
        candidate = session.get(VulnerabilityFinding, link.finding_id)
        if (candidate.asset_id, candidate.installation_id) != (machine.id, iid):
            continue
        finding = lock_finding(session, link.finding_id)
        if (finding.asset_id, finding.installation_id) == (machine.id, iid):
            if (
                finding.status != "open"
                or current_opening(session, finding).id != link.opening_event_id
            ):
                raise InvalidOperationError(
                    "Action target occurrence is no longer open"
                )
            if context.occurred_at < max(link.added_at, finding.current_opened_at):
                raise HistoricalConflictError("Action predates target scope")
            targets.append(link)
    if not targets:
        raise InvalidEvidenceError("Action target is outside the task's active scope")
    for field in ("before_history_id", "after_history_id"):
        identity = values[field]
        if identity is not None:
            history = session.get(InstallationHistory, identity, populate_existing=True)
            if history is None or history.installation_id != iid:
                raise InvalidEvidenceError(
                    "Action version reference belongs to another installation"
                )
    return targets


def _validate_periods(session, context, values):
    before = (
        session.get(InstallationHistory, values["before_history_id"])
        if values["before_history_id"]
        else None
    )
    after = (
        session.get(InstallationHistory, values["after_history_id"])
        if values["after_history_id"]
        else None
    )
    when = context.occurred_at
    if before is not None and (
        before.started_at > when
        or (before.ended_at is not None and before.ended_at < when)
    ):
        raise InvalidEvidenceError(
            "Before-version was not applicable immediately before action time"
        )
    if after is not None and (
        after.started_at > when
        or (after.ended_at is not None and after.ended_at <= when)
    ):
        raise InvalidEvidenceError("After-version was not present at action time")
    if values["action_outcome"] == "succeeded":
        if values["action_kind"] in {"patch", "upgrade", "downgrade"}:
            if (
                before is None
                or after is None
                or before.id == after.id
                or before.ended_at != when
                or after.started_at != when
            ):
                raise InvalidEvidenceError(
                    "Successful software change requires adjacent before/after version periods"
                )
        elif values["action_kind"] == "removal" and (
            before is None
            or before.ended_at != when
            or before.end_reason != "removal"
            or after is not None
        ):
            raise InvalidEvidenceError(
                "Successful removal requires the explicitly closed version period"
            )


def record_action(
    session: Session,
    task_id: UUID,
    *,
    action_kind: str,
    action_outcome: str,
    target_asset_id: UUID,
    context: EventContext,
    operation_id: UUID,
    evidence_ref: str,
    installation_id: UUID | None = None,
    before_history_id: UUID | None = None,
    after_history_id: UUID | None = None,
    evidence: dict | None = None,
    actual_effort_minutes: int | None = None,
):
    """Log observed results; never execute external scanners/processes in this transaction."""
    values = _action_values(
        action_kind,
        action_outcome,
        target_asset_id,
        installation_id,
        before_history_id,
        after_history_id,
        evidence_ref,
        evidence,
        actual_effort_minutes,
    )
    digest = request_digest("record_action", context, **values)
    task = lock_task(session, task_id)
    old = replay_event(session, task.id, operation_id, digest)
    if old is not None:
        return old
    _validate_action(session, task, context, values)
    _validate_periods(session, context, values)
    return append_event(
        session, task, context, operation_id, digest, "action_recorded", **values
    )


def apply_software_change(
    session: Session,
    task_id: UUID,
    *,
    action_kind: str,
    target_asset_id: UUID,
    installation_id: UUID,
    expected_history_id: UUID,
    context: EventContext,
    operation_id: UUID,
    evidence_ref: str,
    version: str | None = None,
    evidence: dict | None = None,
    actual_effort_minutes: int | None = None,
):
    """Inventory state + action event commit together; success alone does not resolve a CVE."""
    if action_kind not in {"patch", "upgrade", "downgrade", "removal"}:
        raise InvalidOperationError("This operation supports software changes only")
    if action_kind != "removal":
        version = nonempty(version, "version")
    elif version is not None:
        raise InvalidOperationError("Removal does not accept a new version")
    values = _action_values(
        action_kind,
        "succeeded",
        target_asset_id,
        installation_id,
        expected_history_id,
        None,
        evidence_ref,
        evidence,
        actual_effort_minutes,
    )
    digest = request_digest("apply_software_change", context, **values, version=version)
    task = lock_task(session, task_id)
    old = replay_event(session, task.id, operation_id, digest)
    if old is not None:
        return old
    _validate_action(session, task, context, values)
    if action_kind == "removal":
        remove_software(
            session,
            installation_id,
            expected_history_id=expected_history_id,
            context=context,
        )
    else:
        period = change_software_version(
            session,
            installation_id,
            version=version,
            change_kind="downgrade" if action_kind == "downgrade" else "upgrade",
            expected_history_id=expected_history_id,
            context=context,
        )
        values["after_history_id"] = period.id
    _validate_periods(session, context, values)
    return append_event(
        session, task, context, operation_id, digest, "action_recorded", **values
    )
