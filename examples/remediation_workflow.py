"""Run a synthetic remediation fixture against an existing finding and installation.

The fixture asserts applicability/absence for demonstration only, not an NVD match.
All writes use existing transactional services; this is not an enterprise simulator.
"""

import argparse
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

from patchledger.core.config import Settings
from patchledger.db.session import make_engine, make_session_factory
from patchledger.operational.models import VulnerabilityFinding
from patchledger.operational.services.assessment import (
    create_scan_run,
    record_observation,
)
from patchledger.operational.services.common import EventContext, effective_time
from patchledger.operational.services.remediation import (
    add_task_finding,
    create_task,
    current_opening,
    transition_task,
)
from patchledger.operational.services.remediation_actions import apply_software_change
from patchledger.operational.services.verification import verify_finding


def run_fixture_workflow(
    session, *, finding_id, history_id, first_at, namespace, patched_version
):
    """Caller supplies an existing installation-scoped fixture finding and exact version."""
    first_at = effective_time(first_at)
    finding = session.get(VulnerabilityFinding, finding_id)
    if finding is None or finding.installation_id is None:
        raise ValueError("An existing installation-scoped fixture finding is required")
    opening = current_opening(session, finding)
    source = "fixture:remediation-example:v1"

    def context(minutes):
        return EventContext(
            first_at + timedelta(minutes=minutes), "fixture:operator", source, True
        )

    def operation(step):
        return uuid5(
            NAMESPACE_URL, f"patchledger:remediation-example:{namespace}:{step}"
        )

    from patchledger.operational.models import Asset

    owner = session.get(Asset, finding.asset_id).department_id
    task = create_task(
        session,
        task_key=f"fixture:remediation:{namespace}",
        title="Synthetic fixture patch",
        owner_department_id=owner,
        assignee_ref="fixture:engineer",
        priority=2,
        goal="eliminate",
        due_at=first_at + timedelta(days=7),
        estimated_effort_minutes=15,
        context=context(0),
        operation_id=operation("create"),
    )
    link = add_task_finding(
        session,
        task.id,
        finding_id=finding.id,
        opening_event_id=opening.id,
        context=context(0),
        operation_id=operation("target"),
    )
    transition_task(
        session,
        task.id,
        status="in_progress",
        context=context(1),
        operation_id=operation("start"),
        reason="Start fixture work",
    )
    action = apply_software_change(
        session,
        task.id,
        action_kind="patch",
        target_asset_id=finding.asset_id,
        installation_id=finding.installation_id,
        expected_history_id=history_id,
        version=patched_version,
        context=context(2),
        operation_id=operation("patch"),
        evidence_ref="fixture:patch-attempt",
        actual_effort_minutes=10,
    )
    transition_task(
        session,
        task.id,
        status="completed",
        context=context(3),
        operation_id=operation("complete"),
        reason="Work completed; verification still required",
    )
    scan = create_scan_run(
        session,
        asset_id=finding.asset_id,
        source_key=source,
        external_run_key=f"{namespace}:verification",
        producer_version="fixture-v1",
        is_synthetic=True,
        scope={"tests": ["fixture:explicit-absence"]},
        status="completed",
        started_at=context(4).occurred_at,
        completed_at=context(4).occurred_at + timedelta(seconds=30),
    )
    observation = record_observation(
        session,
        scan_run_id=scan.id,
        external_observation_key="fixture:absence",
        cve_id=finding.cve_id,
        outcome="not_affected",
        context=context(4),
        test_ref="fixture:explicit-absence",
        installation_id=finding.installation_id,
        installation_history_id=action.after_history_id,
        evidence={
            "applicability": "synthetic-fixture-only",
            "assessment": "explicit absence",
        },
    )
    result = verify_finding(
        session,
        finding.id,
        opening_event_id=opening.id,
        operation_id=operation("verify"),
        method="scan",
        verdict="absence_confirmed",
        observation_id=observation.id,
        task_finding_id=link.id,
        action_event_id=action.id,
        context=context(5),
        verifier_ref="fixture:verifier",
        rationale="Explicit absence from a synthetic fixture assessment",
    )
    transition_task(
        session,
        task.id,
        status="closed",
        context=context(6),
        operation_id=operation("close"),
        reason="All active targets have verified absence",
    )
    return {"task_id": task.id, "finding_id": finding.id, "verification_id": result.id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding-id", required=True, type=UUID)
    parser.add_argument("--history-id", required=True, type=UUID)
    parser.add_argument("--start-at", required=True, type=datetime.fromisoformat)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--patched-version", required=True)
    args = parser.parse_args()
    engine = make_engine(Settings().sqlalchemy_url)
    try:
        with make_session_factory(engine).begin() as session:
            result = run_fixture_workflow(
                session,
                finding_id=args.finding_id,
                history_id=args.history_id,
                first_at=args.start_at,
                namespace=args.namespace,
                patched_version=args.patched_version,
            )
        for name, identity in result.items():
            print(f"{name}={identity}")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
