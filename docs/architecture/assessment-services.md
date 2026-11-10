# Assessment and finding services (Milestone 3)

These services are ordinary Python functions independent of HTTP and callable by
the future simulator. This example uses **synthetic test-fixture applicability**;
`CVE-2099-90001` is a format-valid placeholder, not a validated NVD match. No
matching, external ingestion or verification service is implemented.

The caller supplies an existing asset, its installation, the exact historical
version assessed, and an explicit timezone-aware business time. Both observations
must occur inside that version's period and the asset's registered lifetime. Use
a disposable fixture database and a source/run namespace reserved for the example.

```python
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patchledger.operational.models import ScanObservation, VulnerabilityFinding
from patchledger.operational.services.assessment import (
    SLAPolicy,
    create_scan_run,
    record_observation,
)
from patchledger.operational.services.common import EventContext


def record_fixture_detections(
    session: Session,
    *,
    asset_id: UUID,
    installation_id: UUID,
    history_id: UUID,
    first_at: datetime,
):
    observations = []
    for number in (1, 2):
        when = first_at + timedelta(minutes=number - 1)
        run = create_scan_run(
            session,
            asset_id=asset_id,
            source_key="fixture:assessment-example:v1",
            external_run_key=f"{installation_id}:scan-{number}",
            producer_version="fixture-v1",
            is_synthetic=True,
            scope={"kind": "explicit-fixture", "tests": ["fixture:rule:v1"]},
            status="completed",
            started_at=when,
            completed_at=when + timedelta(seconds=30),
        )
        observations.append(
            record_observation(
                session,
                scan_run_id=run.id,
                external_observation_key="fixture:rule:v1:CVE-2099-90001",
                installation_id=installation_id,
                installation_history_id=history_id,
                cve_id="CVE-2099-90001",
                outcome="affected",
                context=EventContext(
                    when, "fixture:assessor", "fixture:assessment-example:v1", True
                ),
                test_ref="fixture:rule:v1",
                evidence={"applicability": "synthetic-fixture-only"},
                sla_policy=SLAPolicy("fixture:standard:v1", 7 * 86400),
            )
        )
    finding_id = observations[0].finding_id
    assert finding_id == observations[1].finding_id
    finding = session.get(VulnerabilityFinding, finding_id)
    supporting_observations = session.scalar(
        select(func.count())
        .select_from(ScanObservation)
        .where(ScanObservation.finding_id == finding_id)
    )
    assert finding.status == "open" and supporting_observations == 2
    return finding, supporting_observations
```

Invoke with the existing session factory from the inventory documentation:

```python
with sessions.begin() as session:
    finding, evidence_count = record_fixture_detections(
        session,
        asset_id=existing_asset_id,
        installation_id=existing_installation_id,
        history_id=assessed_history_id,
        first_at=fixture_assessment_time,
    )
    print(finding.id, evidence_count)  # One finding, two supporting observations.
```

Here `sessions` comes from `make_session_factory(engine)`; inventory IDs and
`fixture_assessment_time` come from the caller's explicit fixture setup. The
function never commits. Repeating it with the same inputs returns the same rows.
Reusing its keys with changed content raises `IdempotencyConflictError`. Use a new
namespace for a different fixture, rather than changing an existing keyed payload.

For a live producer, create a queued run, call `set_scan_status` to enter running
with an explicit start, record observations, and finalize completed, partial,
failed or cancelled with an explicit completion. An unfinished/partial run and a
missing test are not evidence of absence. An observation can be `affected`,
`not_affected`, `target_absent` or `inconclusive`. Explicit negative outcomes are
retained but **never automatically resolve a finding**. Installation-scoped
positive evidence always needs the historical version ID; a genuinely
asset-scoped detection sets both installation/version IDs to `None`.

The first positive creates one finding and an `opened` event. Repeats update only
its maximum last-positive business time and preserve its opening/SLA. A future
verified resolution followed by strictly later positive evidence creates a
`reopened` event on the same finding with a new SLA snapshot. A supplied policy
applies to the new occurrence; `None` explicitly means no configured policy.
Historical observations in an already-known open period do not cause recurrence.
Evidence before the initial opening, exactly at resolution, or in a closed gap
before an established reopening requires manual reconciliation and is rejected.
On any service error, roll back the caller's transaction; never continue and
commit partial work after catching the error.

Resolution, accepted-absence evidence, SLA editing and remediation workflows are
Milestone 4 work. Tests of recurrence stage a labelled resolved-state fixture;
there is no callable production resolution shortcut in this milestone.
