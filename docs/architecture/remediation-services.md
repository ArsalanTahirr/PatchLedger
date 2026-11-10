# Remediation and verification services (Milestone 4)

All 15 approved operational tables now exist through revision `0004`. These are
transactional Python services, independent of HTTP. They do not execute a scanner,
deploy a patch, fetch evidence documents or perform vulnerability matching.

## Runnable fixture workflow

[The runnable example](../../examples/remediation_workflow.py) starts with an
**existing installation-scoped synthetic finding**, its original historical
version ID and an explicit business start time. It demonstrates:

1. An existing asset/installed version and its open finding.
2. Creating an assigned remediation task and linking the finding's opening event.
3. Starting work.
4. A patch attempt that atomically upgrades the installed version and records its
   before/after periods and actual effort.
5. Marking work completed while the finding is still open.
6. A completed fixture scan with explicit `not_affected` evidence against the new
   version, followed by an evidence-backed verification decision.
7. Resolving the finding with a matching finding-event operation ID.
8. Closing the task only after every active target passes verification.

Its vulnerability applicability and absence are **explicit synthetic fixture
assertions, not independently validated NVD evidence**. Use a local fixture
asset/finding; this example writes the configured operational database.

After applying migrations, inspect the CLI:

```sh
uv run python examples/remediation_workflow.py --help
```

Supply IDs from existing fixture inventory/assessment services and a timezone-aware
start after the current opening/latest positive but before the intended patch:

```sh
uv run python examples/remediation_workflow.py \
  --finding-id YOUR_FIXTURE_FINDING_UUID \
  --history-id ORIGINAL_INSTALLED_HISTORY_UUID \
  --start-at 2024-01-10T09:00:00+00:00 \
  --namespace local-remediation-demo-v1 \
  --patched-version fixture-patched-2
```

The history must be current when the example first runs. The configured start
must be compatible with the asset's registration, version period and established
finding history. The script prints task, finding and verification IDs. Its one
`session_factory.begin()` transaction commits the logical fixture sequence
atomically. It never holds a transaction open for real external work.

The namespace produces stable UUID operation keys. Repeating exactly the same
command returns the same records, including after closure. Keep the original
history ID and dates on replay. A changed payload under the same key conflicts;
use a new namespace for new work. PostgreSQL integration tests execute the example
function and repeat it to verify the complete workflow and idempotency.

## Service calls

- `remediation.create_task`: accountable ownership, optional assignment, immutable
  eliminate/mitigate goal, priority, planning deadline and estimated effort.
- `remediation.update_task`: assign/reassign work or change title, description,
  priority, planning deadline or effort with an explicit reason.
- `remediation.add_task_finding`: link a currently open finding occurrence using
  its `opened`/`reopened` event ID. A task can cover several CVEs.
- `remediation.withdraw_task_finding`: preserve a historical target with explicit
  withdrawal reason, actor and timestamps. The same withdrawn occurrence cannot
  be silently reactivated under that task's unique key.
- `remediation.transition_task`: enforce the documented state machine, target
  requirements, reopening/cancellation and verified closure.
- `remediation_actions.record_action`: record an externally observed attempt and
  outcome with target, reviewable evidence, effort and version references.
- `remediation_actions.apply_software_change`: atomically call existing inventory
  services and record a successful patch/upgrade/downgrade/removal event. Version
  strings remain opaque; no patch applicability is inferred. For build/platform
  qualifier changes use the underlying inventory service and `record_action` in
  the same caller-owned transaction.
- `verification.verify_finding`: record scan/manual evidence, preserve failed or
  inconclusive decisions, resolve only accepted absence, or accept a time-limited
  mitigation while leaving the finding open.

All mutation calls accept a session, explicit `EventContext` business time and a
stable UUID `operation_id`. Event/decision SHA-256 digests distinguish identical
retry from conflicting reuse. Return values are existing stable rows on replay;
they do not reapply old work to a new finding occurrence. Each logical command
belongs in the caller's transaction. Roll back on any exception; never catch a
rejected command and then commit its partial flushed changes.

## Completed work versus verified resolution

`completed` means the assigned work finished; it does not establish absence.
Only an explicit accepted absence decision resolves a finding. Its immutable
verification row and the `resolved` finding event share `(finding_id,
operation_id)` and evidence time; no reverse foreign key creates a cycle.
Decision time (`verified_at`) and database recording time remain separate.

An eliminate task closes only after every active occurrence has accepted absence
and matching current resolution. A mitigate task can instead close with effective
mitigation that remains valid strictly beyond closure time. Effective mitigation
never automatically resolves the underlying finding. The latest verification,
subsequent inventory/actions/positive evidence and expiry are checked atomically
for all targets. An empty task cannot start work or close successfully.

Closed/cancelled task attributes and scope cannot change until explicitly
reopened. Recurrence leaves an old task's historical closure intact; create a new
task, or reopen the old task, withdraw the obsolete link and add the new opening
event. Reopening retains the first start time and writes a new event; prior
completion/closure snapshots remain in history. There is no expiry scheduler that
automatically reopens tasks later.

## Evidence contract

For scan absence, the run must be completed and its explicit observation must
match the finding's asset, installation, CVE and current occurrence. Evidence must
be strictly newer than every positive and follow any referenced action. A
negative software observation must identify the exact historical version. Changes
to inventory or actions between evidence and decision/closure require reassessment.
Neither a missing observation nor an incomplete/failed scan proves absence.

For `target_absent`, the installation must actually be absent at evidence time
and the run must declare complete inventory coverage for that installation:

```python
scope = {
    "inventory_coverage": {
        "complete": True,
        "installation_ids": [str(installation_id)],
    }
}
```

Coverage is a trusted producer assertion, not a matching engine or an independent
measurement. Genuinely asset-scoped findings use explicit `not_affected` evidence;
software-target absence is not used to claim a whole asset absent.

Manual decisions require a verifier, rationale, explicit evidence time and
reviewable evidence reference/nonempty bounded JSON. Set `method="manual"` and
`manual_evidence_kind` to `independent_assessment`, `inventory_review` or
`control_validation`; a patch report alone is not an independent evidence category.
When software is present, supply `assessed_history_id`. The service validates
scope/time/inventory while the caller remains responsible for the evidence's
substance and verifier identity. Such decisions remain distinguishable from scans.

Effective mitigation additionally needs `valid_until`. For scan-based control
verification, the observation evidence must explicitly contain
`{"control_verdict": "effective"}` or `{"control_verdict": "failed"}` as
appropriate. Presence of the CVE alone cannot establish control success/failure.

Historical contradictory or backdated lifecycle changes are rejected for manual
reconciliation. ORM history guards and database constraints supplement the service
contract; arbitrary Core/bulk SQL can bypass append-only guards and cross-row
workflow validation. These services provide no authorization/identity directory,
external evidence validation, SLA-edit command or automatic ongoing monitoring.
