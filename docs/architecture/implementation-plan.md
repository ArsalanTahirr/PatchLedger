# Operational implementation plan

No milestone includes an operational FastAPI application. Keep existing optional
dependencies/scaffolding. Milestones 1–3 are implemented; remediation/verification
and the simulator remain planned. Integration tests accompany each increment.

## Milestone 1 — Database foundation (completed)

- Package the existing `src/patchledger` tree for `uv run` imports.
- Add explicit configuration, SQLAlchemy Base, engine and session factories.
- Move the existing Alembic environment from `warehouse/migrations` to
  `db/migrations`; preserve its environment-driven connection behavior.
- Create only `operational`, with Alembic's bookkeeping table in `public`.
- Register metadata and filter autogeneration to owned operational objects.
- Add isolated PostgreSQL 17 test databases and CI support.
- Document development and migration commands.

Acceptance: fresh upgrade, downgrade and re-upgrade succeed; downgrade does not
cascade-delete objects; unrelated schemas survive and produce no autogenerate
changes; service transaction contexts commit/rollback as expected; unit and real
PostgreSQL tests pass; Ruff passes. No domain tables, simulator, HTTP or warehouse
implementation in that milestone.

## Milestone 2 — Enterprise inventory (implemented; review boundary)

Implement departments, assets, asset events, products, product identifiers,
installations and installation history, plus focused inventory services.

Acceptance: stable identities, atomic snapshot history, correct upgrades,
downgrades and removals; invalid periods rejected; concurrent upgrades on two
connections serialize and stale expectations fail; test backdated gaps/overlaps
and rollback. Preserve historical department assignment/criticality, explicitly
without a department-name history subsystem. Revision `0002` depends on the
unchanged `0001_operational_schema` and creates exactly seven inventory tables.

Implementation choices: reject earlier-gap/backdated rewrites; require expected
current history IDs on upgrade/downgrade/removal; lock asset then installation;
remove software explicitly before asset retirement. Typed asset snapshots and
installation start/end provenance preserve business versus recording times.
ORM identity/history guards supplement ordinary database constraints, without
triggers. All service transactions remain caller-owned.

This increment added inventory only. Runnable examples are in
`inventory-services.md`; assessment was added separately in Milestone 3.

## Milestone 3 — Vulnerability assessment (implemented; review boundary)

Revision `0003`, depending on unchanged `0002`, adds `scan_runs`,
`scan_observations`, `vulnerability_findings` and `finding_events`. Focused
services create and advance scan runs, ingest immutable observations, and
reconcile persistent findings. No extra domain tables are introduced.

Acceptance: identical replay is idempotent; conflicting keys fail; repeated
observations create one finding; absence is never inferred from omission;
source-time ordering avoids false reopenings; each genuine recurrence has a new
opening event; positive/negative/inconclusive evidence remains distinct. Use
labelled applicability fixtures, not invented real-world matches.

Implemented choices: source/run/asset scan identity; observation keys within a run;
canonical payload digests reject conflicting retries; PostgreSQL `NULLS NOT
DISTINCT` finding uniqueness; run/asset/finding locks; exact historical
version validation; caller-owned atomic transactions. Late evidence within known
open periods is accepted without reopening; evidence contradicting established
opening/resolution boundaries or closed gaps requires manual reconciliation.
New openings snapshot an explicit policy/target/deadline without resetting SLAs
on repeats. Composite FKs use one controlled redundant observation asset column
for scope integrity. ORM history guards supplement the service contract.
Inventory closure and retirement additionally reject backdating that would
invalidate existing observations. Assessment readers share-lock the asset;
inventory writers already lock it exclusively. No inventory table or old revision
is changed by these narrowly scoped service guards.

Acceptance tests cover PostgreSQL constraints, both null and installation-scoped
concurrent first detections with an observed lock wait, rollback after finding/
event flush and recurrence failure, plus migration upgrade/downgrade/re-upgrade
and metadata parity. Existing inventory data survives downgrade to `0002`.
Verification/resolution are not implemented: recurrence tests stage test-only
resolved states. See `assessment-services.md` for the minimal fixture example.

Stop after Milestone 3 for review. No remediation, external matching/ingestion,
HTTP endpoint, simulator, warehouse or ML implementation belongs to this increment.

## Milestone 4 — Remediation and verification

Implement tasks, task-finding links, task/action events and verification results.

Acceptance: a task addresses multiple finding occurrences; completion alone does
not resolve them; failed actions remain visible; verification decision, current
state and resolution event commit atomically under a shared operation ID;
injected failures roll back everything; old-cycle/stale evidence is rejected;
retry does not duplicate resolution; eliminate/mitigate closure rules differ.

## Milestone 5 — Python enterprise simulator

Introduce configuration, generators, scenarios and runner only as implemented.
Use reusable transactional services, deterministic seeds and stable scenario IDs.
Support configurable assets, software inventory and simulated dates, assessment,
recurrence, tasks, SLA timing, patch success/failure and verification.

Acceptance: documented `uv run` CLI works without an HTTP server; same seed,
scenario version and inputs yield the same logical timeline; replay is idempotent;
business timestamps follow the simulated clock while recording timestamps reflect
insertion; integration fixtures label applicability; end-to-end tests and data
quality checks cover history, FK consistency, no overlaps and valid transitions.

Future NVD/EPSS/KEV ingestion, Bronze/Silver/Gold, AI and Power BI work is separate.
No corresponding tables or pipelines are part of these OLTP foundation changes.
