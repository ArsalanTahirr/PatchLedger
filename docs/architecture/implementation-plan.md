# Operational implementation plan

No milestone includes an operational FastAPI application. Keep existing optional
dependencies/scaffolding. Milestones 1–4 are implemented. Milestone 5's simulator
is implemented with PostgreSQL validation pending under workspace restrictions.
Integration tests accompany each increment.

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
Those original assessment tests stage test-only resolved states; Milestone 4
adds separate verification-backed lifecycle tests. See `assessment-services.md`
for the minimal fixture example.

Milestone 3 added assessment only. Remediation and verification were added
separately in Milestone 4; external matching/ingestion, HTTP, simulation, warehouse
and ML functionality remain outside these increments.

## Milestone 4 — Remediation and verification (implemented; review boundary)

Revision `0004 -> 0003` completes the 15-table design with `remediation_tasks`,
`task_findings`, `remediation_events` and `verification_results`. Previous revision
files and the first 11 table definitions are unchanged.

Implemented operations: create/assign/plan tasks, add/withdraw occurrence-bound
targets, validated state transitions/reopening/cancellation, record action
outcomes, atomically change software inventory with action history, verify
scan/manual evidence, atomically resolve with a shared operation ID, and close
multi-target eliminate/mitigate work only after all proof requirements pass.
Task completion remains separate from verified closure. Pure action logging
never runs an external scanner/process or claims a successful remediation.

Scan absence is explicit, completed, correctly scoped and newer than positives
and applicable actions; exact inventory and target-absence coverage are checked.
Manual evidence is a documented independent attestation with verifier/rationale.
Mitigation remains distinct from elimination and must be unexpired at closure.
Task/asset/finding locks, replay digests and database uniqueness serialize competing
writers. Existing inventory guards also protect manually verified history.
Backdated reinstallation is rejected when it would contradict accepted absence.
The architecture's finding-first prose was clarified to honor established parent
lock order; no circular FK or extra domain table was introduced.

Tests cover both race orderings for verification/detection, task updates/closure
versus scope withdrawal, multiple targets, invalid and historical evidence,
mitigation expiry, retry conflicts, SQL constraints and rollback. All previous
behavior tests remain; historical `0003` metadata parity is checked against its
11-table subset, while head/foundation parity now includes all 15. Migration
`0004` downgrade preserves the previous 11 tables and their data. The runnable
fixture workflow and its identical replay are also exercised by PostgreSQL tests.

Acceptance: a task addresses multiple finding occurrences; completion alone does
not resolve them; failed actions remain visible; verification decision, current
state and resolution event commit atomically under a shared operation ID;
injected failures roll back everything; old-cycle/stale evidence is rejected;
retry does not duplicate resolution; eliminate/mitigate closure rules differ.

Milestone 4 added remediation/verification only; see `remediation-services.md`.
The simulator is added separately below. External/analytical/ML components remain
unimplemented.

## Milestone 5 — Python enterprise simulator (implemented; validation pending)

`src/patchledger/simulation/` provides typed configuration, independent seeded
streams, pure enterprise/event plans, a separate synthetic applicability catalog,
service-only execution and persisted reporting/audits. The CLI supports JSON
configuration and a database-free `--plan` mode. Defaults are 400 assets, five
installations per asset and 90 simulated days; no NumPy or new dependency is used.

Recipes cover initial inventory, periodic complete/partial/failed scans, explicit
positive/negative/inconclusive observations, multi-target tasks, failed and
ineffective/successful patches, explicit verification/closure, recurrence backlog,
removal/reinstallation, criticality changes and final suspension/retirement.
Everything remains synthetic; no real applicability or threat scores are invented.

Configuration/fixture fingerprints in registration provenance reject conflicting
scenario reuse. PostgreSQL advisory locks isolate scenario runners. Historical
periods/opening events and service operation keys support identical replay and
recovery after a rolled-back workflow. Setup uses batches of at most 25 assets;
scheduled workflows have bounded caller-owned transactions. No bookkeeping table,
schema/migration change or operational business-logic change is introduced.

Acceptance: documented `uv run` CLI works without an HTTP server; same seed,
scenario version and inputs yield the same logical timeline; replay is idempotent;
business timestamps follow the simulated clock while recording timestamps reflect
insertion; integration fixtures label applicability; end-to-end tests and data
quality checks cover history, FK consistency, no overlaps and valid transitions.

Unit/planning checks run in the workspace. Actual PostgreSQL tests are blocked by
sandbox TCP permissions; no permissions were weakened or server version replaced.
Small end-to-end, cross-database reproducibility, retry/recovery and isolation
tests are provided with the existing disposable fixtures. A medium benchmark is
opt-in and the full run is excluded from CI. Persisted counts and database replay
remain unverified until those tests run with PostgreSQL 17 access.

See `enterprise-simulator.md` and `examples/simulation-small.json` for commands,
configuration, provenance, quality checks and limitations. Stop after Milestone 5;
do not begin threat intelligence or warehouse implementation.

Future NVD/EPSS/KEV ingestion, Bronze/Silver/Gold, AI and Power BI work is separate.
No corresponding tables or pipelines are part of these OLTP foundation changes.
