# Operational implementation plan

No milestone includes an operational FastAPI application. Keep existing optional
dependencies/scaffolding. All tables below are planned until their milestone is
implemented. Integration tests accompany each increment.

## Milestone 1 — Database foundation (current scope)

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
implementation. Stop for review after this milestone.

## Milestone 2 — Enterprise inventory

Implement departments, assets, asset events, products, product identifiers,
installations and installation history, plus focused inventory services.

Acceptance: stable identities, atomic snapshot history, correct upgrades,
downgrades and removals; invalid periods rejected; concurrent upgrades on two
connections serialize and stale expectations fail; test backdated gaps/overlaps
and rollback. Preserve historical department assignment/criticality, explicitly
without a department-name history subsystem.

## Milestone 3 — Vulnerability assessment

Implement scans, immutable observations, findings and finding events.

Acceptance: identical replay is idempotent; conflicting keys fail; repeated
observations create one finding; absence is never inferred from omission;
source-time ordering avoids false reopenings; each genuine recurrence has a new
opening event; positive/negative/inconclusive evidence remains distinct. Use
labelled applicability fixtures, not invented real-world matches.

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
