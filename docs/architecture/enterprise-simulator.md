# Python enterprise simulator (Milestone 5)

The simulator writes the existing 15-table `operational` subsystem through its
transactional Python services. It creates no tables, migrations, HTTP endpoints,
warehouse models or ingestion pipelines. It uses standard-library `random.Random`
and `argparse`; no new dependencies are required.

All products, identifiers, applicability associations, observations and evidence
are **synthetic fixtures**. Syntax-only `CVE-2099-*` labels do not establish NVD
existence or independently validated product applicability. No CVSS, EPSS or KEV
values are generated. `fixtures.py` separates mappings from orchestration; unknown
versions produce inconclusive evidence rather than guessed applicability.

## Commands

Apply existing migrations through `0004` to an intentionally selected simulation
database first. The runner reads `DATABASE_URL` through existing settings and
never resets, creates or migrates that database. It never changes `.env` or Docker
volumes. Use a dedicated disposable database for experiments.

Planning loads no credentials, makes no connection and writes no operational data:

```sh
uv run python -m patchledger.simulation.runner --scenario preview --assets 12 --days 14 --plan
uv run python -m patchledger.simulation.runner --config examples/simulation-small.json --plan
```

Small, medium and full executions against the deliberately configured database:

```sh
uv run python -m patchledger.simulation.runner --config examples/simulation-small.json
uv run python -m patchledger.simulation.runner --scenario enterprise-medium-v1 --seed 42 --assets 50 --days 30 --start 2024-01-01T00:00:00+00:00
uv run python -m patchledger.simulation.runner --scenario enterprise-full-v1 --seed 42 --assets 400 --installations-per-asset 5 --days 90 --start 2024-01-01T00:00:00+00:00
```

CLI values override the optional JSON file. JSON supports the distribution options
that would make a large CLI awkward; unknown fields fail validation. Keep original
inputs for recovery: a fingerprint cannot reconstruct a lost configuration file.
`--help` lists the CLI options.

## Configuration

`SimulationConfig` normalizes explicit timezone-aware business time to UTC, with
a fixed default start of 2024-01-01 UTC. Ranges are `[start, start + days)`.
Department/criticality distributions use positive finite relative weights.

| Setting | Default | Meaning |
| --- | --- | --- |
| `scenario` | required | 1–64 character namespace; letters, digits, `_`, `-` |
| `seed` | 42 | Independent deterministic random streams |
| `assets` | 400 | 1–10,000 assets |
| `installations_per_asset` | 5 | 1–50 stable slots; about 2,000 by default |
| `start`, `days` | 2024-01-01 UTC, 90 | Explicit timeline; 1–3,660 days |
| `departments`, `criticality` | Six departments, levels 1–5 | Relative distributions |
| `internet_facing_probability` | 0.2 | Exposure proportion |
| `initial_safe_probability` | 0.3 | Safe fixture versions in nonprimary slots |
| `scan_interval_days` | 3 | Periodic assessment cadence |
| `partial_scan_probability`, `failed_scan_probability` | 0.08, 0.04 | Periodic execution outcomes |
| `inconclusive_probability` | 0.04 | Periodic observation uncertainty |
| `remediation_probability` | 0.7 | Assets selected for primary-installation work |
| `remediation_interval_days`, `max_attempts` | 2, 2 | Retry cadence and 1–5 attempt limit |
| `patch_success_probability` | 0.75 | Work changes the version |
| `ineffective_patch_probability` | 0.15 | Successful work still leaves applicability |
| `retry_probability` | 0.4 | Retry after unsuccessful work/verification |
| `sla_days`, `sla_breach_probability` | 5, 0.3 | SLA and delayed first-attempt tendency |
| `recurrence_probability` | 0.15 | Regression after verified elimination |
| `inventory_churn_probability` | 0.15 | Nonprimary removal/reinstallation |
| `retirement_probability`, `suspension_probability` | 0.025, 0.075 | Final lifecycle mixture |

Probabilities are bounded by 0–1; mutually exclusive scan/lifecycle probabilities
cannot sum above one. The primary slot starts vulnerable by design. A completed,
conclusive commissioning scan establishes its baseline; directed verification and
recurrence scans are also conclusive/completed. Periodic scans use the configured
probabilities. This is an exposure-heavy fixture cohort, not an estimate of real
enterprise prevalence. The six fictional products have two CVE-shaped labels each;
slots cycle through the catalog with separate installation identities. Vendor
identifiers are explicitly synthetic, never invented verified CPEs.

## Modules and workflows

- `config.py`, `random_state.py`: validated configuration, fingerprints, independent
  streams and stable UUID operation keys.
- `enterprise.py`, `inventory.py`: pure enterprise plans and service-driven
  registrations, installations, version changes, churn and asset lifecycle.
- `fixtures.py`, `scenarios.py`: controlled applicability and evidence generation.
- `scheduler.py`, `execution.py`: sorted immutable workflows and dispatch.
- `remediation.py`: multi-CVE tasks, attempts, explicit verification and recurrence.
- `runner.py`: transaction ownership, CLI and scenario advisory lock.
- `reporting.py`, `quality.py`: persisted counts and historical audits.

Registration precedes installation and initial detection. A primary task targets
two CVEs on one installation, with priority from planned criticality, an assigned
synthetic engineer and a due date derived from the opening SLA. Failed attempts
become blocked; successful work becomes completed. An ineffective patch still
produces positive verification and leaves findings open. Only a later completed
scan's explicit absence can authorize resolution and task closure.

A regression downgrades the installation and reopens the same persistent findings.
A new occurrence-bound task remains in the backlog; old closed work is preserved.
Other installations are unmanaged in this first recipe. Missing observations,
removal and retirement never automatically resolve findings. Retirement explicitly
removes installed software first. Criticality changes, suspension and retirement
preserve asset history.

The scheduler uses explicit business timestamps and stable ordering for ties. An
atomic workflow can contain closely spaced evidence, decision and closure times;
equal-time workflows on different assets are independent. Per-entity chronology
and half-open inventory periods remain enforced by existing services. Recording
times use the actual database clock, including for future simulated ranges.
Work beyond the end is omitted and remains legitimate backlog. SLA tendencies are
probabilistic; retries and the finite horizon can change realized compliance.

## Replay and recovery

Business keys use `sim:<scenario>:`. Independent streams depend on scenario, seed
and component identity, never replay progress. Operation/run/observation keys are
stable. Database UUID primary keys and recording timestamps are not seeded;
reproducibility means equivalent logical operations, relationships and outcomes.

Normal synthetic provenance on the first asset's registration holds a normalized
configuration, fixture-content and generator fingerprint. The first registration
batch atomically establishes departments, catalog and this natural anchor. No
fake task, extra table or cross-resource checkpoint file is introduced. Different
inputs or fixture mappings under the same scenario fail before writes. Behaviour
changes require a generator version bump and a new scenario. A PostgreSQL session
advisory lock prevents simultaneous runs of one scenario in one database.

Replay looks up original registration/version periods and historical opening
events rather than today's state. Inventory operations without operation keys
recognize matching historical receipts; other operations reuse existing service
idempotency. The unchanged plan replays from the beginning after interruption.
Completed operations return/check original records, and the failed workflow runs
again. No validation is bypassed and no timeline is rewritten.

Setup batches contain at most 25 assets. Each scheduled business workflow owns a
transaction; action/version and verification/resolution/closure writes remain
atomic. The entire run is not one transaction, and individual rows are not
committed separately. Unexpected errors roll back the current workflow and surface
its stable key; earlier committed workflows remain for recovery. No transaction
waits for an external scanner or patch process.

Scenario-owned records must be exclusively managed by this simulator. Advisory
locks do not coordinate arbitrary other writers. External corrections can
invalidate receipts/audits and require review. There is no destructive reset,
automatic adoption or migration of older scenarios. Keep original input files;
use a new identifier for incompatible experiments.

## Reporting, quality and future extraction

The final report reads a consistent, read-only namespace snapshot. Counts are
persisted scenario totals, not newly inserted rows or attempted operations.
It includes departments, assets, catalog, stable/current installations, history,
scans, observations, unique findings, reopenings, tasks, action outcomes, accepted
resolutions, unsuccessful verification, unresolved backlog and breached SLA
occurrences. Each opening's stored SLA is evaluated against resolution evidence
or the scenario end; task planning dates do not replace finding SLAs.

Audits check scoped references/uniqueness across all 15 tables, synthetic
provenance, timestamp bounds, asset snapshots, installation overlap, fixture
applicability, finding transitions/current state, paired resolution decisions and
historical task closure proof. Closure is checked as of its own occurrence/time;
a later recurrence does not invalidate an earlier legitimate closure.
These checks do not independently verify real applicability or scanner coverage.

Plans and final audit records are currently held in memory per scenario. Runtime
and memory scale with volume; there is no claim of full-scale performance without
an actual database benchmark. Future ETL can read stable identities, occurrence
history and both timestamp kinds. No warehouse extraction or Bronze/Silver/Gold
work is implemented. Replacing fixture applicability with reviewed NVD data is
future work, not a matching engine in this milestone.

## Tests and validation limits

```sh
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run pytest --require-postgres
uv run pytest tests/integration/test_simulation.py::test_small_end_to_end_and_identical_replay --require-postgres -s
PATCHLEDGER_MEDIUM_SIMULATION=1 uv run pytest tests/integration/test_simulation.py::test_medium_simulation --require-postgres -s
```

Normal CI includes small scenarios (12 assets/14 days), recovery and replay tests.
The 50-asset/30-day medium benchmark is opt-in; 400 assets/90 days never runs in
normal CI. Integration fixtures create and drop only their own disposable test
databases. Unit tests need no PostgreSQL connection.

In this implementation workspace, PostgreSQL 17 tests are blocked by sandbox TCP
permissions (`PermissionError`, errno 1). Permissions were not weakened and
PostgreSQL 18 was not substituted. Unit/planning checks can run, but persisted
end-to-end counts, replay results and medium performance still require validation
where the configured PostgreSQL 17 test connection is permitted. Plan counts are
not persisted measurements.
