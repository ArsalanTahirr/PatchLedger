# PatchLedger — Bronze & Silver Reproduction Guide

**Scope:** Bronze ingestion, Silver SQL transformations, OLTP inventory, and NVD/CPE matching only. **No Gold, no `main` merge, and no PR is created by these instructions.**

**Source branch:** `feature/sql-bronze-silver`  
**Verified implementation commit:** `1bbada4`  
**Repository:** https://github.com/ArsalanTahirr/PatchLedger

## Architecture

All operational, Bronze, and Silver tables are in **one PostgreSQL database** (`patchledger`), separated by schemas:

- `operational`: existing OLTP data maintained by the underlying PatchLedger application
- `bronze`: raw NVD, EPSS, KEV CSV records and an OLTP snapshot
- `silver`: cleaned NVD, EPSS and KEV data, rejected-record audit, software inventory, SQL CPE/NVD evaluation functions
- `gold`: **outside this implementation; do not create, change or drop Gold objects**

Python `scripts/ingest_bronze.py` only ingests raw CSV records into `bronze`. Cleaning, deduplication and matching are **SQL**.

## Prerequisites and fixed local assumptions

- macOS/Linux shell with `bash`, Docker Desktop/Engine and `uv` installed. The importer uses `fcntl`, so it is not a native-Windows script.
- Running Docker container **`patchledger-postgres`**; PostgreSQL database **`patchledger`**; PostgreSQL user **`patchledger`**. These are currently hardcoded in `scripts/ingest_bronze.py` and the companion script.
- PostgreSQL **16 or newer** for `pg_input_is_valid`, which the transformation SQL uses.
- The existing PatchLedger operational schema/data must be set up if the OLTP snapshot or software-inventory workflow is required.
- Local CSVs must have the exact expected headers. Default directory:
  `~/Desktop/University/PatchLedgerData`
- Download source data from:
  https://huggingface.co/datasets/patchledger/patchledger-data/tree/main
  and retain these names:
  `nvd_cves.csv`, `epss_scores.csv`, `known_exploited_vulnerabilities.csv`.
- Plan substantial **real disk space** for NVD import and transformation. Do **not** trust Docker virtual-disk reported free space as proof of free Mac disk space. A full NVD source was ~2.9 GiB, and the SQL transformation temporarily consumed many extra GiB in the verified environment.

**Security and data safety:** Run only against a disposable local/development PatchLedger database you control. This guide does not change Gold, but its explicit `--apply` steps **do write** to the specified `patchledger` database. Back up important local data first. Check your Docker context/container and database names yourself.

## Copy the helper into the repository

Place `setup_bronze_silver.sh` at `scripts/setup_bronze_silver.sh`. From the repository root:

```bash
bash scripts/setup_bronze_silver.sh check
```

`check` is read-only and prints connection/schema information.

The commands below deliberately require `--apply` for mutating actions. Do not combine all commands into an unattended pipeline; check outputs and disk capacity between steps.

## Fresh setup and execution order

**1 — Start the project's PostgreSQL service** with the project's existing Docker Compose instructions. Confirm `patchledger-postgres`, `patchledger`, and `patchledger` user are the intended local development database.

**2 — Create Bronze and Silver base tables:**

```bash
bash scripts/setup_bronze_silver.sh init --apply
```

This executes `sql/bronze/001_create_tables.sql` then `sql/silver/001_create_tables.sql`.

**3 — Inspect CSV headers without any writes:**

```bash
uv run python scripts/ingest_bronze.py kev
uv run python scripts/ingest_bronze.py epss
uv run python scripts/ingest_bronze.py nvd
```

If your CSVs are in another folder, supply `--data-dir /path/to/data` on each command.

**4 — Load raw CSVs using Python (Bronze only):**

```bash
uv run python scripts/ingest_bronze.py kev --apply
uv run python scripts/ingest_bronze.py epss --apply
uv run python scripts/ingest_bronze.py nvd --apply
```

Do not add `--limit` for the complete dataset. The importer stores batch source name, file SHA-256 and record count and skips a duplicate import with the same source and hash. Running with `--limit` creates separate `*:sample:N` batches; these sample rows will be deduplicated during Silver transformation.

**5 — Transform to Silver using SQL:**

```bash
bash scripts/setup_bronze_silver.sh transform-kev --apply
bash scripts/setup_bronze_silver.sh transform-epss --apply
bash scripts/setup_bronze_silver.sh transform-nvd --apply --confirm-large-nvd
```

Each SQL file has `BEGIN` / `COMMIT` and creates a temporary review table to validate and deduplicate. **NVD is the high-disk-usage operation**; run once, check storage, and do not rerun casually. `--confirm-large-nvd` is a separate explicit acknowledgment for the large transformation; the helper refuses it with less than 20 GiB host free space.

**6 — Snapshot company OLTP and prepare software inventory (SQL):**

```bash
bash scripts/setup_bronze_silver.sh snapshot-oltp --apply
bash scripts/setup_bronze_silver.sh inventory --apply
```

These require the existing `operational` tables and appropriate permissions. Inspect `sql/bronze/002_snapshot_oltp.sql` and `sql/silver/005_inventory.sql` before running on a populated environment; they are not general-purpose schema migrations. The snapshot source and inventory refresh semantics depend on the project's operational data. If OLTP setup is absent, skip this stage until it is available rather than inventing inventory data.

**7 — Install SQL matching functions in dependency order:**

```bash
bash scripts/setup_bronze_silver.sh functions --apply
```

This loads `006_cpe_match.sql` through `013_evaluate_cve.sql` into the **Silver schema** inside one transaction. It does not perform an all-CVE/all-asset cross join or materialize final vulnerability assessments.

**8 — Verify status (read-only):**

```bash
bash scripts/setup_bronze_silver.sh status
```

Also check batch and duplicate summaries:

```bash
docker exec patchledger-postgres psql -X -v ON_ERROR_STOP=1 \
  -U patchledger -d patchledger -c \
  "SELECT source_name, row_count FROM bronze.ingest_batches ORDER BY source_name;"

docker exec patchledger-postgres psql -X -v ON_ERROR_STOP=1 \
  -U patchledger -d patchledger -c \
  "SELECT source_name, reason, COUNT(*) FROM silver.rejected_records GROUP BY 1,2 ORDER BY 1,2;"
```

**9 — Test only in isolated databases.** Existing integration tests use `TEST_DATABASE_URL` to create disposable test databases. The source repository's existing `.env` can supply the *maintenance* connection to the local `postgres` database, but **never** point the test fixture at the real `patchledger` database. Verify the fixture and connection settings before running:

```bash
uv run ruff check .
uv run ruff format --check .
```

For PostgreSQL integration tests, use the repository's established safe `TEST_DATABASE_URL` setup and `uv run pytest --require-postgres -q`, not an unreviewed database URL.

## Previously observed local validation (not a guarantee for others)

| Feed | Full raw Bronze import | Silver unique records | Rejected duplicate sample rows |
| --- | ---: | ---: | ---: |
| NVD | 424,195 | 424,195 | 10,005 |
| EPSS | 406,184 | 406,184 | 5 |
| KEV | 1,781 | 1,781 | 5 |

The earlier NVD raw table also contained 10,005 sample rows; EPSS and KEV contained five each. Full cross-feed CVE joins yielded 405,034 NVD records with EPSS and 1,780 NVD records in KEV. Inventory had 48 records, of which 12 had usable CPEs. Four targeted CVE/product pairs returned `applicable` when evaluated using SQL; this is not independent confirmation of exploits on physical machines.

Automated baseline: **193 passed, 1 intentionally skipped** on the guarded local PostgreSQL test setup.

## Known limitations and troubleshooting

- **CPE coverage:** Assets without CPE identifiers cannot receive reliable CPE-based matches; the example inventory had 36 of 48 missing CPE.
- **Matching:** Unsupported CPE escape patterns, nonnumeric version schemes, and incomplete/complex NVD configurations can return `inconclusive`. This must not be interpreted as `not_applicable` or “safe.”
- **Single-host ingestion lock:** `fcntl.flock` coordinates importer processes on the same host, not distributed machines.
- **Large NVD SQL memory/temp use:** Its temporary review table carries parsed JSON and window ranking. In a real full-data run, many GiB of temporary disk were consumed. Verify host free space before and during the run. A stopped terminal client does not always prove the PostgreSQL backend has stopped; inspect `pg_stat_activity` before rerunning.
- **Existing sample batches:** Duplicates are recorded in `silver.rejected_records`; Silver holds one row per CVE.
- **Version freshness:** Data and matching quality depend on which CSV snapshots were downloaded.
- **Do not use `docker system prune`, manually delete PostgreSQL files, or rerun the full NVD transform to troubleshoot.** Inspect activity, row counts and storage first.
- **Gold / PR:** This setup does not change Gold, create a PR, switch branches, commit or push. Share the documentation and script in the same feature branch via a *separate* explicitly reviewed commit when ready.
