# PatchLedger

Cybersecurity exposure intelligence through operational simulation, data
warehousing, BI and AI. Currently implemented: **Milestone 1, database foundation
only**. No operational domain tables, enterprise simulator, FastAPI application,
intelligence ingestion or warehouse pipelines are implemented.

- [OLTP architecture and 15-table ERD](docs/architecture/operational-database.md)
- [Implementation milestones and acceptance criteria](docs/architecture/implementation-plan.md)

## Developer setup

Requirements: Python 3.12, uv, Docker and Docker Compose.

1. Copy `.env.example` to `.env` **only if `.env` does not already exist**.
   Set `POSTGRES_PASSWORD`, `DATABASE_URL` and `TEST_DATABASE_URL` consistently.
   Percent-encode special characters in URL passwords. Never commit `.env`.
2. Install the locked environment and local editable package:

   ```sh
   uv sync --locked --dev
   ```

3. Start the existing PostgreSQL 17 service:

   ```sh
   docker compose up -d --wait postgres
   ```

4. Apply the foundation migration from the repository root:

   ```sh
   uv run alembic upgrade head
   uv run alembic current
   uv run alembic check
   ```

`DATABASE_URL` must use `postgresql+psycopg://`. Configuration reads `.env` in the
working directory; real environment variables override it. The example .env's
other project keys are allowed. Credentials are excluded from settings repr and
validation error text. Do not log raw settings URLs or structured validation
errors containing inputs.

The first revision creates only the `operational` schema. Alembic keeps its version
table in `public`. Connections use UTC; all future business event timestamps must
be explicitly supplied and timezone-aware.

## Migrations

Alembic now lives in `db/migrations/`, moved from `warehouse/migrations/` before
the first revision. Analytical transformations are separate future work.

```sh
uv run alembic history
uv run alembic upgrade head
uv run alembic check
uv run alembic upgrade head --sql
```

For future model changes, import the model modules in
`src/patchledger/operational/models/__init__.py`, then generate and review a
revision with `uv run alembic revision --autogenerate -m "describe change"`.
Autogeneration is limited to `operational`. It intentionally reports unknown
objects there as drift; it ignores unrelated schemas. Always review generated DDL.

On a disposable development database, the foundation round trip is:

```sh
uv run alembic downgrade base
uv run alembic upgrade head
```

Downgrade drops `operational` without CASCADE. It fails if unknown objects remain;
it does not delete them. Upgrade fails if an unmanaged `operational` schema already
exists. Do not stamp/adopt an existing schema without checking ownership and DDL.

## Transactions without HTTP

The factories perform no connections on import. A command creates an engine and
session factory, owns the transaction, and disposes the engine when finished:

```python
from patchledger.core.config import Settings
from patchledger.db.session import make_engine, make_session_factory

engine = make_engine(Settings().sqlalchemy_url)
sessions = make_session_factory(engine)
try:
    with sessions.begin() as session:
        # Future services accept this session and domain inputs.
        # They can flush, but must not commit independently.
        pass
finally:
    engine.dispose()
```

Successful context exit commits; exceptions roll back and close the session.
No async engine, repository abstraction, queue, or web server is needed.

## Tests and checks

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest tests/unit
uv run pytest --require-postgres
```

`TEST_DATABASE_URL` is an explicit **maintenance connection** on a local/test
PostgreSQL 17 server. It is never the migration target. Tests create a fresh
`patchledger_test_<uuid>` database per integration test, dispose connections and
drop only the database they created. The role needs CREATEDB and permission to
drop its own databases; Compose's bootstrap role suffices. Tests never fall back
to `DATABASE_URL` and never drop or migrate the supplied maintenance database.

If TEST_DATABASE_URL is absent, ordinary `uv run pytest` reports integration tests
as skipped; `--require-postgres` makes missing configuration a failure. Connection
or permission errors are failures, not skips. An interrupted test process can
leave a UUID-named test database for manual cleanup. CI supplies PostgreSQL 17 and
requires all integration tests.

Integration tests cover upgrade/downgrade/re-upgrade, schema scoping, noncascading
downgrade, existing-schema refusal and session commit/rollback. Test-only probe
tables exist exclusively in disposable test databases. Inventory overlap,
concurrent-upgrade and verification lifecycle tests belong to later milestones
when those tables/services exist.

The simulator CLI is planned for Milestone 5, not available yet. FastAPI remains
installed for possible future analytical use; no OLTP API work is planned.
