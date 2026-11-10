from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from patchledger.db.migrations import (
    get_target_metadata,
    include_name,
    include_object,
)
from patchledger.db.session import make_session_factory

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]
REVISION = "0003"
OPERATIONAL_TABLES = {
    "departments",
    "assets",
    "asset_events",
    "software_products",
    "product_identifiers",
    "software_installations",
    "installation_history",
    "scan_runs",
    "scan_observations",
    "vulnerability_findings",
    "finding_events",
}


def run_alembic(engine, operation, *args):
    config = Config(str(ROOT / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        operation(config, *args)


def test_upgrade_downgrade_reupgrade_preserves_unrelated_data(postgres_engine):
    with postgres_engine.begin() as connection:
        assert connection.dialect.server_version_info[0] == 17
        assert connection.scalar(text("SHOW TIME ZONE")) == "UTC"
        connection.execute(text("CREATE SCHEMA foundation_test_external"))
        connection.execute(
            text("CREATE TABLE foundation_test_external.sentinel (value integer)")
        )
        connection.execute(
            text("INSERT INTO foundation_test_external.sentinel VALUES (42)")
        )
        connection.execute(text("CREATE TABLE public.unrelated (value integer)"))

    run_alembic(postgres_engine, command.upgrade, "head")
    with postgres_engine.connect() as connection:
        assert inspect(connection).has_schema("operational")
        assert (
            set(inspect(connection).get_table_names(schema="operational"))
            == OPERATIONAL_TABLES
        )
        assert (
            connection.scalar(text("SELECT version_num FROM public.alembic_version"))
            == REVISION
        )
    run_alembic(postgres_engine, command.check)

    run_alembic(postgres_engine, command.downgrade, "0001_operational_schema")
    with postgres_engine.connect() as connection:
        assert inspect(connection).get_table_names(schema="operational") == []
        assert (
            connection.scalar(text("SELECT version_num FROM public.alembic_version"))
            == "0001_operational_schema"
        )
    run_alembic(postgres_engine, command.upgrade, "head")
    run_alembic(postgres_engine, command.check)

    run_alembic(postgres_engine, command.downgrade, "base")
    with postgres_engine.connect() as connection:
        assert not inspect(connection).has_schema("operational")
        assert (
            connection.scalar(text("SELECT count(*) FROM public.alembic_version")) == 0
        )
        assert (
            connection.scalar(
                text("SELECT value FROM foundation_test_external.sentinel")
            )
            == 42
        )
        assert inspect(connection).has_table("unrelated", schema="public")

    run_alembic(postgres_engine, command.upgrade, "head")
    run_alembic(postgres_engine, command.check)
    with postgres_engine.connect() as connection:
        assert inspect(connection).has_schema("operational")
        assert (
            set(inspect(connection).get_table_names(schema="operational"))
            == OPERATIONAL_TABLES
        )


def test_alembic_online_environment_uses_database_url(postgres_engine, monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", postgres_engine.url.render_as_string(hide_password=False)
    )
    config = Config(str(ROOT / "alembic.ini"))
    # Exercise the ordinary CLI environment path, without an injected connection.
    command.upgrade(config, "head")
    command.check(config)
    with postgres_engine.connect() as connection:
        assert (
            connection.scalar(text("SELECT version_num FROM public.alembic_version"))
            == REVISION
        )


def test_downgrade_refuses_to_cascade_delete_unknown_objects(postgres_engine):
    run_alembic(postgres_engine, command.upgrade, "head")
    with postgres_engine.begin() as connection:
        connection.execute(text("CREATE TABLE operational.test_guard (id integer)"))

    with pytest.raises(DBAPIError):
        run_alembic(postgres_engine, command.downgrade, "base")

    with postgres_engine.connect() as connection:
        assert inspect(connection).has_table("test_guard", schema="operational")
        assert (
            connection.scalar(text("SELECT version_num FROM public.alembic_version"))
            == REVISION
        )


def test_upgrade_does_not_adopt_an_existing_schema(postgres_engine):
    with postgres_engine.begin() as connection:
        connection.execute(text("CREATE SCHEMA operational"))
    with pytest.raises(DBAPIError):
        run_alembic(postgres_engine, command.upgrade, "head")
    with postgres_engine.connect() as connection:
        assert inspect(connection).has_schema("operational")


def test_autogenerate_ignores_other_schemas_but_detects_operational_drift(
    postgres_engine,
):
    run_alembic(postgres_engine, command.upgrade, "head")
    with postgres_engine.begin() as connection:
        connection.execute(text("CREATE TABLE public.unrelated (id integer)"))
        connection.execute(text("CREATE SCHEMA foundation_test_external"))
        connection.execute(
            text("CREATE TABLE foundation_test_external.unrelated (id integer)")
        )
        connection.execute(text("CREATE TABLE operational.test_drift (id integer)"))
        context = MigrationContext.configure(
            connection,
            opts={
                "include_schemas": True,
                "include_name": include_name,
                "include_object": include_object,
                "version_table_schema": "public",
            },
        )
        differences = compare_metadata(context, get_target_metadata())
    assert len(differences) == 1
    operation, table = differences[0]
    assert operation == "remove_table"
    assert (table.schema, table.name) == ("operational", "test_drift")


def test_session_transactions_commit_and_rollback_as_one_unit(postgres_engine):
    # A disposable test-only table; no application table is introduced.
    with postgres_engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE public.transaction_probe (id integer PRIMARY KEY)")
        )
    factory = make_session_factory(postgres_engine)
    with factory.begin() as session:
        session.execute(text("INSERT INTO public.transaction_probe VALUES (1)"))

    with (
        pytest.raises(RuntimeError, match="service failure"),
        factory.begin() as session,
    ):
        session.execute(text("INSERT INTO public.transaction_probe VALUES (2)"))
        raise RuntimeError("service failure")

    with pytest.raises(IntegrityError), factory.begin() as session:
        session.execute(text("INSERT INTO public.transaction_probe VALUES (3)"))
        session.execute(text("INSERT INTO public.transaction_probe VALUES (1)"))

    with factory.begin() as session:
        session.execute(text("INSERT INTO public.transaction_probe VALUES (4)"))
        assert session.scalars(
            text("SELECT id FROM public.transaction_probe ORDER BY id")
        ).all() == [1, 4]
