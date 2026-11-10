"""Opt-in PostgreSQL tests always use newly created disposable databases."""

import os
from uuid import uuid4

import pytest
from dotenv import dotenv_values
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from patchledger.core.config import parse_database_url
from patchledger.db.session import make_engine


def pytest_addoption(parser):
    parser.addoption(
        "--require-postgres",
        action="store_true",
        help="Fail rather than skip if TEST_DATABASE_URL is not configured",
    )


@pytest.fixture
def postgres_engine(request):
    """TEST_DATABASE_URL is a maintenance connection, never a migration target."""
    database_url = os.environ.get("TEST_DATABASE_URL") or dotenv_values(".env").get(
        "TEST_DATABASE_URL"
    )
    if not database_url:
        message = "Set TEST_DATABASE_URL to run isolated PostgreSQL integration tests"
        if request.config.getoption("--require-postgres"):
            pytest.fail(message)
        pytest.skip(message)

    maintenance_engine = make_engine(parse_database_url(database_url))
    database_name = f"patchledger_test_{uuid4().hex}"
    test_engine = None
    created = False
    try:
        try:
            with maintenance_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as connection:
                # Identifier comes exclusively from the fixed prefix and UUID hex.
                connection.execute(text(f'CREATE DATABASE "{database_name}"'))
                created = True
            test_engine = make_engine(
                maintenance_engine.url.set(database=database_name)
            )
            with test_engine.connect():
                pass
        except DBAPIError:
            # Driver tracebacks can expose connection arguments, including passwords.
            pytest.fail(
                "PostgreSQL setup failed: check TEST_DATABASE_URL, server access "
                "and the role's CREATEDB permission",
                pytrace=False,
            )
        yield test_engine
    finally:
        if test_engine is not None:
            test_engine.dispose()
        try:
            if created:
                with maintenance_engine.connect().execution_options(
                    isolation_level="AUTOCOMMIT"
                ) as connection:
                    connection.execute(text(f'DROP DATABASE "{database_name}"'))
        except DBAPIError:
            pytest.fail(
                f"PostgreSQL cleanup failed; inspect test database {database_name}",
                pytrace=False,
            )
        finally:
            maintenance_engine.dispose()
