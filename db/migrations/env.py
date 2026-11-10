"""Alembic environment for operational DDL only."""

from logging.config import fileConfig

from alembic import context

from patchledger.core.config import Settings
from patchledger.db.migrations import (
    get_target_metadata,
    include_name,
    include_object,
)
from patchledger.db.session import make_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

options = {
    "target_metadata": get_target_metadata(),
    "include_schemas": True,
    "include_name": include_name,
    "include_object": include_object,
    "version_table_schema": "public",
    "compare_type": True,
}


def migrate_connection(connection) -> None:
    context.configure(connection=connection, **options)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Test/embedding callers can supply a connection without loading .env.
    connection = config.attributes.get("connection")
    if connection is not None:
        migrate_connection(connection)
        return

    engine = make_engine(Settings().sqlalchemy_url)
    try:
        with engine.connect() as connection:
            migrate_connection(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    # Pass a URL directly: passwords containing % never enter ConfigParser.
    context.configure(
        url=Settings().sqlalchemy_url,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **options,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    run_migrations_online()
