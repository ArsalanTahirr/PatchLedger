"""Explicit factories; callers own engine lifetime and transaction boundaries."""

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker

from patchledger.core.config import parse_database_url


def make_engine(database_url: str | URL) -> Engine:
    return create_engine(
        parse_database_url(database_url),
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"options": "-c timezone=UTC", "connect_timeout": 10},
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Use factory.begin() to commit on success and roll back on exceptions."""
    return sessionmaker(bind=engine, expire_on_commit=False)
