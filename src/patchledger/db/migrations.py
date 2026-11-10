"""Shared metadata registration and Alembic autogeneration boundaries."""

from sqlalchemy import MetaData

from patchledger.db.base import OPERATIONAL_SCHEMA, Base


def get_target_metadata() -> MetaData:
    # Loading this package registers future model imports on Base.metadata.
    from patchledger.operational import models  # noqa: F401

    return Base.metadata


def include_name(name: str | None, type_: str, parent_names: dict) -> bool:
    if type_ == "schema":
        return name == OPERATIONAL_SCHEMA
    return True


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    if type_ == "table":
        return obj.schema == OPERATIONAL_SCHEMA
    return True
