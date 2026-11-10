"""Inventory domain errors, independent of any transport or user interface."""


class InventoryError(Exception):
    """Base class for rejected inventory operations."""


class NotFoundError(InventoryError):
    """The requested domain identity does not exist."""


class ConflictError(InventoryError):
    """An identity or existing state conflicts with the requested operation."""


class InvalidOperationError(InventoryError):
    """The input or state transition is invalid."""


class HistoricalConflictError(InvalidOperationError):
    """An operation would overlap or rewrite established business history."""


class StaleVersionError(ConflictError):
    """The installation no longer has the caller's expected current version."""


class ImmutableRecordError(InventoryError):
    """An ORM write attempts to change immutable identity or history."""
