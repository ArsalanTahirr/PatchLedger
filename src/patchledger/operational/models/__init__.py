"""Explicit model registration for Alembic and inventory services."""

from patchledger.operational.models.inventory import (
    Asset,
    AssetEvent,
    Department,
    InstallationHistory,
    ProductIdentifier,
    SoftwareInstallation,
    SoftwareProduct,
)

__all__ = [
    "Asset",
    "AssetEvent",
    "Department",
    "InstallationHistory",
    "ProductIdentifier",
    "SoftwareInstallation",
    "SoftwareProduct",
]
