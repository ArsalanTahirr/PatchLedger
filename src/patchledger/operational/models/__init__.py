"""Explicit model registration for Alembic and operational services."""

from patchledger.operational.models.assessment import (
    FindingEvent,
    ScanObservation,
    ScanRun,
    VulnerabilityFinding,
)
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
    "FindingEvent",
    "InstallationHistory",
    "ProductIdentifier",
    "ScanObservation",
    "ScanRun",
    "SoftwareInstallation",
    "SoftwareProduct",
    "VulnerabilityFinding",
]
