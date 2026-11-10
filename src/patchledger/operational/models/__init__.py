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
from patchledger.operational.models.remediation import (
    RemediationEvent,
    RemediationTask,
    TaskFinding,
    VerificationResult,
)

__all__ = [
    "Asset",
    "AssetEvent",
    "Department",
    "FindingEvent",
    "InstallationHistory",
    "ProductIdentifier",
    "RemediationEvent",
    "RemediationTask",
    "ScanObservation",
    "ScanRun",
    "SoftwareInstallation",
    "SoftwareProduct",
    "TaskFinding",
    "VerificationResult",
    "VulnerabilityFinding",
]
