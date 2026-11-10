"""Reviewed synthetic associations, explicitly NOT validated NVD applicability.

CVE-2099-* strings are syntax-only fixture labels; no existence/score is claimed.
Replacing this provider requires a new fixture/generator version and scenario.
"""

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProductFixture:
    key: str
    name: str
    cves: tuple[str, ...]
    affected_versions: tuple[str, ...] = (
        "1.0-fixture",
        "1.1-fixture",
        "1.2-fixture",
        "1.3-fixture",
        "1.4-fixture",
        "1.5-fixture",
    )
    unaffected_versions: tuple[str, ...] = ("2.0-fixture",)
    publisher: str = "PatchLedger Synthetic Publisher"

    def outcome(self, cve: str, version: str | None):
        if cve not in self.cves:
            raise ValueError("CVE is outside this controlled product fixture")
        if version is None:
            return "target_absent"
        if version in self.affected_versions:
            return "affected"
        if version in self.unaffected_versions:
            return "not_affected"
        return "inconclusive"


CATALOG = (
    ProductFixture(
        "gateway", "Fixture Web Gateway", ("CVE-2099-90001", "CVE-2099-90002")
    ),
    ProductFixture(
        "agent", "Fixture Endpoint Agent", ("CVE-2099-90003", "CVE-2099-90004")
    ),
    ProductFixture(
        "database", "Fixture Database Service", ("CVE-2099-90005", "CVE-2099-90006")
    ),
    ProductFixture(
        "runtime", "Fixture Application Runtime", ("CVE-2099-90007", "CVE-2099-90008")
    ),
    ProductFixture(
        "monitor", "Fixture Monitoring Service", ("CVE-2099-90009", "CVE-2099-90010")
    ),
    ProductFixture(
        "backup", "Fixture Backup Agent", ("CVE-2099-90011", "CVE-2099-90012")
    ),
)


def fixture_fingerprint():
    """A mapping change invalidates reuse even if its version label was not bumped."""
    return hashlib.sha256(
        json.dumps([asdict(p) for p in CATALOG], sort_keys=True).encode()
    ).hexdigest()
