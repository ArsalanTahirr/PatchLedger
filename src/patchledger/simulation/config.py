"""Validated, versioned scenario inputs. No wall-clock business-time defaults."""

import hashlib
import json
import math
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from patchledger.simulation.fixtures import fixture_fingerprint

GENERATOR_VERSION = "enterprise-v1"


class SimulationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    scenario: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    seed: int = Field(default=42, strict=True)
    assets: int = Field(default=400, ge=1, le=10000, strict=True)
    installations_per_asset: int = Field(default=5, ge=1, le=50, strict=True)
    start: datetime = datetime(2024, 1, 1, tzinfo=UTC)
    days: int = Field(default=90, ge=1, le=3660, strict=True)
    departments: dict[str, float] = Field(
        default_factory=lambda: {
            "Engineering": 25,
            "Operations": 20,
            "Finance": 12,
            "Sales": 18,
            "Human Resources": 10,
            "Security": 15,
        }
    )
    criticality: dict[int, float] = Field(
        default_factory=lambda: {1: 5, 2: 15, 3: 40, 4: 25, 5: 15}
    )
    internet_facing_probability: float = Field(default=0.2, ge=0, le=1)
    initial_safe_probability: float = Field(default=0.3, ge=0, le=1)
    scan_interval_days: int = Field(default=3, ge=1, le=3660, strict=True)
    inconclusive_probability: float = Field(default=0.04, ge=0, le=1)
    partial_scan_probability: float = Field(default=0.08, ge=0, le=1)
    failed_scan_probability: float = Field(default=0.04, ge=0, le=1)
    remediation_probability: float = Field(default=0.7, ge=0, le=1)
    remediation_interval_days: int = Field(default=2, ge=1, le=3660, strict=True)
    max_attempts: int = Field(default=2, ge=1, le=5, strict=True)
    patch_success_probability: float = Field(default=0.75, ge=0, le=1)
    ineffective_patch_probability: float = Field(default=0.15, ge=0, le=1)
    retry_probability: float = Field(default=0.4, ge=0, le=1)
    sla_days: int = Field(default=5, ge=1, le=365, strict=True)
    sla_breach_probability: float = Field(default=0.3, ge=0, le=1)
    recurrence_probability: float = Field(default=0.15, ge=0, le=1)
    inventory_churn_probability: float = Field(default=0.15, ge=0, le=1)
    retirement_probability: float = Field(default=0.025, ge=0, le=1)
    suspension_probability: float = Field(default=0.075, ge=0, le=1)

    @field_validator("start")
    @classmethod
    def aware_start(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("start must include a timezone")
        return value.astimezone(UTC)

    @field_validator("departments", "criticality")
    @classmethod
    def valid_weights(cls, weights):
        if (
            not weights
            or any(not math.isfinite(w) or w <= 0 for w in weights.values())
            or not math.isfinite(sum(weights.values()))
        ):
            raise ValueError("distribution weights must be finite and positive")
        return weights

    @model_validator(mode="after")
    def compatible_values(self):
        if any(
            not name.strip() or name != name.strip() or len(name) > 64
            for name in self.departments
        ):
            raise ValueError(
                "department names must be nonblank, trimmed and at most 64 characters"
            )
        if set(self.criticality) - {1, 2, 3, 4, 5}:
            raise ValueError("criticality keys must be integers from 1 to 5")
        if self.partial_scan_probability + self.failed_scan_probability > 1:
            raise ValueError(
                "partial and failed scan probabilities must sum to at most one"
            )
        if self.retirement_probability + self.suspension_probability > 1:
            raise ValueError(
                "retirement and suspension probabilities must sum to at most one"
            )
        try:
            self.start + timedelta(days=self.days + self.sla_days + 1)
        except OverflowError as exc:
            raise ValueError("configured dates exceed the datetime range") from exc
        return self

    @property
    def end(self):
        return self.start + timedelta(days=self.days)

    @property
    def prefix(self):
        return f"sim:{self.scenario}:"

    @property
    def fingerprint(self):
        values = {
            "generator": GENERATOR_VERSION,
            "fixture": "catalog-v1",
            "fixture_fingerprint": fixture_fingerprint(),
            **self.model_dump(mode="json"),
        }
        return hashlib.sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @property
    def source(self):
        return f"{self.prefix}{GENERATOR_VERSION}:{self.fingerprint}"
