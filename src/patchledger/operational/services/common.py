"""Explicit business-time and provenance inputs shared by inventory operations."""

from dataclasses import dataclass
from datetime import UTC, datetime

from patchledger.operational.exceptions import InvalidOperationError


def effective_time(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise InvalidOperationError("A timezone-aware effective timestamp is required")
    return value.astimezone(UTC)


def nonempty(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidOperationError(f"{field} must be nonempty text")
    return value.strip()


@dataclass(frozen=True)
class EventContext:
    occurred_at: datetime
    actor_ref: str
    source_key: str
    is_synthetic: bool

    def __post_init__(self):
        object.__setattr__(self, "occurred_at", effective_time(self.occurred_at))
        object.__setattr__(self, "actor_ref", nonempty(self.actor_ref, "actor_ref"))
        object.__setattr__(self, "source_key", nonempty(self.source_key, "source_key"))
        if not isinstance(self.is_synthetic, bool):
            raise InvalidOperationError(
                "is_synthetic must be explicit boolean provenance"
            )
