"""Shared business-time, provenance and bounded idempotency payload helpers."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

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


def bounded_json_object(value, field):
    if not isinstance(value, dict):
        raise InvalidOperationError(f"{field} must be a JSON object")
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode()) > 16384:
            raise InvalidOperationError(f"{field} exceeds 16384 bytes")
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidOperationError(f"{field} must contain valid JSON values") from exc


def payload_digest(values):
    def encode(value):
        if isinstance(value, datetime):
            return effective_time(value).isoformat()
        if isinstance(value, UUID):
            return str(value)
        raise TypeError("Unsupported operational payload value")

    return hashlib.sha256(
        json.dumps(
            values,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            default=encode,
        ).encode()
    ).hexdigest()
