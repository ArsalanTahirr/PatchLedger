from datetime import UTC, datetime, timedelta, timezone

import pytest

from patchledger.operational.exceptions import InvalidOperationError
from patchledger.operational.services.common import EventContext, effective_time


def test_naive_business_time_is_rejected():
    with pytest.raises(InvalidOperationError, match="timezone-aware"):
        effective_time(datetime(2024, 1, 1))


def test_aware_business_time_is_normalized_to_utc():
    event = EventContext(
        datetime(2024, 1, 1, 5, tzinfo=timezone(timedelta(hours=5))),
        "test:actor",
        "fixture:inventory",
        True,
    )
    assert event.occurred_at == datetime(2024, 1, 1, tzinfo=UTC)
    assert event.occurred_at.tzinfo is UTC
