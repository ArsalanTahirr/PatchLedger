from datetime import UTC, datetime

import pytest

from patchledger.simulation.oltp_inventory_adapter import (
    parse_snapshot_csv,
    snapshot_sql,
)

HEADER = (
    "asset_id,asset_key,installation_id,product_id,"
    "product_name,version,covering_rows,"
    "version_status,cpe,mapping_status\n"
)


def test_valid_snapshot():
    csv_text = HEADER + (
        "asset-1,server-1,install-1,product-1,"
        "Fixture App,1.0-fixture,1,resolved,,unmapped\n"
    )

    records = parse_snapshot_csv(csv_text)

    assert len(records) == 1
    assert records[0]["version"] == "1.0-fixture"
    assert records[0]["cpe"] is None


def test_history_gap_remains_unresolved():
    csv_text = HEADER + (
        "asset-1,server-1,install-1,product-1,"
        "Fixture App,,0,no_history_at_time,,unmapped\n"
    )

    record = parse_snapshot_csv(csv_text)[0]

    assert record["version"] is None
    assert record["version_status"] == "no_history_at_time"


def test_ambiguous_history_remains_unresolved():
    csv_text = HEADER + (
        "asset-1,server-1,install-1,product-1,"
        "Fixture App,,2,ambiguous_history,,unmapped\n"
    )

    record = parse_snapshot_csv(csv_text)[0]

    assert record["version"] is None
    assert record["covering_rows"] == 2


def test_duplicate_installation_rejected():
    line = (
        "asset-1,server-1,install-1,product-1,"
        "Fixture App,1.0-fixture,1,resolved,,unmapped\n"
    )

    with pytest.raises(ValueError, match="duplicate"):
        parse_snapshot_csv(HEADER + line + line)


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        snapshot_sql(datetime(2024, 1, 9))


def test_timezone_aware_timestamp_accepted():
    query = snapshot_sql(datetime(2024, 1, 9, tzinfo=UTC))

    assert "2024-01-09T00:00:00+00:00" in query
    assert "operational.installation_history" in query
