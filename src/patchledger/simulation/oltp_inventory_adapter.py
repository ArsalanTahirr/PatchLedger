"""Read-only, time-aware OLTP inventory extraction."""

import csv
import io
import subprocess
import sys
from collections import Counter
from datetime import datetime


def snapshot_sql(as_of):
    if not isinstance(as_of, datetime) or as_of.tzinfo is None:
        raise ValueError("Assessment timestamp must be timezone-aware")

    timestamp = as_of.isoformat()

    return f"""
WITH assessment AS (
    SELECT '{timestamp}'::timestamptz AS as_of
)
SELECT
    a.id::text AS asset_id,
    a.asset_key,
    si.id::text AS installation_id,
    si.installation_key,
    sp.id::text AS product_id,
    sp.name AS product_name,
    sp.publisher_name,
    h.version,
    h.covering_rows,
    CASE
        WHEN h.covering_rows = 0 THEN 'no_history_at_time'
        WHEN h.covering_rows > 1 THEN 'ambiguous_history'
        ELSE 'resolved'
    END AS version_status,
    NULL::text AS cpe,
    'unmapped'::text AS mapping_status
FROM operational.software_installations si
JOIN operational.assets a ON a.id = si.asset_id
JOIN operational.software_products sp ON sp.id = si.product_id
CROSS JOIN assessment t
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS covering_rows,
        CASE WHEN COUNT(*) = 1
            THEN MAX(ih.version)
        END AS version
    FROM operational.installation_history ih
    WHERE ih.installation_id = si.id
      AND ih.started_at <= t.as_of
      AND (
          ih.ended_at > t.as_of
          OR ih.ended_at IS NULL
      )
) h ON TRUE
ORDER BY a.asset_key, si.installation_key
"""


def parse_snapshot_csv(csv_text):
    reader = csv.DictReader(io.StringIO(csv_text))
    required = {
        "asset_id",
        "asset_key",
        "installation_id",
        "product_id",
        "product_name",
        "version",
        "covering_rows",
        "version_status",
        "cpe",
        "mapping_status",
    }

    if not required.issubset(set(reader.fieldnames or [])):
        raise ValueError("Inventory snapshot missing required columns")

    records = []
    seen = set()

    for row in reader:
        installation_id = row["installation_id"]

        if not installation_id or installation_id in seen:
            raise ValueError("Missing or duplicate installation ID")
        seen.add(installation_id)

        count = int(row["covering_rows"])
        expected = (
            "no_history_at_time"
            if count == 0
            else "ambiguous_history"
            if count > 1
            else "resolved"
        )

        if row["version_status"] != expected:
            raise ValueError("Inconsistent history status")

        version = row["version"] or None
        if (count == 1) != (version is not None):
            raise ValueError("Inconsistent resolved version")

        if row["cpe"] or row["mapping_status"] != "unmapped":
            raise ValueError("Unexpected CPE mapping in unmapped adapter")

        row["version"] = version
        row["covering_rows"] = count
        row["cpe"] = None
        records.append(row)

    return records


def read_inventory_snapshot(as_of):
    query = snapshot_sql(as_of)

    # The PostgreSQL session explicitly prohibits database writes.
    command = [
        "docker",
        "compose",
        "exec",
        "-T",
        "postgres",
        "sh",
        "-c",
        (
            "exec psql -X -q --csv -v ON_ERROR_STOP=1 "
            '-U "$POSTGRES_USER" -d "$POSTGRES_DB" '
            '-c "$1"'
        ),
        "sh",
        "SET default_transaction_read_only = on; " + query,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    return parse_snapshot_csv(result.stdout)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: python -m "
            "patchledger.simulation.oltp_inventory_adapter "
            "2024-01-09T00:00:00+00:00"
        )

    as_of = datetime.fromisoformat(sys.argv[1])
    records = read_inventory_snapshot(as_of)
    statuses = Counter(r["version_status"] for r in records)

    print("Assessment:", as_of.isoformat())
    print("Total installations:", len(records))
    print("Resolved:", statuses["resolved"])
    print("Missing history:", statuses["no_history_at_time"])
    print("Ambiguous:", statuses["ambiguous_history"])
    print("CPE mappings: 0 (unmapped)")

    print("\nSample records:")
    for row in records[:5]:
        print(
            row["asset_key"],
            "|",
            row["product_name"],
            "|",
            row["version"],
            "|",
            row["version_status"],
        )


if __name__ == "__main__":
    main()
