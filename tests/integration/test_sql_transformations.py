"""Verify Bronze-to-Silver cleaning, deduplication, and reruns."""

from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import psycopg

ROOT = Path(__file__).resolve().parents[2]

TRANSFORMS = (
    "sql/silver/002_transform_epss.sql",
    "sql/silver/003_transform_nvd.sql",
    "sql/silver/004_transform_kev.sql",
)


def test_bronze_to_silver_transformations(postgres_engine):
    url = postgres_engine.url.set(drivername="postgresql")

    with (
        psycopg.connect(
            url.render_as_string(hide_password=False),
            autocommit=True,
        ) as connection,
        connection.cursor() as cursor,
    ):
        for file in (
            "sql/bronze/001_create_tables.sql",
            "sql/silver/001_create_tables.sql",
        ):
            cursor.execute((ROOT / file).read_text())

        batches = {}
        for index, source in enumerate(("epss", "nvd", "kev")):
            batch_id = uuid4()
            batches[source] = batch_id
            cursor.execute(
                """
                INSERT INTO bronze.ingest_batches
                    (batch_id, source_name, file_sha256, row_count)
                VALUES (%s, %s, %s, 3)
                """,
                (batch_id, source, str(index) * 64),
            )

        cursor.executemany(
            """
            INSERT INTO bronze.epss_scores
                (cve, epss, percentile, batch_id, source_row)
            VALUES (%s, %s, %s, %s, %s)
            """,
            [
                ("CVE-2026-90001", "0.1", "0.5", batches["epss"], 2),
                ("CVE-2026-90001", "0.2", "0.6", batches["epss"], 3),
                ("CVE-2026-90002", "invalid", "0.5", batches["epss"], 4),
            ],
        )

        cursor.executemany(
            """
            INSERT INTO bronze.nvd_cves
                (cve_id, published, last_modified, cvss_score,
                 configurations_json, weaknesses_json, raw_json,
                 batch_id, source_row)
            VALUES (%s, %s, %s, %s, '[]', '[]', '{}', %s, %s)
            """,
            [
                (
                    "CVE-2026-90003",
                    "2026-01-01",
                    "2026-01-02",
                    "5.0",
                    batches["nvd"],
                    2,
                ),
                (
                    "CVE-2026-90003",
                    "2026-01-01",
                    "2026-01-03",
                    "7.0",
                    batches["nvd"],
                    3,
                ),
                (
                    "CVE-2026-90004",
                    "2026-01-01",
                    "2026-01-03",
                    "12.0",
                    batches["nvd"],
                    4,
                ),
            ],
        )

        cursor.executemany(
            """
            INSERT INTO bronze.kev
                ("cveID", "dateAdded", "dueDate", cwes, raw_json,
                 batch_id, source_row)
            VALUES (%s, %s, %s, '[]', '{}', %s, %s)
            """,
            [
                (
                    "CVE-2026-90005",
                    "2026-01-01",
                    "2026-01-10",
                    batches["kev"],
                    2,
                ),
                (
                    "CVE-2026-90005",
                    "2026-01-03",
                    "2026-01-12",
                    batches["kev"],
                    3,
                ),
                (
                    "CVE-2026-90006",
                    "not-a-date",
                    "2026-01-12",
                    batches["kev"],
                    4,
                ),
            ],
        )

        def run_transforms():
            for file in TRANSFORMS:
                cursor.execute((ROOT / file).read_text())

        def snapshot():
            cursor.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM silver.epss_scores),
                    (SELECT COUNT(*) FROM silver.nvd_cves),
                    (SELECT COUNT(*) FROM silver.kev),
                    (SELECT COUNT(*) FROM silver.rejected_records)
                """
            )
            return cursor.fetchone()

        run_transforms()

        assert snapshot() == (1, 1, 1, 6)

        cursor.execute(
            """
            SELECT epss FROM silver.epss_scores
            WHERE cve_id = 'CVE-2026-90001'
            """
        )
        assert cursor.fetchone()[0] == Decimal("0.2")

        cursor.execute(
            """
            SELECT cvss_score FROM silver.nvd_cves
            WHERE cve_id = 'CVE-2026-90003'
            """
        )
        assert cursor.fetchone()[0] == 7

        cursor.execute(
            """
            SELECT date_added FROM silver.kev
            WHERE cve_id = 'CVE-2026-90005'
            """
        )
        assert cursor.fetchone()[0].isoformat() == "2026-01-03"

        cursor.execute(
            """
            SELECT source_name, reason, COUNT(*)
            FROM silver.rejected_records
            GROUP BY source_name, reason
            ORDER BY source_name, reason
            """
        )
        rejections = cursor.fetchall()

        assert rejections == [
            ("epss", "duplicate_cve_id", 1),
            ("epss", "invalid_epss", 1),
            ("kev", "duplicate_cve_id", 1),
            ("kev", "invalid_date_added", 1),
            ("nvd", "duplicate_cve_id", 1),
            ("nvd", "invalid_cvss_score", 1),
        ]

        run_transforms()

        assert snapshot() == (1, 1, 1, 6)

        cursor.execute(
            """
            SELECT source_name, reason, COUNT(*)
            FROM silver.rejected_records
            GROUP BY source_name, reason
            ORDER BY source_name, reason
            """
        )
        assert cursor.fetchall() == rejections
