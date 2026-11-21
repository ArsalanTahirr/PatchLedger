"""Run SQL NVD regression tests in an isolated PostgreSQL database."""

from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[2]

MATCHING_FILES = [
    "sql/silver/006_cpe_match.sql",
    "sql/silver/007_version_compare.sql",
    "sql/silver/008_version_range.sql",
    "sql/silver/009_cpe_rule_match.sql",
    "sql/silver/010_configuration_logic.sql",
    "sql/silver/011_asset_rule_state.sql",
    "sql/silver/012_nvd_node.sql",
    "sql/silver/013_evaluate_cve.sql",
]


def test_sql_nvd_matching(postgres_engine):
    """Assert SQL matching behavior using disposable inventory fixtures."""
    url = postgres_engine.url.set(drivername="postgresql")
    conninfo = url.render_as_string(hide_password=False)

    with (
        psycopg.connect(conninfo, autocommit=True) as connection,
        connection.cursor() as cursor,
    ):
        for filename in (
            "sql/bronze/001_create_tables.sql",
            "sql/silver/001_create_tables.sql",
            "sql/silver/005_inventory.sql",
        ):
            cursor.execute((ROOT / filename).read_text())

        cursor.execute("BEGIN")
        try:
            for filename in MATCHING_FILES:
                cursor.execute((ROOT / filename).read_text())

            cursor.execute((ROOT / "tests/sql/fixtures_inventory.sql").read_text())
            cursor.execute((ROOT / "tests/sql/test_nvd_matching.sql").read_text())
        finally:
            cursor.execute("ROLLBACK")
