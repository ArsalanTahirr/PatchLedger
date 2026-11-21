"""Validate NVD configuration input handling."""

import json
from pathlib import Path
from uuid import uuid4

from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[2]


def test_missing_vulnerable_flag_is_inconclusive(postgres_engine):
    with postgres_engine.begin() as connection:
        connection.exec_driver_sql("CREATE SCHEMA silver")

        # The matcher is deliberately stubbed to isolate
        # configuration validation from inventory matching.
        connection.exec_driver_sql(
            """
            CREATE FUNCTION silver.asset_rule_state(
                UUID, UUID, JSONB
            )
            RETURNS TEXT
            LANGUAGE SQL
            AS $$ SELECT 'match'::text $$;
            """
        )

        for name in (
            "010_configuration_logic.sql",
            "012_nvd_node.sql",
            "013_evaluate_cve.sql",
        ):
            sql = (ROOT / "sql/silver" / name).read_text()
            connection.exec_driver_sql(sql)

        criteria = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"

        config = [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "cpeMatch": [
                            {
                                "criteria": criteria,
                                "vulnerable": True,
                            },
                            {
                                "criteria": criteria,
                            },
                        ],
                    }
                ]
            }
        ]

        result = connection.execute(
            text(
                "SELECT silver.evaluate_nvd_cve("
                "CAST(:batch AS uuid), "
                "CAST(:asset AS uuid), "
                "CAST(:config AS jsonb))"
            ),
            {
                "batch": str(uuid4()),
                "asset": str(uuid4()),
                "config": json.dumps(config),
            },
        ).scalar_one()

    assert result["status"] == "inconclusive"
    assert result["configuration_state"] == "unknown"
    assert result["vulnerable_evidence"] is False
