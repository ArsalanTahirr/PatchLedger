BEGIN ISOLATION LEVEL REPEATABLE READ;

CREATE TEMP TABLE oltp_snapshot_rows ON COMMIT DROP AS
SELECT 'assets'::text AS source_table, id AS source_id,
       to_jsonb(t) AS raw_record
FROM operational.assets t

UNION ALL

SELECT 'software_products', id, to_jsonb(t)
FROM operational.software_products t

UNION ALL

SELECT 'software_installations', id, to_jsonb(t)
FROM operational.software_installations t

UNION ALL

SELECT 'installation_history', id, to_jsonb(t)
FROM operational.installation_history t

UNION ALL

SELECT 'product_identifiers', id, to_jsonb(t)
FROM operational.product_identifiers t;

CREATE TEMP TABLE oltp_snapshot_metadata ON COMMIT DROP AS
SELECT
    gen_random_uuid() AS batch_id,
    'oltp:snapshot:v1'::text AS source_name,
    encode(
        sha256(
            convert_to(
                COALESCE(
                    string_agg(
                        source_table || ':' ||
                        source_id::text || ':' ||
                        raw_record::text,
                        E'\n'
                        ORDER BY source_table, source_id
                    ),
                    ''
                ),
                'UTF8'
            )
        ),
        'hex'
    ) AS content_sha256,
    COUNT(*) AS row_count
FROM oltp_snapshot_rows;

WITH created_batch AS (
    INSERT INTO bronze.ingest_batches (
        batch_id, source_name, file_sha256, row_count
    )
    SELECT
        batch_id, source_name, content_sha256, row_count
    FROM oltp_snapshot_metadata
    ON CONFLICT (source_name, file_sha256) DO NOTHING
    RETURNING batch_id
)
INSERT INTO bronze.oltp_records (
    source_table, source_id, raw_record, batch_id
)
SELECT
    r.source_table,
    r.source_id,
    r.raw_record,
    b.batch_id
FROM oltp_snapshot_rows r
CROSS JOIN created_batch b;

COMMIT;
