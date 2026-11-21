BEGIN;

CREATE TABLE IF NOT EXISTS silver.software_inventory (
    snapshot_batch_id UUID NOT NULL,
    installation_id UUID NOT NULL,
    installation_key TEXT,
    asset_id UUID,
    asset_key TEXT,
    hostname TEXT,
    product_id UUID,
    product_key TEXT,
    software_name TEXT,
    publisher_name TEXT,
    installed_version TEXT,
    current_version_count INTEGER NOT NULL,
    cpe_identifier TEXT,
    cpe_count INTEGER NOT NULL,
    matching_status TEXT NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (snapshot_batch_id, installation_id)
);

WITH latest_batch AS (
    SELECT batch_id
    FROM bronze.ingest_batches
    WHERE source_name = 'oltp:snapshot:v1'
    ORDER BY loaded_at DESC, batch_id DESC
    LIMIT 1
),
records AS (
    SELECT
        source_table,
        source_id,
        raw_record
    FROM bronze.oltp_records
    WHERE batch_id = (SELECT batch_id FROM latest_batch)
),
installations AS (
    SELECT source_id, raw_record
    FROM records
    WHERE source_table = 'software_installations'
),
assets AS (
    SELECT source_id, raw_record
    FROM records
    WHERE source_table = 'assets'
),
products AS (
    SELECT source_id, raw_record
    FROM records
    WHERE source_table = 'software_products'
),
current_versions AS (
    SELECT
        raw_record->>'installation_id' AS installation_id,
        COUNT(*)::INTEGER AS version_count,
        MAX(raw_record->>'version') AS installed_version
    FROM records
    WHERE source_table = 'installation_history'
      AND raw_record->>'ended_at' IS NULL
    GROUP BY raw_record->>'installation_id'
),
cpe_identifiers AS (
    SELECT
        raw_record->>'product_id' AS product_id,
        COUNT(*)::INTEGER AS cpe_count,
        MAX(raw_record->>'identifier') AS cpe_identifier
    FROM records
    WHERE source_table = 'product_identifiers'
      AND raw_record->>'scheme' = 'cpe23'
    GROUP BY raw_record->>'product_id'
)
INSERT INTO silver.software_inventory (
    snapshot_batch_id,
    installation_id,
    installation_key,
    asset_id,
    asset_key,
    hostname,
    product_id,
    product_key,
    software_name,
    publisher_name,
    installed_version,
    current_version_count,
    cpe_identifier,
    cpe_count,
    matching_status
)
SELECT
    b.batch_id,
    i.source_id,
    i.raw_record->>'installation_key',
    a.source_id,
    a.raw_record->>'asset_key',
    a.raw_record->>'hostname',
    p.source_id,
    p.raw_record->>'product_key',
    p.raw_record->>'name',
    p.raw_record->>'publisher_name',
    CASE
        WHEN COALESCE(v.version_count, 0) = 1
        THEN v.installed_version
        ELSE NULL
    END,
    COALESCE(v.version_count, 0),
    CASE
        WHEN COALESCE(c.cpe_count, 0) = 1
        THEN c.cpe_identifier
        ELSE NULL
    END,
    COALESCE(c.cpe_count, 0),
    CASE
        WHEN a.source_id IS NULL THEN 'missing_asset'
        WHEN p.source_id IS NULL THEN 'missing_product'
        WHEN COALESCE(v.version_count, 0) = 0 THEN 'missing_version'
        WHEN v.version_count > 1 THEN 'ambiguous_version'
        WHEN NULLIF(BTRIM(v.installed_version), '') IS NULL
            THEN 'missing_version'
        WHEN COALESCE(c.cpe_count, 0) = 0 THEN 'missing_cpe'
        WHEN c.cpe_count > 1 THEN 'ambiguous_cpe'
        WHEN NULLIF(BTRIM(c.cpe_identifier), '') IS NULL
            THEN 'missing_cpe'
        ELSE 'candidate_for_matching'
    END
FROM installations i
CROSS JOIN latest_batch b
LEFT JOIN assets a
    ON a.source_id::TEXT = i.raw_record->>'asset_id'
LEFT JOIN products p
    ON p.source_id::TEXT = i.raw_record->>'product_id'
LEFT JOIN current_versions v
    ON v.installation_id = i.source_id::TEXT
LEFT JOIN cpe_identifiers c
    ON c.product_id = i.raw_record->>'product_id'
ON CONFLICT (snapshot_batch_id, installation_id) DO NOTHING;

COMMIT;
