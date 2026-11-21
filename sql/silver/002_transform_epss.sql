BEGIN;

CREATE TEMP TABLE epss_review ON COMMIT DROP AS
WITH normalized AS (
    SELECT
        bronze_id,
        batch_id,
        UPPER(BTRIM(cve)) AS cve_id,
        BTRIM(epss) AS epss_text,
        BTRIM(percentile) AS percentile_text
    FROM bronze.epss_scores
),
typed AS (
    SELECT
        *,
        CASE
            WHEN COALESCE(pg_input_is_valid(epss_text, 'numeric'), FALSE)
            THEN epss_text::numeric
            ELSE NULL
        END AS epss_value,
        CASE
            WHEN COALESCE(pg_input_is_valid(percentile_text, 'numeric'), FALSE)
            THEN percentile_text::numeric
            ELSE NULL
        END AS percentile_value
    FROM normalized
),
valid_ranked AS (
    SELECT
        bronze_id,
        ROW_NUMBER() OVER (
            PARTITION BY cve_id
            ORDER BY bronze_id DESC
        ) AS rn
    FROM typed
    WHERE cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
      AND epss_value BETWEEN 0 AND 1
      AND percentile_value BETWEEN 0 AND 1
)
SELECT
    t.bronze_id,
    t.batch_id,
    t.cve_id,
    t.epss_value,
    t.percentile_value,
    CASE
        WHEN t.cve_id IS NULL
          OR t.cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
            THEN 'invalid_cve_id'
        WHEN t.epss_value IS NULL
            THEN 'invalid_epss'
        WHEN t.percentile_value IS NULL
            THEN 'invalid_percentile'
        WHEN t.epss_value NOT BETWEEN 0 AND 1
            THEN 'epss_out_of_range'
        WHEN t.percentile_value NOT BETWEEN 0 AND 1
            THEN 'percentile_out_of_range'
        WHEN r.rn > 1
            THEN 'duplicate_cve_id'
        ELSE NULL
    END AS rejection_reason
FROM typed t
LEFT JOIN valid_ranked r
    ON r.bronze_id = t.bronze_id;

INSERT INTO silver.rejected_records (
    source_name,
    source_batch_id,
    source_bronze_id,
    reason
)
SELECT
    'epss',
    batch_id,
    bronze_id,
    rejection_reason
FROM epss_review
WHERE rejection_reason IS NOT NULL
ON CONFLICT (source_name, source_bronze_id)
DO UPDATE SET
    reason = EXCLUDED.reason,
    source_batch_id = EXCLUDED.source_batch_id;

INSERT INTO silver.epss_scores (
    cve_id,
    epss,
    percentile,
    source_batch_id,
    source_bronze_id
)
SELECT
    cve_id,
    epss_value,
    percentile_value,
    batch_id,
    bronze_id
FROM epss_review
WHERE rejection_reason IS NULL
ON CONFLICT (cve_id)
DO UPDATE SET
    epss = EXCLUDED.epss,
    percentile = EXCLUDED.percentile,
    source_batch_id = EXCLUDED.source_batch_id,
    source_bronze_id = EXCLUDED.source_bronze_id,
    cleaned_at = NOW()
WHERE silver.epss_scores.source_bronze_id
      <= EXCLUDED.source_bronze_id;

COMMIT;
