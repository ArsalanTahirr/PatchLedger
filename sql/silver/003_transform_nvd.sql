BEGIN;

CREATE TEMP TABLE nvd_review ON COMMIT DROP AS
WITH normalized AS (
    SELECT
        bronze_id,
        batch_id,
        UPPER(BTRIM(cve_id)) AS cve_id,
        NULLIF(BTRIM(published), '') AS published_text,
        NULLIF(BTRIM(last_modified), '') AS modified_text,
        NULLIF(BTRIM(cvss_score), '') AS score_text,
        NULLIF(BTRIM(configurations_json), '') AS config_text,
        NULLIF(BTRIM(weaknesses_json), '') AS weakness_text,
        NULLIF(BTRIM(raw_json), '') AS raw_text,
        vulnerability_status,
        description,
        cvss_version,
        cvss_source,
        cvss_severity,
        cwe_ids,
        reference_urls
    FROM bronze.nvd_cves
),
typed AS (
    SELECT *,
        CASE
            WHEN pg_input_is_valid(published_text, 'timestamp')
            THEN published_text::timestamp
        END AS published_value,
        CASE
            WHEN pg_input_is_valid(modified_text, 'timestamp')
            THEN modified_text::timestamp
        END AS modified_value,
        CASE
            WHEN pg_input_is_valid(score_text, 'numeric')
            THEN score_text::numeric
        END AS score_value,
        CASE
            WHEN pg_input_is_valid(config_text, 'jsonb')
            THEN config_text::jsonb
        END AS configurations_value,
        CASE
            WHEN pg_input_is_valid(weakness_text, 'jsonb')
            THEN weakness_text::jsonb
        END AS weaknesses_value,
        CASE
            WHEN pg_input_is_valid(raw_text, 'jsonb')
            THEN raw_text::jsonb
        END AS raw_value
    FROM normalized
),
validated AS (
    SELECT *,
        CASE
            WHEN cve_id IS NULL
              OR cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                THEN 'invalid_cve_id'
            WHEN published_value IS NULL
                THEN 'invalid_published_date'
            WHEN modified_value IS NULL
                THEN 'invalid_last_modified_date'
            WHEN score_text IS NOT NULL
              AND (score_value IS NULL
                   OR score_value NOT BETWEEN 0 AND 10)
                THEN 'invalid_cvss_score'
            WHEN config_text IS NOT NULL
              AND (
                  configurations_value IS NULL
                  OR jsonb_typeof(configurations_value) <> 'array'
              )
                THEN 'invalid_configurations_json'
            WHEN weakness_text IS NOT NULL
              AND (
                  weaknesses_value IS NULL
                  OR jsonb_typeof(weaknesses_value) <> 'array'
              )
                THEN 'invalid_weaknesses_json'
            WHEN raw_value IS NULL
              OR jsonb_typeof(raw_value) <> 'object'
                THEN 'invalid_raw_json'
            ELSE NULL
        END AS validation_error
    FROM typed
),
ranked AS (
    SELECT *,
        ROW_NUMBER() OVER (
            PARTITION BY cve_id
            ORDER BY modified_value DESC NULLS LAST, bronze_id DESC
        ) AS rn
    FROM validated
    WHERE validation_error IS NULL
)
SELECT
    v.*,
    CASE
        WHEN v.validation_error IS NOT NULL
            THEN v.validation_error
        WHEN r.rn > 1
            THEN 'duplicate_cve_id'
        ELSE NULL
    END AS rejection_reason
FROM validated v
LEFT JOIN ranked r USING (bronze_id);

INSERT INTO silver.rejected_records (
    source_name, source_batch_id, source_bronze_id, reason
)
SELECT 'nvd', batch_id, bronze_id, rejection_reason
FROM nvd_review
WHERE rejection_reason IS NOT NULL
ON CONFLICT (source_name, source_bronze_id)
DO UPDATE SET
    reason = EXCLUDED.reason,
    source_batch_id = EXCLUDED.source_batch_id;

INSERT INTO silver.nvd_cves (
    cve_id,
    published,
    last_modified,
    vulnerability_status,
    description,
    cvss_version,
    cvss_source,
    cvss_score,
    cvss_severity,
    cwe_ids,
    reference_urls,
    configurations,
    weaknesses,
    source_batch_id,
    source_bronze_id
)
SELECT
    cve_id,
    published_value,
    modified_value,
    vulnerability_status,
    description,
    cvss_version,
    cvss_source,
    score_value,
    cvss_severity,
    cwe_ids,
    reference_urls,
    configurations_value,
    weaknesses_value,
    batch_id,
    bronze_id
FROM nvd_review
WHERE rejection_reason IS NULL
ON CONFLICT (cve_id)
DO UPDATE SET
    published = EXCLUDED.published,
    last_modified = EXCLUDED.last_modified,
    vulnerability_status = EXCLUDED.vulnerability_status,
    description = EXCLUDED.description,
    cvss_version = EXCLUDED.cvss_version,
    cvss_source = EXCLUDED.cvss_source,
    cvss_score = EXCLUDED.cvss_score,
    cvss_severity = EXCLUDED.cvss_severity,
    cwe_ids = EXCLUDED.cwe_ids,
    reference_urls = EXCLUDED.reference_urls,
    configurations = EXCLUDED.configurations,
    weaknesses = EXCLUDED.weaknesses,
    source_batch_id = EXCLUDED.source_batch_id,
    source_bronze_id = EXCLUDED.source_bronze_id,
    cleaned_at = NOW()
WHERE (EXCLUDED.last_modified, EXCLUDED.source_bronze_id)
   >= (silver.nvd_cves.last_modified, silver.nvd_cves.source_bronze_id);

COMMIT;
