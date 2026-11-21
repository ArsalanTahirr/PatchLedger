BEGIN;

CREATE TEMP TABLE kev_review ON COMMIT DROP AS
WITH normalized AS (
    SELECT
        bronze_id,
        batch_id,
        UPPER(BTRIM("cveID")) AS cve_id,
        NULLIF(BTRIM("dateAdded"), '') AS date_added_text,
        NULLIF(BTRIM("dueDate"), '') AS due_date_text,
        NULLIF(BTRIM(cwes), '') AS cwes_text,
        NULLIF(BTRIM(raw_json), '') AS raw_text,
        "vendorProject" AS vendor_project,
        product,
        "vulnerabilityName" AS vulnerability_name,
        "shortDescription" AS short_description,
        "requiredAction" AS required_action,
        "knownRansomwareCampaignUse" AS ransomware_use,
        notes,
        "forensicTriage" AS forensic_triage
    FROM bronze.kev
),
typed AS (
    SELECT *,
        CASE
            WHEN pg_input_is_valid(date_added_text, 'date')
            THEN date_added_text::date
        END AS date_added_value,
        CASE
            WHEN pg_input_is_valid(due_date_text, 'date')
            THEN due_date_text::date
        END AS due_date_value,
        CASE
            WHEN pg_input_is_valid(cwes_text, 'jsonb')
            THEN cwes_text::jsonb
        END AS cwes_value,
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
            WHEN date_added_value IS NULL
                THEN 'invalid_date_added'
            WHEN due_date_text IS NOT NULL
              AND due_date_value IS NULL
                THEN 'invalid_due_date'
            WHEN cwes_text IS NOT NULL
              AND (
                  cwes_value IS NULL
                  OR jsonb_typeof(cwes_value) <> 'array'
              )
                THEN 'invalid_cwes_json'
            WHEN raw_value IS NULL
              OR jsonb_typeof(raw_value) <> 'object'
                THEN 'invalid_raw_json'
            ELSE NULL
        END AS validation_error
    FROM typed
),
ranked AS (
    SELECT
        bronze_id,
        ROW_NUMBER() OVER (
            PARTITION BY cve_id
            ORDER BY date_added_value DESC, bronze_id DESC
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
SELECT
    'kev', batch_id, bronze_id, rejection_reason
FROM kev_review
WHERE rejection_reason IS NOT NULL
ON CONFLICT (source_name, source_bronze_id)
DO UPDATE SET
    reason = EXCLUDED.reason,
    source_batch_id = EXCLUDED.source_batch_id;

INSERT INTO silver.kev (
    cve_id,
    vendor_project,
    product,
    vulnerability_name,
    date_added,
    short_description,
    required_action,
    due_date,
    known_ransomware_campaign_use,
    notes,
    cwes,
    forensic_triage,
    source_batch_id,
    source_bronze_id
)
SELECT
    cve_id,
    vendor_project,
    product,
    vulnerability_name,
    date_added_value,
    short_description,
    required_action,
    due_date_value,
    ransomware_use,
    notes,
    cwes_value,
    forensic_triage,
    batch_id,
    bronze_id
FROM kev_review
WHERE rejection_reason IS NULL
ON CONFLICT (cve_id)
DO UPDATE SET
    vendor_project = EXCLUDED.vendor_project,
    product = EXCLUDED.product,
    vulnerability_name = EXCLUDED.vulnerability_name,
    date_added = EXCLUDED.date_added,
    short_description = EXCLUDED.short_description,
    required_action = EXCLUDED.required_action,
    due_date = EXCLUDED.due_date,
    known_ransomware_campaign_use =
        EXCLUDED.known_ransomware_campaign_use,
    notes = EXCLUDED.notes,
    cwes = EXCLUDED.cwes,
    forensic_triage = EXCLUDED.forensic_triage,
    source_batch_id = EXCLUDED.source_batch_id,
    source_bronze_id = EXCLUDED.source_bronze_id,
    cleaned_at = NOW()
WHERE (EXCLUDED.date_added, EXCLUDED.source_bronze_id)
   >= (silver.kev.date_added, silver.kev.source_bronze_id);

COMMIT;
