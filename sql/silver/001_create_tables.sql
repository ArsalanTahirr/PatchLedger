CREATE SCHEMA IF NOT EXISTS silver;

CREATE TABLE IF NOT EXISTS silver.nvd_cves (
    cve_id TEXT PRIMARY KEY,
    published TIMESTAMP,
    last_modified TIMESTAMP,
    vulnerability_status TEXT,
    description TEXT,
    cvss_version TEXT,
    cvss_source TEXT,
    cvss_score NUMERIC(4,1),
    cvss_severity TEXT,
    cwe_ids TEXT,
    reference_urls TEXT,
    configurations JSONB,
    weaknesses JSONB,
    source_batch_id UUID NOT NULL,
    source_bronze_id BIGINT NOT NULL,
    cleaned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (cvss_score BETWEEN 0 AND 10)
);

CREATE TABLE IF NOT EXISTS silver.epss_scores (
    cve_id TEXT PRIMARY KEY,
    epss NUMERIC(10,8),
    percentile NUMERIC(10,8),
    source_batch_id UUID NOT NULL,
    source_bronze_id BIGINT NOT NULL,
    cleaned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (epss BETWEEN 0 AND 1),
    CHECK (percentile BETWEEN 0 AND 1)
);

CREATE TABLE IF NOT EXISTS silver.kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_campaign_use TEXT,
    notes TEXT,
    cwes JSONB,
    forensic_triage TEXT,
    source_batch_id UUID NOT NULL,
    source_bronze_id BIGINT NOT NULL,
    cleaned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS silver.rejected_records (
    rejection_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name TEXT NOT NULL,
    source_batch_id UUID NOT NULL,
    source_bronze_id BIGINT NOT NULL,
    reason TEXT NOT NULL,
    rejected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_name, source_bronze_id)
);
