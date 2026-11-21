CREATE SCHEMA IF NOT EXISTS bronze;

CREATE TABLE IF NOT EXISTS bronze.ingest_batches (
    batch_id UUID PRIMARY KEY,
    source_name TEXT NOT NULL,
    file_sha256 CHAR(64) NOT NULL,
    row_count BIGINT NOT NULL CHECK (row_count >= 0),
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_name, file_sha256)
);

CREATE TABLE IF NOT EXISTS bronze.nvd_cves (
    bronze_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id TEXT,
    published TEXT,
    last_modified TEXT,
    vulnerability_status TEXT,
    description TEXT,
    cvss_version TEXT,
    cvss_source TEXT,
    cvss_score TEXT,
    cvss_severity TEXT,
    cwe_ids TEXT,
    reference_urls TEXT,
    configurations_json TEXT,
    weaknesses_json TEXT,
    raw_json TEXT,
    batch_id UUID NOT NULL REFERENCES bronze.ingest_batches(batch_id),
    source_row BIGINT NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (batch_id, source_row)
);

CREATE TABLE IF NOT EXISTS bronze.epss_scores (
    bronze_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve TEXT,
    epss TEXT,
    percentile TEXT,
    batch_id UUID NOT NULL REFERENCES bronze.ingest_batches(batch_id),
    source_row BIGINT NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (batch_id, source_row)
);

CREATE TABLE IF NOT EXISTS bronze.kev (
    bronze_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "cveID" TEXT,
    "vendorProject" TEXT,
    product TEXT,
    "vulnerabilityName" TEXT,
    "dateAdded" TEXT,
    "shortDescription" TEXT,
    "requiredAction" TEXT,
    "dueDate" TEXT,
    "knownRansomwareCampaignUse" TEXT,
    notes TEXT,
    cwes TEXT,
    "forensicTriage" TEXT,
    raw_json TEXT,
    batch_id UUID NOT NULL REFERENCES bronze.ingest_batches(batch_id),
    source_row BIGINT NOT NULL,
    loaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (batch_id, source_row)
);

CREATE TABLE IF NOT EXISTS bronze.oltp_records (
    bronze_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_table TEXT NOT NULL,
    source_id UUID NOT NULL,
    raw_record JSONB NOT NULL,
    batch_id UUID NOT NULL REFERENCES bronze.ingest_batches(batch_id),
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (batch_id, source_table, source_id)
);
