# PatchLedger — Bronze to Silver Pipeline

## 1. Overview

The Silver layer cleans and standardizes vulnerability data from
three external sources:

- NVD: CVE records, descriptions, severity and affected configurations
- EPSS: exploit prediction scores and percentiles
- CISA KEV: known exploited vulnerabilities

The pipeline produces cleaned CSV files, rejected-record files,
and data-quality reports.

## 2. Source Data

Source dataset:
https://huggingface.co/datasets/patchledger/patchledger-data/tree/main

Expected input files:

- nvd_cves.csv
- epss_scores.csv
- known_exploited_vulnerabilities.csv

Keep source data outside the Git repository.

Example directory structure:

University/
├── PatchLedger/
└── PatchLedgerData/
    ├── nvd_cves.csv
    ├── epss_scores.csv
    └── known_exploited_vulnerabilities.csv

## 3. Prerequisites

Use the Python version and dependencies configured by the repository.

From the PatchLedger directory:

    uv sync --extra etl

Ensure that the three input CSV files exist in the data directory.

## Download the Published Silver Dataset

Most teammates do not need to run the ETL.

The validated Silver v1 snapshot is published at:

https://huggingface.co/datasets/patchledger/patchledger-data/tree/main/silver/v1

From the PatchLedger repository, run:

    bash scripts/download_silver.sh

This downloads four cleaned CSV files into:

    ../PatchLedgerData/silver/v1/

The downloader uses a pinned Hugging Face revision, ensuring
teammates receive the same published dataset version.

The full Bronze-to-Silver ETL instructions below are intended
for developers rebuilding or updating the dataset.

## 4. Limited Silver Mode

Script:

    scripts/bronze_to_silver.py

This mode selects a limited subset of the source data.
It is useful for experimentation and smaller processing runs.

Example:

    uv run python scripts/bronze_to_silver.py \
      --data-dir ../PatchLedgerData \
      --output-dir ../PatchLedgerData/silver_sample_v1 \
      --max-rows 15000

This is NOT a complete NVD/EPSS/KEV export.

## 5. Full Silver Mode

Script:

    scripts/bronze_to_silver_full.py

This mode processes the complete source datasets rather than
applying the limited mode's record cap.

Example:

    uv run python scripts/bronze_to_silver_full.py \
      --data-dir ../PatchLedgerData \
      --output-dir ../PatchLedgerData/silver_full_v2

The full-mode script depends on bronze_to_silver.py.
Keep both scripts together.

The output directory must not already exist.
Use a new output name for each run.

Full processing requires sufficient available disk space.

## 6. Output Structure

A completed full run produces:

silver_full_v2/
├── silver/
│   ├── nvd_clean.csv
│   ├── nvd_affected_cpe.csv
│   ├── epss_clean.csv
│   └── kev_clean.csv
├── rejected/
│   ├── nvd_rejected.csv
│   ├── epss_rejected.csv
│   └── kev_rejected.csv
└── reports/
    ├── data_quality_report.csv
    └── data_quality_details.json

The Silver CSVs are cleaned outputs.
The rejected files preserve records excluded during processing.
The reports document data-quality results.

## 7. NVD Configuration Metadata

nvd_affected_cpe.csv contains extracted CPE matching rules.

The export includes configuration-level and node-level metadata,
including configuration_operator, node_operator, node_negate,
version boundaries and CPE criteria.

These fields help downstream processes evaluate vulnerability
applicability without discarding important NVD configuration logic.

Multiple CPE rows may refer to the same CVE.
Repeated CVE IDs in the CPE export are not automatically errors.

## 8. Validate the Silver Layer

Run:

    uv run python scripts/audit_silver.py \
      --silver-dir ../PatchLedgerData/silver_full_v2/silver

The audit reports:

- Total rows and distinct CVEs
- Repeated CVE identifiers
- Missing or invalid CVE identifiers
- Invalid EPSS scores
- NVD vulnerability statuses
- Cross-dataset CVE coverage

The audit is read-only.

## 9. Unit Tests

Run the Silver-specific tests:

    uv run --with pytest python -m pytest \
      tests/unit/test_bronze_to_silver_cpe.py \
      tests/unit/test_silver_etl_alignment.py \
      tests/unit/test_silver_etl_full.py -v

Run the complete unit suite:

    uv run --with pytest python -m pytest tests/unit -q

Run code-quality checks:

    uv run --with ruff ruff check \
      scripts/bronze_to_silver.py \
      scripts/bronze_to_silver_full.py \
      scripts/audit_silver.py

## 10. Validated Dataset Snapshot

Snapshot validated on 2026-11-20:

| Dataset | Rows | Distinct CVEs |
|---|---:|---:|
| NVD | 424,195 | 424,195 |
| NVD affected CPE | 3,283,427 | 325,152 |
| EPSS | 405,034 | 405,034 |
| KEV | 1,781 | 1,781 |

Observed validation results:

- No missing or invalid CVE identifiers
- No invalid EPSS scores
- No repeated CVE identifiers in the NVD, EPSS or KEV exports
- All EPSS CVEs represented in NVD
- 1 KEV CVE not represented in the NVD snapshot

These numbers describe this validated snapshot, not permanent
expected row counts. Source updates may change future results.

## 11. Known Limitations

- Source coverage depends on the downloaded dataset versions.
- Some NVD records have unresolved or non-final analysis statuses.
- One KEV CVE was absent from the validated NVD snapshot.
- Multiple affected CPE rules for a single CVE are legitimate.
- NVD applicability candidates are not confirmed scanner findings.
- The full-data pipeline has been validated on the development
  environment; teammates should test their own environment.

## 12. Git Collaboration

Commit source code, tests and documentation.

Do not commit:

- Large raw NVD, EPSS or KEV datasets
- Generated Silver CSV exports
- Python cache directories
- Local virtual environments
- Temporary ETL outputs

Teammates should download the source data and reproduce
the Silver outputs using the commands above.
