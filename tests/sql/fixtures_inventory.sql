INSERT INTO silver.software_inventory (
    snapshot_batch_id,
    installation_id,
    asset_id,
    asset_key,
    software_name,
    installed_version,
    cpe_identifier,
    current_version_count,
    cpe_count,
    matching_status
)
VALUES
(
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'test:asset:with-cpe',
    'Test Application',
    '1.5',
    'cpe:2.3:a:example:app:1.5:*:*:*:*:*:*:*',
    1,
    1,
    'candidate_for_matching'
),
(
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002',
    'test:asset:missing-cpe',
    'Unknown Application',
    '1.0',
    NULL,
    1,
    0,
    'missing_cpe'
);
