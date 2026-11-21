CREATE OR REPLACE FUNCTION silver.asset_rule_state(
    p_batch_id UUID,
    p_asset_id UUID,
    p_rule JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    record_row RECORD;
    result TEXT;
BEGIN
    IF p_batch_id IS NULL
       OR p_asset_id IS NULL
       OR p_rule IS NULL
       OR jsonb_typeof(p_rule) <> 'object'
       OR jsonb_typeof(p_rule->'criteria') IS DISTINCT FROM 'string'
    THEN
        RETURN 'unknown';
    END IF;

    FOR record_row IN
        SELECT cpe_identifier
        FROM silver.software_inventory
        WHERE snapshot_batch_id = p_batch_id
          AND asset_id = p_asset_id
          AND matching_status = 'candidate_for_matching'
    LOOP
        result := silver.cpe_rule_match(
            record_row.cpe_identifier,
            p_rule
        );

        IF result = 'match' THEN
            RETURN 'match';
        END IF;
    END LOOP;

    -- Missing CPE or missing matching product is not proof
    -- that the required software is absent.
    RETURN 'unknown';
END;
$$;
