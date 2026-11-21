CREATE OR REPLACE FUNCTION silver.evaluate_nvd_cve(
    p_batch_id UUID,
    p_asset_id UUID,
    p_configurations JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    configuration JSONB;
    node JSONB;
    node_result JSONB;
    node_states TEXT[];
    configuration_states TEXT[] := ARRAY[]::TEXT[];
    configuration_state TEXT;
    overall_state TEXT;
    configuration_has_evidence BOOLEAN;
    applicable_configuration BOOLEAN := FALSE;
BEGIN
    IF p_batch_id IS NULL
       OR p_asset_id IS NULL
       OR p_configurations IS NULL
       OR jsonb_typeof(p_configurations) <> 'array'
       OR jsonb_array_length(p_configurations) = 0
    THEN
        RETURN jsonb_build_object(
            'status', 'inconclusive',
            'vulnerable_evidence', FALSE,
            'configuration_state', 'unknown'
        );
    END IF;

    FOR configuration IN
        SELECT value FROM jsonb_array_elements(p_configurations)
    LOOP
        IF jsonb_typeof(configuration) <> 'object'
           OR jsonb_typeof(configuration->'nodes') <> 'array'
        THEN
            configuration_states :=
                array_append(configuration_states, 'unknown');
            CONTINUE;
        END IF;

        node_states := ARRAY[]::TEXT[];
        configuration_has_evidence := FALSE;

        FOR node IN
            SELECT value FROM jsonb_array_elements(configuration->'nodes')
        LOOP
            node_result := silver.evaluate_nvd_node(
                p_batch_id, p_asset_id, node
            );

            node_states := array_append(
                node_states, node_result->>'state'
            );

            IF node_result->>'state' = 'match'
               AND node_result->'vulnerable_evidence' = 'true'::jsonb
            THEN
                configuration_has_evidence := TRUE;
            END IF;
        END LOOP;

        configuration_state :=
            silver.combine_match_states(node_states, 'OR');

        configuration_states := array_append(
            configuration_states, configuration_state
        );

        IF configuration_state = 'match'
           AND configuration_has_evidence
        THEN
            applicable_configuration := TRUE;
        END IF;
    END LOOP;

    overall_state := silver.combine_match_states(
        configuration_states, 'OR'
    );

    RETURN jsonb_build_object(
        'status',
        CASE
            WHEN applicable_configuration THEN 'applicable'
            WHEN overall_state = 'no_match' THEN 'not_applicable'
            ELSE 'inconclusive'
        END,
        'vulnerable_evidence', applicable_configuration,
        'configuration_state', overall_state
    );
END;
$$;
