CREATE OR REPLACE FUNCTION silver.evaluate_nvd_node(
    p_batch_id UUID,
    p_asset_id UUID,
    p_node JSONB,
    p_depth INTEGER DEFAULT 0
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    item JSONB;
    result JSONB;
    states TEXT[] := ARRAY[]::TEXT[];
    combined TEXT;
    has_positive BOOLEAN := FALSE;
    item_state TEXT;
    item_positive BOOLEAN;
    op TEXT;
BEGIN
    IF p_node IS NULL
       OR jsonb_typeof(p_node) <> 'object'
       OR p_depth < 0
       OR p_depth > 16 THEN
        RETURN jsonb_build_object(
            'state', 'unknown',
            'vulnerable_evidence', FALSE
        );
    END IF;

    IF p_node ? 'negate' THEN
        IF jsonb_typeof(p_node->'negate') <> 'boolean' THEN
            RETURN jsonb_build_object(
                'state', 'unknown',
                'vulnerable_evidence', FALSE
            );
        END IF;

        IF p_node->'negate' = 'true'::jsonb THEN
            result := silver.evaluate_nvd_node(
                p_batch_id,
                p_asset_id,
                p_node - 'negate',
                p_depth + 1
            );

            RETURN jsonb_build_object(
                'state',
                CASE
                    WHEN result->>'state' = 'match'
                        THEN 'no_match'
                    ELSE 'unknown'
                END,
                'vulnerable_evidence', FALSE
            );
        END IF;
    END IF;

    op := p_node->>'operator';

    IF op IS NULL OR op NOT IN ('AND', 'OR') THEN
        RETURN jsonb_build_object(
            'state', 'unknown',
            'vulnerable_evidence', FALSE
        );
    END IF;

    IF p_node ? 'cpeMatch' THEN
        IF jsonb_typeof(p_node->'cpeMatch') <> 'array' THEN
            RETURN jsonb_build_object(
                'state', 'unknown',
                'vulnerable_evidence', FALSE
            );
        END IF;

        FOR item IN
            SELECT value
            FROM jsonb_array_elements(p_node->'cpeMatch')
        LOOP
            IF jsonb_typeof(item) IS DISTINCT FROM 'object'
               OR jsonb_typeof(item->'vulnerable')
                  IS DISTINCT FROM 'boolean' THEN
                item_state := 'unknown';
                item_positive := FALSE;
            ELSE
                item_state := silver.asset_rule_state(
                    p_batch_id, p_asset_id, item
                );

                item_positive :=
                    item_state = 'match'
                    AND item->'vulnerable' = 'true'::jsonb;
            END IF;

            states := array_append(states, item_state);

            IF item_positive THEN
                has_positive := TRUE;
            END IF;
        END LOOP;
    END IF;

    IF p_node ? 'children' THEN
        IF jsonb_typeof(p_node->'children') <> 'array' THEN
            RETURN jsonb_build_object(
                'state', 'unknown',
                'vulnerable_evidence', FALSE
            );
        END IF;

        FOR item IN
            SELECT value
            FROM jsonb_array_elements(p_node->'children')
        LOOP
            result := silver.evaluate_nvd_node(
                p_batch_id, p_asset_id, item, p_depth + 1
            );

            item_state := result->>'state';
            item_positive :=
                item_state = 'match'
                AND result->'vulnerable_evidence' = 'true'::jsonb;

            states := array_append(states, item_state);

            IF item_positive THEN
                has_positive := TRUE;
            END IF;
        END LOOP;
    END IF;

    combined := silver.combine_match_states(states, op);

    RETURN jsonb_build_object(
        'state', combined,
        'vulnerable_evidence',
        combined = 'match' AND has_positive
    );
END;
$$;
