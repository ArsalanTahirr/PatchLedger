CREATE OR REPLACE FUNCTION silver.combine_match_states(
    states TEXT[],
    logical_operator TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    state TEXT;
    has_match BOOLEAN := FALSE;
    has_no_match BOOLEAN := FALSE;
    has_unknown BOOLEAN := FALSE;
BEGIN
    IF states IS NULL
       OR CARDINALITY(states) = 0
       OR logical_operator NOT IN ('AND', 'OR')
       OR logical_operator IS NULL THEN
        RETURN 'unknown';
    END IF;

    FOREACH state IN ARRAY states LOOP
        IF state = 'match' THEN
            has_match := TRUE;
        ELSIF state = 'no_match' THEN
            has_no_match := TRUE;
        ELSE
            has_unknown := TRUE;
        END IF;
    END LOOP;

    IF logical_operator = 'AND' THEN
        IF has_no_match THEN
            RETURN 'no_match';
        ELSIF has_unknown THEN
            RETURN 'unknown';
        END IF;

        RETURN 'match';
    END IF;

    IF has_match THEN
        RETURN 'match';
    ELSIF has_unknown THEN
        RETURN 'unknown';
    END IF;

    RETURN 'no_match';
END;
$$;


CREATE OR REPLACE FUNCTION silver.negate_match_state(
    state TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN state = 'match' THEN 'no_match'
        WHEN state = 'no_match' THEN 'match'
        ELSE 'unknown'
    END;
$$;
