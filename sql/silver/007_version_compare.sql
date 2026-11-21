CREATE OR REPLACE FUNCTION silver.compare_versions(
    version_a TEXT,
    version_b TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    a_parts TEXT[];
    b_parts TEXT[];
    a_number NUMERIC;
    b_number NUMERIC;
    i INTEGER;
BEGIN
    IF version_a IS NULL OR version_b IS NULL THEN
        RETURN NULL;
    END IF;

    IF version_a !~ '^[0-9]+(\.[0-9]+)*$'
       OR version_b !~ '^[0-9]+(\.[0-9]+)*$' THEN
        RETURN NULL;
    END IF;

    a_parts := STRING_TO_ARRAY(version_a, '.');
    b_parts := STRING_TO_ARRAY(version_b, '.');

    FOR i IN 1..GREATEST(
        ARRAY_LENGTH(a_parts, 1),
        ARRAY_LENGTH(b_parts, 1)
    ) LOOP
        IF COALESCE(LENGTH(a_parts[i]), 0) > 1000
           OR COALESCE(LENGTH(b_parts[i]), 0) > 1000 THEN
            RETURN NULL;
        END IF;

        a_number := COALESCE(a_parts[i], '0')::numeric;
        b_number := COALESCE(b_parts[i], '0')::numeric;

        IF a_number < b_number THEN
            RETURN -1;
        ELSIF a_number > b_number THEN
            RETURN 1;
        END IF;
    END LOOP;

    RETURN 0;
END;
$$;
