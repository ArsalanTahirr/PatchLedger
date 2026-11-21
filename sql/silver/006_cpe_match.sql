CREATE OR REPLACE FUNCTION silver.cpe_parts(value TEXT)
RETURNS TEXT[]
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    parts TEXT[] := ARRAY[]::TEXT[];
    token TEXT := '';
    character TEXT;
    next_character TEXT;
    position INTEGER := 1;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;

    WHILE position <= LENGTH(value) LOOP
        character := SUBSTR(value, position, 1);

        IF character = CHR(92) THEN
            IF position = LENGTH(value) THEN
                RETURN NULL;
            END IF;

            next_character := SUBSTR(value, position + 1, 1);

            IF next_character ~ '^[[:alnum:]]$' THEN
                RETURN NULL;
            END IF;

            IF next_character IN ('*', '?') THEN
                RETURN NULL;
            END IF;

            token := token || next_character;
            position := position + 2;

        ELSIF character = ':' THEN
            parts := ARRAY_APPEND(parts, token);
            token := '';
            position := position + 1;

        ELSE
            token := token || character;
            position := position + 1;
        END IF;
    END LOOP;

    parts := ARRAY_APPEND(parts, token);

    IF CARDINALITY(parts) <> 13
       OR parts[1] <> 'cpe'
       OR parts[2] <> '2.3'
       OR EXISTS (
           SELECT 1
           FROM UNNEST(parts) AS p
           WHERE p = ''
       )
    THEN
        RETURN NULL;
    END IF;

    RETURN parts;
END;
$$;


CREATE OR REPLACE FUNCTION silver.cpe_has_pattern(value TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    position INTEGER := 1;
    character TEXT;
BEGIN
    IF value IS NULL THEN
        RETURN NULL;
    END IF;

    WHILE position <= LENGTH(value) LOOP
        character := SUBSTR(value, position, 1);

        IF character = CHR(92) THEN
            position := position + 2;
        ELSIF character IN ('*', '?') THEN
            RETURN TRUE;
        ELSE
            position := position + 1;
        END IF;
    END LOOP;

    RETURN FALSE;
END;
$$;


CREATE OR REPLACE FUNCTION silver.cpe_match_basic(
    installed_cpe TEXT,
    nvd_criteria TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    installed_parts TEXT[];
    criteria_parts TEXT[];
    i INTEGER;
    uncertain BOOLEAN := FALSE;
BEGIN
    installed_parts := silver.cpe_parts(installed_cpe);
    criteria_parts := silver.cpe_parts(nvd_criteria);

    IF installed_parts IS NULL OR criteria_parts IS NULL THEN
        RETURN 'unknown';
    END IF;

    FOR i IN 3..13 LOOP
        IF criteria_parts[i] = '*' THEN
            CONTINUE;
        END IF;

        IF installed_parts[i] = '*' THEN
            uncertain := TRUE;

        ELSIF silver.cpe_has_pattern(criteria_parts[i])
           OR silver.cpe_has_pattern(installed_parts[i])
        THEN
            uncertain := TRUE;

        ELSIF installed_parts[i] IS DISTINCT FROM criteria_parts[i] THEN
            IF i = 6 AND criteria_parts[i] = '-' THEN
                uncertain := TRUE;
            ELSE
                RETURN 'no_match';
            END IF;
        END IF;
    END LOOP;

    IF uncertain THEN
        RETURN 'unknown';
    END IF;

    RETURN 'match';
END;
$$;
