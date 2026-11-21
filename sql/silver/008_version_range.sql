CREATE OR REPLACE FUNCTION silver.version_range_match(
    installed_version TEXT,
    rule JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    start_inc TEXT;
    start_exc TEXT;
    end_inc TEXT;
    end_exc TEXT;
    boundary TEXT;
    comparison INTEGER;
    has_range BOOLEAN;
BEGIN
    IF rule IS NULL OR jsonb_typeof(rule) <> 'object' THEN
        RETURN 'unknown';
    END IF;

    start_inc := rule->>'versionStartIncluding';
    start_exc := rule->>'versionStartExcluding';
    end_inc := rule->>'versionEndIncluding';
    end_exc := rule->>'versionEndExcluding';

    has_range := start_inc IS NOT NULL
              OR start_exc IS NOT NULL
              OR end_inc IS NOT NULL
              OR end_exc IS NOT NULL;

    IF NOT has_range THEN
        RETURN 'match';
    END IF;

    IF installed_version IS NULL
       OR BTRIM(installed_version) = '' THEN
        RETURN 'unknown';
    END IF;

    IF (start_inc IS NOT NULL AND start_exc IS NOT NULL)
       OR (end_inc IS NOT NULL AND end_exc IS NOT NULL) THEN
        RETURN 'unknown';
    END IF;

    FOR boundary IN
        SELECT value
        FROM jsonb_each_text(rule)
        WHERE key IN (
            'versionStartIncluding',
            'versionStartExcluding',
            'versionEndIncluding',
            'versionEndExcluding'
        )
    LOOP
        IF silver.compare_versions(installed_version, boundary)
           IS NULL THEN
            RETURN 'unknown';
        END IF;
    END LOOP;

    IF start_inc IS NOT NULL THEN
        comparison := silver.compare_versions(
            installed_version, start_inc
        );
        IF comparison < 0 THEN
            RETURN 'no_match';
        END IF;
    END IF;

    IF start_exc IS NOT NULL THEN
        comparison := silver.compare_versions(
            installed_version, start_exc
        );
        IF comparison <= 0 THEN
            RETURN 'no_match';
        END IF;
    END IF;

    IF end_inc IS NOT NULL THEN
        comparison := silver.compare_versions(
            installed_version, end_inc
        );
        IF comparison > 0 THEN
            RETURN 'no_match';
        END IF;
    END IF;

    IF end_exc IS NOT NULL THEN
        comparison := silver.compare_versions(
            installed_version, end_exc
        );
        IF comparison >= 0 THEN
            RETURN 'no_match';
        END IF;
    END IF;

    RETURN 'match';
END;
$$;
