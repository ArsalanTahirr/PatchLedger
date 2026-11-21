CREATE OR REPLACE FUNCTION silver.cpe_rule_match(
    installed_cpe TEXT,
    rule JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    cpe_result TEXT;
    range_result TEXT;
    installed_version TEXT;
    criteria_parts TEXT[];
    has_range BOOLEAN;
BEGIN
    IF rule IS NULL
       OR jsonb_typeof(rule) <> 'object'
       OR jsonb_typeof(rule->'criteria') IS DISTINCT FROM 'string'
    THEN
        RETURN 'unknown';
    END IF;

    cpe_result := silver.cpe_match_basic(
        installed_cpe,
        rule->>'criteria'
    );

    IF cpe_result = 'no_match' THEN
        RETURN 'no_match';
    END IF;

    criteria_parts := silver.cpe_parts(rule->>'criteria');

    IF criteria_parts IS NULL THEN
        RETURN 'unknown';
    END IF;

    has_range := (
        rule->>'versionStartIncluding' IS NOT NULL
        OR rule->>'versionStartExcluding' IS NOT NULL
        OR rule->>'versionEndIncluding' IS NOT NULL
        OR rule->>'versionEndExcluding' IS NOT NULL
    );

    IF has_range AND criteria_parts[6] <> '*' THEN
        RETURN 'unknown';
    END IF;

    IF silver.cpe_parts(installed_cpe) IS NULL THEN
        RETURN 'unknown';
    END IF;

    installed_version := (silver.cpe_parts(installed_cpe))[6];

    IF installed_version IN ('*', '-') THEN
        RETURN 'unknown';
    END IF;

    range_result := silver.version_range_match(
        installed_version,
        rule
    );

    IF range_result = 'no_match' THEN
        RETURN 'no_match';
    END IF;

    IF cpe_result = 'unknown'
       OR range_result = 'unknown'
    THEN
        RETURN 'unknown';
    END IF;

    RETURN 'match';
END;
$$;
