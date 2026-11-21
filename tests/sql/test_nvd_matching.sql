DO $$
DECLARE
    batch_id UUID;
    asset UUID;
    cpe TEXT;
    other_asset UUID;
    actual TEXT;
    result JSONB;
    config JSONB;
BEGIN
    SELECT snapshot_batch_id, asset_id, cpe_identifier
    INTO STRICT batch_id, asset, cpe
    FROM silver.software_inventory
    WHERE asset_key = 'test:asset:with-cpe'
    LIMIT 1;

    SELECT asset_id INTO STRICT other_asset
    FROM silver.software_inventory
    WHERE snapshot_batch_id = batch_id
      AND asset_key = 'test:asset:missing-cpe'
    LIMIT 1;

    IF silver.cpe_match_basic(cpe, cpe) IS DISTINCT FROM 'match' THEN
        RAISE EXCEPTION 'FAIL: exact CPE match';
    END IF;

    IF silver.cpe_match_basic(
        cpe,
        'cpe:2.3:a:nonexistent:product:*:*:*:*:*:*:*:*'
    ) IS DISTINCT FROM 'no_match' THEN
        RAISE EXCEPTION 'FAIL: different product';
    END IF;

    IF silver.cpe_match_basic(
        'cpe:2.3:a:example:my\:product:1.0:*:*:*:*:*:*:*',
        'cpe:2.3:a:example:my\:product:1.0:*:*:*:*:*:*:*'
    ) IS DISTINCT FROM 'match' THEN
        RAISE EXCEPTION 'FAIL: escaped CPE colon';
    END IF;

    IF silver.version_range_match(
        '7.0.3',
        '{"versionEndExcluding":"7.0.3"}'::jsonb
    ) IS DISTINCT FROM 'no_match' THEN
        RAISE EXCEPTION 'FAIL: exclusive version boundary';
    END IF;

    IF silver.version_range_match(
        '7.0.3',
        '{"versionEndIncluding":"7.0.3"}'::jsonb
    ) IS DISTINCT FROM 'match' THEN
        RAISE EXCEPTION 'FAIL: inclusive version boundary';
    END IF;

    IF silver.version_range_match(
        '4.0.3c',
        '{"versionEndIncluding":"4.0.3"}'::jsonb
    ) IS DISTINCT FROM 'unknown' THEN
        RAISE EXCEPTION 'FAIL: unsupported version';
    END IF;

    config := jsonb_build_array(
        jsonb_build_object(
            'nodes', jsonb_build_array(
                jsonb_build_object(
                    'operator', 'OR',
                    'cpeMatch', jsonb_build_array(
                        jsonb_build_object(
                            'criteria', cpe,
                            'vulnerable', TRUE
                        )
                    )
                )
            )
        )
    );

    result := silver.evaluate_nvd_cve(batch_id, asset, config);

    IF result->>'status' IS DISTINCT FROM 'applicable' THEN
        RAISE EXCEPTION 'FAIL: vulnerable software match';
    END IF;

    result := silver.evaluate_nvd_cve(
        batch_id, other_asset, config
    );

    IF result->>'status' IS DISTINCT FROM 'inconclusive' THEN
        RAISE EXCEPTION 'FAIL: cross-asset isolation';
    END IF;

    config := jsonb_build_array(
        jsonb_build_object(
            'nodes', jsonb_build_array(
                jsonb_build_object(
                    'operator', 'OR',
                    'cpeMatch', jsonb_build_array(
                        jsonb_build_object(
                            'criteria', cpe,
                            'vulnerable', FALSE
                        )
                    )
                )
            )
        )
    );

    result := silver.evaluate_nvd_cve(batch_id, asset, config);

    IF result->>'status' IS DISTINCT FROM 'inconclusive' THEN
        RAISE EXCEPTION 'FAIL: platform-only configuration';
    END IF;

    result := silver.evaluate_nvd_node(
        batch_id,
        asset,
        jsonb_build_object(
            'operator', 'OR',
            'negate', TRUE,
            'cpeMatch', jsonb_build_array(
                jsonb_build_object(
                    'criteria', cpe,
                    'vulnerable', TRUE
                )
            )
        )
    );

    IF result->>'state' IS DISTINCT FROM 'no_match' THEN
        RAISE EXCEPTION 'FAIL: negated known match';
    END IF;

    RAISE NOTICE 'PASS: All 10 SQL NVD regression checks passed';
END;
$$;


-- Python-SQL CPE parity regression checks
DO $$
DECLARE
    test_case RECORD;
    actual TEXT;
BEGIN
    FOR test_case IN
        SELECT *
        FROM (VALUES
            (
                'dash_version',
                'cpe:2.3:o:linux:linux_kernel:6.8.0:-:-:-:-:-:-:-',
                '{"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}'::jsonb,
                'unknown'
            ),
            (
                'fixed_version_with_range',
                'cpe:2.3:a:example:app:7.0:*:*:*:*:*:*:*',
                '{"criteria":"cpe:2.3:a:example:app:7.0:*:*:*:*:*:*:*",
                  "versionEndExcluding":"8.0"}'::jsonb,
                'unknown'
            ),
            (
                'escaped_equivalent_value',
                'cpe:2.3:a:example:my\!product:1.0:*:*:*:*:*:*:*',
                '{"criteria":"cpe:2.3:a:example:my!product:1.0:*:*:*:*:*:*:*"}'::jsonb,
                'match'
            ),
            (
                'dash_wrong_product',
                'cpe:2.3:o:example:other_os:6.8.0:-:-:-:-:-:-:-',
                '{"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}'::jsonb,
                'no_match'
            ),
            (
                'escaped_wildcard_unsupported',
                'cpe:2.3:a:example:my\*product:1.0:*:*:*:*:*:*:*',
                '{"criteria":"cpe:2.3:a:example:my\\*product:1.0:*:*:*:*:*:*:*"}'::jsonb,
                'unknown'
            )
        ) AS cases(test, installed, rule, expected)
    LOOP
        actual := silver.cpe_rule_match(
            test_case.installed,
            test_case.rule
        );

        IF actual IS DISTINCT FROM test_case.expected THEN
            RAISE EXCEPTION
                'FAIL: % (expected %, got %)',
                test_case.test,
                test_case.expected,
                actual;
        END IF;
    END LOOP;

    RAISE NOTICE 'PASS: All 5 Python-SQL CPE parity checks passed';
END;
$$;


-- Unknown installed-version regression checks
DO $$
DECLARE
    case_row RECORD;
    actual TEXT;
    passed INTEGER := 0;
BEGIN
    FOR case_row IN
        SELECT *
        FROM (VALUES
            (
                'unknown_installed_version',
                'cpe:2.3:a:example:app:*:*:*:*:*:*:*:*',
                '{"criteria":"cpe:2.3:a:example:app:*:*:*:*:*:*:*:*"}'::jsonb,
                'unknown'
            ),
            (
                'known_installed_version',
                'cpe:2.3:a:example:app:1.5:*:*:*:*:*:*:*',
                '{"criteria":"cpe:2.3:a:example:app:*:*:*:*:*:*:*:*"}'::jsonb,
                'match'
            ),
            (
                'wrong_product_unknown_version',
                'cpe:2.3:a:example:other:*:*:*:*:*:*:*:*',
                '{"criteria":"cpe:2.3:a:example:app:*:*:*:*:*:*:*:*"}'::jsonb,
                'no_match'
            )
        ) AS cases(test, installed, rule, expected)
    LOOP
        actual := silver.cpe_rule_match(
            case_row.installed,
            case_row.rule
        );

        IF actual IS DISTINCT FROM case_row.expected THEN
            RAISE EXCEPTION
                'FAIL: % expected %, got %',
                case_row.test, case_row.expected, actual;
        END IF;

        passed := passed + 1;
    END LOOP;

    RAISE NOTICE 'PASS: % unknown-version regression checks', passed;
END;
$$;

-- Branch-aware vulnerability evidence regression
DO $$
DECLARE
    test_batch UUID;
    test_asset UUID;
    test_cpe TEXT;
    result JSONB;
    config JSONB;
BEGIN
    SELECT snapshot_batch_id, asset_id, cpe_identifier
    INTO STRICT test_batch, test_asset, test_cpe
    FROM silver.software_inventory
    WHERE asset_key = 'test:asset:with-cpe'
    LIMIT 1;

    config := jsonb_build_array(
        jsonb_build_object(
            'nodes', jsonb_build_array(
                jsonb_build_object(
                    'operator', 'OR',
                    'cpeMatch', jsonb_build_array(
                        jsonb_build_object(
                            'criteria', test_cpe,
                            'vulnerable', false
                        ),
                        jsonb_build_object(
                            'criteria',
                            'cpe:2.3:a:nonexistent:software:*:*:*:*:*:*:*:*',
                            'vulnerable', true
                        )
                    )
                )
            )
        )
    );

    result := silver.evaluate_nvd_cve(
        test_batch, test_asset, config
    );

    IF result->>'status' IS DISTINCT FROM 'inconclusive'
       OR (result->>'vulnerable_evidence')::boolean
          IS DISTINCT FROM FALSE
    THEN
        RAISE EXCEPTION
            'FAIL: Platform-only OR branch incorrectly implies exposure: %',
            result;
    END IF;

    RAISE NOTICE 'PASS: Platform-only OR branch does not imply vulnerability';
END;
$$;

-- Mixed inventory: missing CPE must not imply non-vulnerability.
DO $$
DECLARE
    test_batch UUID;
    test_asset UUID;
    result JSONB;
BEGIN
    SELECT snapshot_batch_id, asset_id
    INTO STRICT test_batch, test_asset
    FROM silver.software_inventory
    WHERE asset_key = 'test:asset:with-cpe'
    LIMIT 1;

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
    VALUES (
        test_batch,
        '00000000-0000-0000-0000-000000000003',
        test_asset,
        'test:asset:with-cpe',
        'Unknown Application',
        '1.0',
        NULL,
        1,
        0,
        'missing_cpe'
    );

    result := silver.evaluate_nvd_cve(
        test_batch,
        test_asset,
        '[{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:example:other_product:*:*:*:*:*:*:*:*"
                }]
            }]
        }]'::jsonb
    );

    IF result->>'status' IS DISTINCT FROM 'inconclusive'
       OR result->>'configuration_state' IS DISTINCT FROM 'unknown'
    THEN
        RAISE EXCEPTION
            'FAIL: Incomplete inventory classification: %',
            result;
    END IF;

    RAISE NOTICE 'PASS: Unknown inventory remains inconclusive';
END;
$$;
