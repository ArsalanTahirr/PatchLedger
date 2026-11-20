import pytest

from patchledger.simulation.nvd_inventory_mapping import (
    VerifiedCpeMapping,
    prepare_nvd_inventory,
)


def record(version="1.0-fixture", status="resolved"):
    return {
        "asset_id": "asset-1",
        "installation_id": "install-1",
        "product_id": "product-1",
        "version": version,
        "version_status": status,
        "cpe": None,
        "mapping_status": "unmapped",
    }


def mapping():
    return VerifiedCpeMapping(
        product_id="product-1",
        version="1.0-fixture",
        cpe="cpe:2.3:a:example:app:1.0-fixture:*:*:*:*:*:*:*",
        source_ref="reviewed-test-fixture",
    )


def test_unmapped_product_does_not_generate_cpe():
    result = prepare_nvd_inventory([record()], [])

    assert result.mapped == ()
    assert result.unresolved[0]["reason"] == ("no_verified_cpe_mapping")


def test_explicit_mapping_produces_cpe():
    result = prepare_nvd_inventory([record()], [mapping()])

    assert len(result.mapped) == 1
    assert result.mapped[0]["installation_id"] == "install-1"
    assert result.mapped[0]["cpe"].startswith("cpe:2.3:")
    assert result.unresolved == ()


def test_version_mismatch_is_not_mapped():
    result = prepare_nvd_inventory(
        [record(version="2.0-fixture")],
        [mapping()],
    )

    assert result.mapped == ()
    assert len(result.unresolved) == 1


def test_history_gap_cannot_be_mapped():
    result = prepare_nvd_inventory(
        [record(version=None, status="no_history_at_time")],
        [mapping()],
    )

    assert result.mapped == ()
    assert result.unresolved[0]["reason"] == ("unresolved_version")


def test_duplicate_mappings_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        prepare_nvd_inventory(
            [record()],
            [mapping(), mapping()],
        )


def test_synthetic_oltp_product_cannot_use_real_cpe():
    synthetic = record()
    synthetic["product_name"] = "Fixture Database Service"
    synthetic["publisher_name"] = "PatchLedger Synthetic Publisher"

    result = prepare_nvd_inventory(
        [synthetic],
        [mapping()],
    )

    assert result.mapped == ()
    assert len(result.unresolved) == 1
    assert result.unresolved[0]["reason"] == ("synthetic_product_unmapped")


def test_synthetic_history_gap_stays_unresolved():
    synthetic = record(
        version=None,
        status="no_history_at_time",
    )
    synthetic["product_name"] = "Fixture Database Service"
    synthetic["publisher_name"] = "PatchLedger Synthetic Publisher"

    result = prepare_nvd_inventory(
        [synthetic],
        [mapping()],
    )

    assert result.mapped == ()
    assert result.unresolved[0]["reason"] == ("unresolved_version")


def test_cpe_version_must_match_mapping_version():
    bad = VerifiedCpeMapping(
        product_id="product-1",
        version="1.0-fixture",
        cpe="cpe:2.3:a:example:app:2.0:*:*:*:*:*:*:*",
        source_ref="negative-test",
    )

    with pytest.raises(ValueError, match="CPE version mismatch"):
        prepare_nvd_inventory([record()], [bad])


def test_wildcard_cpe_version_rejected():
    bad = VerifiedCpeMapping(
        product_id="product-1",
        version="1.0-fixture",
        cpe="cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
        source_ref="negative-test",
    )

    with pytest.raises(ValueError, match="Unsupported CPE identity"):
        prepare_nvd_inventory([record()], [bad])


def test_wildcard_vendor_rejected():
    bad = VerifiedCpeMapping(
        product_id="product-1",
        version="1.0-fixture",
        cpe="cpe:2.3:a:*:app:1.0-fixture:*:*:*:*:*:*:*",
        source_ref="negative-test",
    )

    with pytest.raises(ValueError, match="Unsupported CPE identity"):
        prepare_nvd_inventory([record()], [bad])
