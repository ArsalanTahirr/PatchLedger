"""Conservative mapping of OLTP inventory to NVD CPE inputs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class VerifiedCpeMapping:
    product_id: str
    version: str
    cpe: str
    source_ref: str


@dataclass(frozen=True)
class MappingResult:
    mapped: tuple[dict, ...]
    unresolved: tuple[dict, ...]


def prepare_nvd_inventory(records, mappings):
    """Map only explicitly reviewed product/version identities.

    An unmapped inventory entry is not evidence of safety.
    """

    index = {}

    for mapping in mappings:
        if not isinstance(mapping, VerifiedCpeMapping):
            raise ValueError("Mapping must be VerifiedCpeMapping")  # noqa: TRY004

        key = (mapping.product_id, mapping.version)

        if key in index:
            raise ValueError("Duplicate product/version mapping")

        if not all(
            (
                mapping.product_id,
                mapping.version,
                mapping.source_ref.strip(),
            )
        ):
            raise ValueError("Incomplete mapping provenance")

        if (
            not mapping.cpe.startswith("cpe:2.3:")
            or len(mapping.cpe.split(":")) != 13
            or mapping.cpe.split(":")[2] not in ("a", "o", "h")
        ):
            raise ValueError("Invalid or unsupported CPE")

        parts = mapping.cpe.split(":")

        if any(parts[i] in ("", "*", "-") for i in (3, 4, 5)):
            raise ValueError("Unsupported CPE identity")

        if parts[5] != mapping.version:
            raise ValueError("CPE version mismatch")

        index[key] = mapping

    mapped = []
    unresolved = []
    seen = set()

    for record in records:
        installation_id = record["installation_id"]

        if not installation_id or installation_id in seen:
            raise ValueError("Duplicate or missing installation ID")
        seen.add(installation_id)

        if record["version_status"] != "resolved":
            reason = "unresolved_version"
        elif record["mapping_status"] != "unmapped" or record["cpe"] is not None:
            raise ValueError("Unexpected upstream CPE state")
        else:
            reason = None

        if (
            reason is None
            and record.get("publisher_name") == "PatchLedger Synthetic Publisher"
        ):
            reason = "synthetic_product_unmapped"

        if reason is None:
            key = (record["product_id"], record["version"])
            mapping = index.get(key)

            if mapping is None:
                reason = "no_verified_cpe_mapping"
            else:
                mapped.append(
                    {
                        "asset_id": record["asset_id"],
                        "installation_id": installation_id,
                        "cpe": mapping.cpe,
                        "source_ref": mapping.source_ref,
                    }
                )
                continue

        unresolved.append(
            {
                "asset_id": record["asset_id"],
                "installation_id": installation_id,
                "product_id": record["product_id"],
                "version": record["version"],
                "reason": reason,
            }
        )

    return MappingResult(
        mapped=tuple(mapped),
        unresolved=tuple(unresolved),
    )
