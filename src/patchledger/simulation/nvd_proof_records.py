"""Structured, read-only NVD applicability proof records."""

from dataclasses import dataclass

from patchledger.simulation.nvd_evidence import evaluate_asset
from patchledger.simulation.nvd_proof import select_applicability_proof


@dataclass(frozen=True)
class ProofRecord:
    asset_id: str
    cve_id: str
    installation_id: str
    installed_cpe: str
    rule_path: str
    match_criteria_id: str | None
    rule_criteria: str
    vulnerable: bool


@dataclass(frozen=True)
class ProofReport:
    asset_id: str
    cve_id: str
    applicable: bool | None
    proof_verified: bool
    supporting_records: tuple[ProofRecord, ...]
    other_matched_paths: tuple[str, ...]


def build_proof_report(
    cve_id,
    configurations,
    asset_id,
    installations,
    *,
    inventory_complete=False,
):
    proof = select_applicability_proof(
        cve_id,
        configurations,
        asset_id,
        installations,
        inventory_complete=inventory_complete,
    )

    evidence = evaluate_asset(
        cve_id,
        configurations,
        asset_id,
        installations,
        inventory_complete=inventory_complete,
    )

    rules_by_path = {rule.path: rule for rule in evidence.rules}

    installations_by_id = {item["installation_id"]: item for item in installations}

    records = []

    if proof.proof_verified:
        for path in proof.supporting_paths:
            rule = rules_by_path.get(path)

            if rule is None or not rule.matched_installations:
                raise ValueError(f"Missing matching evidence for {path}")

            for installation_id in rule.matched_installations:
                installation = installations_by_id[installation_id]

                records.append(
                    ProofRecord(
                        asset_id=asset_id,
                        cve_id=cve_id,
                        installation_id=installation_id,
                        installed_cpe=installation["cpe"],
                        rule_path=path,
                        match_criteria_id=rule.match_criteria_id,
                        rule_criteria=rule.criteria,
                        vulnerable=rule.vulnerable,
                    )
                )

    verified = proof.proof_verified and any(record.vulnerable for record in records)

    return ProofReport(
        asset_id=asset_id,
        cve_id=cve_id,
        applicable=proof.applicable,
        proof_verified=verified,
        supporting_records=tuple(records) if verified else (),
        other_matched_paths=proof.other_matched_paths,
    )
