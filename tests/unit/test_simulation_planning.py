"""Pure scenario planning, fixture semantics and persisted-record audit checks."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from patchledger.db.migrations import get_target_metadata
from patchledger.operational.models import (
    Asset,
    AssetEvent,
    Department,
    FindingEvent,
    InstallationHistory,
    ProductIdentifier,
    RemediationEvent,
    RemediationTask,
    ScanObservation,
    ScanRun,
    SoftwareInstallation,
    SoftwareProduct,
    TaskFinding,
    VulnerabilityFinding,
)
from patchledger.simulation.config import SimulationConfig
from patchledger.simulation.enterprise import enterprise_plan
from patchledger.simulation.errors import DataQualityError
from patchledger.simulation.fixtures import CATALOG
from patchledger.simulation.quality import check_quality
from patchledger.simulation.random_state import operation_id, random_stream
from patchledger.simulation.reporting import sla_breaches, summarize
from patchledger.simulation.runner import main, plan_simulation


@pytest.mark.parametrize(
    "changes",
    [
        {"assets": 0},
        {"assets": True},
        {"assets": 10001},
        {"days": 0},
        {"installations_per_asset": 0},
        {"scan_interval_days": 0},
        {"max_attempts": 6},
        {"remediation_probability": -0.1},
        {"patch_success_probability": 1.1},
        {"initial_safe_probability": float("nan")},
        {"scenario": "unsafe%scenario"},
        {"start": "2024-01-01"},
        {"departments": {}},
        {"departments": {"Engineering": 0}},
        {"departments": {" Bad ": 1}},
        {"criticality": {6: 1}},
        {"failed_scan_probability": 0.8, "partial_scan_probability": 0.8},
        {"retirement_probability": 0.6, "suspension_probability": 0.6},
        {"unknown_setting": 1},
    ],
)
def test_configuration_rejects_invalid_ranges_and_shapes(changes):
    with pytest.raises(ValidationError):
        SimulationConfig.model_validate({"scenario": "valid", **changes})


def test_defaults_timezone_and_fingerprint_are_stable():
    config = SimulationConfig(scenario="baseline")
    assert (
        config.assets == 400
        and config.installations_per_asset == 5
        and config.days == 90
    )
    offset = SimulationConfig(scenario="baseline", start="2024-01-01T05:00:00+05:00")
    assert offset.start == config.start and offset.fingerprint == config.fingerprint
    reordered = SimulationConfig.model_validate(
        {
            **config.model_dump(),
            "departments": dict(reversed(list(config.departments.items()))),
        }
    )
    assert reordered.fingerprint == config.fingerprint
    assert (
        SimulationConfig.model_validate({**config.model_dump(), "seed": 99}).fingerprint
        != config.fingerprint
    )


def test_enterprise_generation_is_deterministic_and_scoped():
    config = SimulationConfig(scenario="coherent", assets=20, installations_per_asset=8)
    first = enterprise_plan(config)
    assert first == enterprise_plan(config)
    assert len({a.asset_key for a in first}) == 20
    assert all(
        a.asset_key.startswith(config.prefix) and len(a.products) == 8 for a in first
    )
    assert all(
        a.department in config.departments and a.criticality in config.criticality
        for a in first
    )
    assert all(a.versions[0] == "1.0-fixture" for a in first)
    assert any("2.0-fixture" in a.versions for a in first)
    other = enterprise_plan(
        SimulationConfig(scenario="another", assets=20, installations_per_asset=8)
    )
    assert not {a.asset_key for a in first} & {a.asset_key for a in other}


def test_independent_random_streams_and_operation_ids():
    config = SimulationConfig(scenario="stable")
    expected = random_stream(config, "asset:1").random()
    for _ in range(20):
        random_stream(config, "unrelated").random()
    assert random_stream(config, "asset:1").random() == expected
    assert operation_id(config, "work") == operation_id(config, "work")
    assert operation_id(config, "work") != operation_id(config, "other-work")


def test_fixture_applicability_never_guesses_unknown_versions():
    for fixture in CATALOG:
        for cve in fixture.cves:
            assert fixture.outcome(cve, "1.0-fixture") == "affected"
            assert fixture.outcome(cve, "1.5-fixture") == "affected"
            assert fixture.outcome(cve, "2.0-fixture") == "not_affected"
            assert fixture.outcome(cve, "not-reviewed") == "inconclusive"
            assert fixture.outcome(cve, None) == "target_absent"
        with pytest.raises(ValueError):
            fixture.outcome("CVE-2024-0001", "1.0-fixture")


def test_schedule_respects_time_dependencies_and_supports_all_planned_outcomes():
    config = SimulationConfig(
        scenario="schedule",
        assets=30,
        days=14,
        sla_days=2,
        remediation_probability=1,
        patch_success_probability=0.5,
        ineffective_patch_probability=0.5,
        retry_probability=1,
        recurrence_probability=1,
        inventory_churn_probability=1,
    )
    plans, events = plan_simulation(config)
    assert events == tuple(sorted(events))
    assert len({e.key for e in events}) == len(events)
    assert all(config.start < e.at < config.end for e in events)
    attempts = [e for e in events if e.kind == "attempt"]
    assert {e.detail.split(":")[1] for e in attempts} == {
        "effective",
        "ineffective",
        "failed",
    }
    assert {e.kind for e in events} >= {
        "scan",
        "task",
        "attempt",
        "verify",
        "regression",
        "recurrence_task",
        "remove",
        "reinstall",
    }
    for attempt in attempts:
        verify = next(
            e
            for e in events
            if e.asset == attempt.asset
            and e.kind == "verify"
            and e.detail == attempt.detail
        )
        assert verify.at > attempt.at
    assert len(plans) == 30


def test_one_day_and_non_midnight_start_remain_valid_plans():
    config = SimulationConfig(
        scenario="short",
        assets=1,
        days=1,
        sla_days=1,
        start="2024-01-01T22:00:00+00:00",
        remediation_probability=1,
        sla_breach_probability=0,
    )
    _, events = plan_simulation(config)
    assert any(e.kind == "attempt" for e in events)
    assert all(config.start < e.at < config.end for e in events)


def test_cli_plan_never_loads_credentials_or_connects(monkeypatch, capsys):
    from patchledger.simulation import runner

    def forbidden(*args, **kwargs):
        raise AssertionError("Planning mode must not touch database configuration")

    monkeypatch.setattr(runner, "Settings", forbidden)
    assert (
        main(["--scenario", "dry-run", "--assets", "12", "--days", "14", "--plan"]) == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["planned_assets"] == 12 and report["planned_installations"] == 60
    assert "no persisted data" in report["mode"]


def test_cli_json_overrides_and_rejects_bad_input(tmp_path, capsys):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps({"scenario": "from-file", "assets": 3, "days": 10}))
    assert main(["--config", str(path), "--assets", "4", "--plan"]) == 0
    assert json.loads(capsys.readouterr().out)["planned_assets"] == 4
    with pytest.raises(SystemExit) as error:
        main(["--scenario", "bad", "--assets", "0", "--plan"])
    assert error.value.code == 2
    path.write_text("[]")
    with pytest.raises(SystemExit):
        main(["--config", str(path), "--plan"])


@pytest.fixture
def audited_records():
    config = SimulationConfig(
        scenario="audit", assets=1, installations_per_asset=1, days=14
    )
    start, detected = config.start, config.start + timedelta(hours=9)
    records = {table.name: [] for table in get_target_metadata().sorted_tables}
    department = Department(
        id=uuid4(), code=f"{config.prefix}department:Engineering", name="Engineering"
    )
    asset_values = {
        "hostname": "audit-host",
        "department_id": department.id,
        "owner_ref": "simulator:audit",
        "asset_type": "server",
        "environment": "test",
        "business_criticality": 3,
        "exposure": "internal",
        "lifecycle_status": "active",
        "registered_at": start,
        "retired_at": None,
    }
    asset = Asset(id=uuid4(), asset_key=f"{config.prefix}asset:000000", **asset_values)
    event = AssetEvent(
        id=uuid4(),
        asset_id=asset.id,
        event_number=1,
        event_type="registered",
        occurred_at=start,
        actor_ref="simulator:audit",
        source_key=config.source,
        is_synthetic=True,
        **asset_values,
    )
    product = SoftwareProduct(
        id=uuid4(),
        product_key=f"{config.prefix}product:gateway",
        name=CATALOG[0].name,
        publisher_name=CATALOG[0].publisher,
        ecosystem="synthetic-fixture",
    )
    identifier = ProductIdentifier(
        id=uuid4(),
        product_id=product.id,
        scheme="vendor",
        identifier="synthetic:catalog-v1:gateway",
        source_ref=config.source,
    )
    installation = SoftwareInstallation(
        id=uuid4(),
        asset_id=asset.id,
        product_id=product.id,
        installation_key="slot:0:gateway",
    )
    period = InstallationHistory(
        id=uuid4(),
        installation_id=installation.id,
        version="1.0-fixture",
        started_at=start + timedelta(seconds=1),
        start_basis="actual",
        actor_ref="simulator:audit",
        source_key=config.source,
        is_synthetic=True,
    )
    run = ScanRun(
        id=uuid4(),
        asset_id=asset.id,
        source_key=config.source,
        external_run_key="baseline",
        producer_version="fixture-v1",
        is_synthetic=True,
        scope={},
        status="completed",
        started_at=detected,
        completed_at=detected + timedelta(seconds=20),
        request_digest="0" * 64,
    )
    finding = VulnerabilityFinding(
        id=uuid4(),
        asset_id=asset.id,
        installation_id=installation.id,
        cve_id=CATALOG[0].cves[0],
        status="open",
        first_detected_at=detected,
        last_observed_at=detected,
        current_opened_at=detected,
        sla_policy_ref="fixture:policy",
        sla_target_seconds=86400,
        sla_deadline=detected + timedelta(days=1),
    )
    observation = ScanObservation(
        id=uuid4(),
        scan_run_id=run.id,
        asset_id=asset.id,
        external_observation_key="positive",
        installation_id=installation.id,
        installation_history_id=period.id,
        finding_id=finding.id,
        cve_id=finding.cve_id,
        outcome="affected",
        occurred_at=detected,
        test_ref="fixture:rule",
        payload_digest="0" * 64,
    )
    opened = FindingEvent(
        id=uuid4(),
        finding_id=finding.id,
        event_number=1,
        operation_id=observation.id,
        event_type="opened",
        status_after="open",
        occurred_at=detected,
        actor_ref="simulator:audit",
        source_key=config.source,
        is_synthetic=True,
        sla_deadline=finding.sla_deadline,
        sla_policy_ref="fixture:policy",
        sla_target_seconds=86400,
    )
    for row in (
        department,
        asset,
        event,
        product,
        identifier,
        installation,
        period,
        run,
        finding,
        observation,
        opened,
    ):
        records[row.__tablename__].append(row)
    return config, records


def test_persisted_record_quality_and_summary_are_not_attempt_counts(audited_records):
    config, records = audited_records
    assert check_quality(config, records) == "passed"
    report = summarize(config, records)
    assert (
        report["counts"]["assets"] == 1
        and report["counts"]["vulnerability_findings"] == 1
    )
    assert report["counts"]["verified_resolutions"] == 0
    assert report["counts"]["sla_breached_occurrences"] == 1
    assert "not validated NVD" in report["applicability"]


@pytest.mark.parametrize(
    "corruption",
    [
        "orphan",
        "period",
        "fixture",
        "provenance",
        "transition",
        "state",
        "timestamp",
        "duplicate",
    ],
)
def test_quality_rejects_invalid_persisted_graph(audited_records, corruption):
    config, records = audited_records
    if corruption == "orphan":
        records["software_products"].clear()
    elif corruption == "period":
        records["installation_history"][0].ended_at = config.start
        records["installation_history"][0].end_is_synthetic = True
        records["installation_history"][0].end_source_key = config.source
    elif corruption == "fixture":
        records["scan_observations"][0].outcome = "not_affected"
    elif corruption == "provenance":
        records["scan_runs"][0].is_synthetic = False
    elif corruption == "transition":
        records["finding_events"][0].event_type = "reopened"
    elif corruption == "state":
        records["assets"][0].business_criticality = 5
    elif corruption == "timestamp":
        records["scan_observations"][0].occurred_at = config.end
    else:
        records["software_products"].append(records["software_products"][0])
    with pytest.raises(DataQualityError):
        check_quality(config, records)


def test_sla_counts_occurrences_with_exact_deadline_boundary():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    events = [
        SimpleNamespace(
            finding_id="one",
            event_number=1,
            event_type="opened",
            occurred_at=start,
            sla_deadline=start + timedelta(days=1),
        ),
        SimpleNamespace(
            finding_id="one",
            event_number=2,
            event_type="resolved",
            occurred_at=start + timedelta(days=1),
        ),
        SimpleNamespace(
            finding_id="one",
            event_number=3,
            event_type="reopened",
            occurred_at=start + timedelta(days=2),
            sla_deadline=start + timedelta(days=3),
        ),
    ]
    assert sla_breaches(events, start + timedelta(days=4)) == 1


def test_fixture_content_changes_invalidate_fingerprint(monkeypatch):
    from dataclasses import replace

    from patchledger.simulation import fixtures

    config = SimulationConfig(scenario="fixture-version")
    original = config.fingerprint
    monkeypatch.setattr(
        fixtures,
        "CATALOG",
        (replace(CATALOG[0], unaffected_versions=("3.0-fixture",)), *CATALOG[1:]),
    )
    assert config.fingerprint != original


def test_quality_rejects_overlapping_closed_and_open_periods(audited_records):
    config, records = audited_records
    period = records["installation_history"][0]
    period.ended_at = config.start + timedelta(hours=10)
    period.end_is_synthetic, period.end_source_key = True, config.source
    records["installation_history"].append(
        InstallationHistory(
            id=uuid4(),
            installation_id=period.installation_id,
            version="1.1-fixture",
            started_at=config.start + timedelta(hours=8),
            source_key=config.source,
            is_synthetic=True,
            start_basis="actual",
            actor_ref="simulator:audit",
        )
    )
    with pytest.raises(DataQualityError, match="Overlapping"):
        check_quality(config, records)


def test_quality_rejects_task_closure_without_verification(audited_records):
    config, records = audited_records
    finding = records["vulnerability_findings"][0]
    opening = records["finding_events"][0]
    start = config.start
    values = {
        "title": "Audit work",
        "description": None,
        "owner_department_id": records["departments"][0].id,
        "assignee_ref": "simulator:audit",
        "priority": 3,
        "goal": "eliminate",
        "due_at": config.end,
        "estimated_effort_minutes": 30,
        "started_at": start + timedelta(hours=10, seconds=1),
        "work_completed_at": start + timedelta(hours=11),
        "closed_at": start + timedelta(hours=12),
    }
    task = RemediationTask(
        id=uuid4(), task_key=f"{config.prefix}task:audit", status="closed", **values
    )
    link = TaskFinding(
        id=uuid4(),
        task_id=task.id,
        finding_id=finding.id,
        opening_event_id=opening.id,
        added_at=start + timedelta(hours=10),
        added_by_ref="simulator:audit",
    )
    records["remediation_tasks"].append(task)
    records["task_findings"].append(link)
    steps = [
        ("created", "open", 10),
        ("target_added", "open", 10),
        ("status_changed", "in_progress", 10.1),
        ("status_changed", "completed", 11),
        ("status_changed", "closed", 12),
    ]
    for number, (kind, status, hour) in enumerate(steps, start=1):
        snapshot = {
            **values,
            "started_at": values["started_at"] if status != "open" else None,
            "work_completed_at": values["work_completed_at"]
            if status in {"completed", "closed"}
            else None,
            "closed_at": values["closed_at"] if status == "closed" else None,
        }
        records["remediation_events"].append(
            RemediationEvent(
                id=uuid4(),
                task_id=task.id,
                event_number=number,
                event_type=kind,
                operation_id=uuid4(),
                payload_digest="0" * 64,
                status=status,
                occurred_at=start + timedelta(hours=hour),
                source_key=config.source,
                actor_ref="simulator:audit",
                is_synthetic=True,
                task_finding_id=link.id if kind == "target_added" else None,
                **snapshot,
            )
        )
    with pytest.raises(DataQualityError, match="before verification"):
        check_quality(config, records)
