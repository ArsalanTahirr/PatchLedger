"""Small service-driven simulations use only newly created disposable databases."""

import json
import os
from pathlib import Path
from time import perf_counter
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text, update

from patchledger.db.session import make_engine, make_session_factory
from patchledger.operational.models import (
    InstallationHistory,
    RemediationEvent,
    ScanRun,
)
from patchledger.simulation import execution
from patchledger.simulation.config import SimulationConfig
from patchledger.simulation.errors import (
    DataQualityError,
    ScenarioConflictError,
    SimulationError,
)
from patchledger.simulation.quality import check_quality
from patchledger.simulation.reporting import load_records
from patchledger.simulation.runner import main, run_simulation

pytestmark = pytest.mark.integration


def migrate(engine):
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


@pytest.fixture
def simulation_engine(postgres_engine):
    migrate(postgres_engine)
    return postgres_engine


def small_config(**changes):
    values = {
        "scenario": "integration",
        "assets": 12,
        "installations_per_asset": 3,
        "days": 14,
        "sla_days": 2,
        "scan_interval_days": 2,
        "remediation_probability": 0.9,
        "patch_success_probability": 0.55,
        "ineffective_patch_probability": 0.25,
        "recurrence_probability": 1,
        "inventory_churn_probability": 1,
        "retirement_probability": 0.15,
        "suspension_probability": 0.15,
        "initial_safe_probability": 0,
        "partial_scan_probability": 0.3,
        "failed_scan_probability": 0.2,
        "inconclusive_probability": 0.25,
    }
    return SimulationConfig.model_validate({**values, **changes})


def database_rows(engine, config):
    with make_session_factory(engine).begin() as session:
        return load_records(session, config)


def logical_rows(records):
    """Compare business outcomes across databases without random PKs/recording clocks."""
    assets = {a.id: a.asset_key for a in records["assets"]}
    installations = {
        i.id: (assets[i.asset_id], i.installation_key)
        for i in records["software_installations"]
    }
    histories = {
        p.id: (installations[p.installation_id], p.version, p.started_at)
        for p in records["installation_history"]
    }
    findings = {
        f.id: (assets[f.asset_id], installations.get(f.installation_id), f.cve_id)
        for f in records["vulnerability_findings"]
    }
    tasks = {t.id: t.task_key for t in records["remediation_tasks"]}
    scans = {s.id: s.external_run_key for s in records["scan_runs"]}
    openings = {e.id: e.event_number for e in records["finding_events"]}
    values = {
        "assets": [
            (
                a.asset_key,
                a.hostname,
                a.asset_type,
                a.environment,
                a.business_criticality,
                a.exposure,
                a.lifecycle_status,
            )
            for a in records["assets"]
        ],
        "history": [
            (
                installations[p.installation_id],
                p.version,
                p.started_at,
                p.ended_at,
                p.end_reason,
            )
            for p in records["installation_history"]
        ],
        "scans": [
            (s.external_run_key, s.status, s.started_at, s.completed_at)
            for s in records["scan_runs"]
        ],
        "observations": [
            (
                scans[o.scan_run_id],
                installations[o.installation_id],
                o.cve_id,
                o.outcome,
                o.occurred_at,
            )
            for o in records["scan_observations"]
        ],
        "findings": [
            (
                findings[f.id],
                f.status,
                f.first_detected_at,
                f.last_observed_at,
                f.current_opened_at,
                f.resolved_at,
                f.sla_deadline,
            )
            for f in records["vulnerability_findings"]
        ],
        "events": [
            (
                findings[e.finding_id],
                e.event_number,
                e.event_type,
                e.status_after,
                e.occurred_at,
                e.sla_deadline,
            )
            for e in records["finding_events"]
        ],
        "tasks": [
            (
                t.task_key,
                t.status,
                t.priority,
                t.due_at,
                t.started_at,
                t.work_completed_at,
                t.closed_at,
            )
            for t in records["remediation_tasks"]
        ],
        "links": [
            (
                tasks[t.task_id],
                findings[t.finding_id],
                openings[t.opening_event_id],
                t.added_at,
                t.withdrawn_at,
            )
            for t in records["task_findings"]
        ],
        "actions": [
            (
                tasks[e.task_id],
                e.event_number,
                e.event_type,
                e.status,
                e.action_kind,
                e.action_outcome,
                e.occurred_at,
                histories.get(e.before_history_id),
                histories.get(e.after_history_id),
            )
            for e in records["remediation_events"]
        ],
        "decisions": [
            (
                findings[v.finding_id],
                openings[v.opening_event_id],
                v.method,
                v.verdict,
                v.accepted,
                v.evidence_at,
                v.verified_at,
            )
            for v in records["verification_results"]
        ],
    }
    return {key: sorted(rows, key=repr) for key, rows in values.items()}


def test_small_end_to_end_and_identical_replay(simulation_engine):
    config = small_config()
    report = run_simulation(simulation_engine, config)
    rows = database_rows(simulation_engine, config)
    counts = report["counts"]
    assert report["data_quality"] == "passed"
    assert counts["assets"] == 12 and counts["software_installations"] == 36
    assert counts["software_products"] == 6 and counts["vulnerability_findings"] == 72
    assert counts["successful_actions"] > 0 and counts["failed_actions"] > 0
    assert (
        counts["verified_resolutions"] > 0 and counts["unsuccessful_verifications"] > 0
    )
    assert counts["finding_reopenings"] > 0 and counts["closed_tasks"] > 0
    assert (
        counts["removals"] > 0
        and counts["reinstallations"] > 0
        and counts["downgrades"] > 0
    )
    assert counts["unresolved_findings"] > 0 and counts["sla_breached_occurrences"] > 0
    assert {r.status for r in rows["scan_runs"]} >= {"completed", "partial", "failed"}
    assert {o.outcome for o in rows["scan_observations"]} >= {
        "affected",
        "not_affected",
        "inconclusive",
    }
    links_by_task = {
        t.id: sum(link.task_id == t.id for link in rows["task_findings"])
        for t in rows["remediation_tasks"]
    }
    assert max(links_by_task.values()) == 2
    before = {
        name: {
            r.id: (getattr(r, "recorded_at", None), getattr(r, "updated_at", None))
            for r in values
        }
        for name, values in rows.items()
    }
    assert run_simulation(simulation_engine, config) == report
    after = database_rows(simulation_engine, config)
    assert before == {
        name: {
            r.id: (getattr(r, "recorded_at", None), getattr(r, "updated_at", None))
            for r in values
        }
        for name, values in after.items()
    }
    print(json.dumps(report, sort_keys=True))


def test_same_config_on_two_fresh_databases_has_same_logical_results(simulation_engine):
    config = small_config(
        assets=3, days=7, retirement_probability=0, suspension_probability=0
    )
    first = run_simulation(simulation_engine, config)
    expected = logical_rows(database_rows(simulation_engine, config))
    name = f"patchledger_test_{uuid4().hex}"
    second = None
    created = False
    try:
        with simulation_engine.connect().execution_options(
            isolation_level="AUTOCOMMIT"
        ) as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
            created = True
        second = make_engine(simulation_engine.url.set(database=name))
        migrate(second)
        assert run_simulation(second, config) == first
        assert logical_rows(database_rows(second, config)) == expected
    finally:
        if second is not None:
            second.dispose()
        if created:
            with simulation_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as connection:
                connection.execute(text(f'DROP DATABASE "{name}"'))


@pytest.mark.parametrize(
    "changes",
    [{"seed": 43}, {"days": 2}, {"assets": 2}, {"installations_per_asset": 2}],
)
def test_conflicting_scenario_reuse_is_rejected_before_writes(
    simulation_engine, changes
):
    config = SimulationConfig(
        scenario="conflict",
        assets=1,
        installations_per_asset=1,
        days=1,
        remediation_probability=0,
    )
    first = run_simulation(simulation_engine, config)
    other = SimulationConfig.model_validate({**config.model_dump(), **changes})
    with pytest.raises(ScenarioConflictError, match="different configuration"):
        run_simulation(simulation_engine, other)
    assert run_simulation(simulation_engine, config) == first


def test_rollback_and_recovery_of_interrupted_patch(simulation_engine, monkeypatch):
    config = small_config(
        assets=3,
        days=7,
        remediation_probability=1,
        patch_success_probability=1,
        ineffective_patch_probability=0,
        recurrence_probability=0,
        sla_breach_probability=0,
        inventory_churn_probability=0,
        retirement_probability=0,
        suspension_probability=0,
    )
    original = execution.execute_event

    def fail_after_attempt(session, settings, plan, event):
        original(session, settings, plan, event)
        if event.kind == "attempt":
            raise RuntimeError("Injected failure after inventory/action flush")

    monkeypatch.setattr(execution, "execute_event", fail_after_attempt)
    with pytest.raises(SimulationError, match="rolled back"):
        run_simulation(simulation_engine, config)
    with make_session_factory(simulation_engine).begin() as session:
        assert (
            session.scalar(select(func.count()).select_from(InstallationHistory)) == 9
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(RemediationEvent)
                .where(RemediationEvent.event_type == "action_recorded")
            )
            == 0
        )
    monkeypatch.setattr(execution, "execute_event", original)
    report = run_simulation(simulation_engine, config)
    assert (
        report["counts"]["successful_actions"] == 3
        and report["counts"]["closed_tasks"] == 3
    )
    assert run_simulation(simulation_engine, config) == report


def test_namespace_isolation_and_negative_evidence_without_resolution(
    simulation_engine,
):
    configs = [
        SimulationConfig(
            scenario=name,
            assets=1,
            installations_per_asset=2,
            days=4,
            remediation_probability=0,
            inventory_churn_probability=1,
            retirement_probability=0,
            suspension_probability=0,
            initial_safe_probability=0,
            scan_interval_days=1,
            inconclusive_probability=0,
            partial_scan_probability=0,
            failed_scan_probability=0,
        )
        for name in ("case_", "caseX")
    ]
    for config in configs:
        report = run_simulation(simulation_engine, config)
        assert (
            report["counts"]["assets"] == 1
            and report["counts"]["unresolved_findings"] == 4
        )
        records = database_rows(simulation_engine, config)
        assert any(o.outcome == "target_absent" for o in records["scan_observations"])
        assert not any(e.event_type == "resolved" for e in records["finding_events"])
        assert all(a.asset_key.startswith(config.prefix) for a in records["assets"])


def test_quality_detects_missing_synthetic_provenance(simulation_engine):
    config = SimulationConfig(
        scenario="quality",
        assets=1,
        installations_per_asset=1,
        days=1,
        remediation_probability=0,
    )
    run_simulation(simulation_engine, config)
    with make_session_factory(simulation_engine).begin() as session:
        session.execute(update(ScanRun).values(is_synthetic=False))
        with pytest.raises(DataQualityError, match="synthetic"):
            check_quality(config, load_records(session, config))


def test_cli_executes_only_the_supplied_disposable_database(
    simulation_engine, monkeypatch, capsys
):
    monkeypatch.setenv(
        "DATABASE_URL", simulation_engine.url.render_as_string(hide_password=False)
    )
    assert (
        main(
            [
                "--scenario",
                "cli-fixture",
                "--assets",
                "1",
                "--installations-per-asset",
                "1",
                "--days",
                "1",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["assets"] == 1 and report["data_quality"] == "passed"


@pytest.mark.skipif(
    os.environ.get("PATCHLEDGER_MEDIUM_SIMULATION") != "1",
    reason="Opt-in medium benchmark; excluded from normal CI",
)
def test_medium_simulation(simulation_engine):
    config = SimulationConfig(
        scenario="medium-benchmark", assets=50, installations_per_asset=5, days=30
    )
    started = perf_counter()
    report = run_simulation(simulation_engine, config)
    assert (
        report["counts"]["assets"] == 50
        and report["counts"]["software_installations"] == 250
    )
    assert report["data_quality"] == "passed"
    print(
        json.dumps(
            {"elapsed_seconds": perf_counter() - started, **report}, sort_keys=True
        )
    )
