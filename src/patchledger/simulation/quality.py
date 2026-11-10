"""Read-only checks on all 15 scenario-scoped operational tables."""

from collections import defaultdict
from itertools import pairwise

from sqlalchemy import PrimaryKeyConstraint, UniqueConstraint

from patchledger.db.migrations import get_target_metadata
from patchledger.operational.services.assets import SNAPSHOT_FIELDS
from patchledger.operational.services.remediation import SNAPSHOT, TRANSITIONS
from patchledger.simulation.errors import DataQualityError
from patchledger.simulation.fixtures import CATALOG


def require(condition, message):
    if not condition:
        raise DataQualityError(message)


def _keys_and_provenance(config, records):
    metadata = get_target_metadata()
    indexes = {}
    for table in metadata.sorted_tables:
        rows = records[table.name]
        for constraint in table.constraints:
            if isinstance(constraint, (PrimaryKeyConstraint, UniqueConstraint)):
                keys = [
                    tuple(getattr(row, c.name) for c in constraint.columns)
                    for row in rows
                ]
                nulls_equal = isinstance(
                    constraint, PrimaryKeyConstraint
                ) or constraint.dialect_options["postgresql"].get(
                    "nulls_not_distinct", False
                )
                if not nulls_equal:
                    keys = [key for key in keys if None not in key]
                require(
                    len(keys) == len(set(keys)), f"Duplicate identity in {table.name}"
                )
        for constraint in table.foreign_key_constraints:
            elements = list(constraint.elements)
            parent = elements[0].column.table.name
            remote = tuple(e.column.name for e in elements)
            identity = (parent, remote)
            if identity not in indexes:
                indexes[identity] = {
                    tuple(getattr(row, key) for key in remote)
                    for row in records[parent]
                }
            for row in rows:
                local = tuple(getattr(row, e.parent.name) for e in elements)
                require(
                    None in local or local in indexes[identity],
                    f"Orphan or cross-scenario reference in {table.name}",
                )
        for row in rows:
            if hasattr(row, "is_synthetic"):
                require(
                    row.is_synthetic is True,
                    f"Missing synthetic provenance in {table.name}",
                )
                require(
                    row.source_key == config.source,
                    f"Unexpected source provenance in {table.name}",
                )
            if table.name == "installation_history" and row.ended_at is not None:
                require(
                    row.end_is_synthetic is True
                    and row.end_source_key == config.source,
                    "Missing inventory end provenance",
                )
            for column in table.columns:
                if column.name in {
                    "occurred_at",
                    "registered_at",
                    "started_at",
                    "ended_at",
                    "completed_at",
                    "evidence_at",
                    "verified_at",
                    "added_at",
                    "withdrawn_at",
                    "work_completed_at",
                    "closed_at",
                }:
                    value = getattr(row, column.name)
                    if value is not None:
                        require(
                            value.tzinfo is not None
                            and config.start <= value < config.end,
                            f"Invalid simulated timestamp in {table.name}.{column.name}",
                        )


def _inventory_and_observations(records):
    periods = defaultdict(list)
    for row in records["installation_history"]:
        periods[row.installation_id].append(row)
        require(
            row.ended_at is None or row.ended_at > row.started_at,
            "Nonpositive installation interval",
        )
    for rows in periods.values():
        ordered = sorted(rows, key=lambda p: p.started_at)
        for before, after in pairwise(ordered):
            require(
                before.ended_at is not None and before.ended_at <= after.started_at,
                "Overlapping installation history",
            )
    scans = {row.id: row for row in records["scan_runs"]}
    histories = {row.id: row for row in records["installation_history"]}
    installations = {row.id: row for row in records["software_installations"]}
    products = {row.id: row for row in records["software_products"]}
    fixtures = {row.key: row for row in CATALOG}
    for row in records["scan_observations"]:
        scan = scans[row.scan_run_id]
        require(
            scan.asset_id == row.asset_id
            and scan.started_at <= row.occurred_at <= scan.completed_at,
            "Observation outside scan scope/time",
        )
        installation = installations[row.installation_id]
        require(installation.asset_id == row.asset_id, "Cross-asset observation")
        fixture = fixtures[
            products[installation.product_id].product_key.rsplit(":", 1)[1]
        ]
        require(
            row.cve_id in fixture.cves,
            "Observation uses a CVE outside its controlled fixture",
        )
        if row.outcome == "target_absent":
            require(
                not any(
                    p.started_at <= row.occurred_at
                    and (p.ended_at is None or row.occurred_at < p.ended_at)
                    for p in periods[row.installation_id]
                ),
                "Absent target is still installed",
            )
        elif row.installation_history_id is not None:
            period = histories[row.installation_history_id]
            require(
                period.installation_id == row.installation_id
                and period.started_at <= row.occurred_at
                and (period.ended_at is None or row.occurred_at < period.ended_at),
                "Observation references an invalid historical period",
            )
            if row.outcome != "inconclusive":
                require(
                    fixture.outcome(row.cve_id, period.version) == row.outcome,
                    "Observation contradicts fixture applicability",
                )
        else:
            require(
                row.outcome == "inconclusive",
                "Conclusive software evidence lacks a version",
            )
    return scans


def _finding_history(records):
    timelines = defaultdict(list)
    positives_by_finding = defaultdict(list)
    for observation in records["scan_observations"]:
        if observation.outcome == "affected":
            positives_by_finding[observation.finding_id].append(observation.occurred_at)
    for event in records["finding_events"]:
        timelines[event.finding_id].append(event)
    for finding in records["vulnerability_findings"]:
        status, opening, last_time = None, None, None
        for number, event in enumerate(
            sorted(timelines[finding.id], key=lambda r: r.event_number), start=1
        ):
            require(event.event_number == number, "Noncontiguous finding events")
            require(
                last_time is None or event.occurred_at >= last_time,
                "Backdated finding lifecycle",
            )
            if event.event_type == "opened":
                require(
                    status is None
                    and number == 1
                    and event.occurred_at == finding.first_detected_at,
                    "Invalid first opening",
                )
                status, opening = "open", event
            elif event.event_type == "reopened":
                require(status == "resolved", "Reopening without resolution")
                status, opening = "open", event
            elif event.event_type == "resolved":
                require(status == "open", "Resolution without an open occurrence")
                status = "resolved"
            else:
                require(event.event_type == "sla_changed", "Unknown finding transition")
            require(event.status_after == status, "Finding event status mismatch")
            last_time = event.occurred_at
        require(
            opening is not None
            and opening.occurred_at == finding.current_opened_at
            and status == finding.status,
            "Finding state/history mismatch",
        )
        positives = positives_by_finding[finding.id]
        require(
            positives and max(positives) == finding.last_observed_at,
            "Last positive observation mismatch",
        )
    return timelines


def _verification_and_closure(records, scans, timelines):
    observations = {o.id: o for o in records["scan_observations"]}
    resolutions = {
        (e.finding_id, e.operation_id): e
        for e in records["finding_events"]
        if e.event_type == "resolved"
    }
    decisions = defaultdict(list)
    for result in records["verification_results"]:
        require(
            result.method == "scan" and result.observation_id in observations,
            "Simulator verification lacks scan evidence",
        )
        obs = observations[result.observation_id]
        require(
            scans[obs.scan_run_id].status == "completed"
            and obs.finding_id == result.finding_id,
            "Verification has incomplete/wrong evidence",
        )
        require(
            result.evidence_at == obs.occurred_at
            and result.verified_at >= result.evidence_at,
            "Invalid verification timestamps",
        )
        if result.accepted and result.verdict == "absence_confirmed":
            require(
                obs.outcome in {"not_affected", "target_absent"},
                "Resolution without explicit absence",
            )
            event = resolutions.get((result.finding_id, result.operation_id))
            require(
                event is not None and event.occurred_at == result.evidence_at,
                "Unpaired resolution decision",
            )
        decisions[(result.finding_id, result.opening_event_id)].append(result)
    verified_keys = {
        (r.finding_id, r.operation_id)
        for r in records["verification_results"]
        if r.accepted and r.verdict == "absence_confirmed"
    }
    require(
        set(resolutions) == verified_keys,
        "Resolution event has no accepted verification",
    )
    links = {row.id: row for row in records["task_findings"]}
    opening_ids = {
        e.id
        for e in records["finding_events"]
        if e.event_type in {"opened", "reopened"}
    }
    require(
        all(link.opening_event_id in opening_ids for link in links.values()),
        "Task target does not reference an opening event",
    )
    task_events = defaultdict(list)
    for event in records["remediation_events"]:
        task_events[event.task_id].append(event)
    for task in records["remediation_tasks"]:
        active, last = set(), None
        for number, event in enumerate(
            sorted(task_events[task.id], key=lambda r: r.event_number), start=1
        ):
            require(
                event.event_number == number
                and (last is None or event.occurred_at >= last.occurred_at),
                "Invalid task event chronology",
            )
            if last is None:
                require(
                    event.event_type == "created" and event.status == "open",
                    "Task lacks an initial creation event",
                )
            elif event.status != last.status:
                require(
                    event.status in TRANSITIONS[last.status],
                    "Unsupported task transition",
                )
            if event.event_type == "target_added":
                active.add(event.task_finding_id)
            elif event.event_type == "target_withdrawn":
                active.discard(event.task_finding_id)
            if event.status == "closed":
                require(active, "Closed task has no historical active scope")
                for identity in active:
                    link = links[identity]
                    eligible = [
                        v
                        for v in decisions[(link.finding_id, link.opening_event_id)]
                        if v.verified_at <= event.occurred_at
                    ]
                    require(eligible, "Task closed before verification")
                    decision = max(
                        eligible, key=lambda v: (v.verified_at, v.recorded_at)
                    )
                    openings = [
                        e
                        for e in timelines[link.finding_id]
                        if e.event_type in {"opened", "reopened"}
                        and e.occurred_at <= event.occurred_at
                    ]
                    require(
                        openings
                        and max(openings, key=lambda e: e.event_number).id
                        == link.opening_event_id,
                        "Task closed against an obsolete occurrence",
                    )
                    require(
                        decision.accepted
                        and (
                            decision.verdict == "absence_confirmed"
                            or task.goal == "mitigate"
                            and decision.valid_until > event.occurred_at
                        ),
                        "Task closed without qualifying proof",
                    )
            last = event
        require(
            last is not None
            and all(getattr(task, key) == getattr(last, key) for key in SNAPSHOT),
            "Task current state/history mismatch",
        )


def check_quality(config, records):
    require(
        len(records["assets"]) == config.assets,
        "Asset count differs from scenario configuration",
    )
    require(
        len(records["software_installations"])
        == config.assets * config.installations_per_asset,
        "Installation count mismatch",
    )
    _keys_and_provenance(config, records)
    asset_events = defaultdict(list)
    for event in records["asset_events"]:
        asset_events[event.asset_id].append(event)
    for asset in records["assets"]:
        history = sorted(asset_events[asset.id], key=lambda event: event.event_number)
        require(
            history and history[0].event_type == "registered",
            "Missing asset registration history",
        )
        require(
            [e.event_number for e in history] == list(range(1, len(history) + 1)),
            "Noncontiguous asset events",
        )
        require(
            all(
                getattr(asset, key) == getattr(history[-1], key)
                for key in SNAPSHOT_FIELDS
            ),
            "Asset state/history mismatch",
        )
    scans = _inventory_and_observations(records)
    timelines = _finding_history(records)
    _verification_and_closure(records, scans, timelines)
    return "passed"
