"""Dispatch scheduled atomic workflows; no direct ORM mutations."""

from datetime import timedelta

from patchledger.simulation.inventory import mutate_inventory, update_lifecycle
from patchledger.simulation.remediation import attempt_work, create_work, verify_work
from patchledger.simulation.scenarios import scan_asset


def execute_event(session, config, plan, event):
    if event.kind == "scan":
        scan_asset(
            session,
            config,
            plan,
            event.at,
            event.key,
            definitive=event.at == config.start + timedelta(hours=9)
            or event.detail == "recurrence",
        )
    elif event.kind in {"task", "recurrence_task"}:
        create_work(session, config, plan, event)
    elif event.kind == "attempt":
        attempt_work(session, config, plan, event)
    elif event.kind == "verify":
        verify_work(session, config, plan, event)
    elif event.kind == "remove":
        mutate_inventory(session, config, plan, event, "remove")
    elif event.kind == "reinstall":
        mutate_inventory(session, config, plan, event, "reinstall")
    elif event.kind == "regression":
        mutate_inventory(session, config, plan, event, "downgrade", "1.0-fixture")
    elif event.kind in {"attributes", "retired", "suspended"}:
        update_lifecycle(session, config, plan, event)
    else:
        raise ValueError(f"Unknown scheduled event kind: {event.kind}")
