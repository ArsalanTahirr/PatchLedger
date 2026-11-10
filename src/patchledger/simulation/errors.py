"""Simulator failures are surfaced; expected failed patches are operational events."""


class SimulationError(Exception):
    """Scenario execution or persisted data failed validation."""


class ScenarioConflictError(SimulationError):
    """Scenario configuration, ownership or an existing receipt conflicts."""


class DataQualityError(SimulationError):
    """Persisted operational data failed a scenario invariant."""
