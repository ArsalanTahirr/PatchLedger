"""Independent seeded streams and operation identities, unaffected by replay progress."""

import hashlib
from random import Random
from uuid import NAMESPACE_URL, uuid5

from patchledger.simulation.config import GENERATOR_VERSION, SimulationConfig


def random_stream(config: SimulationConfig, key: str) -> Random:
    raw = f"{GENERATOR_VERSION}:{config.scenario}:{config.seed}:{key}".encode()
    return Random(int.from_bytes(hashlib.sha256(raw).digest(), "big"))


def operation_id(config: SimulationConfig, key: str):
    return uuid5(NAMESPACE_URL, f"patchledger:{config.source}:{key}")
