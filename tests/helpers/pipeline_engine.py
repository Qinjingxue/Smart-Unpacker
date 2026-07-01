from __future__ import annotations

from collections.abc import Iterable

from sunpack.coordinator.engine import PipelineEngine


def execute_pipeline(config: dict, targets: str | Iterable[str], *, direct: bool = False):
    paths = [targets] if isinstance(targets, str) else list(targets)
    with PipelineEngine(config) as engine:
        return engine.submit(paths, direct=direct).result().summary

