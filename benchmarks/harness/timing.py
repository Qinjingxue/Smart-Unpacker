from __future__ import annotations

import statistics
import time
from dataclasses import asdict, dataclass
from typing import Callable, Generic, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class Measurement(Generic[T]):
    iteration: int
    wall_ms: float
    cpu_ms: float
    value: T

    def to_dict(self, *, include_value: bool = False) -> dict:
        row = asdict(self)
        if not include_value:
            row.pop("value")
        return row


def measure(call: Callable[[], T], *, runs: int, warmups: int = 0) -> list[Measurement[T]]:
    """Measure a callable using the same wall/CPU clock policy for every scenario."""
    if runs < 1 or warmups < 0:
        raise ValueError("runs must be positive and warmups nonnegative")
    for _ in range(warmups):
        call()
    rows: list[Measurement[T]] = []
    for iteration in range(runs):
        wall_started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        value = call()
        rows.append(Measurement(
            iteration=iteration,
            wall_ms=(time.perf_counter_ns() - wall_started) / 1_000_000,
            cpu_ms=(time.process_time_ns() - cpu_started) / 1_000_000,
            value=value,
        ))
    return rows


def timing_summary(rows: list[Measurement[object]]) -> dict[str, float]:
    if not rows:
        return {}
    wall = [row.wall_ms for row in rows]
    cpu = [row.cpu_ms for row in rows]
    return {
        "median_wall_ms": statistics.median(wall),
        "min_wall_ms": min(wall),
        "max_wall_ms": max(wall),
        "median_cpu_ms": statistics.median(cpu),
    }
