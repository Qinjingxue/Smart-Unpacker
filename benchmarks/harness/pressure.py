from __future__ import annotations

import time
from dataclasses import asdict, dataclass

import psutil


@dataclass(frozen=True)
class PressureWait:
    waited_seconds: float
    samples: int
    last_cpu_percent: float
    last_available_memory_percent: float
    reason: str

    def to_dict(self) -> dict[str, float | int | str]:
        return asdict(self)


class AdaptivePressureGate:
    """Delay a benchmark launch only while host CPU or memory pressure is high."""

    def __init__(
        self,
        *,
        max_cpu_percent: float = 85.0,
        min_available_memory_percent: float = 15.0,
        sample_seconds: float = 0.1,
        max_wait_seconds: float = 30.0,
    ) -> None:
        self.max_cpu_percent = max(1.0, min(100.0, float(max_cpu_percent)))
        self.min_available_memory_percent = max(0.0, min(100.0, float(min_available_memory_percent)))
        self.sample_seconds = max(0.01, float(sample_seconds))
        self.max_wait_seconds = max(0.0, float(max_wait_seconds))
        self.waits: list[PressureWait] = []

    def wait(self) -> PressureWait:
        started = time.perf_counter()
        samples = 0
        cpu = 0.0
        available = 100.0
        reason = "ready"
        while True:
            cpu = float(psutil.cpu_percent(interval=self.sample_seconds))
            available = float(psutil.virtual_memory().available / max(1, psutil.virtual_memory().total) * 100.0)
            samples += 1
            overloaded = cpu > self.max_cpu_percent or available < self.min_available_memory_percent
            elapsed = time.perf_counter() - started
            if not overloaded:
                reason = "ready"
                break
            if elapsed >= self.max_wait_seconds:
                reason = "max_wait_reached"
                break
        result = PressureWait(round(time.perf_counter() - started, 6), samples, cpu, available, reason)
        self.waits.append(result)
        return result

    def summary(self) -> dict[str, object]:
        return {
            "launches": len(self.waits),
            "total_wait_seconds": round(sum(item.waited_seconds for item in self.waits), 6),
            "max_wait_seconds": max((item.waited_seconds for item in self.waits), default=0.0),
            "max_cpu_percent": self.max_cpu_percent,
            "min_available_memory_percent": self.min_available_memory_percent,
            "max_wait_reached": sum(item.reason == "max_wait_reached" for item in self.waits),
        }
