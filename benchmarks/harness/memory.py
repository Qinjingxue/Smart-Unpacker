from __future__ import annotations

import os
import threading
import time
from dataclasses import asdict, dataclass

import psutil


def bytes_to_mib(value: int | float) -> float:
    return float(value) / 1024**2


@dataclass(frozen=True)
class ProcessSample:
    elapsed_ms: float
    rss_mib: float
    children_rss_mib: float
    child_count: int
    private_mib: float = 0.0
    threads: int = 0
    handles: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class ProcessSampler:
    """Sample the current process tree without embedding scenario-specific policy."""

    def __init__(self, interval_seconds: float = 0.1):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.interval_seconds = interval_seconds
        self.samples: list[ProcessSample] = []
        self._process = psutil.Process(os.getpid())
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = 0.0

    def take(self) -> ProcessSample:
        children = [child for child in self._process.children(recursive=True) if child.is_running()]
        children_rss = 0
        for child in children:
            try:
                children_rss += child.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        try:
            info = self._process.memory_info()
            rss = info.rss
            private = int(getattr(info, "private", 0) or 0)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            rss = 0
            private = 0
        try:
            threads = self._process.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            threads = 0
        try:
            handles = self._process.num_handles()
        except (AttributeError, psutil.NoSuchProcess, psutil.AccessDenied):
            handles = 0
        sample = ProcessSample(
            elapsed_ms=(time.perf_counter() - self._started) * 1000 if self._started else 0.0,
            rss_mib=bytes_to_mib(rss),
            children_rss_mib=bytes_to_mib(children_rss),
            child_count=len(children),
            private_mib=bytes_to_mib(private),
            threads=int(threads),
            handles=int(handles),
        )
        self.samples.append(sample)
        return sample

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("sampler is already running")
        self._started = time.perf_counter()
        self._stop.clear()
        self.take()
        self._thread = threading.Thread(target=self._run, name="benchmark-process-sampler", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.take()

    def stop(self) -> list[ProcessSample]:
        if self._thread is None:
            return self.samples
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_seconds * 2))
        self._thread = None
        self.take()
        return self.samples

    def __enter__(self) -> "ProcessSampler":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()
