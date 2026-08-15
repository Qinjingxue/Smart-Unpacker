"""Real-time progress and wall-clock phase timing for benchmark scenarios.

Progress lines are written to stderr so scenarios that publish JSON on stdout
(for example the format-matrix detection worker, whose stdout is parsed by the
parent process) keep their stdout contract intact.
"""
from __future__ import annotations

import sys
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Iterator, TextIO


class PhaseReporter:
    """Record wall time per named phase and emit timestamped progress lines.

    ``phase()`` is a context manager: every entry appends its duration to the
    phase's sample list, so a phase entered once per case accumulates the total
    spent across all cases (``totals()`` reports the sum).  ``note()`` emits a
    ``[HH:MM:SS]`` timestamped line to the configured stream (stderr by
    default) and flushes immediately so long-running scenarios stay observable.
    """

    def __init__(self, *, enabled: bool = True, stream: TextIO | None = None) -> None:
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr
        self._started = time.perf_counter()
        self._stack: list[tuple[str, float]] = []
        self._phases: dict[str, list[float]] = defaultdict(list)

    def note(self, message: str) -> None:
        if not self.enabled:
            return
        print(f"[{time.strftime('%H:%M:%S')}] {message}", file=self.stream, flush=True)

    @contextmanager
    def phase(self, name: str, message: str | None = None) -> Iterator[None]:
        """Time a named phase; ``message`` is emitted when the phase starts."""
        if not self.enabled:
            yield
            return
        if message:
            self.note(f"{name}: {message}")
        self._stack.append((name, time.perf_counter()))
        try:
            yield
        finally:
            name, started = self._stack.pop()
            seconds = time.perf_counter() - started
            self._phases[name].append(seconds)
            self.note(f"{name}: done in {seconds:.2f}s")

    def record(self, name: str, seconds: float) -> None:
        """Add an externally measured duration to a phase's sample list."""
        self._phases[name].append(float(seconds))

    @property
    def elapsed(self) -> float:
        return time.perf_counter() - self._started

    def totals(self) -> dict[str, float]:
        return {name: round(sum(values), 6) for name, values in sorted(self._phases.items())}

    def render_summary(self) -> str:
        """Render a fixed-width phase breakdown, slowest first."""
        totals = self.totals()
        if not totals:
            return "(no phases recorded)"
        total = sum(totals.values())
        width = max(len(name) for name in totals)
        lines = [f"{'phase':<{width}}  {'seconds':>9}  {'share':>7}", "-" * (width + 22)]
        for name, seconds in sorted(totals.items(), key=lambda item: item[1], reverse=True):
            share = f"{seconds / total * 100:5.1f}%" if total else "-"
            lines.append(f"{name:<{width}}  {seconds:9.2f}  {share:>7}")
        lines.append(f"{'total':<{width}}  {total:9.2f}  100.0%")
        return "\n".join(lines)
