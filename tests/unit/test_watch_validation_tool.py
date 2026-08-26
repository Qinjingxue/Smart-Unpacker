from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import pytest


def _load_tool():
    path = Path(__file__).resolve().parents[2] / "tests" / "integration" / "watch_validation.py"
    spec = importlib.util.spec_from_file_location("sunpack_watch_validation_tool", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _report(module, *, known: int, latency: float) -> dict:
    result = module.ScenarioResult(
        name="slow_append",
        description="test",
        passed=True,
        final_ready=True,
        final_zip_valid=True,
        journal_delta_queries=2,
        journal_known_deltas=known,
        stable_latency_seconds=latency,
    )
    return module.build_report("broker", [result], "now", 1.0)


def test_scenario_matrix_has_unique_names_and_covers_download_patterns():
    module = _load_tool()

    names = [scenario.name for scenario in module.scenario_matrix()]

    assert len(names) == len(set(names))
    assert {
        "atomic_move",
        "slow_append",
        "parallel_ranges",
        "browser_temp_rename",
        "aria2_sidecar",
        "long_network_pause",
        "same_size_mtime",
        "writer_lock",
        "event_storm",
    } <= set(names)


def test_baseline_report_enforces_journal_coverage_and_latency():
    module = _load_tool()
    current = _report(module, known=2, latency=6.2)
    baseline = _report(module, known=2, latency=6.0)

    comparison = module.build_baseline_comparison(
        current,
        baseline,
        maximum_regression_seconds=0.25,
        maximum_regression_ratio=0.01,
    )

    assert comparison["passed"] is True
    assert comparison["journal_coverage_complete"] is True
    assert comparison["no_premature_processing"] is True
    assert comparison["premature_attempts_not_regressed"] is True
    assert comparison["scenarios"][0]["delta_seconds"] == pytest.approx(0.2)


def test_baseline_comparison_allows_existing_probe_attempts_but_rejects_regressions():
    module = _load_tool()
    current = _report(module, known=2, latency=1.01)
    baseline = _report(module, known=2, latency=1.0)
    current["summary"]["premature_attempts"] = 1
    baseline["summary"]["premature_attempts"] = 1

    comparison = module.build_baseline_comparison(
        current,
        baseline,
        maximum_regression_seconds=0.25,
        maximum_regression_ratio=0.01,
    )

    assert comparison["passed"] is True
    assert comparison["no_premature_processing"] is False
    assert comparison["premature_attempts_not_regressed"] is True

    current["summary"]["premature_attempts"] = 2
    regression = module.build_baseline_comparison(
        current,
        baseline,
        maximum_regression_seconds=0.25,
        maximum_regression_ratio=0.01,
    )
    assert regression["passed"] is False
    assert regression["premature_attempts_not_regressed"] is False


def test_detection_scheduler_lifecycle_uses_blocking_targets_without_leaking_coroutines():
    module = _load_tool()

    class Scheduler:
        def __init__(self):
            self.started = 0
            self.stopped = 0

        def _start_blocking(self):
            self.started += 1

        def _stop_blocking(self):
            self.stopped += 1

        async def start(self):
            raise AssertionError("the synchronous benchmark must not create an unawaited coroutine")

        async def stop(self):
            raise AssertionError("the synchronous benchmark must not create an unawaited coroutine")

    scheduler = Scheduler()
    module._start_detection_scheduler(scheduler)
    module._stop_detection_scheduler(scheduler)

    assert scheduler.started == 1
    assert scheduler.stopped == 1
