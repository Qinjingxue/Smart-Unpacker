from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_tool():
    path = Path(__file__).resolve().parents[2] / "tools" / "watch_validation.py"
    spec = importlib.util.spec_from_file_location("sunpack_watch_validation_tool", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _report(module, *, elevated: bool, known: int, latency: float) -> dict:
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
    report = module.build_report("elevated" if elevated else "non_elevated", [result], "now", 1.0)
    report["process_elevated"] = elevated
    return report


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


def test_matrix_report_compares_privilege_coverage_and_latency():
    module = _load_tool()
    normal = _report(module, elevated=False, known=0, latency=8.0)
    admin = _report(module, elevated=True, known=2, latency=6.0)

    matrix = module.build_matrix_report(normal, admin, elevated_launched=True)

    assert matrix["summary"]["all_passed"] is True
    assert matrix["summary"]["non_elevated_journal_coverage"] == 0.0
    assert matrix["summary"]["elevated_journal_coverage"] == 1.0
    assert matrix["summary"]["median_latency_delta_seconds"] == -2.0
    assert "slow_append" in module.matrix_report_markdown(matrix)
