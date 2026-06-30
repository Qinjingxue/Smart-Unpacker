from __future__ import annotations

import pytest

from sunpack.config.fields.watch import normalize_watch_config
from sunpack.filesystem.watcher.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker
from tests.helpers.watch_write_simulator import WriteScenario, representative_write_scenarios, simulate_writes


def test_watch_quiet_config_keeps_initial_value_inside_dynamic_bounds():
    config = normalize_watch_config(
        {"quiet_seconds": 5, "quiet_min_seconds": 8, "quiet_max_seconds": 3}
    )

    assert config["quiet_min_seconds"] == 5
    assert config["quiet_seconds"] == 5
    assert config["quiet_max_seconds"] == 5


def test_policy_starts_at_existing_default_and_waits_for_evidence_before_shrinking():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())

    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(0.1, size=2, mtime=0.1)
    tracker.observe(0.2, size=3, mtime=0.2)

    assert tracker.quiet_seconds == 10.0
    tracker.observe(0.3, size=4, mtime=0.3)
    assert 2.5 < tracker.quiet_seconds < 10.0


def test_policy_extends_immediately_after_one_long_observed_interval():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)

    tracker.observe(20.0, size=2, mtime=20.0)

    assert tracker.quiet_seconds > 20.0


def test_same_metadata_event_does_not_distort_write_interval_history():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(0.1, size=2, mtime=0.1)

    tracker.observe(5.0, size=2, mtime=0.1)

    assert tracker.intervals == (0.1,)


@pytest.mark.parametrize(
    ("scenario_name", "maximum_latency"),
    (("very_fast", 4.0), ("fast", 6.0), ("moderate", 10.0)),
)
def test_fast_and_moderate_writes_complete_quickly(scenario_name: str, maximum_latency: float):
    scenarios = {item.name: item for item in representative_write_scenarios()}
    result = simulate_writes(scenarios[scenario_name], AdaptiveQuietPolicy())

    assert result.premature_attempts == 0
    assert result.completion_latency <= maximum_latency


@pytest.mark.parametrize("scenario", representative_write_scenarios())
def test_representative_writes_avoid_repeated_premature_attempts(scenario: WriteScenario):
    result = simulate_writes(scenario, AdaptiveQuietPolicy())

    assert result.premature_attempts <= (1 if scenario.name == "very_slow" else 0)
