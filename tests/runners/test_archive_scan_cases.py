from pathlib import Path

import pytest

from sunpack.detection import DetectionScheduler
from tests.helpers.archive_scan_case_loader import (
    archive_scan_case_id,
    load_archive_scan_cases,
    materialize_archive_scan_case,
)
from tests.helpers.config_factory import get_config


CASES_DIR = Path(__file__).resolve().parents[1] / "cases" / "archive_scan"
CASES = load_archive_scan_cases(CASES_DIR)


@pytest.mark.parametrize("case", CASES, ids=archive_scan_case_id)
def test_archive_scan_case(case, case_workspace):
    workspace = materialize_archive_scan_case(case, case_workspace)
    config_name = case.manifest.get("config", "archive_scan_full")
    config_overrides = case.manifest.get("config_overrides")
    config = get_config(config_name, config_overrides)

    detector = DetectionScheduler(config)
    from sunpack.coordinator.target_scan import build_fact_bags_for_targets
    results = detector.evaluate_bags(build_fact_bags_for_targets([str(workspace)]))
    by_relative_path = {
        Path(result.fact_bag.get("file.path")).relative_to(workspace).as_posix(): result
        for result in results
    }

    for expected in case.manifest.get("expect", []):
        rel_path = expected["path"]
        assert rel_path in by_relative_path, f"Expected file was not scanned: {rel_path}"
        decision = by_relative_path[rel_path].decision
        assert decision.should_extract is bool(expected["should_extract"]), (
            f"{rel_path}: expected should_extract={expected['should_extract']}, "
            f"got {decision.should_extract}; decision={decision.decision}, "
            f"score={decision.total_score}, rules={decision.matched_rules}"
        )
        if "decision" in expected:
            assert decision.decision == expected["decision"]
        if "min_score" in expected:
            assert decision.total_score >= int(expected["min_score"])
        if "max_score" in expected:
            assert decision.total_score <= int(expected["max_score"])
        for rule in expected.get("matched_rules_include", []):
            assert rule in decision.matched_rules
        fact_bag = by_relative_path[rel_path].fact_bag
        for fact_name, expected_value in expected.get("facts", {}).items():
            actual_value = fact_bag.get(fact_name)
            assert_fact_matches(rel_path, fact_name, actual_value, expected_value)


def assert_fact_matches(rel_path, fact_name, actual_value, expected_value):
    if isinstance(expected_value, dict):
        assert isinstance(actual_value, dict), (
            f"{rel_path}: expected fact {fact_name} to be a dict containing "
            f"{expected_value!r}, got {actual_value!r}"
        )
        for key, nested_expected in expected_value.items():
            nested_actual = actual_value.get(key)
            assert_fact_matches(rel_path, f"{fact_name}.{key}", nested_actual, nested_expected)
        return
    assert actual_value == expected_value, (
        f"{rel_path}: expected fact {fact_name}={expected_value!r}, "
        f"got {actual_value!r}"
    )
