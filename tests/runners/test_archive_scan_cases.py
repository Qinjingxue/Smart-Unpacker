from pathlib import Path

import pytest

from smart_unpacker.detection import DetectionScheduler
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
    results = detector.evaluate_bags(detector.build_candidate_fact_bags([str(workspace)]))
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
