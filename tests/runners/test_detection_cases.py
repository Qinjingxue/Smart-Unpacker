from pathlib import Path

import pytest

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from tests.helpers.assertions import MISSING, assert_case_expectations, get_path
from tests.helpers.case_loader import case_id, load_json_cases
from tests.helpers.config_factory import get_config
from tests.helpers.fs_builder import build_files


CASES_DIR = Path(__file__).resolve().parents[1] / "cases" / "detection"
CASES = load_json_cases(CASES_DIR)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_detection_case(case, case_workspace):
    workspace = build_files(case_workspace, case.get("arrange"))
    result = run_detection_case(case, workspace)

    assert_case_expectations(result, case.get("assert", {}))
    for path in case.get("has", []):
        assert get_path(result, path) is not MISSING, f"Missing expected path: {path}"
    for path, needles in case.get("contains", {}).items():
        value = get_path(result, path)
        assert value is not MISSING, f"Missing contains path: {path}"
        for needle in needles:
            assert needle in value


def run_detection_case(case, workspace: Path) -> dict:
    act = case["act"]
    if act["type"] != "rule_evaluate":
        raise ValueError(f"Unsupported detection act type: {act['type']}")

    target = workspace / act["target"]
    config = get_config(act.get("config", "minimal"), act.get("config_overrides"))
    bag = FactBag()
    bag.set("file.path", str(target))
    for fact_name, value in act.get("facts", {}).items():
        bag.set(fact_name, value)

    decision = DetectionScheduler(config).evaluate_bag(bag)
    return {
        "decision": {
            "should_extract": decision.should_extract,
            "total_score": decision.total_score,
            "matched_rules": decision.matched_rules,
            "stop_reason": decision.stop_reason,
            "decision": decision.decision,
        },
        "facts": bag.to_dict(),
        "errors": bag.get_errors(),
    }
