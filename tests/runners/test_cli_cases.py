from pathlib import Path

import pytest

from tests.helpers.assertions import MISSING, assert_case_expectations, get_path
from tests.helpers.case_loader import case_id, load_json_cases
from tests.helpers.cli_runner import run_cli
from tests.helpers.generated_fixtures import build_cli_pipeline_fixture


CASES_DIR = Path(__file__).resolve().parents[1] / "cases" / "cli"
CASES = load_json_cases(CASES_DIR)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_cli_case(case, repo_root, tmp_path):
    act = case["act"]
    assert act["type"] == "cli"
    args = [
        str(build_cli_pipeline_fixture(tmp_path)) if arg == "{cli_pipeline_fixture}" else arg
        for arg in act["args"]
    ]

    result = run_cli(repo_root, args, timeout=act.get("timeout", 20))

    assert_case_expectations(result, case.get("assert", {}))
    for path in case.get("has", []):
        assert get_path(result, path) is not MISSING, f"Missing expected path: {path}"
    for path, needles in case.get("contains", {}).items():
        value = get_path(result, path)
        assert value is not MISSING, f"Missing contains path: {path}"
        for needle in needles:
            assert needle in value
