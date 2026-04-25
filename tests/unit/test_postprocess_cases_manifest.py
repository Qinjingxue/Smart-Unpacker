from pathlib import Path

from tests.helpers.case_loader import load_json_cases


def test_postprocess_script_cases_are_data_driven():
    cases = load_json_cases(Path(__file__).resolve().parents[1] / "cases" / "postprocess")

    assert {case["act"]["type"] for case in cases} == {"cleanup", "flatten", "failed_log"}
