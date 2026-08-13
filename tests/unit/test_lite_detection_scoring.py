import os
from pathlib import Path
import subprocess
import sys
import textwrap


ROOT = Path(__file__).resolve().parents[2]


def _run_lite_python(source: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["SUNPACK_REPAIR_SYSTEM"] = "lite"
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(source)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _assert_success(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stderr or result.stdout


def test_lite_does_not_import_scoring_rule_modules():
    result = _run_lite_python(
        """
        import sys

        from sunpack.detection.pipeline.rules.registry import discover_rules, get_rule_registry

        discover_rules()
        assert not any(
            name.startswith("sunpack.detection.pipeline.rules.scoring")
            for name in sys.modules
        )
        assert get_rule_registry().get_all_rules("scoring") == {}
        """
    )
    _assert_success(result)


def test_lite_keeps_precheck_detection_but_skips_scoring_execution():
    result = _run_lite_python(
        """
        from sunpack.contracts.detection import FactBag
        from sunpack.detection.scheduler import DetectionScheduler

        config = {
            "thresholds": {
                "archive_score_threshold": 6,
                "maybe_archive_threshold": 3,
            },
            "detection": {
                "fact_collectors": [],
                "processors": [],
                "rule_pipeline": {
                    "precheck": [{"name": "zip_structure_accept", "enabled": True}],
                    "scoring": [{"name": "zip_structure_identity", "enabled": True}],
                },
            },
        }

        def evaluate(structure, name):
            bag = FactBag()
            bag.set("file.path", name)
            bag.set("candidate.entry_path", name)
            bag.set("candidate.logical_name", name)
            bag.set("zip.eocd_structure", structure)
            return DetectionScheduler(config).evaluate_bag(bag)

        valid = evaluate(
            {
                "plausible": True,
                "archive_offset": 0,
                "central_directory_present": True,
                "central_directory_walk_ok": True,
                "local_header_links_ok": True,
                "total_entries": 1,
                "central_directory_size": 56,
            },
            "valid.zip",
        )
        damaged = evaluate({}, "damaged.zip")

        assert valid.should_extract is True
        assert valid.decision_stage == "precheck"
        assert damaged.should_extract is False
        assert damaged.total_score == 0
        """
    )
    _assert_success(result)
