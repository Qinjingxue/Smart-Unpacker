import pytest

from sunpack.contracts.detection import FactBag
from sunpack.detection import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.edition import is_lite_edition


@pytest.mark.parametrize(
    "rule_names",
    [
        ["zip_structure_identity", "seven_zip_structure_identity"],
        ["seven_zip_structure_identity", "zip_structure_identity"],
    ],
)
def test_alternative_format_hypotheses_use_best_score_instead_of_sum(rule_names):
    if is_lite_edition():
        pytest.skip("scoring rules are disabled in Lite edition")

    config = with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3}},
        precheck=[],
        scoring=[{"name": name, "enabled": True} for name in rule_names],
    )
    bag = FactBag()
    bag.set("file.path", "opaque.bin")
    bag.set("candidate.entry_path", "opaque.bin")
    bag.set("candidate.logical_name", "opaque.bin")
    bag.set("zip.local_header", {"magic_matched": True, "plausible": False})
    bag.set("zip.eocd_structure", {})
    bag.set("7z.structure", {
        "magic_matched": True,
        "version_major": 0,
        "next_header_offset": 32,
        "next_header_size": 64,
        "start_header_crc_ok": False,
        "next_header_crc_ok": False,
        "next_header_nid_valid": False,
    })

    decision = DetectionScheduler(config).evaluate_bag(bag)

    assert decision.should_extract is False
    assert decision.total_score == 5
    assert decision.matched_rules == ["seven_zip_structure_identity"]
    assert bag.get("file.detected_ext") == ".7z"
