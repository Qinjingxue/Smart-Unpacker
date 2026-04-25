from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.rules.scoring.extension import normalize_extension_score_groups
from tests.helpers.detection_config import with_detection_pipeline


def _config(extension_rule):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[extension_rule])


def test_extension_score_groups_are_configurable(tmp_path):
    target = tmp_path / "payload.foo"
    target.write_bytes(b"not important")
    rule = {
        "name": "extension",
        "enabled": True,
        "extension_score_groups": [
            {"score": 5, "extensions": [".foo"]},
            {"score": 2, "extensions": [".zip"]},
        ],
    }

    decision = DetectionScheduler(_config(rule)).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.total_score == 5
    assert decision.matched_rules == ["extension"]


def test_extension_score_groups_can_lower_archive_extension(tmp_path):
    target = tmp_path / "payload.zip"
    target.write_bytes(b"not important")
    rule = {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 2, "extensions": [".zip"]}]}

    decision = DetectionScheduler(_config(rule)).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.decision == "not_archive"
    assert decision.total_score == 2


def test_normalize_extension_score_groups_accepts_missing_dot_and_ignores_bad_values():
    scores = normalize_extension_score_groups([
        {"score": 5, "extensions": ["zip", ""]},
        {"score": "oops", "extensions": [".bad"]},
    ])

    assert scores == {".zip": 5}


def test_extension_rule_without_external_scores_does_not_match(tmp_path):
    target = tmp_path / "payload.zip"
    target.write_bytes(b"not important")
    rule = {"name": "extension", "enabled": True}

    decision = DetectionScheduler(_config(rule)).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.total_score == 0
