from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.detection import DetectionScheduler
from sunpack.detection.pipeline.rules.scoring.zip_structure_identity import ZipStructureIdentityScoreRule
from tests.helpers.scene_rules import RECOMMENDED_SCENE_RULES_PAYLOAD
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def _rule_pipeline_config():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "blacklist", "enabled": True, "blocked_files": []},
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {
            "name": "scene_protect",
            "enabled": True,
            "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
        },
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "zip_structure_identity", "enabled": True},
        {
            "name": "scene_penalty",
            "enabled": True,
            "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
        },
    ])


@pytest.mark.parametrize(
    ("relative_path", "content", "expected_extract"),
    [
        ("archive.zip", make_zip({"inside.txt": "hello"}), True),
        ("notes.txt", b"plain text", False),
        ("game/www/audio/bgm.7z", b"7z\xbc\xaf\x27\x1c", True),
    ],
    ids=["zip archive", "plain text", "runtime archive"],
)
def test_rule_pipeline_evaluates_generated_files(tmp_path, relative_path, content, expected_extract):
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    if "game/" in relative_path:
        (tmp_path / "game" / "game.exe").write_bytes(b"MZ")
        (tmp_path / "game" / "www" / "data").mkdir(parents=True, exist_ok=True)
        (tmp_path / "game" / "www" / "data" / "Map001.json").write_text("{}", encoding="utf-8")

    bag = FactBag()
    bag.set("file.path", str(target))
    decision = DetectionScheduler(_rule_pipeline_config()).evaluate_bag(bag)

    assert decision.should_extract is expected_extract
    if target.name == "bgm.7z":
        assert bag.get("scene.is_runtime_resource_archive") is None


def test_scoring_stops_after_archive_threshold_when_remaining_rules_cannot_reduce_score(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(make_zip({"inside.txt": "hello"}))

    def fail_if_called(self, facts, config):
        raise AssertionError("zip_structure_identity should be skipped after score is fixed")

    monkeypatch.setattr(ZipStructureIdentityScoreRule, "evaluate", fail_if_called)
    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
        {"name": "zip_structure_identity", "enabled": True},
    ])

    bag = FactBag()
    bag.set("file.path", str(target))
    decision = DetectionScheduler(config).evaluate_bag(bag)

    assert decision.should_extract is True
    assert decision.total_score == 5
    assert decision.matched_rules == ["extension"]

