from pathlib import Path

from smart_unpacker.detection.nested_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from smart_unpacker.coordinator.scanner import ScanOrchestrator
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD
from tests.helpers.detection_config import with_detection_pipeline


def scan_config(patterns=None, blocked_extensions=None):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {
            "name": "blacklist",
            "enabled": True,
            "patterns": patterns or [],
            "blocked_extensions": blocked_extensions or [],
        },
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True},
    ])


def decisions_for(root: Path, config: dict):
    detector = DetectionScheduler(config)
    bags = detector.build_candidate_fact_bags([str(root)])
    decisions = detector.evaluate_pool(bags)
    return {Path(bag.get("file.path")).relative_to(root).as_posix(): decisions[bag] for bag in bags}


def test_directory_blacklist_matches_directory_names_and_slash_paths(tmp_path):
    weapon_dir = tmp_path / "FBX" / "weapon"
    weapon_dir.mkdir(parents=True)
    (weapon_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    for pattern in ["weapon", r"FBX/weapon", r".*/weapon"]:
        decisions = decisions_for(tmp_path, scan_config(patterns=[pattern]))

        assert decisions["keep.zip"].should_extract
        assert "FBX/weapon/payload.zip" not in decisions


def test_filename_blacklist_supports_name_and_relative_path_patterns(tmp_path):
    nested = tmp_path / "FBX" / "weapon"
    nested.mkdir(parents=True)
    (tmp_path / "demo.zip").write_bytes(b"PK\x03\x04payload")
    (nested / "demo.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    decisions = decisions_for(tmp_path, scan_config(patterns=[r"^demo\.zip$", r"FBX/weapon/demo\.zip"]))

    assert decisions["keep.zip"].should_extract
    assert "demo.zip" not in decisions
    assert "FBX/weapon/demo.zip" not in decisions


def test_directory_blacklist_prevents_archive_from_becoming_scan_task(tmp_path):
    weapon_dir = tmp_path / "FBX" / "weapon"
    weapon_dir.mkdir(parents=True)
    (weapon_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    results = ScanOrchestrator(scan_config(patterns=[r"FBX/weapon"])).scan(str(tmp_path))

    assert [Path(result.main_path).name for result in results] == ["keep.zip"]


def test_filename_blacklist_filters_single_rename_candidate_before_planning(tmp_path):
    archive = tmp_path / "asset.foo"
    archive.write_bytes(b"PK\x03\x04payload")

    results = ScanOrchestrator(scan_config(patterns=[r"asset\.foo"])).scan(str(tmp_path))

    assert results == []


def test_filename_blacklist_filters_series_rename_candidate_before_planning(tmp_path):
    first = tmp_path / "bundle.part01.rar.jpg"
    second = tmp_path / "bundle.part02.rar.jpg"
    first.write_bytes(b"Rar!" + b"x" * 128)
    second.write_bytes(b"x" * 128)

    results = ScanOrchestrator(scan_config(patterns=[r"bundle\.part01\.rar\.jpg"])).scan(str(tmp_path))

    assert results == []


def test_blocked_semantic_extension_stops_magic_archive_in_generic_directory(tmp_path):
    archive = tmp_path / "asset.unitypackage"
    archive.write_bytes(b"\x1f\x8b" + b"x" * 128)

    decisions = decisions_for(tmp_path, scan_config(blocked_extensions=[".unitypackage"]))

    assert "asset.unitypackage" not in decisions


def test_docx_semantic_container_is_not_promoted_to_extract_task(tmp_path):
    archive = tmp_path / "sample.docx"
    archive.write_bytes(b"PK\x03\x04" + b"x" * 128)

    results = ScanOrchestrator(scan_config(blocked_extensions=[".docx"])).scan(str(tmp_path))
    decisions = decisions_for(tmp_path, scan_config(blocked_extensions=[".docx"]))

    assert results == []
    assert "sample.docx" not in decisions


def test_output_dir_scan_ignores_unitypackage_only_payloads(tmp_path):
    archive = tmp_path / "asset.unitypackage"
    archive.write_bytes(b"\x1f\x8b" + b"x" * 128)

    assert not OutputScanPolicy(scan_config()).should_scan_output_dir(str(tmp_path))


def test_scene_protect_stops_runtime_resource_archive_but_not_generic_control(tmp_path):
    game_root = tmp_path / "game"
    (game_root / "www" / "audio").mkdir(parents=True)
    (game_root / "www" / "data").mkdir(parents=True)
    (game_root / "game.exe").write_bytes(b"MZ")
    protected = game_root / "www" / "audio" / "bgm.7z"
    protected.write_bytes(b"7z\xbc\xaf\x27\x1c")

    generic = tmp_path / "generic"
    generic.mkdir()
    generic_archive = generic / "payload.7z"
    generic_archive.write_bytes(b"7z\xbc\xaf\x27\x1c")

    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {"name": "scene_protect", "enabled": True, "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True},
    ])

    decisions = decisions_for(tmp_path, config)

    assert not decisions["game/www/audio/bgm.7z"].should_extract
    assert decisions["game/www/audio/bgm.7z"].matched_rules == ["scene_protect"]
    assert decisions["generic/payload.7z"].should_extract
