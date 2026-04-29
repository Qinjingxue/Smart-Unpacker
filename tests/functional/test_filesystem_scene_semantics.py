import json
from pathlib import Path

from sunpack.detection import ArchiveTaskProvider
from sunpack.filesystem.directory_scanner import DirectoryScanner


def _config() -> dict:
    return {
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "filesystem": {
            "directory_scan_mode": "*",
            "scan_filters_enabled": True,
            "scan_filters": [
                {
                    "name": "scene_semantics",
                    "enabled": True,
                    "protect_runtime_resources": True,
                    "scene_rules": _scene_rules(),
                },
                {"name": "size_range", "enabled": True, "range": "r >= 0 B"},
            ],
        },
        "detection": {
            "enabled": True,
            "fact_collectors": [
                {"name": "file_facts", "enabled": True},
                {"name": "magic_bytes", "enabled": True},
            ],
            "processors": [
                {"name": "embedded_archive", "enabled": True},
                {"name": "seven_zip_probe", "enabled": True},
                {"name": "seven_zip_validation", "enabled": True},
                {"name": "zip_structure", "enabled": True},
                {"name": "zip_eocd_structure", "enabled": True},
                {"name": "tar_header_structure", "enabled": True},
                {"name": "compression_stream_structure", "enabled": True},
                {"name": "archive_container_structure", "enabled": True},
                {"name": "pe_overlay_structure", "enabled": True},
                {"name": "seven_zip_structure", "enabled": True},
                {"name": "rar_structure", "enabled": True},
            ],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [
                    {
                        "name": "extension",
                        "enabled": True,
                        "extension_score_groups": [{"score": 5, "extensions": [".7z", ".zip", ".rar"]}],
                    }
                ],
                "confirmation": [],
            },
        },
    }


def _write_rpg_maker(root: Path) -> Path:
    (root / "www" / "audio").mkdir(parents=True)
    (root / "www" / "data").mkdir(parents=True)
    (root / "www" / "js").mkdir(parents=True)
    (root / "game.exe").write_bytes(b"MZ")
    (root / "www" / "js" / "rpg_core.js").write_text("// core", encoding="utf-8")
    archive = root / "www" / "audio" / "bgm.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
    return archive


def test_scene_semantics_annotates_runtime_resource_before_filtering(tmp_path):
    archive = _write_rpg_maker(tmp_path / "game")

    config = _config()
    config["filesystem"]["scan_filters"][0]["protect_runtime_resources"] = False
    snapshot = DirectoryScanner(str(tmp_path), config=config).scan()

    entry = next(item for item in snapshot.entries if item.path == archive)
    scene = entry.metadata["scene"]
    assert scene["scene_type"] == "rpg_maker_game"
    assert scene["is_runtime_resource_archive"] is True


def test_scene_semantics_filters_runtime_resource_before_detection(tmp_path):
    protected = _write_rpg_maker(tmp_path / "game")
    generic = tmp_path / "generic.7z"
    generic.write_bytes(b"7z\xbc\xaf\x27\x1c")

    tasks = ArchiveTaskProvider(_config()).scan_targets([str(tmp_path)])

    task_paths = {Path(task.main_path) for task in tasks}
    assert generic in task_paths
    assert protected not in task_paths


def test_scene_semantics_prune_dir_globs_skip_scene_matching(tmp_path):
    archive = _write_rpg_maker(tmp_path / "game")

    config = _config()
    config["filesystem"]["scan_filters"][0]["protect_runtime_resources"] = False
    config["filesystem"]["scan_filters"][0]["prune_dir_globs"] = ["game"]
    snapshot = DirectoryScanner(str(tmp_path), config=config).scan()

    entry = next(item for item in snapshot.entries if item.path == archive)
    assert not (entry.metadata or {}).get("scene")


def test_scene_semantics_prune_dir_globs_stop_descending_into_subtree(tmp_path):
    archive = _write_rpg_maker(tmp_path / "ignored" / "deep" / "game")

    config = _config()
    config["filesystem"]["scan_filters"][0]["protect_runtime_resources"] = False
    config["filesystem"]["scan_filters"][0]["prune_dir_globs"] = ["ignored"]
    snapshot = DirectoryScanner(str(tmp_path), config=config).scan()

    entry = next(item for item in snapshot.entries if item.path == archive)
    assert not (entry.metadata or {}).get("scene")


def _scene_rules() -> list[dict]:
    config_path = Path(__file__).resolve().parents[2] / "sunpack_advanced_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for item in config["filesystem"]["scan_filters"]:
        if isinstance(item, dict) and item.get("name") == "scene_semantics":
            return item["scene_rules"]
    raise AssertionError("scene_semantics scene_rules not found in advanced config")
