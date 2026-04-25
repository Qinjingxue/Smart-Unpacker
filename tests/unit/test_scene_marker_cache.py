from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.scene.markers import collect_scene_markers_from_directory, collect_scene_markers_from_snapshot
from smart_unpacker.detection.pipeline.facts.context import FactCollectorContext
from smart_unpacker.detection.pipeline.facts.collectors import scene_markers
from smart_unpacker.filesystem.directory_scanner import DirectoryScanner
from smart_unpacker.support.external_command_cache import clear_all_caches
from tests.helpers.detection_config import with_detection_pipeline


def _context_for(path, max_depth: int = 1) -> FactCollectorContext:
    bag = FactBag()
    bag.set("file.path", str(path))
    return FactCollectorContext(
        base_path=str(path),
        fact_bag=bag,
        fact_name="scene.directory_markers",
        fact_config={"scene_context_max_parent_depth": max_depth},
    )


def test_scene_marker_cache_reuses_parent_directory_markers(tmp_path, monkeypatch):
    clear_all_caches()
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    left_file = left / "archive.zip"
    right_file = right / "archive.zip"
    left_file.write_bytes(b"PK\x03\x04")
    right_file.write_bytes(b"PK\x03\x04")
    (tmp_path / "www").mkdir()

    scan_counts: dict[str, int] = {}
    original_scan = DirectoryScanner.scan

    def counting_scan(self):
        key = str(self.root_path)
        scan_counts[key] = scan_counts.get(key, 0) + 1
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", counting_scan)

    scene_markers.collect_scene_directory_markers(_context_for(left_file))
    scene_markers.collect_scene_directory_markers(_context_for(right_file))

    assert scan_counts == {}


def test_scene_markers_are_prefetched_once_per_directory_for_batch(tmp_path, monkeypatch):
    clear_all_caches()
    game = tmp_path / "game"
    (game / "www" / "audio").mkdir(parents=True)
    (game / "www" / "data").mkdir(parents=True)
    (game / "game.exe").write_bytes(b"MZ")
    first = game / "www" / "audio" / "bgm.7z"
    second = game / "www" / "data" / "payload.7z"
    first.write_bytes(b"7z\xbc\xaf\x27\x1c")
    second.write_bytes(b"7z\xbc\xaf\x27\x1c")

    scan_counts: dict[str, int] = {}
    original_scan = DirectoryScanner.scan

    def counting_scan(self):
        key = str(self.root_path)
        scan_counts[key] = scan_counts.get(key, 0) + 1
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", counting_scan)

    config = with_detection_pipeline(hard_stop=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {"name": "scene_protect", "enabled": True},
    ])

    DetectionScheduler(config).detect_targets([str(game)])

    assert scan_counts == {str(game): 1}


def test_scene_marker_batch_collector_respects_disabled_module(tmp_path, monkeypatch):
    clear_all_caches()
    game = tmp_path / "game"
    game.mkdir()
    target = game / "archive.zip"
    target.write_bytes(b"PK\x03\x04")

    scan_counts: dict[str, int] = {}
    original_scan = DirectoryScanner.scan

    def counting_scan(self):
        key = str(self.root_path)
        scan_counts[key] = scan_counts.get(key, 0) + 1
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", counting_scan)

    config = with_detection_pipeline(
        hard_stop=[{"name": "scene_protect", "enabled": True}],
    )
    config["detection"]["fact_collectors"] = [{"name": "scene_markers", "enabled": False}]

    results = DetectionScheduler(config).detect_targets([str(game)])

    assert results[0].fact_bag.is_missing("scene.directory_markers")
    assert scan_counts[str(game)] == 1


def test_scene_markers_use_snapshot_index_for_nested_and_child_paths(tmp_path):
    game = tmp_path / "game"
    (game / "www" / "js").mkdir(parents=True)
    (game / "www" / "data").mkdir(parents=True)
    (game / "resources").mkdir()
    (game / "resources" / "app.asar").write_bytes(b"asar")
    (game / "game.exe").write_bytes(b"MZ")
    for index in range(300):
        (game / f"noise_{index:03d}.txt").write_text("x", encoding="utf-8")

    snapshot = DirectoryScanner(str(game)).scan()
    rules = [{
        "top_level_dir_markers": {},
        "top_level_file_markers": {},
        "top_level_glob_markers": (),
        "nested_path_markers": {"resources/app.asar": "app_asar"},
    }]

    markers = collect_scene_markers_from_snapshot(snapshot, rules)

    assert "app_asar" in markers
    assert "js_dir" in markers
    assert "data_dir" in markers
    assert "runtime_exe" in markers


def test_scene_markers_use_lightweight_directory_probe_for_nested_and_child_paths(tmp_path, monkeypatch):
    game = tmp_path / "game"
    (game / "www" / "js").mkdir(parents=True)
    (game / "www" / "data").mkdir(parents=True)
    (game / "resources").mkdir()
    (game / "resources" / "app.asar").write_bytes(b"asar")
    (game / "game.exe").write_bytes(b"MZ")
    for index in range(300):
        (game / f"noise_{index:03d}.txt").write_text("x", encoding="utf-8")

    def fail_scan(self):
        raise AssertionError("lightweight scene probing should not use DirectoryScanner")

    monkeypatch.setattr(DirectoryScanner, "scan", fail_scan)
    rules = [{
        "top_level_dir_markers": {},
        "top_level_file_markers": {},
        "top_level_glob_markers": (),
        "nested_path_markers": {"resources/app.asar": "app_asar"},
    }]

    markers = collect_scene_markers_from_directory(str(game), rules)

    assert "app_asar" in markers
    assert "js_dir" in markers
    assert "data_dir" in markers
    assert "runtime_exe" in markers
