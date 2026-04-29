from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.detection import DetectionScheduler
from sunpack.detection.task_provider import ArchiveTaskProvider
from sunpack.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD
from tests.helpers.detection_config import with_detection_pipeline


def test_directory_scanner_captures_files_and_directories(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04")
    (tmp_path / "nested" / "notes.txt").write_text("hello", encoding="utf-8")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    names = {entry.path.name for entry in snapshot.entries}

    assert snapshot.root_path == tmp_path
    assert {"nested", "archive.zip", "notes.txt"} <= names
    assert any(entry.is_dir and entry.path.name == "nested" for entry in snapshot.entries)
    assert any(not entry.is_dir and entry.path.name == "archive.zip" for entry in snapshot.entries)


def test_directory_scanner_records_file_size(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    entry = next(entry for entry in snapshot.entries if entry.path == target)

    assert entry.size == target.stat().st_size


def test_directory_scanner_current_dir_only_scan_mode_skips_subdirectories(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "root.zip").write_bytes(b"PK\x03\x04payload")
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "directory_scan_mode": "-",
            "scan_filters": [],
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "root.zip" in names
    assert "nested" not in names
    assert "nested.zip" not in names


def test_directory_scanner_custom_filters_fail_without_native_mapping(tmp_path):
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04payload")

    class KeepAllFilter:
        name = "keep_all"
        stage = "path"

        def evaluate(self, candidate):
            from sunpack.filesystem.filters.base import keep
            return keep()

    import pytest
    with pytest.raises(RuntimeError, match="Native directory scan requires"):
        DirectoryScanner(str(tmp_path), filters=[KeepAllFilter()]).scan()


def test_directory_scanner_explicit_max_depth_overrides_scan_mode(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), max_depth=1, config={
        "filesystem": {
            "directory_scan_mode": "-",
            "scan_filters": [],
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "nested" in names
    assert "nested.zip" in names


def test_directory_scanner_path_filter_skips_file_before_stat(tmp_path, monkeypatch):
    blocked = tmp_path / "skip.py"
    blocked.write_text("print('skip')", encoding="utf-8")
    keep = tmp_path / "keep.zip"
    keep.write_bytes(b"PK\x03\x04payload")

    original_stat = type(blocked).stat

    def fail_if_blocked(self):
        if self == blocked:
            raise AssertionError("path-stage blacklist should reject before file stat")
        return original_stat(self)

    monkeypatch.setattr(type(blocked), "stat", fail_if_blocked)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "skip.py" not in names
    assert "keep.zip" in names


def test_directory_scanner_blacklist_prunes_directory(tmp_path):
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "patterns": ["blocked"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "blocked" not in names
    assert "payload.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_blacklist_prune_dirs_is_directory_only(tmp_path):
    blocked_dir = tmp_path / "site-packages"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    same_name_file = tmp_path / "site-packages.zip"
    same_name_file.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "prune_dirs": ["^site-packages$"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "site-packages" not in names
    assert "payload.zip" not in names
    assert "site-packages.zip" in names


def test_target_scan_reuses_session_for_duplicate_directories(tmp_path, monkeypatch):
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04payload")

    scan_count = 0
    original_scan = DirectoryScanner.scan

    def counting_scan(self):
        nonlocal scan_count
        scan_count += 1
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", counting_scan)

    bags = DetectionScheduler({}).build_candidate_fact_bags([str(tmp_path), str(tmp_path)])

    assert len([bag for bag in bags if bag.get("file.path") == str(tmp_path / "archive.zip")]) == 1
    assert scan_count == 1


def test_archive_task_provider_reuses_scan_session_for_scene_facts(tmp_path, monkeypatch):
    target = tmp_path / "archive.7z"
    target.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"payload")

    import sunpack.detection.pipeline.facts.collectors.scene_markers as scene_markers

    def fail_if_directory_fallback(directory, rules):
        raise AssertionError(f"scene facts should use scan-session snapshots, got fallback scan for {directory}")

    monkeypatch.setattr(scene_markers, "collect_scene_markers_from_directory", fail_if_directory_fallback)

    config = with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3}},
        precheck=[
            {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
            {
                "name": "scene_protect",
                "enabled": True,
                "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
            },
        ],
        scoring=[
            {
                "name": "extension",
                "enabled": True,
                "extension_score_groups": [{"score": 5, "extensions": [".7z"]}],
            },
        ],
    )

    tasks = ArchiveTaskProvider(config).scan_targets([str(tmp_path)])

    assert [task.main_path for task in tasks] == [str(target)]


def test_scene_marker_directory_fallback_uses_bounded_depth(tmp_path, monkeypatch):
    from sunpack.detection.pipeline.facts.collectors.scene_markers import _collect_scene_markers_for_directory

    observed_depths = []
    original_scan = DirectoryScanner.scan

    def recording_scan(self):
        observed_depths.append(self.max_depth)
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", recording_scan)

    markers = _collect_scene_markers_for_directory(str(tmp_path), RECOMMENDED_SCENE_RULES_PAYLOAD, snapshot=None)

    assert markers == []
    assert observed_depths == [3]


def test_scene_context_does_not_scan_above_selected_root(tmp_path, monkeypatch):
    selected_root = tmp_path / "selected"
    archive = selected_root / "game" / "www" / "audio" / "bgm.7z"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"payload")

    original_scan = DirectoryScanner.scan

    def fail_if_outside_selected_root(self):
        root = self.root_path
        if root != selected_root and not str(root).startswith(str(selected_root) + "\\"):
            raise AssertionError(f"scene scan escaped selected root: {root}")
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", fail_if_outside_selected_root)

    config = with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3}},
        precheck=[
            {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
            {
                "name": "scene_protect",
                "enabled": True,
                "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
            },
        ],
        scoring=[
            {
                "name": "extension",
                "enabled": True,
                "extension_score_groups": [{"score": 5, "extensions": [".7z"]}],
            },
        ],
    )

    tasks = ArchiveTaskProvider(config).scan_targets([str(selected_root)])

    assert [task.main_path for task in tasks] == [str(archive)]
