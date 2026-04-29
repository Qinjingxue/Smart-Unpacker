from packrelic.filesystem.directory_scanner import DirectoryScanner
from packrelic.detection import DetectionScheduler


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
            from packrelic.filesystem.filters.base import keep
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
