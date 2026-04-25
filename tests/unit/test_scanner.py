from smart_unpacker.filesystem.directory_scanner import DirectoryScanner
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.internal.scan_session import DetectionScanSession
from smart_unpacker.detection.pipeline.facts.provider import FactProvider


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
            "directory_scan_mode": "current_dir_only",
            "scan_filters": [],
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "root.zip" in names
    assert "nested" not in names
    assert "nested.zip" not in names


def test_directory_scanner_native_fast_path_wraps_file_entries(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")
    calls = []

    def fake_native(root_path, max_depth, patterns, prune_dirs, blocked_extensions, min_size):
        calls.append({
            "root_path": root_path,
            "max_depth": max_depth,
            "patterns": patterns,
            "prune_dirs": prune_dirs,
            "blocked_extensions": blocked_extensions,
            "min_size": min_size,
        })
        return [{
            "path": str(target),
            "is_dir": False,
            "size": 11,
            "mtime_ns": 123,
        }]

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE_DIRECTORY_SCAN", raising=False)
    monkeypatch.setattr("smart_unpacker.filesystem.directory_scanner._NATIVE_SCAN_DIRECTORY_ENTRIES", fake_native)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "directory_scan_mode": "current_dir_only",
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
                {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 1024},
            ],
        }
    }).scan()

    assert calls
    assert calls[0]["max_depth"] == 0
    assert calls[0]["blocked_extensions"] == [".py"]
    assert calls[0]["min_size"] == 1024
    assert snapshot.entries == [type(snapshot.entries[0])(path=target, is_dir=False, size=11, mtime_ns=123)]


def test_directory_scanner_custom_filters_use_python_path(tmp_path, monkeypatch):
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04payload")

    def unexpected_native(*_args, **_kwargs):
        raise AssertionError("custom filters should not use native directory scan")

    class KeepAllFilter:
        name = "keep_all"
        stage = "path"

        def evaluate(self, candidate):
            from smart_unpacker.filesystem.filters.base import keep
            return keep()

    monkeypatch.setattr("smart_unpacker.filesystem.directory_scanner._NATIVE_SCAN_DIRECTORY_ENTRIES", unexpected_native)

    snapshot = DirectoryScanner(str(tmp_path), filters=[KeepAllFilter()]).scan()

    assert {entry.path.name for entry in snapshot.entries} == {"archive.zip"}


def test_directory_scanner_explicit_max_depth_overrides_scan_mode(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), max_depth=1, config={
        "filesystem": {
            "directory_scan_mode": "current_dir_only",
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


def test_target_scan_reuses_scanned_file_size(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")

    bags = DetectionScheduler({}).build_candidate_fact_bags([str(tmp_path)])
    bag = next(bag for bag in bags if bag.get("file.path") == str(target))

    def fail_getsize(_path):
        raise AssertionError("file.size should come from the directory snapshot")

    monkeypatch.setattr("os.path.getsize", fail_getsize)

    assert FactProvider(str(target)).fill_fact(bag, "file.size") == target.stat().st_size


def test_detection_scan_session_reuses_directory_snapshot(tmp_path, monkeypatch):
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04payload")

    scan_count = 0
    original_scan = DirectoryScanner.scan

    def counting_scan(self):
        nonlocal scan_count
        scan_count += 1
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", counting_scan)

    session = DetectionScanSession()

    assert session.snapshot_for_directory(str(tmp_path)) is session.snapshot_for_directory(str(tmp_path))
    assert session.relation_groups_for_directory(str(tmp_path)) is session.relation_groups_for_directory(str(tmp_path))
    assert session.fact_bags_for_directory(str(tmp_path)) is session.fact_bags_for_directory(str(tmp_path))
    assert scan_count == 1


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
