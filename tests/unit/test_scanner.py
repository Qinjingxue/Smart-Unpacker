from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.detection import DetectionScheduler
from sunpack.detection.task_provider import ArchiveTaskProvider
from tests.helpers.scene_rules import RECOMMENDED_SCENE_RULES_PAYLOAD
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


def test_directory_scanner_size_range_filters_files_outside_range(tmp_path):
    small = tmp_path / "small.zip"
    medium = tmp_path / "medium.zip"
    large = tmp_path / "large.zip"
    small.write_bytes(b"a" * 8)
    medium.write_bytes(b"b" * 16)
    large.write_bytes(b"c" * 32)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10, "lt": 32},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "small.zip" not in names
    assert "medium.zip" in names
    assert "large.zip" not in names


def test_directory_scanner_size_range_accepts_human_expression(tmp_path):
    small = tmp_path / "small.zip"
    keep = tmp_path / "keep.zip"
    large = tmp_path / "large.zip"
    small.write_bytes(b"a" * 512 * 1024)
    keep.write_bytes(b"b" * 2 * 1024 * 1024)
    large.write_bytes(b"c" * 11 * 1024 * 1024)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "range": "1 MB < r < 10 MB"},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "small.zip" not in names
    assert "keep.zip" in names
    assert "large.zip" not in names


def test_directory_scanner_size_minimum_legacy_config_still_filters(tmp_path):
    small = tmp_path / "small.zip"
    keep = tmp_path / "keep.zip"
    small.write_bytes(b"a" * 8)
    keep.write_bytes(b"b" * 16)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 10},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "small.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_mtime_range_filters_files_outside_range(tmp_path):
    old = tmp_path / "old.zip"
    keep = tmp_path / "keep.zip"
    new = tmp_path / "new.zip"
    old.write_bytes(b"old")
    keep.write_bytes(b"keep")
    new.write_bytes(b"new")
    old_ns = 1_700_000_000_000_000_000
    keep_ns = 1_800_000_000_000_000_000
    new_ns = 1_900_000_000_000_000_000
    import os
    os.utime(old, ns=(old_ns, old_ns))
    os.utime(keep, ns=(keep_ns, keep_ns))
    os.utime(new, ns=(new_ns, new_ns))

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "gte": keep_ns, "lt": new_ns},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "old.zip" not in names
    assert "keep.zip" in names
    assert "new.zip" not in names


def test_directory_scanner_mtime_range_accepts_date_expression(tmp_path):
    old = tmp_path / "old.zip"
    keep = tmp_path / "keep.zip"
    new = tmp_path / "new.zip"
    old.write_bytes(b"old")
    keep.write_bytes(b"keep")
    new.write_bytes(b"new")

    from datetime import datetime
    import os

    def ns(value: str) -> int:
        return int(datetime.strptime(value, "%Y%m%d %H:%M").timestamp() * 1_000_000_000)

    os.utime(old, ns=(ns("20250101 00:00"), ns("20250101 00:00")))
    os.utime(keep, ns=(ns("20260101 00:00"), ns("20260101 00:00")))
    os.utime(new, ns=(ns("20270101 00:00"), ns("20270101 00:00")))

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "date": "20260430 01:40 > d > 20250320 01:30"},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "old.zip" not in names
    assert "keep.zip" in names
    assert "new.zip" not in names


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


def test_directory_scanner_blacklist_blocks_exact_file_names(tmp_path):
    blocked = tmp_path / "Thumbs.db"
    blocked.write_bytes(b"not an archive")
    keep = tmp_path / "Thumbs.zip"
    keep.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_files": ["thumbs.db"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "Thumbs.db" not in names
    assert "Thumbs.zip" in names


def test_directory_scanner_scan_filters_global_switch_disables_filters(tmp_path):
    blocked = tmp_path / "skip.py"
    blocked.write_text("print('keep when filters are globally disabled')", encoding="utf-8")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters_enabled": False,
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
            ],
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "skip.py" in names


def test_directory_scanner_applies_filters_in_config_order(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")
    observed = []

    from sunpack.filesystem.filters.modules.blacklist import BlacklistScanFilter
    from sunpack.filesystem.filters.modules.mtime_range import MtimeRangeScanFilter
    from sunpack.filesystem.filters.modules.size_minimum import SizeRangeScanFilter
    from sunpack.filesystem.filters.modules.whitelist import WhitelistScanFilter

    originals = {
        "whitelist": WhitelistScanFilter.evaluate,
        "blacklist": BlacklistScanFilter.evaluate,
        "size_range": SizeRangeScanFilter.evaluate,
        "mtime_range": MtimeRangeScanFilter.evaluate,
    }

    def record(name, original):
        def wrapped(self, candidate):
            if candidate.path == target:
                observed.append(name)
            return original(self, candidate)
        return wrapped

    monkeypatch.setattr(WhitelistScanFilter, "evaluate", record("whitelist", originals["whitelist"]))
    monkeypatch.setattr(BlacklistScanFilter, "evaluate", record("blacklist", originals["blacklist"]))
    monkeypatch.setattr(SizeRangeScanFilter, "evaluate", record("size_range", originals["size_range"]))
    monkeypatch.setattr(MtimeRangeScanFilter, "evaluate", record("mtime_range", originals["mtime_range"]))

    DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True},
                {"name": "whitelist", "enabled": True},
                {"name": "size_range", "enabled": True},
                {"name": "blacklist", "enabled": True},
            ]
        }
    }).scan()

    assert observed == ["mtime_range", "whitelist", "size_range", "blacklist"]


def test_directory_scanner_whitelist_disabled_does_not_filter(tmp_path):
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "other.rar").write_bytes(b"Rar!\x1a\x07\x00payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": False, "allowed_extensions": [".zip"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "keep.zip" in names
    assert "other.rar" in names


def test_directory_scanner_whitelist_keeps_only_allowed_extensions(tmp_path):
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "skip.rar").write_bytes(b"Rar!\x1a\x07\x00payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": True, "allowed_extensions": [".zip"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "keep.zip" in names
    assert "skip.rar" not in names


def test_directory_scanner_whitelist_keeps_only_allowed_path_globs(tmp_path):
    allowed_dir = tmp_path / "archives"
    blocked_dir = tmp_path / "other"
    allowed_dir.mkdir()
    blocked_dir.mkdir()
    (allowed_dir / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (blocked_dir / "skip.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": True, "path_globs": ["archives/**"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "archives" in names
    assert "keep.zip" in names
    assert "other" not in names
    assert "skip.zip" not in names


def test_directory_scanner_whitelist_then_blacklist_both_apply(tmp_path):
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "skip.py").write_text("print('skip')", encoding="utf-8")
    (tmp_path / "skip.rar").write_bytes(b"Rar!\x1a\x07\x00payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": True, "allowed_extensions": [".zip", ".py"]},
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "keep.zip" in names
    assert "skip.py" not in names
    assert "skip.rar" not in names


def test_directory_scanner_whitelist_empty_fields_are_not_restrictions(tmp_path):
    allowed_dir = tmp_path / "archives"
    allowed_dir.mkdir()
    (allowed_dir / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (allowed_dir / "skip.rar").write_bytes(b"Rar!\x1a\x07\x00payload")
    (tmp_path / "other.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {
                    "name": "whitelist",
                    "enabled": True,
                    "path_globs": ["archives/**"],
                    "prune_dir_globs": [],
                    "allowed_files": [],
                    "allowed_extensions": [".zip"],
                },
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "archives" in names
    assert "keep.zip" in names
    assert "skip.rar" not in names
    assert "other.zip" not in names


def test_directory_scanner_whitelist_non_empty_fields_are_combined_as_constraints(tmp_path):
    (tmp_path / "sample.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "sample.rar").write_bytes(b"Rar!\x1a\x07\x00payload")
    (tmp_path / "other.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {
                    "name": "whitelist",
                    "enabled": True,
                    "allowed_files": ["sample.zip"],
                    "allowed_extensions": [".zip"],
                },
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "sample.zip" in names
    assert "sample.rar" not in names
    assert "other.zip" not in names


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


def test_directory_scanner_blacklist_supports_path_globs(tmp_path):
    blocked_dir = tmp_path / "$RECYCLE.BIN"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "path_globs": ["$RECYCLE.BIN/**"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "$RECYCLE.BIN" not in names
    assert "payload.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_blacklist_supports_prune_dir_globs(tmp_path):
    blocked_dir = tmp_path / "node_modules"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "prune_dir_globs": ["node_*"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in snapshot.entries}
    assert "node_modules" not in names
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


def test_archive_task_provider_detection_enabled_false_uses_standard_archive_fallback(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")

    provider = ArchiveTaskProvider({
        "detection": {
            "enabled": False,
            "fact_collectors": [{"name": "file_facts", "enabled": True}],
            "processors": [{"name": "zip_structure", "enabled": True}],
            "rule_pipeline": {
                "precheck": [{"name": "zip_structure_accept", "enabled": True}],
                "scoring": [{"name": "extension", "enabled": True}],
                "confirmation": [],
            },
        },
        "filesystem": {"scan_filters": []},
    })

    def fail_if_rules_run(*_args, **_kwargs):
        raise AssertionError("detection.enabled=false should not evaluate detection rules")

    monkeypatch.setattr(provider.detector, "evaluate_bags", fail_if_rules_run)

    tasks = provider.scan_targets([str(tmp_path)])

    assert [task.main_path for task in tasks] == [str(target)]


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

