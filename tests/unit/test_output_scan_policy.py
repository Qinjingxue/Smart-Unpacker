from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.contracts.filesystem import FileEntry
from sunpack.support.output_inventory import OutputInventory, OutputStats
from tests.helpers.detection_config import with_detection_pipeline
import sunpack.coordinator.output_scan_policy as policy_module


def _config():
    return with_detection_pipeline(scoring=[
        {
            "name": "extension",
            "extension_score_groups": [{"score": 5, "extensions": [".zip"]}],
        },
        {
            "name": "embedded_payload_identity",
            "ambiguous_resource_exts": [".bin"],
            "carrier_exts": [".png"],
        },
    ])


def test_output_scan_policy_accepts_standard_archive_extension(tmp_path):
    candidate = tmp_path / "nested.zip"
    candidate.write_bytes(b"PK")

    assert OutputScanPolicy(_config()).should_consider_file_for_nested_scan(str(candidate))


def test_output_scan_policy_applies_carrier_size_gate(tmp_path):
    small = tmp_path / "cover.png"
    large = tmp_path / "payload.png"
    small.write_bytes(b"x")
    large.write_bytes(b"x" * (1024 * 1024))

    policy = OutputScanPolicy(_config())

    assert not policy.should_consider_file_for_nested_scan(str(small))
    assert policy.should_consider_file_for_nested_scan(str(large))


def test_output_scan_policy_accepts_ambiguous_named_archive(tmp_path):
    candidate = tmp_path / "backup_archive.bin"
    candidate.write_bytes(b"data")

    assert OutputScanPolicy(_config()).should_consider_file_for_nested_scan(str(candidate))


def test_output_scan_policy_uses_file_entry_size_without_stat(tmp_path, monkeypatch):
    candidate = tmp_path / "payload.png"
    candidate.write_bytes(b"x")

    def fail_getsize(_path):
        raise AssertionError("getsize should not be called when entry size is available")

    monkeypatch.setattr("sunpack.coordinator.output_scan_policy.os.path.getsize", fail_getsize)

    entry = FileEntry(path=candidate, is_dir=False, size=1024 * 1024)

    assert OutputScanPolicy(_config()).should_consider_entry_for_nested_scan(entry)


def test_output_scan_policy_finds_nested_archive_when_initial_scan_is_current_dir_only(tmp_path):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.zip"
    nested.write_bytes(b"7z" + b"x" * (1024 * 1024))
    config = _config()
    config.setdefault("filesystem", {})["directory_scan_mode"] = "current_dir_only"

    policy = OutputScanPolicy(config)

    assert policy.should_scan_output_dir(str(tmp_path))
    assert policy.scan_roots_from_outputs([str(tmp_path)]) == [str(segment_dir.resolve())]


def test_output_scan_policy_reuses_extraction_inventory(tmp_path, monkeypatch):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.zip"
    nested.write_bytes(b"PK")
    inventory = OutputInventory(
        root=str(tmp_path.resolve()),
        stats=OutputStats(
            exists=True,
            is_dir=True,
            file_count=1,
            dir_count=1,
            total_size=2,
            relative_paths=("embedded_00_rar/payload.zip",),
        ),
        files=({"path": "embedded_00_rar/payload.zip", "size": 2},),
    )

    monkeypatch.setattr(
        "sunpack.coordinator.output_scan_policy.DirectoryScanner.scan",
        lambda _self: (_ for _ in ()).throw(AssertionError("directory must not be rescanned")),
    )

    roots = OutputScanPolicy(_config()).scan_roots_from_outputs(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory.to_dict()},
    )

    assert roots == [str(segment_dir.resolve())]


def test_output_scan_policy_compiles_extension_rules_once_per_config(monkeypatch, tmp_path):
    policy_module._compile_extension_rules.cache_clear()
    calls = {"groups": 0, "exts": 0}
    original_groups = policy_module.normalize_extension_score_groups
    original_exts = policy_module.normalize_exts

    def count_groups(values):
        calls["groups"] += 1
        return original_groups(values)

    def count_exts(values):
        calls["exts"] += 1
        return original_exts(values)

    monkeypatch.setattr(policy_module, "normalize_extension_score_groups", count_groups)
    monkeypatch.setattr(policy_module, "normalize_exts", count_exts)
    config = _config()
    first = OutputScanPolicy(config)
    second = OutputScanPolicy(config)

    for index in range(100):
        entry = FileEntry(path=tmp_path / f"nested_{index}.zip", is_dir=False, size=2)
        assert first.should_consider_entry_for_nested_scan(entry)
        assert second.should_consider_entry_for_nested_scan(entry)

    assert calls == {"groups": 1, "exts": 2}
