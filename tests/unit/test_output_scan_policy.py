from sunpack.detection.nested_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.contracts.filesystem import FileEntry
from tests.helpers.detection_config import with_detection_pipeline


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

    monkeypatch.setattr("sunpack.detection.nested_scan_policy.os.path.getsize", fail_getsize)

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
