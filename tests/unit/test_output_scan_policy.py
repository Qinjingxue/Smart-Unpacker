from smart_unpacker.coordinator.output_scan import OutputScanPolicy
from smart_unpacker.contracts.filesystem import FileEntry
from tests.helpers.detection_config import with_detection_pipeline


def _config():
    return with_detection_pipeline(scoring=[
        {
            "name": "extension",
            "extension_score_groups": [{"score": 5, "extensions": [".zip"]}],
        },
        {
            "name": "archive_identity",
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

    monkeypatch.setattr("smart_unpacker.coordinator.output_scan.os.path.getsize", fail_getsize)

    entry = FileEntry(path=candidate, is_dir=False, size=1024 * 1024)

    assert OutputScanPolicy(_config()).should_consider_entry_for_nested_scan(entry)
