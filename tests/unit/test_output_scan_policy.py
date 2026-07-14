from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.support.output_inventory import OutputInventory, OutputStats
from tests.helpers.detection_config import with_detection_pipeline


def _config():
    return with_detection_pipeline()


def test_output_scan_policy_schedules_disguised_archive_for_full_scan(tmp_path):
    candidate = tmp_path / "K社27作.ISO"
    candidate.write_bytes(b"7z\xbc\xaf'\x1c" + b"payload")

    policy = OutputScanPolicy(_config())

    assert policy.should_scan_output_dir(str(tmp_path))
    assert policy.scan_roots_from_outputs([str(tmp_path)]) == [str(tmp_path.resolve())]


def test_output_scan_policy_finds_nested_archive_when_initial_scan_is_current_dir_only(tmp_path):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.ISO"
    nested.write_bytes(b"7z" + b"x" * (1024 * 1024))
    config = _config()
    config.setdefault("filesystem", {})["directory_scan_mode"] = "current_dir_only"

    policy = OutputScanPolicy(config)

    assert policy.should_scan_output_dir(str(tmp_path))
    assert policy.scan_roots_from_outputs([str(tmp_path)]) == [str(segment_dir.resolve())]


def test_output_scan_policy_reuses_extraction_inventory(tmp_path, monkeypatch):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.ISO"
    nested.write_bytes(b"PK")
    inventory = OutputInventory(
        root=str(tmp_path.resolve()),
        stats=OutputStats(
            exists=True,
            is_dir=True,
            file_count=1,
            dir_count=1,
            total_size=2,
            relative_paths=("embedded_00_rar/payload.ISO",),
        ),
        files=({"path": "embedded_00_rar/payload.ISO", "size": 2},),
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
