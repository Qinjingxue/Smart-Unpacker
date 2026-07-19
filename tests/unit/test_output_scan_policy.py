from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy as OutputScanPolicy
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
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
    assert policy.scan_roots_from_outputs([str(tmp_path)]) == [str(tmp_path.resolve())]


def test_output_scan_policy_reuses_extraction_inventory(tmp_path, monkeypatch):
    segment_dir = tmp_path / "embedded_00_rar"
    segment_dir.mkdir()
    nested = segment_dir / "payload.ISO"
    payload = b"PK" + b"x" * (1024 * 1024)
    nested.write_bytes(payload)
    inventory = OutputInventory(
        root=str(tmp_path.resolve()),
        stats=OutputStats(
            exists=True,
            is_dir=True,
            file_count=1,
            dir_count=1,
            total_size=len(payload),
            relative_paths=("embedded_00_rar/payload.ISO",),
        ),
        files=({"path": "embedded_00_rar/payload.ISO", "size": len(payload)},),
    )

    monkeypatch.setattr(
        "sunpack.coordinator.output_scan_policy.DirectoryScanner.scan",
        lambda _self: (_ for _ in ()).throw(AssertionError("directory must not be rescanned")),
    )
    policy = OutputScanPolicy(_config())
    roots = policy.scan_roots_from_outputs(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory.to_dict()},
    )

    assert roots == [str(tmp_path.resolve())]
    session = policy.take_scan_session(roots)
    assert session is not None
    assert session.include_raw_snapshots is True
    bags = build_fact_bags_for_targets(roots, session=session, config=_config())
    assert [bag.get("candidate.entry_path") for bag in bags] == [str(nested.resolve())]


def test_output_scan_policy_inventory_batch_primes_file_heads(tmp_path, monkeypatch):
    archive = tmp_path / "nested.zip"
    archive.write_bytes(b"PK\x03\x04" + b"x" * (1024 * 1024))
    inventory = OutputInventory(
        root=str(tmp_path.resolve()),
        stats=OutputStats(
            exists=True,
            is_dir=True,
            file_count=1,
            total_size=archive.stat().st_size,
            relative_paths=(archive.name,),
        ),
        files=({"path": archive.name, "size": archive.stat().st_size},),
    )
    policy = OutputScanPolicy(_config())
    roots = policy.scan_roots_from_outputs(
        [str(tmp_path)],
        inventories={str(tmp_path.resolve()).lower(): inventory.to_dict()},
    )
    session = policy.take_scan_session(roots)
    assert session is not None

    monkeypatch.setattr(
        "sunpack.coordinator.scan_session._native_batch_file_head_facts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("file heads must be cached")),
    )
    facts = session.file_head_facts_for_paths([str(archive)], magic_size=16)

    row = facts[next(iter(facts))]
    assert row["size"] == archive.stat().st_size
    assert row["magic"].startswith(b"PK\x03\x04")
