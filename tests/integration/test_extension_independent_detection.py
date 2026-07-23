from pathlib import Path

import pytest

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar


ARCHIVE_FORMATS = [
    "zip",
    "7z",
    "tar",
    "tar.gz",
    "tar.bz2",
    "tar.xz",
    "tar.zst",
    "gzip",
    "bzip2",
    "xz",
    "zstd",
]


def _detected(path: Path):
    config = with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3}},
        precheck=[
            {"name": "zip_structure_accept", "enabled": True},
            {"name": "tar_structure_accept", "enabled": True},
            {"name": "seven_zip_structure_accept", "enabled": True},
            {"name": "rar_structure_accept", "enabled": True},
            {"name": "compression_stream_accept", "enabled": True},
            {
                "name": "embedded_payload_identity",
                "enabled": True,
                "deep_scan_single_candidate_ratio": 0.3,
            },
        ],
        scoring=[
            {"name": "seven_zip_structure_identity", "enabled": True},
            {"name": "rar_structure_identity", "enabled": True},
            {"name": "zip_structure_identity", "enabled": True},
            {"name": "tar_structure_identity", "enabled": True},
            {"name": "compression_stream_identity", "enabled": True},
        ],
    )
    results = ArchiveTaskProvider(config).detect_targets([str(path)])
    return [item for item in results if item.decision.should_extract]


@pytest.mark.parametrize("archive_format", ARCHIVE_FORMATS)
def test_archive_detection_does_not_depend_on_extension(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"chaos_{archive_format.replace('.', '_')}",
        archive_format,
        disguise_ext=".unrelated",
    )

    detected = _detected(case.entry_path)

    assert len(detected) == 1
    assert detected[0].fact_bag.get("file.detected_ext")


def test_split_7z_is_analyzed_as_one_logical_stream_with_chaotic_names(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "split_7z_chaos",
        "7z",
        split=True,
        disguise_ext=".unrelated",
    )

    detected = _detected(case.entry_path)

    assert len(detected) == 1
    bag = detected[0].fact_bag
    assert bag.get("file.detected_ext") == ".7z"
    assert len(bag.get("candidate.member_paths") or []) > 1


@pytest.mark.parametrize("archive_format", ["zip", "7z"])
def test_archive_embedded_in_middle_is_found_by_selected_embedded_deep_scan(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path, f"middle_{archive_format}", archive_format)
    archive_bytes = case.entry_path.read_bytes()
    carrier = tmp_path / f"middle_{archive_format}.video"
    prefix = b"carrier-prefix\0" + b"A" * (2 * 1024 * 1024)
    suffix = b"carrier-suffix\0" + b"B" * (2 * 1024 * 1024)
    carrier.write_bytes(prefix + archive_bytes + suffix)

    detected = _detected(carrier)

    assert len(detected) == 1
    bag = detected[0].fact_bag
    embedded = bag.get("embedded_archive.analysis")
    assert embedded["complete"] is True
    assert embedded["candidates"][0]["format"] == archive_format
    assert embedded["candidates"][0]["offset"] == len(prefix)


@pytest.mark.skipif(get_optional_rar() is None, reason="RAR generator is not configured")
def test_header_encrypted_rar_is_confirmed_from_crc_valid_encryption_header(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "encrypted_rar_chaos",
        "rar",
        password="secret",
        disguise_ext=".unrelated",
    )

    detected = _detected(case.entry_path)

    assert len(detected) == 1
    bag = detected[0].fact_bag
    assert bag.get("file.detected_ext") == ".rar"
    assert bag.get("rar.structure", {}).get("magic_matched") is True


def test_signature_bytes_without_valid_structure_are_not_accepted(tmp_path):
    fake = tmp_path / "random.payload"
    fake.write_bytes(b"noise" * 100 + b"7z\xbc\xaf\x27\x1c" + b"not-a-seven-zip" * 100)

    assert _detected(fake) == []
