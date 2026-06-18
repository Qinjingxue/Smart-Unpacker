from pathlib import Path

import pytest

from sunpack.detection.scheduler import DetectionScheduler
from tests.helpers.real_archives import ArchiveFixtureFactory
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
    results = DetectionScheduler({}).detect_targets([str(path)])
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
    assert detected[0].fact_bag.get("analysis.selected_format") or detected[0].fact_bag.get("file.detected_ext")


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
    assert bag.get("analysis.selected_format") == "7z"
    assert len(bag.get("candidate.member_paths") or []) > 1


@pytest.mark.parametrize("archive_format", ["zip", "7z"])
def test_archive_embedded_in_middle_is_found_by_bounded_structural_rescue(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path, f"middle_{archive_format}", archive_format)
    archive_bytes = case.entry_path.read_bytes()
    carrier = tmp_path / f"middle_{archive_format}.video"
    prefix = b"carrier-prefix\0" + b"A" * (2 * 1024 * 1024)
    suffix = b"carrier-suffix\0" + b"B" * (2 * 1024 * 1024)
    carrier.write_bytes(prefix + archive_bytes + suffix)

    detected = _detected(carrier)

    assert len(detected) == 1
    bag = detected[0].fact_bag
    assert bag.get("analysis.selected_format") == archive_format
    assert bag.get("file.probe_offset") == len(prefix)
    assert bag.get("analysis.prepass").get("full_scan_complete") is True


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
    assert bag.get("analysis.selected_format") == "rar"
    evidence = next(item for item in bag.get("analysis.prepass")["hits"] if item["name"] == "rar5")
    assert evidence["offset"] == 0


def test_signature_bytes_without_valid_structure_are_not_rescued(tmp_path):
    fake = tmp_path / "random.payload"
    fake.write_bytes(b"noise" * 100 + b"7z\xbc\xaf\x27\x1c" + b"not-a-seven-zip" * 100)

    assert _detected(fake) == []
