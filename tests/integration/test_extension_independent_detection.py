from pathlib import Path

import pytest

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_probe import detect_archive_hits
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar


@pytest.mark.parametrize("archive_format", ["zip", "7z"])
def test_archive_embedded_in_middle_is_found_by_selected_embedded_deep_scan(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path, f"middle_{archive_format}", archive_format)
    archive_bytes = case.entry_path.read_bytes()
    carrier = tmp_path / f"middle_{archive_format}.video"
    prefix = b"carrier-prefix\0" + b"A" * (2 * 1024 * 1024)
    suffix = b"carrier-suffix\0" + b"B" * (2 * 1024 * 1024)
    carrier.write_bytes(prefix + archive_bytes + suffix)

    detected = detect_archive_hits(carrier)

    assert len(detected) == 1
    bag = detected[0].fact_bag
    embedded = bag.get("embedded_archive.analysis")
    assert embedded["complete"] is True
    assert embedded["candidates"][0]["format"] == archive_format
    assert embedded["candidates"][0]["offset"] == len(prefix)


def test_mp4_like_prefix_does_not_override_verified_appended_zip(tmp_path):
    case = ArchiveFixtureFactory().create(tmp_path, "appended_zip", "zip")
    prefix = bytearray(512)
    prefix[:32] = b"\x00\x00\x00 ftypisom\x00\x00\x02\x00isomiso2avc1mp41"
    prefix[100] = 1
    prefix[116] = 0x40
    prefix[147] = 3
    prefix[148:156] = b"\x00#\x1e\xfctrak"
    carrier = tmp_path / "video.mp4"
    carrier.write_bytes(prefix + case.entry_path.read_bytes())
    config = with_detection_pipeline(
        {"thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3}},
        precheck=[
            {"name": "zip_structure_accept", "enabled": True},
            {"name": "tar_structure_accept", "enabled": True},
        ],
        scoring=[
            {"name": "zip_structure_identity", "enabled": True},
            {"name": "tar_structure_identity", "enabled": True},
        ],
    )

    detected = [
        item
        for item in ArchiveTaskProvider(config).detect_targets([str(carrier)])
        if item.decision.should_extract
    ]

    assert len(detected) == 1
    result = detected[0]
    assert result.decision.total_score >= 6
    assert result.decision.matched_rules == ["zip_structure_identity"]
    assert result.fact_bag.get("file.detected_ext") == ".zip"
    assert result.fact_bag.get("file.probe_offset") == len(prefix)


@pytest.mark.skipif(get_optional_rar() is None, reason="RAR generator is not configured")
def test_header_encrypted_rar_is_confirmed_from_crc_valid_encryption_header(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "encrypted_rar_chaos",
        "rar",
        password="secret",
        disguise_ext=".unrelated",
    )

    detected = detect_archive_hits(case.entry_path)

    assert len(detected) == 1
    bag = detected[0].fact_bag
    assert bag.get("file.detected_ext") == ".rar"
    assert bag.get("rar.structure", {}).get("magic_matched") is True


def test_signature_bytes_without_valid_structure_are_not_accepted(tmp_path):
    fake = tmp_path / "random.payload"
    fake.write_bytes(b"noise" * 100 + b"7z\xbc\xaf\x27\x1c" + b"not-a-seven-zip" * 100)

    assert detect_archive_hits(fake) == []
