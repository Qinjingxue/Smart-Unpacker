from pathlib import Path
import struct
from binascii import crc32

import pytest

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_probe import detect_archive_hits
from tests.helpers.detection_probe import detection_pipeline_config
from tests.helpers.real_archives import ArchiveFixtureFactory
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


def test_header_encrypted_rar4_primary_uses_normal_precheck(tmp_path):
    body = bytes([0x73]) + struct.pack("<HH", 0x0080, 7)
    main_header = struct.pack("<H", crc32(body) & 0xFFFF) + body
    path = tmp_path / "header_encrypted_rar4.rar"
    path.write_bytes(
        b"Rar!\x1a\x07\x00"
        + main_header
        + b"\xd6\xd3\x77\xb9\xf7\x5d\xe8"
    )

    detections = ArchiveTaskProvider(detection_pipeline_config()).detect_targets([str(path)])

    assert len(detections) == 1
    detection = detections[0]
    assert detection.decision.should_extract is True
    assert detection.decision.deciding_rule == "rar_structure_accept"
    structure = detection.fact_bag.get("rar.structure") or {}
    assert structure["header_encrypted"] is True
    assert structure["password_required"] is True
    assert structure["strong_accept"] is True


def test_signature_bytes_without_valid_structure_are_not_accepted(tmp_path):
    fake = tmp_path / "random.payload"
    fake.write_bytes(b"noise" * 100 + b"7z\xbc\xaf\x27\x1c" + b"not-a-seven-zip" * 100)

    assert detect_archive_hits(fake) == []
