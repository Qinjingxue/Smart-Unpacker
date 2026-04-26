import struct
import zipfile

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.processors.modules.embedded_payload.pe_overlay import inspect_pe_overlay_structure
from tests.helpers.detection_config import with_detection_pipeline


def _minimal_pe(overlay: bytes = b"") -> bytes:
    section_raw_offset = 0x200
    section_raw_size = 0x200
    pe_offset = 0x80
    optional_header_size = 0xE0
    data = bytearray(section_raw_offset + section_raw_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    coff_offset = pe_offset + 4
    struct.pack_into("<H", data, coff_offset, 0x8664)
    struct.pack_into("<H", data, coff_offset + 2, 1)
    struct.pack_into("<H", data, coff_offset + 16, optional_header_size)
    struct.pack_into("<H", data, coff_offset + 18, 0x0002)
    optional_offset = pe_offset + 24
    struct.pack_into("<H", data, optional_offset, 0x20B)
    section_offset = optional_offset + optional_header_size
    data[section_offset:section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, section_offset + 16, section_raw_size)
    struct.pack_into("<I", data, section_offset + 20, section_raw_offset)
    return bytes(data) + overlay


def _config():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": "embedded_payload_identity", "enabled": True},
    ])


def test_pe_overlay_structure_detects_archive_at_overlay_start(tmp_path):
    target = tmp_path / "setup.exe"
    target.write_bytes(_minimal_pe(b"7z\xbc\xaf\x27\x1c" + b"x" * 64))

    structure = inspect_pe_overlay_structure(str(target))
    assert structure["is_pe"] is True
    assert structure["has_overlay"] is True
    assert structure["archive_like"] is True
    assert structure["detected_ext"] == ".7z"
    assert structure["offset_delta_from_overlay"] == 0

    bag = FactBag()
    decision = DetectionScheduler(_config()).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.decision == "maybe_archive"
    assert decision.total_score == 5
    assert decision.matched_rules == ["embedded_payload_identity"]
    assert bag.get("file.container_type") == "pe"
    assert bag.get("file.detected_ext") == ".7z"
    assert bag.get("file.embedded_archive_found") is True


def test_pe_overlay_structure_detects_plausible_zip_overlay(tmp_path):
    zip_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("hello.txt", "hello")
    target = tmp_path / "setup.exe"
    target.write_bytes(_minimal_pe(zip_path.read_bytes()))

    structure = inspect_pe_overlay_structure(str(target))
    assert structure["archive_like"] is True
    assert structure["detected_ext"] == ".zip"
    assert structure["zip_local_header"]["plausible"] is True


def test_pe_overlay_structure_ignores_archive_magic_inside_pe_body(tmp_path):
    data = bytearray(_minimal_pe())
    data[0x260:0x266] = b"7z\xbc\xaf\x27\x1c"
    target = tmp_path / "ordinary.exe"
    target.write_bytes(bytes(data))

    structure = inspect_pe_overlay_structure(str(target))
    assert structure["is_pe"] is True
    assert structure["has_overlay"] is False
    assert structure["archive_like"] is False

    decision = DetectionScheduler(_config()).evaluate(FactBag(), FactProvider(str(target)))
    assert decision.total_score == 0
