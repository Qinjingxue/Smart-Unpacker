import struct
import zlib

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.processors.modules.format_structure.rar import inspect_rar_structure
from smart_unpacker.detection.pipeline.processors.modules.format_structure.seven_zip import inspect_seven_zip_structure
from tests.helpers.detection_config import with_detection_pipeline


def _seven_zip_header(next_header: bytes = b"\x17\x06") -> bytes:
    next_header_offset = 0
    next_header_size = len(next_header)
    next_header_crc = zlib.crc32(next_header) & 0xFFFFFFFF
    start_header = struct.pack("<QQI", next_header_offset, next_header_size, next_header_crc)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", start_crc) + start_header + next_header


def _rar4_header() -> bytes:
    body = bytes([0x73]) + b"\x00\x00" + struct.pack("<H", 7)
    header_crc = zlib.crc32(body) & 0xFFFF
    first_header = struct.pack("<H", header_crc) + body
    return b"Rar!\x1a\x07\x00" + first_header + b"payload"


def _rar5_header() -> bytes:
    # CRC32 + header size vint + main header type vint.
    header_data = b"\x02" + b"\x01"
    first_header = struct.pack("<I", zlib.crc32(header_data) & 0xFFFFFFFF) + header_data
    return b"Rar!\x1a\x07\x01\x00" + first_header + b"payload"


def _config(rule_name: str):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": rule_name, "enabled": True},
    ])


def _precheck_config(rule_name: str):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, precheck=[
        {"name": rule_name, "enabled": True},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": []}]},
    ])


def test_seven_zip_structure_identity_scores_crc_valid_header(tmp_path):
    target = tmp_path / "payload.bin"
    target.write_bytes(_seven_zip_header())

    structure = inspect_seven_zip_structure(str(target))
    assert structure["plausible"] is True
    assert structure["start_header_crc_ok"] is True
    assert structure["next_header_crc_ok"] is True
    assert structure["strong_accept"] is True

    bag = FactBag()
    decision = DetectionScheduler(_config("seven_zip_structure_identity")).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.matched_rules == ["seven_zip_structure_identity"]
    assert bag.get("file.detected_ext") == ".7z"


def test_seven_zip_structure_accept_precheck_requires_next_header_crc(tmp_path):
    target = tmp_path / "payload.bin"
    target.write_bytes(_seven_zip_header())

    bag = FactBag()
    decision = DetectionScheduler(_precheck_config("seven_zip_structure_accept")).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.decision_stage == "precheck"
    assert decision.matched_rules == ["seven_zip_structure_accept"]
    assert bag.get("file.detected_ext") == ".7z"


def test_seven_zip_structure_accept_passes_on_bad_next_header_crc(tmp_path):
    target = tmp_path / "bad-next-header.7z"
    data = bytearray(_seven_zip_header())
    data[-1] ^= 0xFF
    target.write_bytes(bytes(data))

    structure = inspect_seven_zip_structure(str(target))
    assert structure["plausible"] is True
    assert structure["next_header_crc_ok"] is False
    assert structure["strong_accept"] is False

    decision = DetectionScheduler(_precheck_config("seven_zip_structure_accept")).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.decision_stage == "scoring"


def test_seven_zip_structure_rejects_bad_start_header_crc(tmp_path):
    target = tmp_path / "bad.7z"
    data = bytearray(_seven_zip_header())
    data[8] ^= 0xFF
    target.write_bytes(bytes(data))

    structure = inspect_seven_zip_structure(str(target))
    assert structure["plausible"] is False
    assert structure["error"] == "start_header_crc_mismatch"


def test_rar_structure_identity_scores_rar4_and_rar5_headers(tmp_path):
    samples = {
        "rar4.bin": (4, _rar4_header()),
        "rar5.bin": (5, _rar5_header()),
    }
    for filename, (version, content) in samples.items():
        target = tmp_path / filename
        target.write_bytes(content)

        structure = inspect_rar_structure(str(target))
        assert structure["plausible"] is True
        assert structure["version"] == version
        assert structure["header_crc_ok"] is True
        assert structure["strong_accept"] is True

        bag = FactBag()
        decision = DetectionScheduler(_config("rar_structure_identity")).evaluate(bag, FactProvider(str(target)))

        assert decision.should_extract is True
        assert decision.matched_rules == ["rar_structure_identity"]
        assert bag.get("file.detected_ext") == ".rar"


def test_rar_structure_accept_precheck_scores_rar4_and_rar5_headers(tmp_path):
    for filename, content in {"rar4.bin": _rar4_header(), "rar5.bin": _rar5_header()}.items():
        target = tmp_path / filename
        target.write_bytes(content)

        bag = FactBag()
        decision = DetectionScheduler(_precheck_config("rar_structure_accept")).evaluate(bag, FactProvider(str(target)))

        assert decision.should_extract is True
        assert decision.decision_stage == "precheck"
        assert decision.matched_rules == ["rar_structure_accept"]
        assert bag.get("file.detected_ext") == ".rar"


def test_rar_structure_accept_passes_on_bad_header_crc(tmp_path):
    target = tmp_path / "bad.rar"
    data = bytearray(_rar5_header())
    data[len(b"Rar!\x1a\x07\x01\x00")] ^= 0xFF
    target.write_bytes(bytes(data))

    structure = inspect_rar_structure(str(target))
    assert structure["plausible"] is True
    assert structure["header_crc_ok"] is False
    assert structure["strong_accept"] is False

    decision = DetectionScheduler(_precheck_config("rar_structure_accept")).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is False
    assert decision.decision_stage == "scoring"


def test_rar_structure_rejects_unknown_rar4_first_header_type(tmp_path):
    target = tmp_path / "bad.rar"
    first_header = b"\x00\x00" + bytes([0x01]) + b"\x00\x00" + struct.pack("<H", 7)
    target.write_bytes(b"Rar!\x1a\x07\x00" + first_header)

    structure = inspect_rar_structure(str(target))
    assert structure["plausible"] is False
    assert structure["error"] == "rar4_unknown_first_header_type"
