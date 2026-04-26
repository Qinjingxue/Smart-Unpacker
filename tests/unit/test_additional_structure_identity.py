import bz2
import gzip
import lzma
import struct
import zlib

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.processors.modules.format_structure.archive_container import (
    inspect_archive_container_structure,
)
from smart_unpacker.detection.pipeline.processors.modules.format_structure.compression_stream import (
    inspect_compression_stream_structure,
)
from tests.helpers.detection_config import with_detection_pipeline


def _score_config(rule_name: str):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": rule_name, "enabled": True},
    ])


def _evaluate(path, rule_name: str):
    bag = FactBag()
    decision = DetectionScheduler(_score_config(rule_name)).evaluate(bag, FactProvider(str(path)))
    return bag, decision


def _cpio_newc(name: str, payload: bytes = b"payload") -> bytes:
    encoded_name = name.encode("utf-8") + b"\x00"
    fields = [
        "070701",
        f"{1:08x}",
        f"{0o100644:08x}",
        f"{0:08x}",
        f"{0:08x}",
        f"{1:08x}",
        f"{0:08x}",
        f"{len(payload):08x}",
        f"{0:08x}",
        f"{0:08x}",
        f"{0:08x}",
        f"{0:08x}",
        f"{len(encoded_name):08x}",
        f"{0:08x}",
    ]
    header = "".join(fields).encode("ascii")
    name_pad = b"\x00" * ((4 - (len(header) + len(encoded_name)) % 4) % 4)
    data_pad = b"\x00" * ((4 - len(payload) % 4) % 4)
    return header + encoded_name + name_pad + payload + data_pad


def _cab_header() -> bytes:
    header = bytearray(64)
    header[:8] = b"MSCF\x00\x00\x00\x00"
    struct.pack_into("<I", header, 8, len(header))
    struct.pack_into("<I", header, 16, 44)
    header[24] = 3
    header[25] = 1
    struct.pack_into("<H", header, 26, 1)
    struct.pack_into("<H", header, 28, 1)
    return bytes(header)


def _arj_header() -> bytes:
    header_data = bytes([30]) + b"\x00" * 29
    return b"\x60\xea" + struct.pack("<H", len(header_data)) + header_data + struct.pack(
        "<I",
        zlib.crc32(header_data) & 0xFFFFFFFF,
    )


def test_compression_stream_structure_detects_gzip_bzip2_xz_and_zstd(tmp_path):
    samples = {
        "payload.gz": ("gzip", ".gz", gzip.compress(b"payload")),
        "payload.bz2": ("bzip2", ".bz2", bz2.compress(b"payload")),
        "payload.xz": ("xz", ".xz", lzma.compress(b"payload", format=lzma.FORMAT_XZ)),
        "payload.zst": ("zstd", ".zst", b"\x28\xb5\x2f\xfd\x00\x00payload"),
    }

    for filename, (expected_format, expected_ext, content) in samples.items():
        target = tmp_path / filename
        target.write_bytes(content)

        structure = inspect_compression_stream_structure(str(target))
        assert structure["plausible"] is True
        assert structure["format"] == expected_format
        assert structure["detected_ext"] == expected_ext

        bag, decision = _evaluate(target, "compression_stream_identity")
        assert decision.should_extract is True
        assert decision.matched_rules == ["compression_stream_identity"]
        assert bag.get("file.detected_ext") == expected_ext


def test_compression_stream_structure_rejects_invalid_reserved_bits(tmp_path):
    target = tmp_path / "bad.gz"
    target.write_bytes(b"\x1f\x8b\x08\xe0" + b"\x00" * 32)

    structure = inspect_compression_stream_structure(str(target))
    assert structure["plausible"] is False
    assert structure["error"] == "gzip_reserved_flags_set"


def test_archive_container_structure_detects_cab_arj_and_cpio(tmp_path):
    samples = {
        "payload.cab": ("cab", ".cab", _cab_header()),
        "payload.arj": ("arj", ".arj", _arj_header()),
        "payload.cpio": ("cpio", ".cpio", _cpio_newc("hello.txt")),
    }

    for filename, (expected_format, expected_ext, content) in samples.items():
        target = tmp_path / filename
        target.write_bytes(content)

        structure = inspect_archive_container_structure(str(target))
        assert structure["plausible"] is True
        assert structure["format"] == expected_format
        assert structure["detected_ext"] == expected_ext

        bag, decision = _evaluate(target, "archive_container_identity")
        assert decision.should_extract is True
        assert decision.matched_rules == ["archive_container_identity"]
        assert bag.get("file.detected_ext") == expected_ext


def test_archive_container_structure_rejects_bad_arj_crc(tmp_path):
    target = tmp_path / "bad.arj"
    data = bytearray(_arj_header())
    data[-1] ^= 0xFF
    target.write_bytes(bytes(data))

    structure = inspect_archive_container_structure(str(target))
    assert structure["plausible"] is False
    assert structure["error"] == "arj_header_crc_mismatch"
