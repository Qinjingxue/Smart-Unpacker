import struct
import zlib

from pathlib import Path

from sunpack_native import seven_zip_next_header_field_repair


def test_next_header_field_repair_rejects_nonterminated_crc_collision_candidate(tmp_path):
    fake = bytearray(b"\x01" + bytes((index * 37) % 255 or 1 for index in range(1, 5000)))
    fake[-1] = 0x41
    stored_crc = zlib.crc32(fake) & 0xFFFFFFFF
    real_next_header = b"\x17" + b"\0" * 35
    stored_offset = len(fake) + 32
    start_header = struct.pack("<QQI", stored_offset, len(real_next_header), stored_crc)
    data = (
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + bytes(fake)
        + (b"x" * 32)
        + real_next_header
    )

    result = seven_zip_next_header_field_repair({"kind": "bytes", "data": bytes(data)}, str(tmp_path), 512, 1024 * 1024)

    assert result["status"] == "unrepairable"


def test_next_header_field_repair_keeps_compact_fixture_candidate(tmp_path):
    gap = b"abcdefgh"
    next_header = b"\x01\x02\x03"
    start_header = struct.pack("<QQI", 0, len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    data = bytearray(
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + gap
        + next_header
    )

    result = seven_zip_next_header_field_repair({"kind": "bytes", "data": bytes(data)}, str(tmp_path), 512, 1024 * 1024)

    assert result["status"] == "repaired"
    repaired = Path(result["selected_path"]).read_bytes()
    assert struct.unpack_from("<Q", repaired, 12)[0] == len(gap)
    assert struct.unpack_from("<Q", repaired, 20)[0] == len(next_header)
