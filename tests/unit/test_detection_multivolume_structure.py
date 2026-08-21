import struct
from binascii import crc32

from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.format_structure.rar import process_rar_structure
from sunpack.detection.pipeline.processors.modules.format_structure.seven_zip import process_seven_zip_structure
from sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd import process_zip_eocd_structure


def _context(paths, style, output_fact):
    bag = FactBag()
    bag.set("file.path", str(paths[0]))
    bag.set("candidate.member_paths", [str(path) for path in paths])
    bag.set("relation.split_volumes", [
        {"path": str(path), "number": index + 1, "style": style}
        for index, path in enumerate(paths)
    ])
    return FactProcessorContext(bag, output_fact, {}, {}, None)


def _seven_zip_bytes():
    next_header = b"\x01\x00"
    start_header = struct.pack("<QQI", 0, len(next_header), crc32(next_header) & 0xFFFFFFFF)
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", crc32(start_header) & 0xFFFFFFFF) + start_header + next_header


def _rar4_block(header_type, flags=0):
    body = bytes([header_type]) + struct.pack("<HH", flags, 7)
    return struct.pack("<H", crc32(body) & 0xFFFF) + body


def test_seven_zip_detection_reads_next_header_from_later_volume(tmp_path):
    archive = _seven_zip_bytes()
    parts = [tmp_path / "a.7z.001", tmp_path / "a.7z.002"]
    parts[0].write_bytes(archive[:32])
    parts[1].write_bytes(archive[32:])

    result = process_seven_zip_structure(_context(parts, "numeric_suffix", "7z.structure"))

    assert result["plausible"] is True
    assert result["strong_accept"] is True
    assert result["next_header_semantic_ok"] is True


def test_seven_zip_detection_preserves_magic_for_truncated_logical_volume(tmp_path):
    part = tmp_path / "missing.7z.001"
    part.write_bytes(b"7z\xbc\xaf\x27\x1cpartial")

    result = process_seven_zip_structure(_context([part], "numeric_suffix", "7z.structure"))

    assert result["magic_matched"] is True
    assert result["plausible"] is False
    assert result["error"] in {"file_too_small", "unsupported_version"}


def test_rar_detection_walks_blocks_across_raw_volume_boundary(tmp_path):
    archive = b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)
    parts = [tmp_path / "a.rar.001", tmp_path / "a.rar.002"]
    parts[0].write_bytes(archive[:14])
    parts[1].write_bytes(archive[14:])

    result = process_rar_structure(_context(parts, "numeric_suffix", "rar.structure"))

    assert result["plausible"] is True
    assert result["strong_accept"] is True
    assert result["block_walk_ok"] is True


def test_rar4_header_encryption_is_accepted_by_rust_probe(tmp_path):
    # RAR4 -hp leaves the plaintext main header and marks every following
    # header as encrypted.  The following bytes are ciphertext and must not
    # be interpreted as another RAR block.
    archive = (
        b"Rar!\x1a\x07\x00"
        + _rar4_block(0x73, flags=0x0080)
        + b"\xd6\xd3\x77\xb9\xf7\x5d\xe8"
    )
    part = tmp_path / "encrypted.rar.001"
    part.write_bytes(archive)

    result = process_rar_structure(_context([part], "numeric_suffix", "rar.structure"))

    assert result["magic_matched"] is True
    assert result["header_crc_ok"] is True
    assert result["header_encrypted"] is True
    assert result["password_required"] is True
    assert result["strong_accept"] is True
    assert result["block_walk_ok"] is True
    assert result["error"] == ""


def test_zip_detection_finds_directory_and_eocd_in_later_volume(tmp_path):
    name = b"a"
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, 1, 0) + name
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0,
    ) + name
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    parts = [tmp_path / "a.zip.0000", tmp_path / "a.zip.0001"]
    parts[0].write_bytes(local + central[:5])
    parts[1].write_bytes(central[5:] + eocd)

    result = process_zip_eocd_structure(_context(parts, "zip_zero_numbered", "zip.eocd_structure"))

    assert result["plausible"] is True
    assert result["central_directory_walk_ok"] is True
    assert result["local_header_links_ok"] is True
