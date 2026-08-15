import struct
from binascii import crc32

from sunpack.analysis import ArchiveAnalyzer, RarProbeOptions


def _rar4_block(header_type: int, flags: int = 0) -> bytes:
    body = bytes([header_type]) + struct.pack("<HH", flags, 7)
    return struct.pack("<H", crc32(body) & 0xFFFF) + body


def _rar5_block(header_type: int, *, corrupt_crc: bool = False) -> bytes:
    header = bytes([header_type, 0, 0])
    size = bytes([len(header)])
    checksum = crc32(size + header) & 0xFFFFFFFF
    if corrupt_crc:
        checksum ^= 1
    return checksum.to_bytes(4, "little") + size + header


def test_public_rar_capability_preserves_detection_fields(tmp_path):
    path = tmp_path / "archive.bin"
    path.write_bytes(b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B))

    raw = ArchiveAnalyzer().probe_rar(
        str(path),
        RarProbeOptions(max_blocks_to_walk=2, accept_validated_prefix=True),
    ).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["version"] == 4
    assert raw["first_header_type"] == 0x73
    assert raw["first_header_size"] == 7
    assert raw["header_crc_ok"] is True
    assert raw["second_block_ok"] is True
    assert raw["block_walk_ok"] is True
    assert raw["strong_accept"] is True
    assert raw["detected_ext"] == ".rar"


def test_public_rar_capability_retains_type_and_size_when_crc_is_bad(tmp_path):
    path = tmp_path / "damaged.rar"
    path.write_bytes(b"Rar!\x1a\x07\x01\x00" + _rar5_block(1, corrupt_crc=True))

    raw = ArchiveAnalyzer().probe_rar(str(path)).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["version"] == 5
    assert raw["first_header_type"] == 1
    assert raw["first_header_size"] == 3
    assert raw["header_crc_checked"] is True
    assert raw["header_crc_ok"] is False
    assert raw["strong_accept"] is False
    assert raw["error"] == "rar5_block_crc_mismatch"


def test_public_rar_capability_accepts_crc_protected_encryption_header(tmp_path):
    path = tmp_path / "encrypted.rar"
    path.write_bytes(b"Rar!\x1a\x07\x01\x00" + _rar5_block(4) + b"\x00" * 16)

    raw = ArchiveAnalyzer().probe_rar(str(path)).to_raw_dict()

    assert raw["first_header_type"] == 4
    assert raw["header_crc_ok"] is True
    assert raw["header_encrypted"] is True
    assert raw["password_required"] is True
    assert raw["block_walk_ok"] is True
    assert raw["strong_accept"] is True


def test_public_rar_capability_reports_truncated_block_chain(tmp_path):
    path = tmp_path / "truncated.rar"
    path.write_bytes(b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + b"partial")

    observation = ArchiveAnalyzer().probe_rar(str(path))
    raw = observation.to_raw_dict()

    assert raw["header_crc_ok"] is True
    assert raw["strong_accept"] is False
    assert raw["error"] == "rar4_block_size_out_of_range"
    assert "probably_truncated" in raw["damage_flags"]
    assert observation.boundary_confidence == "low"


def test_public_rar_capability_accepts_header_encrypted_rar4_main_header(tmp_path):
    """RAR4 header encryption (-hp) leaves the main header plaintext but sets
    MHD_PASSWORD (0x0080): every following header is encrypted, so the probe
    must stop at the end of the main header and report a password-protected
    archive instead of misreading the encrypted file header as a truncated
    block chain (regression for embedded rar4-header segments being dropped).
    """
    path = tmp_path / "header_encrypted.rar"
    main_block = _rar4_block(0x73, flags=0x0080)
    encrypted_file_header = b"\xd6\xd3\x77\xb9\xf7\x5d\xe8"  # ciphertext fields
    path.write_bytes(b"Rar!\x1a\x07\x00" + main_block + encrypted_file_header)

    raw = ArchiveAnalyzer().probe_rar(str(path)).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["version"] == 4
    assert raw["first_header_type"] == 0x73
    assert raw["header_crc_checked"] is True
    assert raw["header_crc_ok"] is True
    assert raw["header_encrypted"] is True
    assert raw["password_required"] is True
    assert raw["block_walk_ok"] is True
    assert raw["strong_accept"] is True
    assert raw["error"] == ""
    assert raw["segment_end"] == 0
    assert raw["blocks_checked"] == 1
