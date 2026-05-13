import struct
import subprocess
import zlib

from pathlib import Path

import pytest
from sunpack.repair.pipeline.modules.seven_zip.atomic import (
    SevenZipQuarantineBadFolder,
    SevenZipSalvageNonSolidEntries,
    SevenZipSalvageSolidPrefix,
)

sunpack_native = pytest.importorskip("sunpack_native")
seven_zip_atomic_repair = getattr(sunpack_native, "seven_zip_atomic_repair", None)
seven_zip_scan_source = getattr(sunpack_native, "seven_zip_scan_source", None)
if seven_zip_atomic_repair is None:
    pytest.skip("sunpack_native seven_zip_atomic_repair API is not installed", allow_module_level=True)


def _seven_zip_tool() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / "tools" / "7z.exe",
        Path("tools") / "7z.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    pytest.skip("7z.exe is required for this test")


def _sz_vint(value: int) -> bytes:
    first = 0
    mask = 0x80
    extra = 0
    while extra < 8:
        if value < (1 << (7 * (extra + 1))):
            first |= value >> (8 * extra)
            break
        first |= mask
        mask >>= 1
        extra += 1
    out = bytearray([first & 0xFF])
    while extra:
        out.append(value & 0xFF)
        value >>= 8
        extra -= 1
    return bytes(out)


def _packinfo_header(payload: bytes, *, pack_pos: int = 0, pack_size: int | None = None, crc: int | None = None) -> bytes:
    if pack_size is None:
        pack_size = len(payload)
    if crc is None:
        crc = zlib.crc32(payload) & 0xFFFFFFFF
    return b"".join(
        [
            b"\x01",  # Header
            b"\x04",  # MainStreamsInfo
            b"\x06",  # PackInfo
            _sz_vint(pack_pos),
            _sz_vint(1),
            b"\x09",
            _sz_vint(pack_size),
            b"\x0a",
            b"\x01",  # all CRCs defined
            struct.pack("<I", crc),
            b"\x00",  # End PackInfo
            b"\x00",  # End MainStreamsInfo
            b"\x05",  # FilesInfo
            _sz_vint(0),
            b"\x00",  # End FilesInfo
            b"\x00",  # End Header
        ]
    )


def _encoded_packinfo_header(payload: bytes, *, crc: int | None = None) -> bytes:
    if crc is None:
        crc = zlib.crc32(payload) & 0xFFFFFFFF
    return b"".join(
        [
            b"\x17",  # EncodedHeader
            b"\x06",  # PackInfo
            _sz_vint(0),
            _sz_vint(1),
            b"\x09",
            _sz_vint(len(payload)),
            b"\x0a",
            b"\x01",
            struct.pack("<I", crc),
            b"\x00",  # End PackInfo
            b"\x00",  # End StreamsInfo
        ]
    )


def _seven_zip_with_header(payload: bytes, header: bytes) -> bytes:
    start_header = struct.pack("<QQI", len(payload), len(header), zlib.crc32(header) & 0xFFFFFFFF)
    return (
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + payload
        + header
    )


def test_next_header_offset_rejects_nonterminated_crc_collision_candidate(tmp_path):
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

    result = seven_zip_atomic_repair({"kind": "bytes", "data": bytes(data)}, str(tmp_path), "next_header_offset", 512, 1024 * 1024)

    assert result["status"] == "unrepairable"


def test_next_header_offset_keeps_compact_fixture_candidate(tmp_path):
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

    result = seven_zip_atomic_repair({"kind": "bytes", "data": bytes(data)}, str(tmp_path), "next_header_offset", 512, 1024 * 1024)

    assert result["status"] == "repaired"
    repaired = Path(result["selected_path"]).read_bytes()
    assert struct.unpack_from("<Q", repaired, 12)[0] == len(gap)
    assert struct.unpack_from("<Q", repaired, 20)[0] == len(next_header)


def test_signature_header_version_repairs_only_version_bytes(tmp_path):
    payload = b"payload bytes"
    data = bytearray(_seven_zip_with_header(payload, _packinfo_header(payload)))
    data[6] = 1
    data[7] = 99

    result = seven_zip_atomic_repair({"kind": "bytes", "data": bytes(data)}, str(tmp_path), "signature_header_version")

    assert result["status"] == "repaired"
    assert result["native_target"] == "signature_header_version"
    assert "fixed_field=signature_header_version" in result["patch_facts"]
    repaired = Path(result["selected_path"]).read_bytes()
    assert repaired[6:8] == b"\x00\x04"
    assert repaired[:6] == data[:6]
    assert repaired[8:] == data[8:]


def test_seven_zip_scan_reports_password_presence_without_plaintext():
    payload = b"payload bytes"
    data = _seven_zip_with_header(payload, _packinfo_header(payload))

    scan = seven_zip_scan_source({"kind": "bytes", "data": data, "password": "secret"})

    assert scan["password_present"] is True
    assert scan["structure"]["password_present"] is True
    assert "secret" not in repr(scan)


def test_pack_stream_offset_repairs_header_graph_ast(tmp_path):
    payload = b"payload bytes"
    data = _seven_zip_with_header(payload, _packinfo_header(payload, pack_pos=3))

    result = seven_zip_atomic_repair({"kind": "bytes", "data": data}, str(tmp_path), "pack_stream_offset")

    assert result["status"] == "repaired"
    assert result["native_target"] == "pack_stream_offset"
    assert "fixed_field=pack_stream_offset" in result["patch_facts"]
    repaired = Path(result["selected_path"]).read_bytes()
    scan = seven_zip_scan_source({"kind": "bytes", "data": repaired})
    assert "pack_stream_offset_bad" not in scan["route_evidence_flags"]
    assert scan["structure"]["pack_stream_offset"] == 0


def test_pack_stream_size_repairs_header_graph_ast(tmp_path):
    payload = b"payload bytes"
    data = _seven_zip_with_header(payload, _packinfo_header(payload, pack_size=1))

    result = seven_zip_atomic_repair({"kind": "bytes", "data": data}, str(tmp_path), "pack_stream_size")

    assert result["status"] == "repaired"
    assert result["native_target"] == "pack_stream_size"
    assert "fixed_field=pack_stream_size" in result["patch_facts"]
    repaired = Path(result["selected_path"]).read_bytes()
    scan = seven_zip_scan_source({"kind": "bytes", "data": repaired})
    assert "pack_stream_size_bad" not in scan["route_evidence_flags"]
    assert scan["structure"]["pack_stream_sizes"] == [len(payload)]


def test_stream_crc_repairs_header_graph_ast(tmp_path):
    payload = b"payload bytes"
    data = _seven_zip_with_header(payload, _packinfo_header(payload, crc=0))

    result = seven_zip_atomic_repair({"kind": "bytes", "data": data}, str(tmp_path), "stream_crc")

    assert result["status"] == "repaired"
    assert result["native_target"] == "stream_crc"
    assert "stream_crc_recomputed_from_payload" in result["patch_facts"]
    repaired = Path(result["selected_path"]).read_bytes()
    scan = seven_zip_scan_source({"kind": "bytes", "data": repaired})
    assert "stream_crc_bad" not in scan["route_evidence_flags"]
    assert scan["structure"]["stored_stream_crc"] == zlib.crc32(payload) & 0xFFFFFFFF


def test_non_solid_salvage_outputs_same_format_7z_partial_container(tmp_path):
    seven_zip = _seven_zip_tool()
    source = tmp_path / "src"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (source / "alpha.txt").write_text("alpha payload", encoding="utf-8")
    (nested / "beta.txt").write_bytes(b"beta payload")
    (source / "empty.bin").write_bytes(b"")
    archive = tmp_path / "input.7z"
    subprocess.run(
        [
            str(seven_zip),
            "a",
            "-t7z",
            "-mx=0",
            "-ms=off",
            str(archive),
            "alpha.txt",
            "nested\\beta.txt",
            "empty.bin",
        ],
        cwd=source,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    result = seven_zip_atomic_repair({"kind": "file", "path": str(archive)}, str(tmp_path), "non_solid_entries")

    assert result["status"] == "partial"
    assert result["native_target"] == "non_solid_entries"
    assert result["format"] == "7z"
    assert result["selected_path"].endswith(".7z")
    assert "output_container=7z" in result["patch_facts"]
    assert "output_container=zip" not in result["patch_facts"]
    assert "repacked_recovered_entries_as_7z" in result["patch_facts"]
    assert result["recovered_entry_count"] == 3

    output_dir = tmp_path / "out"
    subprocess.run(
        [str(seven_zip), "x", "-y", result["selected_path"], f"-o{output_dir}"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert (output_dir / "alpha.txt").read_text(encoding="utf-8") == "alpha payload"
    assert (output_dir / "nested" / "beta.txt").read_bytes() == b"beta payload"
    assert (output_dir / "empty.bin").exists()
    assert (output_dir / "empty.bin").stat().st_size == 0


def test_seven_zip_salvage_modules_advertise_same_format_output():
    assert SevenZipSalvageNonSolidEntries().format_hint == "7z"
    assert SevenZipSalvageSolidPrefix().format_hint == "7z"
    assert SevenZipQuarantineBadFolder().format_hint == "7z"


def test_encoded_header_stream_crc_repairs_header_graph_ast(tmp_path):
    payload = b"encoded header payload"
    data = _seven_zip_with_header(payload, _encoded_packinfo_header(payload, crc=0))

    result = seven_zip_atomic_repair({"kind": "bytes", "data": data}, str(tmp_path), "encoded_header_stream_crc")

    assert result["status"] == "repaired"
    assert result["native_target"] == "encoded_header_stream_crc"
    assert "encoded_header_stream_crc_recomputed_from_payload" in result["patch_facts"]
    repaired = Path(result["selected_path"]).read_bytes()
    scan = seven_zip_scan_source({"kind": "bytes", "data": repaired})
    assert "encoded_header_stream_crc_bad" not in scan["route_evidence_flags"]
    assert scan["structure"]["stored_stream_crc"] == zlib.crc32(payload) & 0xFFFFFFFF


@pytest.mark.parametrize(
    "target",
    [
        "encoded_header_decode",
        "bad_folder_quarantine",
        "empty_stream_flags",
        "encoded_header_stream_crc",
        "unpack_size",
        "folder_bind_pairs",
        "folder_stream_counts",
        "file_count_metadata",
        "file_names_utf16",
        "unreferenced_folder",
        "unreferenced_file_record",
        "stream_crc_defined_flag",
    ],
)
def test_metadata_targets_return_structured_no_candidate(tmp_path, target):
    next_header = b"\x01"
    gap = b"abcde"
    start_header = struct.pack("<QQI", len(gap), len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    data = (
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + gap
        + next_header
    )

    result = seven_zip_atomic_repair({"kind": "bytes", "data": data}, str(tmp_path), target)

    assert result["native_target"] == target
    assert result["candidate_status"] == "no_candidate"
    assert result["residual_facts"]
